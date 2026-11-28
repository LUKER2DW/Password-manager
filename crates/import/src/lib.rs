//! Import from and export to other password managers and browsers.
//!
//! One entry point, [`import`], reads every supported file by its format:
//! - **JSON**: unencrypted exports in the common layout (`.json`)
//! - **KDBX**: KeePass-format databases (`.kdbx`, KDBX 3 and 4), opened with their password;
//!   [`export_kdbx`] writes one (KDBX 4)
//! - **CSV**: exports from browsers and most managers, read by their header row
//! - **CXF**: the FIDO Alliance's Credential Exchange Format (JSON), read and written
//!   ([`export_cxf`])
//! - one-time code keys from authenticator apps: `otpauth://` and `otpauth-migration://`
//!   links and the apps' JSON exports ([`authenticator`])
//!
//! [`Source`] lists where an export can come from, for the app to explain how to make one.
//! On Windows, [`browser`] can also read a browser's own password store directly, when the user
//! asks for it.
//!
//! Importers only produce [`ItemData`]; they never touch the vault or its keys.

pub mod authenticator;
#[cfg(feature = "browser")]
pub mod browser;
mod csv_import;
mod cxf;
mod dates;
mod export;
mod json;
mod kdbx;
mod kdbx_export;

pub use cxf::export_cxf;
pub use export::{
    ExportFormat, ExportReport, InClear, LeftOut, export_csv, export_json, export_report,
    export_sealed,
};
pub use kdbx_export::{KDF as KDBX_KDF, KdfParams as KdbxKdf, export_kdbx};

pub(crate) use csv_import::import_csv;
pub(crate) use json::import_json;
pub(crate) use kdbx::import_kdbx;

/// Reads an export. `password` matters for KDBX databases and password-protected exports,
/// `keyfile` for KDBX only.
pub fn import(
    bytes: &[u8],
    format: Format,
    password: &str,
    keyfile: Option<&[u8]>,
) -> Result<ImportReport, ImportError> {
    match format {
        Format::Json => import_json(bytes),
        Format::Csv => import_csv(bytes),
        Format::Kdbx => import_kdbx(bytes, password, keyfile),
        Format::OtpLinks => authenticator::import_links(bytes),
        Format::Sealed => {
            let plain = vault_core::sealed_export::open(password, bytes)
                .map_err(|_| ImportError::SealedExport)?;
            import_json(&plain)
        }
    }
}

use std::collections::HashMap;

use vault_core::{FolderId, ItemData, ItemKind, Vault};
use zeroize::Zeroizing;

/// File formats the importer understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Csv,
    Kdbx,
    /// This app's own export protected by a password (JSON inside).
    Sealed,
    /// `otpauth://` (and `otpauth-migration://`) links, one per line: an authenticator app's
    /// plain-text export.
    OtpLinks,
}

impl Format {
    /// The file is opened with a password typed for it.
    pub fn needs_password(self) -> bool {
        matches!(self, Format::Kdbx | Format::Sealed)
    }
}

/// Guesses the format from the file contents.
pub fn detect_format(bytes: &[u8]) -> Format {
    if vault_core::sealed_export::is_sealed_export(bytes) {
        return Format::Sealed;
    }
    // KDBX signature: 0x9AA2D903 (little-endian).
    if bytes.starts_with(&[0x03, 0xd9, 0xa2, 0x9a]) {
        return Format::Kdbx;
    }
    if authenticator::is_link_list(bytes) {
        return Format::OtpLinks;
    }
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    match text.iter().find(|b| !b.is_ascii_whitespace()) {
        Some(b'{' | b'[') => Format::Json,
        _ => Format::Csv,
    }
}

/// Result of an import: the items plus notes about anything that could not be carried over.
#[derive(Debug, Default)]
pub struct ImportReport {
    pub items: Vec<ItemData>,
    /// Folder name for each item (same order as `items`); nested folders as `Parent/Child`.
    pub folders: Vec<Option<String>>,
    /// Human-readable warnings (skipped rows, unsupported data such as passkeys).
    pub warnings: Vec<String>,
}

impl ImportReport {
    pub(crate) fn push(&mut self, item: ItemData, folder: Option<String>) {
        self.items.push(item);
        self.folders.push(folder.filter(|f| !f.trim().is_empty()));
    }

    /// One row per item for a review screen (no secrets), with duplicates of items already
    /// in `vault` (or earlier in the file) marked.
    pub fn review(&self, vault: &Vault) -> Result<Vec<ReviewRow>, vault_core::Error> {
        let mut known = Known::of(vault)?;
        Ok(self
            .items
            .iter()
            .zip(&self.folders)
            .map(|(item, folder)| ReviewRow {
                kind: item.kind,
                title: item.title.clone(),
                username: item.username.clone(),
                site: item
                    .urls
                    .first()
                    .and_then(|url| host_of(url))
                    .unwrap_or_default(),
                has_password: !item.password.is_empty(),
                has_totp: !item.totp.trim().is_empty(),
                folder: folder.clone().unwrap_or_default(),
                duplicate: !known.insert(item),
            })
            .collect())
    }

    /// Adds the items whose `selected` entry is true (all when `selected` is shorter), filed
    /// as `target` says. Duplicates are skipped as in [`ImportReport::add_to_vault`].
    pub fn add_selected(
        self,
        vault: &mut Vault,
        selected: &[bool],
        target: &FolderTarget,
    ) -> Result<ImportOutcome, vault_core::Error> {
        let mut known = Known::of(vault)?;
        let mut outcome = ImportOutcome::default();
        let mut shared_folder: Option<FolderId> = match target {
            FolderTarget::Existing(id) => {
                if !vault.folders().iter().any(|f| f.id == *id) {
                    return Err(vault_core::Error::FolderNotFound);
                }
                Some(*id)
            }
            _ => None,
        };
        for (index, (mut item, folder)) in self.items.into_iter().zip(self.folders).enumerate() {
            if !selected.get(index).copied().unwrap_or(true) {
                continue;
            }
            if !known.insert(&item) {
                outcome.duplicates += 1;
                continue;
            }
            item.folder = match target {
                FolderTarget::FromFile => match folder {
                    Some(name) => {
                        let name = name.trim();
                        Some(match find_folder(vault, &name.to_lowercase()) {
                            Some(id) => id,
                            None => {
                                outcome.new_folders += 1;
                                vault.add_folder(name)?
                            }
                        })
                    }
                    None => None,
                },
                FolderTarget::NoFolder => None,
                FolderTarget::Existing(_) => shared_folder,
                FolderTarget::New(name) => match shared_folder {
                    Some(id) => Some(id),
                    None => {
                        let id = match find_folder(vault, &name.trim().to_lowercase()) {
                            Some(id) => id,
                            None => {
                                outcome.new_folders += 1;
                                vault.add_folder(name)?
                            }
                        };
                        shared_folder = Some(id);
                        Some(id)
                    }
                },
            };
            vault.add_item(&item)?;
            outcome.titles.push(item.title.clone());
            outcome.added += 1;
        }
        Ok(outcome)
    }

    /// What [`ImportReport::add_to_vault`] would do, without changing the vault.
    pub fn preview(&self, vault: &Vault) -> Result<ImportOutcome, vault_core::Error> {
        let mut known = Known::of(vault)?;
        let mut outcome = ImportOutcome::default();
        let mut new_folders: Vec<String> = Vec::new();
        for (item, folder) in self.items.iter().zip(&self.folders) {
            if !known.insert(item) {
                outcome.duplicates += 1;
                continue;
            }
            if let Some(name) = folder {
                let lower = name.trim().to_lowercase();
                if find_folder(vault, &lower).is_none() && !new_folders.contains(&lower) {
                    new_folders.push(lower);
                }
            }
            outcome.titles.push(item.title.clone());
            outcome.added += 1;
        }
        outcome.new_folders = new_folders.len();
        Ok(outcome)
    }

    /// Adds the items to `vault`, skipping ones it already has (the same item, holding nothing
    /// the vault's copy lacks: see `Known`) and creating missing folders (an existing folder
    /// with the same name, ignoring case, is reused).
    pub fn add_to_vault(self, vault: &mut Vault) -> Result<ImportOutcome, vault_core::Error> {
        self.add_selected(vault, &[], &FolderTarget::FromFile)
    }
}

/// Where imported items are filed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FolderTarget {
    /// The folders named in the file (created when missing; matched ignoring case).
    FromFile,
    /// No folder.
    NoFolder,
    /// All into one folder of the vault.
    Existing(FolderId),
    /// All into a folder with this name (created unless one exists, ignoring case).
    New(String),
}

/// One imported item as shown for review: nothing secret, only whether there is a password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewRow {
    pub kind: ItemKind,
    pub title: String,
    pub username: String,
    /// Host of the first URL.
    pub site: String,
    pub has_password: bool,
    pub has_totp: bool,
    /// Folder named in the file ("" = none).
    pub folder: String,
    /// The same as an item already in the vault (or earlier in the file), holding nothing that
    /// one lacks: it will be skipped.
    pub duplicate: bool,
}

/// Where an export can come from. The app shows how to make the export for each one; every
/// browser and most managers produce a CSV, which [`import_csv`] reads by its header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Chrome,
    Edge,
    Firefox,
    Brave,
    Opera,
    OperaGx,
    Vivaldi,
    Safari,
    Bitwarden,
    OnePassword,
    LastPass,
    KeePass,
    Dashlane,
    ProtonPass,
    NordPass,
    OtherCsv,
}

impl Source {
    /// Browsers first, then password managers, then any CSV.
    pub const ALL: [Source; 16] = [
        Source::Chrome,
        Source::Edge,
        Source::Firefox,
        Source::Brave,
        Source::Opera,
        Source::OperaGx,
        Source::Vivaldi,
        Source::Safari,
        Source::Bitwarden,
        Source::OnePassword,
        Source::LastPass,
        Source::KeePass,
        Source::Dashlane,
        Source::ProtonPass,
        Source::NordPass,
        Source::OtherCsv,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Source::Chrome => "Google Chrome",
            Source::Edge => "Microsoft Edge",
            Source::Firefox => "Firefox",
            Source::Brave => "Brave",
            Source::Opera => "Opera",
            Source::OperaGx => "Opera GX",
            Source::Vivaldi => "Vivaldi",
            Source::Safari => "Safari",
            Source::Bitwarden => "Bitwarden",
            Source::OnePassword => "1Password",
            Source::LastPass => "LastPass",
            Source::KeePass => "KeePass / KeePassXC",
            Source::Dashlane => "Dashlane",
            Source::ProtonPass => "Proton Pass",
            Source::NordPass => "NordPass",
            Source::OtherCsv => "Other (CSV)",
        }
    }

    pub fn is_browser(self) -> bool {
        matches!(
            self,
            Source::Chrome
                | Source::Edge
                | Source::Firefox
                | Source::Brave
                | Source::Opera
                | Source::OperaGx
                | Source::Vivaldi
                | Source::Safari
        )
    }

    /// File types to offer in the file picker.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Source::Bitwarden => &["json", "csv"],
            Source::KeePass => &["kdbx", "csv"],
            _ => &["csv"],
        }
    }
}

/// Counts from adding an import to a vault.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportOutcome {
    pub added: usize,
    pub duplicates: usize,
    pub new_folders: usize,
    /// Titles of the items added (or that would be added), in order.
    pub titles: Vec<String>,
}

fn find_folder(vault: &Vault, lowercase_name: &str) -> Option<vault_core::FolderId> {
    vault
        .folders()
        .iter()
        .find(|f| f.name.to_lowercase() == lowercase_name)
        .map(|f| f.id)
}

/// An item for duplicate detection, as SHA-256 digests: what identifies it (title, username,
/// password, first website), each thing it holds, and what it covers as an item already there.
/// The digest of something short (a PIN) gives it away to whoever tries them all, so they are
/// wiped like what they were made from.
struct Fingerprint {
    key: Digest,
    /// All of it must be covered by a known item for this one to be its duplicate.
    holds: Digests,
    /// What it holds, and the other forms it comes back in from an export.
    covers: Digests,
}

type Digest = [u8; 32];
/// Sorted.
type Digests = Zeroizing<Vec<Digest>>;

fn digest(parts: &[&[u8]]) -> Digest {
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

fn fingerprint(item: &ItemData) -> Fingerprint {
    let kind = |kind: ItemKind| digest(&[b"kind", format!("{kind:?}").as_bytes()]);
    let title = Zeroizing::new(item.title.to_lowercase());
    let key = digest(&[
        title.as_bytes(),
        item.username.as_bytes(),
        item.password.as_bytes(),
        item.urls.first().map(String::as_bytes).unwrap_or_default(),
    ]);
    // Made of its whole size: a buffer that grew would leave copies behind.
    let field_lines = |f: &vault_core::CustomField| 1 + f.value.matches('\n').count();
    let mut holds = Zeroizing::new(Vec::with_capacity(
        3 + item.urls.len()
            + item.custom_fields.iter().map(field_lines).sum::<usize>()
            + item.recovery_codes.len()
            + item.password_history.len()
            + item.attachments.len()
            + item.passkeys.len(),
    ));
    // A passkey item comes back from an export as a login.
    holds.push(kind(match item.kind {
        ItemKind::Passkey => ItemKind::Login,
        other => other,
    }));
    if !item.notes.is_empty() {
        holds.push(digest(&[b"notes", item.notes.as_bytes()]));
    }
    if !item.totp.trim().is_empty() {
        holds.push(digest(&[b"totp", item.totp.trim().as_bytes()]));
    }
    for url in &item.urls {
        holds.push(digest(&[b"website", url.as_bytes()]));
    }
    for field in &item.custom_fields {
        if field.value.trim().is_empty() {
            continue; // a name alone holds nothing
        }
        // Recovery codes as the text exports hold them in are the same codes, whichever are
        // marked used (the CSV has them all on one line, see `covers`).
        if field.name == export::RECOVERY_CODES_FIELD {
            for line in field.value.lines() {
                let code = Zeroizing::new(line.replace(export::USED_MARK, ""));
                holds.push(digest(&[b"code", code.as_bytes()]));
            }
            continue;
        }
        // Whether it is hidden is no content: a CSV import judges that by the name alone.
        holds.push(digest(&[
            b"field",
            field.name.as_bytes(),
            field.value.as_bytes(),
        ]));
    }
    for code in &item.recovery_codes {
        holds.push(digest(&[b"code", code.code.as_bytes()]));
    }
    for old in &item.password_history {
        holds.push(digest(&[b"earlier", old.password.as_bytes()]));
    }
    for file in &item.attachments {
        holds.push(digest(&[b"file", file.name.as_bytes(), &file.data]));
    }
    for passkey in &item.passkeys {
        holds.push(digest(&[
            b"passkey",
            passkey.rp_id.as_bytes(),
            &passkey.credential_id,
        ]));
    }
    let mut covers = Zeroizing::new(Vec::with_capacity(holds.len() + 2));
    covers.extend_from_slice(&holds);
    // The CSV writes a card and an SSH key as notes, and the recovery codes on one line.
    if matches!(item.kind, ItemKind::Card | ItemKind::SshKey) {
        covers.push(kind(ItemKind::SecureNote));
    }
    if let Some(codes) = export::codes_text(&item.recovery_codes) {
        let line = Zeroizing::new(codes.replace(export::USED_MARK, ""));
        let line = Zeroizing::new(line.replace('\n', " "));
        covers.push(digest(&[b"code", line.as_bytes()]));
    }
    holds.sort_unstable();
    covers.sort_unstable();
    Fingerprint { key, holds, covers }
}

/// The items known so far, to tell duplicates. An item is a duplicate only when a known one
/// is the same item and holds everything it holds: two notes of one title with different
/// texts, or a login with notes, a code or an earlier password the known one lacks, are both
/// kept. A duplicate is left out of an import, so it must never be the only copy of anything.
#[derive(Default)]
struct Known(HashMap<Digest, Vec<Digests>>);

impl Known {
    fn of(vault: &Vault) -> Result<Self, vault_core::Error> {
        let mut known = Self::default();
        for id in vault.item_ids() {
            let Fingerprint { key, covers, .. } = fingerprint(&vault.get_item(&id)?);
            known.0.entry(key).or_default().push(covers);
        }
        Ok(known)
    }

    /// Adds `item`; `false` when it is a duplicate (and nothing was added).
    fn insert(&mut self, item: &ItemData) -> bool {
        let Fingerprint { key, holds, covers } = fingerprint(item);
        let same = self.0.entry(key).or_default();
        let covered = |known: &Digests| holds.iter().all(|part| known.binary_search(part).is_ok());
        if same.iter().any(covered) {
            return false;
        }
        same.push(covers);
        true
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("this export is encrypted; export again choosing the unencrypted JSON format")]
    EncryptedExport,
    #[error("could not open the protected export (wrong password, or the file is damaged)")]
    SealedExport,
    /// What is wrong and where, never what the file holds there.
    #[error("invalid JSON: {0}")]
    Json(String),
    #[error("invalid CSV: {0}")]
    Csv(#[from] csv::Error),
    #[error(
        "the CSV has no recognizable columns (need at least a password, username or URL column)"
    )]
    UnknownCsvLayout,
    #[error("could not open the KeePass database (wrong password or key file?): {0}")]
    Kdbx(String),
    #[error("{0}")]
    Browser(String),
    #[error("that primary password doesn't open this Firefox profile")]
    WrongBrowserPassword,
}

impl From<serde_json::Error> for ImportError {
    /// Only the kind of problem and its place: serde's own message quotes the value it did
    /// not expect (`invalid type: integer `1234`…`), which may well be a password.
    fn from(err: serde_json::Error) -> Self {
        use serde_json::error::Category;
        let problem = match err.classify() {
            Category::Io => "it can't be read",
            Category::Syntax => "a syntax error",
            Category::Data => "something this layout doesn't have there",
            Category::Eof => "it ends too early",
        };
        Self::Json(format!(
            "{problem} (line {}, column {})",
            err.line(),
            err.column()
        ))
    }
}

/// Title fallback for entries without one: the host part of a URL.
pub(crate) fn host_of(url: &str) -> Option<String> {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?
        .split(':')
        .next()?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_owned())
}

pub(crate) fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

/// "1 passkey", "3 passkeys": a count for a warning.
pub(crate) fn counted(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Counts that name what was left out, for a warning: "2 attached files and 1 passkey", and
/// the verb that follows them ("was" for a single thing, else "were"). `None` when all are 0.
pub(crate) fn left_out_list(counts: &[(usize, &str, &str)]) -> Option<(String, &'static str)> {
    let parts: Vec<String> = counts
        .iter()
        .filter(|(n, ..)| *n > 0)
        .map(|&(n, one, many)| counted(n, one, many))
        .collect();
    // One thing, or several. (No sum: the counts of an import come from the file, as large as
    // it likes.)
    let mut some = counts.iter().map(|(n, ..)| *n).filter(|n| *n > 0);
    let verb = match (some.next(), some.next()) {
        (None, _) => return None,
        (Some(1), None) => "was",
        _ => "were",
    };
    let text = match parts.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => return None,
    };
    Some((text, verb))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_vault() -> Vault {
        let key = vault_core::SecretKey::generate().unwrap();
        Vault::create("pw", &key, None, vault_core::KdfParams::minimum().unwrap()).unwrap()
    }

    #[test]
    fn notes_of_one_title_with_different_texts_all_come_back_from_a_protected_export() {
        let mut vault = empty_vault();
        let note = |text: &str| {
            let mut item = ItemData::new(ItemKind::SecureNote, "Recovery");
            item.notes = text.into();
            item
        };
        vault.add_item(&note("bank: call the branch")).unwrap();
        vault.add_item(&note("mail: use the backup codes")).unwrap();
        vault
            .add_item(&ItemData::new(ItemKind::SecureNote, "Other"))
            .unwrap();
        let sealed = export::export_sealed(&vault, "a long password for the file").unwrap();
        let report = import(
            &sealed,
            Format::Sealed,
            "a long password for the file",
            None,
        )
        .unwrap();
        assert_eq!(report.items.len(), 3);
        let mut restored = empty_vault();
        let outcome = report.add_to_vault(&mut restored).unwrap();
        assert_eq!((outcome.added, outcome.duplicates), (3, 0));
        let mut texts: Vec<String> = restored
            .item_ids()
            .map(|id| restored.get_item(&id).unwrap())
            .map(|item| format!("{}: {}", item.title, item.notes))
            .collect();
        texts.sort();
        assert_eq!(
            texts,
            [
                "Other: ",
                "Recovery: bank: call the branch",
                "Recovery: mail: use the backup codes"
            ]
        );
    }

    #[test]
    fn a_duplicate_is_only_one_that_brings_nothing_new() {
        let mut vault = empty_vault();
        let mut known = ItemData::login("Mail", "me", "pw1", "https://mail.example");
        known.totp = "JBSWY3DPEHPK3PXP".into();
        vault.add_item(&known).unwrap();
        let same = ItemData::login("mail", "me", "pw1", "https://mail.example");
        let mut with_notes = same.clone();
        with_notes.notes = "the security answer is in the safe".into();
        let mut other_code = same.clone();
        other_code.totp = "GEZDGNBVGY3TQOJQ".into();
        let mut known_in_file = Known::of(&vault).unwrap();
        assert!(
            !known_in_file.insert(&same),
            "a part of what is known: a duplicate"
        );
        assert!(
            known_in_file.insert(&with_notes),
            "notes the vault lacks: kept"
        );
        assert!(known_in_file.insert(&other_code), "another code: kept");
        assert!(
            !known_in_file.insert(&with_notes),
            "twice in the file: once"
        );
    }

    #[test]
    fn a_duplicate_is_told_by_what_an_item_holds_not_by_how_it_is_kept() {
        let field = |name: &str, value: &str, sensitive| vault_core::CustomField {
            name: name.into(),
            value: value.into(),
            sensitive,
        };
        let mut vault = empty_vault();
        let mut mail = ItemData::login("Mail", "me", "pw1", "https://mail.example");
        mail.custom_fields = vec![
            field("PIN", "42", false),
            field("Plan", "family", false),
            field("Nothing yet", "", false),
        ];
        mail.recovery_codes = vec![
            vault_core::RecoveryCode {
                code: "aaaa".into(),
                used: true,
            },
            vault_core::RecoveryCode {
                code: "bbbb".into(),
                used: false,
            },
        ];
        vault.add_item(&mail).unwrap();
        let mut shop = ItemData::new(ItemKind::Passkey, "Shop");
        shop.username = "me".into();
        vault.add_item(&shop).unwrap();
        let known = || Known::of(&vault).unwrap();

        // Hidden by its name (a CSV import), in another order, or fewer of them: nothing new.
        let mut again = ItemData::login("Mail", "me", "pw1", "https://mail.example");
        again.custom_fields = vec![field("Plan", "family", false), field("PIN", "42", true)];
        assert!(!known().insert(&again));
        // The codes as the hidden text of an older export, another one marked used since.
        again
            .custom_fields
            .push(field("Recovery codes", "aaaa (used)\nbbbb (used)", true));
        assert!(!known().insert(&again));
        // A code the vault doesn't have, or another value of a field: kept.
        let mut other_codes = again.clone();
        other_codes.custom_fields[2].value.push_str("\ncccc");
        assert!(known().insert(&other_codes));
        let mut other_pin = again.clone();
        other_pin.custom_fields[1].value = "43".into();
        assert!(known().insert(&other_pin));
        // Earlier passwords the vault's copy doesn't have are only in this one: kept.
        let mut with_history = again.clone();
        with_history
            .password_history
            .push(vault_core::PasswordChange {
                password: "pw0".into(),
                replaced_at: 1,
            });
        let mut twice = known();
        assert!(twice.insert(&with_history));
        assert!(!twice.insert(&with_history), "twice in the file: once");
        // A passkey item comes back from an export as a login, with nothing the vault lacks.
        let mut back = ItemData::new(ItemKind::Login, "Shop");
        back.username = "me".into();
        assert!(!known().insert(&back));
    }

    #[test]
    fn a_csv_of_the_vault_brings_nothing_new_back_into_it() {
        let mut vault = empty_vault();
        let mut mail = ItemData::login("Mail", "me", "pw1", "https://mail.example");
        mail.urls.push("https://webmail.example".into());
        mail.recovery_codes = vault_core::RecoveryCode::parse_list("aaaa bbbb\ncccc dddd");
        mail.recovery_codes[0].used = true;
        vault.add_item(&mail).unwrap();
        // As notes in the CSV, the card with nothing but its fields.
        let mut card = ItemData::new(ItemKind::Card, "Visa");
        vault_core::card::CardDetails {
            number: "4111111111111111".into(),
            expiry: "08/29".into(),
            security_code: "737".into(),
        }
        .apply(&mut card);
        vault.add_item(&card).unwrap();
        let mut ssh = ItemData::new(ItemKind::SshKey, "Server");
        ssh.password = "test private key".into();
        vault.add_item(&ssh).unwrap();
        // Only a name, and its passkey, which stays in the vault.
        let mut shop = ItemData::new(ItemKind::Passkey, "Shop");
        shop.passkeys
            .push(vault_core::Passkey::new("shop.example", b"user", "me", "Me").unwrap());
        vault.add_item(&shop).unwrap();

        let csv = export_csv(&vault).unwrap();
        let report = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(report.items.len(), vault.len(), "every item is in the file");
        let outcome = report.preview(&vault).unwrap();
        assert_eq!((outcome.added, outcome.duplicates), (0, vault.len()));

        // The other way around the kind is new: a card whose note is all the vault has.
        let mut notes = empty_vault();
        import_csv(csv.as_bytes())
            .unwrap()
            .add_to_vault(&mut notes)
            .unwrap();
        assert!(Known::of(&notes).unwrap().insert(&card));
        // Codes that differ are still told apart, on one line or not.
        let mut other = mail.clone();
        other.recovery_codes[1].code = "eeee ffff".into();
        assert!(Known::of(&vault).unwrap().insert(&other));
        let line = csv.replace("cccc dddd", "eeee ffff");
        assert_ne!(line, csv.as_str());
        let report = import_csv(line.as_bytes()).unwrap();
        assert_eq!(report.preview(&vault).unwrap().added, 1);
    }

    #[test]
    fn an_import_error_never_quotes_the_file() {
        for json in [
            r#"{"items": [{"type": 1, "name": "Mail", "login": {"password": 48213377}}]}"#,
            r#"{"items": [{"type": 1, "name": "Mail", "login": "48213377"}]}"#,
            r#"{"items": [{"type": 1, "name": "Mail", "notes": ["48213377"]}]}"#,
            r#"{"items": [{"type": 1, "name": "Mail", "login": {"password": "48213377"#,
        ] {
            let err = import(json.as_bytes(), Format::Json, "", None).unwrap_err();
            assert!(!err.to_string().contains("48213377"), "{err}");
            assert!(!format!("{err:?}").contains("48213377"), "{err:?}");
            assert!(std::error::Error::source(&err).is_none());
            assert!(err.to_string().contains("line 1"), "{err}");
        }
    }

    #[test]
    fn warnings_hold_no_secret_and_stand_any_count_a_file_claims() {
        let json = format!(
            r#"{{"items": [{{"type": 1, "name": "Mail", "login": {{"username": "me",
               "password": "hunter2-test", "totp": "JBSWY3DPEHPK3PXP",
               "uris": [{{"match": 5, "uri": "https://mail.example/?token=hunter2-test"}}],
               "fido2Credentials": [{{"keyValue": "hunter2-test"}}]}},
               "fields": [{{"name": "PIN", "value": "hunter2-test", "type": 1}}],
               "recoveryCodes": [{{"code": "hunter2-test"}}],
               "passwordHistory": [{{"password": "hunter2-test"}}],
               "leftOut": {{"attachments": {max}, "passkeys": {max}, "passwordHistory": {max}}}
            }}]}}"#,
            max = u64::MAX
        );
        let report = import(json.as_bytes(), Format::Json, "", None).unwrap();
        assert_eq!(report.warnings.len(), 3, "{:?}", report.warnings);
        for warning in &report.warnings {
            assert!(!warning.contains("hunter2-test"), "{warning}");
        }
        assert!(report.warnings[2].contains("attached files"));
        let csv = "name,password,fields\nMail,hunter2-test,\"PIN: hunter2-test\nhunter2-test\"\n";
        let report = import(csv.as_bytes(), Format::Csv, "", None).unwrap();
        assert_eq!(report.warnings.len(), 1);
        assert!(!report.warnings[0].contains("hunter2-test"));
        // Counts in another shape are no counts.
        let odd = r#"{"items": [{"type": 1, "name": "Mail", "leftOut": {"passkeys": "2", "attachments": -1}},
                                {"type": 1, "name": "Shop", "leftOut": [1, 2]}]}"#;
        let report = import(odd.as_bytes(), Format::Json, "", None).unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }

    #[test]
    fn detects_formats() {
        assert_eq!(detect_format(&[0x03, 0xd9, 0xa2, 0x9a, 0x67]), Format::Kdbx);
        assert_eq!(
            detect_format(b"\xEF\xBB\xBF  {\"items\": []}"),
            Format::Json
        );
        assert_eq!(detect_format(b"name,url,username,password\n"), Format::Csv);
    }

    #[test]
    fn review_and_selective_import() {
        let key = vault_core::SecretKey::generate().unwrap();
        let mut vault =
            Vault::create("pw", &key, None, vault_core::KdfParams::minimum().unwrap()).unwrap();
        vault
            .add_item(&ItemData::login("Old", "me", "pw0", "https://old.example"))
            .unwrap();
        let csv = "name,url,username,password,folder\n\
                   Old,https://old.example,me,pw0,\n\
                   Mail,https://www.mail.example/in,me,pw1,Work\n\
                   Shop,https://shop.example,me,pw2,Home\n\
                   Bank,https://bank.example,me,,Home\n";
        let report = import_csv(csv.as_bytes()).unwrap();
        let rows = report.review(&vault).unwrap();
        assert_eq!(rows.len(), 4);
        assert!(rows[0].duplicate && !rows[1].duplicate);
        assert_eq!(rows[1].site, "mail.example");
        assert_eq!(rows[1].folder, "Work");
        assert!(rows[1].has_password && !rows[3].has_password);
        assert!(!format!("{rows:?}").contains("pw1"));

        // Everything but "Shop", all into one new folder.
        let outcome = report
            .add_selected(
                &mut vault,
                &[true, true, false, true],
                &FolderTarget::New("Imported".into()),
            )
            .unwrap();
        assert_eq!(
            (outcome.added, outcome.duplicates, outcome.new_folders),
            (2, 1, 1)
        );
        let folder = vault.folders()[0].id;
        let filed = vault
            .item_ids()
            .filter(|id| vault.get_item(id).unwrap().folder == Some(folder))
            .count();
        assert_eq!(filed, 2);
        assert!(
            import_csv(csv.as_bytes())
                .unwrap()
                .add_selected(
                    &mut vault,
                    &[],
                    &FolderTarget::Existing(FolderId::from_hex(&"0".repeat(32)).unwrap())
                )
                .is_err()
        );
        assert_eq!(Source::ALL.iter().filter(|s| s.is_browser()).count(), 8);
    }

    #[test]
    fn hosts() {
        assert_eq!(
            host_of("https://www.github.com/login?x=1").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            host_of("http://user@host.example:8080/").as_deref(),
            Some("host.example")
        );
        assert_eq!(
            host_of("android://hash@com.example.app/").as_deref(),
            Some("com.example.app")
        );
        assert_eq!(host_of("").as_deref(), None);
    }
}
