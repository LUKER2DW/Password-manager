//! Import from and export to other password managers and browsers.
//!
//! One entry point, [`import`], reads every supported file by its format:
//! - **JSON**: unencrypted exports in the common layout (`.json`)
//! - **KDBX**: KeePass-format databases (`.kdbx`, KDBX 3 and 4), opened with their password
//! - **CSV**: exports from browsers and most managers, read by their header row
//!
//! [`Source`] lists where an export can come from, for the app to explain how to make one.
//! On Windows, [`browser`] can also read a browser's own password store directly, when the user
//! asks for it.
//!
//! Importers only produce [`ItemData`]; they never touch the vault or its keys.

pub mod browser;
mod csv_import;
mod dates;
mod export;
mod json;
mod kdbx;

pub use export::{export_csv, export_json, export_sealed};

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
        Format::Sealed => {
            let plain = vault_core::sealed_export::open(password, bytes)
                .map_err(|_| ImportError::SealedExport)?;
            import_json(&plain)
        }
    }
}

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
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    match text.iter().find(|b| !b.is_ascii_whitespace()) {
        Some(b'{') => Format::Json,
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
        let mut known = known_fingerprints(vault)?;
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
                duplicate: !known.insert(fingerprint(item)),
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
        let mut known = known_fingerprints(vault)?;
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
            if !known.insert(fingerprint(&item)) {
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
        let mut known = known_fingerprints(vault)?;
        let mut outcome = ImportOutcome::default();
        let mut new_folders: Vec<String> = Vec::new();
        for (item, folder) in self.items.iter().zip(&self.folders) {
            if !known.insert(fingerprint(item)) {
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

    /// Adds the items to `vault`, skipping ones it already has (same title, username, password
    /// and first URL) and creating missing folders (an existing folder with the same name,
    /// ignoring case, is reused).
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
    /// Same title, username, password and URL as an item already in the vault (or earlier in
    /// the file): it will be skipped.
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

/// Identity of an item for duplicate detection: a SHA-256 digest, so the set of known items
/// holds no copy of any password.
fn fingerprint(item: &ItemData) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let text = Zeroizing::new(format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        item.title.to_lowercase(),
        item.username,
        item.password,
        item.urls.first().map(String::as_str).unwrap_or_default()
    ));
    Sha256::digest(text.as_bytes()).into()
}

fn known_fingerprints(
    vault: &Vault,
) -> Result<std::collections::HashSet<[u8; 32]>, vault_core::Error> {
    vault
        .item_ids()
        .map(|id| vault.get_item(&id).map(|item| fingerprint(&item)))
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("this export is encrypted; export again choosing the unencrypted JSON format")]
    EncryptedExport,
    #[error("could not open the protected export (wrong password, or the file is damaged)")]
    SealedExport,
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
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

#[cfg(test)]
mod tests {
    use super::*;

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
