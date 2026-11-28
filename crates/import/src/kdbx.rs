//! KeePass / KeePassXC databases (KDBX 3.1 and 4).
//!
//! Besides KeePass's own fields this reads what KeePassXC and KeePass2Android keep in their
//! own: more websites (`KP2A_URL…`), a passkey (`KPEX_PASSKEY_*`), and what this app's KDBX
//! export writes in the entry's custom data (`vault.item`, [`crate::kdbx_export`]).

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use keepass::db::{CustomDataValue, EntryRef};
use keepass::{Database, DatabaseKey, db::fields};
use vault_core::{Attachment, CustomField, ItemData, ItemKind, Passkey, PasswordChange};
use zeroize::Zeroizing;

use crate::{ImportError, ImportReport, host_of, left_out_list, non_empty};

/// More websites of an entry, `KP2A_URL_1`, `KP2A_URL_2`… (KeePass2Android, KeePassXC).
pub(crate) const URL_PREFIX: &str = "KP2A_URL";
/// A passkey in an entry, as KeePassXC keeps it.
pub(crate) const PASSKEY_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
pub(crate) const PASSKEY_RP: &str = "KPEX_PASSKEY_RELYING_PARTY";
pub(crate) const PASSKEY_USER: &str = "KPEX_PASSKEY_USERNAME";
pub(crate) const PASSKEY_USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";
pub(crate) const PASSKEY_KEY: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
/// This app's own data in an entry's custom data: one JSON object of texts under this key
/// (JSON, as the `keepass` crate reads a value that happens to be Base64 as bytes).
pub(crate) const ITEM_DATA: &str = "vault.item";
/// The item's kind when it isn't a login ([`kind_name`]).
pub(crate) const KIND_DATA: &str = "kind";
/// "1" when it is a favourite, or asks for the master password again.
pub(crate) const FAVORITE_DATA: &str = "favorite";
pub(crate) const REPROMPT_DATA: &str = "reprompt";
/// "1": the field "Recovery codes" holds the item's codes, one per line.
pub(crate) const CODES_DATA: &str = "recoveryCodes";
/// The passkey's display name and when it was made (Unix seconds).
pub(crate) const DISPLAY_NAME_DATA: &str = "passkeyDisplayName";
pub(crate) const PASSKEY_CREATED_DATA: &str = "passkeyCreated";

/// The name [`KIND_DATA`] gives a kind; `None` for a login, which needs none.
pub(crate) fn kind_name(kind: ItemKind) -> Option<&'static str> {
    match kind {
        ItemKind::Login => None,
        ItemKind::Card => Some("card"),
        ItemKind::SecureNote => Some("note"),
        ItemKind::Passkey => Some("passkey"),
        ItemKind::SshKey => Some("ssh-key"),
    }
}

/// Opens a KDBX database with its password (and optional key file) and converts every entry
/// outside the recycle bin.
pub(crate) fn import_kdbx(
    bytes: &[u8],
    password: &str,
    keyfile: Option<&[u8]>,
) -> Result<ImportReport, ImportError> {
    let mut key = DatabaseKey::new();
    if !password.is_empty() {
        key = key.with_password(password);
    }
    if let Some(mut keyfile) = keyfile {
        key = key
            .with_keyfile(&mut keyfile)
            .map_err(|e| ImportError::Kdbx(e.to_string()))?;
    }
    if !kdf_within_limits(bytes) {
        return Err(ImportError::Kdbx(
            "this database asks for more memory or work to open than this app accepts".into(),
        ));
    }
    let db = Database::parse(bytes, key).map_err(|e| ImportError::Kdbx(e.to_string()))?;

    // Everything that sits (directly or in a subgroup) in the recycle bin is skipped.
    let mut deleted = Vec::new();
    if let Some(bin) = db.recycle_bin() {
        collect_entry_ids(bin, &mut deleted);
    }
    // KeePass groups become folders: "Parent/Child", the root group itself left out.
    let mut group_paths = HashMap::new();
    collect_group_paths(db.root(), "", &mut group_paths);

    let mut report = ImportReport::default();
    for entry in db.iter_all_entries() {
        if deleted.contains(&entry.id()) {
            continue;
        }
        let folder = group_paths.get(&entry.id()).cloned();
        let (item, warnings) = item_of(&entry);
        report.warnings.extend(warnings);
        report.push(item, folder);
    }
    Ok(report)
}

/// One text of this app's own data in an entry ([`ITEM_DATA`]).
fn own_data(entry: &EntryRef<'_>, key: &str) -> Option<String> {
    let CustomDataValue::String(json) = entry.custom_data.get(ITEM_DATA)?.value.as_ref()? else {
        return None;
    };
    let data: serde_json::Value = serde_json::from_str(json).ok()?;
    data.get(key)?.as_str().map(str::to_owned)
}

/// One entry as an item, and what couldn't come with it.
fn item_of(entry: &EntryRef<'_>) -> (ItemData, Vec<String>) {
    let mut warnings = Vec::new();
    let get = |name: &str| non_empty(entry.get(name).map(str::to_owned));
    let url = get(fields::URL);
    let title = get(fields::TITLE)
        .or_else(|| url.as_deref().and_then(host_of))
        .unwrap_or_else(|| "Untitled".into());
    let username = get(fields::USERNAME);
    let password = get(fields::PASSWORD);
    let marked = own_data(entry, KIND_DATA).and_then(|name| {
        let name = name.as_str();
        [
            ItemKind::Card,
            ItemKind::SecureNote,
            ItemKind::Passkey,
            ItemKind::SshKey,
        ]
        .into_iter()
        .find(|kind| kind_name(*kind) == Some(name))
    });
    let kind = marked.unwrap_or(
        if username.is_none() && password.is_none() && url.is_none() {
            ItemKind::SecureNote
        } else {
            ItemKind::Login
        },
    );

    let mut item = ItemData::new(kind, &title);
    item.username = username.unwrap_or_default();
    item.password = password.unwrap_or_default();
    item.urls = url.into_iter().collect();
    item.notes = get(fields::NOTES).unwrap_or_default();
    item.totp = get(fields::OTP)
        .or_else(|| get("TimeOtp-Secret-Base32"))
        .unwrap_or_default();
    item.favorite = own_data(entry, FAVORITE_DATA).as_deref() == Some("1");
    item.reprompt = own_data(entry, REPROMPT_DATA).as_deref() == Some("1");
    if let Some(created) = entry.times.creation {
        item.created_at = created.and_utc().timestamp();
    }
    if let Some(modified) = entry.times.last_modification {
        item.updated_at = modified.and_utc().timestamp();
    }

    // More websites, in their order (`KP2A_URL`, `KP2A_URL_1`, …).
    let mut more_urls: Vec<(usize, String)> = entry
        .fields
        .iter()
        .filter_map(|(name, value)| {
            let rest = name.strip_prefix(URL_PREFIX)?;
            let n = match rest.strip_prefix('_') {
                Some(n) => n.parse().ok()?,
                None if rest.is_empty() => 0,
                None => return None,
            };
            Some((n, non_empty(Some(value.get().clone()))?))
        })
        .collect();
    more_urls.sort();
    item.urls.extend(more_urls.into_iter().map(|(_, url)| url));

    let mut extra: Vec<(&String, &keepass::db::Value<String>)> = entry
        .fields
        .iter()
        .filter(|(name, _)| {
            !fields::KNOWN_FIELDS.contains(&name.as_str())
                && name.as_str() != fields::OTP
                && !name.starts_with("TimeOtp-")
                && !name.starts_with("KP2A_")
                && !name.starts_with("KPEX_PASSKEY_")
        })
        .collect();
    extra.sort_by(|a, b| a.0.cmp(b.0));
    let codes_marked = own_data(entry, CODES_DATA).as_deref() == Some("1");
    for (name, value) in extra {
        let Some(text) = non_empty(Some(value.get().clone())) else {
            continue;
        };
        if codes_marked && name == crate::export::RECOVERY_CODES_FIELD {
            item.recovery_codes = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| match line.strip_suffix(crate::export::USED_MARK) {
                    Some(code) => vault_core::RecoveryCode {
                        code: code.to_owned(),
                        used: true,
                    },
                    None => vault_core::RecoveryCode {
                        code: line.to_owned(),
                        used: false,
                    },
                })
                .collect();
            continue;
        }
        item.custom_fields.push(CustomField {
            name: name.clone(),
            value: text,
            sensitive: value.is_protected(),
        });
    }
    // A passkey in KeePassXC's fields.
    if entry.get(PASSKEY_KEY).is_some() {
        match passkey_of(entry) {
            Some(passkey) => item.passkeys.push(passkey),
            None => warnings.push(format!(
                "\"{title}\": its passkey was not imported (damaged, or not a P-256 key)"
            )),
        }
    }
    if item.kind == ItemKind::Passkey && item.passkeys.is_empty() {
        item.kind = ItemKind::Login;
    }

    // Attached files, as far as an item keeps them.
    let mut unread = 0;
    for (name, file) in entry.attachments_named() {
        let data = file.data.get();
        match Attachment::new(name, Vec::new()) {
            Ok(mut attachment)
                if data.len() <= Attachment::MAX_BYTES
                    && item.attachments.len() < Attachment::MAX_PER_ITEM =>
            {
                attachment.data = data.clone();
                item.attachments.push(attachment);
            }
            _ => unread += 1,
        }
    }
    if let Some((what, verb)) = left_out_list(&[(unread, "attached file", "attached files")]) {
        warnings.push(format!(
            "\"{title}\": {what} {verb} not imported (too large, or more than an item keeps)"
        ));
    }

    // Earlier passwords, from the entry's history: each one once, not the one in use.
    if let Some(history) = entry.history.as_ref() {
        for old in history.get_entries() {
            let Some(password) = old.get_password().filter(|p| !p.is_empty()) else {
                continue;
            };
            if password == item.password
                || item.password_history.iter().any(|c| c.password == password)
            {
                continue;
            }
            item.password_history.push(PasswordChange {
                password: password.to_owned(),
                replaced_at: old
                    .times
                    .last_modification
                    .map_or(0, |t| t.and_utc().timestamp()),
            });
        }
        item.password_history.sort_by_key(|c| c.replaced_at);
    }
    (item, warnings)
}

/// The passkey in KeePassXC's fields of an entry, with this app's display name and date.
fn passkey_of(entry: &EntryRef<'_>) -> Option<Passkey> {
    let text = |name: &str| entry.get(name).map(str::trim).unwrap_or_default();
    let binary = |name: &str| {
        let value = text(name).trim_end_matches('=');
        URL_SAFE_NO_PAD
            .decode(value)
            .or_else(|_| STANDARD_NO_PAD.decode(value))
            .ok()
    };
    let body: Zeroizing<String> = Zeroizing::new(
        text(PASSKEY_KEY)
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .map(str::trim)
            .collect(),
    );
    let der = Zeroizing::new(STANDARD.decode(body.as_bytes()).ok()?);
    let scalar = Passkey::scalar_from_pkcs8(&der)?;
    let user_name = text(PASSKEY_USER);
    let display_name = own_data(entry, DISPLAY_NAME_DATA).unwrap_or_else(|| user_name.to_owned());
    let created = own_data(entry, PASSKEY_CREATED_DATA)
        .and_then(|t| t.parse().ok())
        .or_else(|| entry.times.creation.map(|t| t.and_utc().timestamp()))
        .unwrap_or(0);
    Passkey::from_parts(
        &binary(PASSKEY_ID)?,
        text(PASSKEY_RP),
        &binary(PASSKEY_USER_HANDLE).unwrap_or_default(),
        user_name,
        &display_name,
        created,
        &scalar,
    )
    .ok()
}

/// Most memory (Argon2) a database may ask for: 2 GiB.
const MAX_KDF_MEMORY: u64 = 2 * 1024 * 1024 * 1024;
/// Most Argon2 passes and lanes.
const MAX_KDF_PASSES: u64 = 1000;
const MAX_KDF_LANES: u64 = 64;
/// Most AES-KDF rounds: well above what a one-second setting gives on a fast computer.
const MAX_KDF_ROUNDS: u64 = 500_000_000;

/// Whether the key derivation the file's (unauthenticated) header asks for is something a
/// real database would use. The header is read before the password is tried, so a crafted
/// file could otherwise ask for all the computer's memory or hours of work. A header this
/// can't read is left to the parser, which refuses it.
fn kdf_within_limits(bytes: &[u8]) -> bool {
    let u16_at = |at: usize| {
        bytes
            .get(at..at + 2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_le_bytes)
    };
    let u32_at = |at: usize| {
        bytes
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    };
    let number = |value: &[u8]| match value.len() {
        4 => value
            .try_into()
            .ok()
            .map(|b| u64::from(u32::from_le_bytes(b))),
        8 => value.try_into().ok().map(u64::from_le_bytes),
        _ => None,
    };
    let Some(major) = u16_at(10) else {
        return true;
    };
    let mut at = 12;
    loop {
        // One header field: its id, its length (16 bits before version 4, 32 after), its value.
        let Some(&id) = bytes.get(at) else {
            return true;
        };
        let (length, start) = if major >= 4 {
            (u32_at(at + 1).map(|n| n as usize), at + 5)
        } else {
            (u16_at(at + 1).map(usize::from), at + 3)
        };
        let Some(value) = length.and_then(|n| bytes.get(start..start.checked_add(n)?)) else {
            return true;
        };
        at = start + value.len();
        match (major >= 4, id) {
            (_, 0) => return true,
            // Version 3: the number of AES-KDF rounds.
            (false, 6) => {
                if number(value).is_some_and(|rounds| rounds > MAX_KDF_ROUNDS) {
                    return false;
                }
            }
            // Version 4: a dictionary of named values (after its 2-byte version).
            (true, 11) => {
                let mut pos = 2;
                while let Some(&kind) = value.get(pos) {
                    if kind == 0 {
                        break;
                    }
                    let read = |pos: usize| {
                        let n = value
                            .get(pos..pos + 4)
                            .and_then(|b| b.try_into().ok())
                            .map(u32::from_le_bytes)? as usize;
                        Some((value.get(pos + 4..(pos + 4).checked_add(n)?)?, pos + 4 + n))
                    };
                    let Some((name, after_name)) = read(pos + 1) else {
                        return true;
                    };
                    let Some((entry, after)) = read(after_name) else {
                        return true;
                    };
                    pos = after;
                    let limit = match name {
                        b"M" => MAX_KDF_MEMORY,
                        b"I" => MAX_KDF_PASSES,
                        b"P" => MAX_KDF_LANES,
                        b"R" => MAX_KDF_ROUNDS,
                        _ => continue,
                    };
                    if number(entry).is_some_and(|n| n > limit) {
                        return false;
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_group_paths(
    group: keepass::db::GroupRef<'_>,
    path: &str,
    out: &mut HashMap<keepass::db::EntryId, String>,
) {
    if !path.is_empty() {
        for entry in group.entries() {
            out.insert(entry.id(), path.to_owned());
        }
    }
    for child in group.groups() {
        let name = child.name.trim();
        let child_path = match (path.is_empty(), name.is_empty()) {
            (_, true) => path.to_owned(),
            (true, false) => name.to_owned(),
            (false, false) => format!("{path}/{name}"),
        };
        collect_group_paths(child, &child_path, out);
    }
}

fn collect_entry_ids(group: keepass::db::GroupRef<'_>, out: &mut Vec<keepass::db::EntryId>) {
    out.extend(group.entries().map(|entry| entry.id()));
    for child in group.groups() {
        collect_entry_ids(child, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_database(password: &str) -> Vec<u8> {
        let mut db = Database::new();
        let mut root = db.root_mut();
        root.add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Mail");
            e.set_unprotected(fields::USERNAME, "me@example.com");
            e.set_protected(fields::PASSWORD, "kp-secret");
            e.set_unprotected(fields::URL, "https://mail.example.com");
            e.set_unprotected(fields::NOTES, "note");
            e.set_unprotected(fields::OTP, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
            e.set_protected("PIN", "4321");
            e.set_unprotected("Plan", "family");
        });
        root.add_group()
            .edit(|g| g.name = "Sub".into())
            .add_entry()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Nested note");
                e.set_unprotected(fields::NOTES, "only notes");
            });
        let mut buffer = Vec::new();
        db.save(&mut buffer, DatabaseKey::new().with_password(password))
            .unwrap();
        buffer
    }

    #[test]
    fn imports_entries_and_fields() {
        let bytes = sample_database("kdbx test password");
        assert_eq!(crate::detect_format(&bytes), crate::Format::Kdbx);
        let report = import_kdbx(&bytes, "kdbx test password", None).unwrap();
        assert_eq!(report.items.len(), 2);

        let mail = report.items.iter().find(|i| i.title == "Mail").unwrap();
        assert_eq!(mail.password, "kp-secret");
        assert_eq!(mail.urls, ["https://mail.example.com"]);
        assert!(mail.totp.starts_with("otpauth://"));
        assert_eq!(mail.custom_fields.len(), 2);
        assert!(
            mail.custom_fields
                .iter()
                .any(|f| f.name == "PIN" && f.sensitive)
        );
        assert!(
            mail.custom_fields
                .iter()
                .any(|f| f.name == "Plan" && !f.sensitive)
        );

        let note = report
            .items
            .iter()
            .find(|i| i.title == "Nested note")
            .unwrap();
        assert_eq!(note.kind, ItemKind::SecureNote);

        // Groups become folders; entries in the root group have none.
        let folder_of = |title: &str| {
            let index = report.items.iter().position(|i| i.title == title).unwrap();
            report.folders[index].clone()
        };
        assert_eq!(folder_of("Mail"), None);
        assert_eq!(folder_of("Nested note").as_deref(), Some("Sub"));
    }

    #[test]
    fn a_header_asking_for_too_much_is_refused_before_any_work() {
        assert!(kdf_within_limits(&sample_database("pw")));
        let start = |major: u16| {
            let mut bytes = vec![0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0, 0];
            bytes.extend(major.to_le_bytes());
            bytes
        };
        // Version 4: a dictionary with one 64-bit value under `name`.
        let v4 = |name: &[u8], number: u64| {
            let mut dictionary = vec![0x00, 0x01, 0x05];
            dictionary.extend((name.len() as u32).to_le_bytes());
            dictionary.extend(name);
            dictionary.extend(8u32.to_le_bytes());
            dictionary.extend(number.to_le_bytes());
            dictionary.push(0);
            let mut bytes = start(4);
            bytes.push(11);
            bytes.extend((dictionary.len() as u32).to_le_bytes());
            bytes.extend(dictionary);
            bytes.extend([0, 0, 0, 0, 0]);
            bytes
        };
        assert!(kdf_within_limits(&v4(b"M", 64 * 1024 * 1024)));
        assert!(!kdf_within_limits(&v4(b"M", 64 * 1024 * 1024 * 1024)));
        assert!(!kdf_within_limits(&v4(b"I", 1_000_000)));
        assert!(!kdf_within_limits(&v4(b"R", u64::MAX)));
        assert!(kdf_within_limits(&v4(b"S", u64::MAX)), "not a cost");
        // Version 3: field 6 is the number of rounds.
        let v3 = |rounds: u64| {
            let mut bytes = start(3);
            bytes.push(6);
            bytes.extend(8u16.to_le_bytes());
            bytes.extend(rounds.to_le_bytes());
            bytes.extend([0, 0, 0]);
            bytes
        };
        assert!(kdf_within_limits(&v3(60_000)));
        assert!(!kdf_within_limits(&v3(u64::MAX)));
        let refused = import_kdbx(&v3(u64::MAX), "pw", None);
        assert!(matches!(refused, Err(ImportError::Kdbx(text)) if text.contains("accepts")));
        // Cut short or empty: left to the parser.
        assert!(kdf_within_limits(&[]));
        assert!(kdf_within_limits(&v4(b"M", 1)[..20]));
    }

    #[test]
    fn attached_files_and_earlier_passwords_come_in() {
        let mut db = Database::new();
        let mut root = db.root_mut();
        root.add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Scans");
            e.set_protected(fields::PASSWORD, "kp-secret");
            e.add_attachment("one.txt", keepass::db::Value::unprotected(b"1".to_vec()));
            e.add_attachment(
                "big.bin",
                keepass::db::Value::protected(vec![0u8; Attachment::MAX_BYTES + 1]),
            );
        });
        let mut changed = root.add_entry();
        changed.edit(|e| {
            e.set_unprotected(fields::TITLE, "Changed");
            e.set_protected(fields::PASSWORD, "kp-first");
        });
        changed.edit_tracking(|e| e.set_protected(fields::PASSWORD, "kp-second"));
        changed.edit_tracking(|e| e.set_unprotected(fields::TITLE, "Changed"));
        let mut bytes = Vec::new();
        db.save(&mut bytes, DatabaseKey::new().with_password("pw"))
            .unwrap();
        let report = import_kdbx(&bytes, "pw", None).unwrap();
        let scans = report.items.iter().find(|i| i.title == "Scans").unwrap();
        assert_eq!(scans.attachments.len(), 1);
        assert_eq!(scans.attachments[0].name, "one.txt");
        assert_eq!(scans.attachments[0].data, b"1");
        assert_eq!(
            report.warnings,
            ["\"Scans\": 1 attached file was not imported (too large, or more than an item keeps)"]
        );
        let changed = report.items.iter().find(|i| i.title == "Changed").unwrap();
        assert_eq!(changed.password, "kp-second");
        let earlier: Vec<&str> = changed
            .password_history
            .iter()
            .map(|c| c.password.as_str())
            .collect();
        assert_eq!(earlier, ["kp-first"], "each once, not the one in use");
    }

    #[test]
    fn more_websites_and_a_passkey_in_keepassxc_fields_come_in() {
        let passkey = Passkey::new("shop.example", b"user-1", "me@example.com", "Me").unwrap();
        let der = passkey.private_key_pkcs8().unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----
{}
-----END PRIVATE KEY-----",
            STANDARD.encode(der.as_slice())
        );
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Shop");
            e.set_unprotected(fields::URL, "https://shop.example");
            e.set_unprotected("KP2A_URL_2", "https://three.example");
            e.set_unprotected("KP2A_URL_1", "https://two.example");
            e.set_unprotected(PASSKEY_ID, URL_SAFE_NO_PAD.encode(&passkey.credential_id));
            e.set_unprotected(PASSKEY_RP, "shop.example");
            e.set_unprotected(PASSKEY_USER, "me@example.com");
            e.set_unprotected(PASSKEY_USER_HANDLE, URL_SAFE_NO_PAD.encode(b"user-1"));
            e.set_protected(PASSKEY_KEY, pem);
        });
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Broken");
            e.set_unprotected(fields::USERNAME, "me");
            e.set_protected(
                PASSKEY_KEY,
                "-----BEGIN PRIVATE KEY-----
AAAA
-----END PRIVATE KEY-----",
            );
        });
        let mut bytes = Vec::new();
        db.save(&mut bytes, DatabaseKey::new().with_password("pw"))
            .unwrap();
        let report = import_kdbx(&bytes, "pw", None).unwrap();
        let shop = report.items.iter().find(|i| i.title == "Shop").unwrap();
        assert_eq!(
            shop.urls,
            [
                "https://shop.example",
                "https://two.example",
                "https://three.example"
            ]
        );
        assert!(shop.custom_fields.is_empty(), "{:?}", shop.custom_fields);
        assert_eq!(shop.passkeys.len(), 1);
        let back = &shop.passkeys[0];
        assert_eq!(back.private_key(), passkey.private_key());
        assert_eq!(back.credential_id, passkey.credential_id);
        assert_eq!(back.user_handle, b"user-1");
        assert_eq!(
            back.display_name, "me@example.com",
            "no display name: the user's"
        );
        assert_eq!(
            report.warnings,
            ["\"Broken\": its passkey was not imported (damaged, or not a P-256 key)"]
        );
        assert!(!format!("{:?}", report.warnings).contains("AAAA"));
    }

    #[test]
    fn wrong_password_fails() {
        let bytes = sample_database("right");
        assert!(matches!(
            import_kdbx(&bytes, "wrong", None),
            Err(ImportError::Kdbx(_))
        ));
    }
}
