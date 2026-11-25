//! KeePass / KeePassXC databases (KDBX 3.1 and 4).

use std::collections::HashMap;

use keepass::{Database, DatabaseKey, db::fields};
use vault_core::{CustomField, ItemData, ItemKind};

use crate::{ImportError, ImportReport, counted, host_of, left_out_list, non_empty};

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
    // Entries with a password in their history that isn't the one in use.
    let mut with_earlier = 0usize;
    for entry in db.iter_all_entries() {
        if deleted.contains(&entry.id()) {
            continue;
        }
        let folder = group_paths.get(&entry.id()).cloned();

        let get = |name: &str| non_empty(entry.get(name).map(str::to_owned));
        let url = get(fields::URL);
        let title = get(fields::TITLE)
            .or_else(|| url.as_deref().and_then(host_of))
            .unwrap_or_else(|| "Untitled".into());
        let username = get(fields::USERNAME);
        let password = get(fields::PASSWORD);
        let kind = if username.is_none() && password.is_none() && url.is_none() {
            ItemKind::SecureNote
        } else {
            ItemKind::Login
        };

        let mut item = ItemData::new(kind, &title);
        item.username = username.unwrap_or_default();
        item.password = password.unwrap_or_default();
        item.urls = url.into_iter().collect();
        item.notes = get(fields::NOTES).unwrap_or_default();
        item.totp = get(fields::OTP)
            .or_else(|| get("TimeOtp-Secret-Base32"))
            .unwrap_or_default();
        if let Some(created) = entry.times.creation {
            item.created_at = created.and_utc().timestamp();
        }
        if let Some(modified) = entry.times.last_modification {
            item.updated_at = modified.and_utc().timestamp();
        }

        let mut extra: Vec<(&String, &keepass::db::Value<String>)> = entry
            .fields
            .iter()
            .filter(|(name, _)| {
                !fields::KNOWN_FIELDS.contains(&name.as_str()) && name.as_str() != fields::OTP
            })
            .collect();
        extra.sort_by(|a, b| a.0.cmp(b.0));
        for (name, value) in extra {
            if name.starts_with("TimeOtp-") || name.starts_with("KP2A_") {
                continue;
            }
            if let Some(text) = non_empty(Some(value.get().clone())) {
                item.custom_fields.push(CustomField {
                    name: name.clone(),
                    value: text,
                    sensitive: value.is_protected(),
                });
            }
        }

        let attachments = entry.attachments().count();
        if let Some((what, verb)) =
            left_out_list(&[(attachments, "attached file", "attached files")])
        {
            let them = if verb == "was" { "it" } else { "them" };
            report.warnings.push(format!(
                "\"{title}\": {what} {verb} not imported (files are not read from a KeePass database); attach {them} again by hand"
            ));
        }
        with_earlier += usize::from(entry.history.as_ref().is_some_and(|history| {
            history.get_entries().iter().any(|old| {
                old.get_password()
                    .is_some_and(|old| !old.is_empty() && old != item.password)
            })
        }));
        report.push(item, folder);
    }
    if with_earlier > 0 {
        // First, as it is about the whole file: the app shows only the first few.
        let warning = format!(
            "earlier passwords of {} were not imported (the history in a KeePass database is not read); they are only in that database",
            counted(with_earlier, "entry", "entries")
        );
        report.warnings.insert(0, warning);
    }
    Ok(report)
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
    fn attached_files_left_behind_are_counted() {
        let mut db = Database::new();
        let mut root = db.root_mut();
        root.add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Scans");
            e.set_protected(fields::PASSWORD, "kp-secret");
            e.add_attachment("one.txt", keepass::db::Value::unprotected(b"1".to_vec()));
            e.add_attachment("two.txt", keepass::db::Value::unprotected(b"2".to_vec()));
        });
        root.add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Receipt");
            e.set_protected(fields::PASSWORD, "kp-secret");
            e.add_attachment(
                "receipt.txt",
                keepass::db::Value::unprotected(b"3".to_vec()),
            );
        });
        let mut bytes = Vec::new();
        db.save(&mut bytes, DatabaseKey::new().with_password("pw"))
            .unwrap();
        let mut warnings = import_kdbx(&bytes, "pw", None).unwrap().warnings;
        warnings.sort();
        assert_eq!(
            warnings,
            [
                "\"Receipt\": 1 attached file was not imported (files are not read from a KeePass database); attach it again by hand",
                "\"Scans\": 2 attached files were not imported (files are not read from a KeePass database); attach them again by hand",
            ]
        );
    }

    #[test]
    fn earlier_passwords_left_behind_are_told_once_for_the_file() {
        let mut db = Database::new();
        let mut root = db.root_mut();
        let mut changed = root.add_entry();
        changed.edit(|e| {
            e.set_unprotected(fields::TITLE, "Changed");
            e.set_protected(fields::PASSWORD, "kp-first");
        });
        changed.edit_tracking(|e| e.set_protected(fields::PASSWORD, "kp-second"));
        let mut renamed = root.add_entry();
        renamed.edit(|e| {
            e.set_unprotected(fields::TITLE, "Renamed");
            e.set_protected(fields::PASSWORD, "kp-same");
        });
        renamed.edit_tracking(|e| e.set_unprotected(fields::TITLE, "Renamed later"));
        let mut bytes = Vec::new();
        db.save(&mut bytes, DatabaseKey::new().with_password("pw"))
            .unwrap();
        assert_eq!(
            import_kdbx(&bytes, "pw", None).unwrap().warnings,
            [
                "earlier passwords of 1 entry were not imported (the history in a KeePass database is not read); they are only in that database"
            ]
        );
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
