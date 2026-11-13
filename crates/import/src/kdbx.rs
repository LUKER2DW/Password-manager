//! KeePass / KeePassXC databases (KDBX 3.1 and 4).

use std::collections::HashMap;

use keepass::{Database, DatabaseKey, db::fields};
use vault_core::{CustomField, ItemData, ItemKind};

use crate::{ImportError, ImportReport, host_of, non_empty};

/// Opens a KDBX database with its password (and optional key file) and converts every entry
/// outside the recycle bin.
pub fn import_kdbx(
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
        if attachments > 0 {
            report.warnings.push(format!(
                "\"{title}\": {attachments} attachment(s) not imported yet (attachments come in a later version)"
            ));
        }
        report.push(item, folder);
    }
    Ok(report)
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
    fn wrong_password_fails() {
        let bytes = sample_database("right");
        assert!(matches!(
            import_kdbx(&bytes, "wrong", None),
            Err(ImportError::Kdbx(_))
        ));
    }
}
