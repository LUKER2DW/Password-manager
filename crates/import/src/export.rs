//! Unencrypted exports, for moving to another password manager.
//!
//! Both use the common layout most managers import: JSON (`.json`, keeps folders,
//! custom fields and cards) and CSV (`.csv`, logins and notes). The output is plain text holding
//! every password: it is returned in a wiped-on-drop buffer and should go straight to a file the
//! user chose.

use serde_json::{Value, json};
use vault_core::{ItemData, ItemKind, Vault};
use zeroize::Zeroizing;

/// Every item, decrypted one at a time, with its folder name.
fn items(vault: &Vault) -> Result<Vec<(ItemData, Option<String>)>, vault_core::Error> {
    let mut out = Vec::with_capacity(vault.len());
    for id in vault.item_ids().collect::<Vec<_>>() {
        let item = vault.get_item(&id)?;
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

/// Recovery codes have no place in other managers: they travel as one hidden custom field.
fn codes_text(item: &ItemData) -> Option<String> {
    (!item.recovery_codes.is_empty()).then(|| {
        item.recovery_codes
            .iter()
            .map(|c| {
                if c.used {
                    format!("{} (used)", c.code)
                } else {
                    c.code.clone()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
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
/// copy to carry elsewhere that is not readable by whoever finds the file.
pub fn export_sealed(vault: &Vault, password: &str) -> Result<Vec<u8>, vault_core::Error> {
    let json = export_json(vault)?;
    vault_core::sealed_export::seal(password, json.as_bytes())
}

/// Unencrypted JSON in the common layout (keeps folders, cards and fields).
pub fn export_json(vault: &Vault) -> Result<Zeroizing<String>, vault_core::Error> {
    let folders: Vec<Value> = vault
        .folders()
        .iter()
        .map(|f| json!({ "id": f.id.to_hex(), "name": f.name }))
        .collect();
    let mut items_json = Vec::new();
    for (index, (item, _)) in items(vault)?.iter().enumerate() {
        let mut fields: Vec<Value> = item
            .custom_fields
            .iter()
            .map(|f| json!({ "name": f.name, "value": f.value, "type": u8::from(f.sensitive) }))
            .collect();
        if let Some(codes) = codes_text(item) {
            fields.push(json!({ "name": "Recovery codes", "value": codes, "type": 1 }));
        }
        let mut entry = json!({
            "id": format!("item-{index}"),
            "folderId": item.folder.map(|f| f.to_hex()),
            "type": match item.kind {
                ItemKind::Login | ItemKind::Passkey => 1,
                ItemKind::SecureNote => 2,
                ItemKind::Card => 3,
            },
            "reprompt": u8::from(item.reprompt),
            "name": item.title,
            "notes": (!item.notes.is_empty()).then_some(&item.notes),
            "favorite": item.favorite,
            "fields": fields,
            "creationDate": iso8601(item.created_at),
            "revisionDate": iso8601(item.updated_at),
        });
        match item.kind {
            ItemKind::Login | ItemKind::Passkey => {
                entry["login"] = json!({
                    "uris": item.urls.iter().map(|u| json!({ "match": null, "uri": u })).collect::<Vec<_>>(),
                    "username": item.username,
                    "password": item.password,
                    "totp": (!item.totp.is_empty()).then_some(&item.totp),
                });
            }
            ItemKind::SecureNote => entry["secureNote"] = json!({ "type": 0 }),
            ItemKind::Card => {
                entry["card"] = json!({
                    "cardholderName": item.username,
                    "code": (!item.password.is_empty()).then_some(&item.password),
                });
            }
        }
        items_json.push(entry);
    }
    let document = json!({ "encrypted": false, "folders": folders, "items": items_json });
    let text = serde_json::to_string_pretty(&document).map_err(|_| vault_core::Error::Malformed)?;
    Ok(Zeroizing::new(text))
}

/// CSV in the common layout (logins and notes; cards go out as notes with their fields).
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
        let mut fields: Vec<String> = item
            .custom_fields
            .iter()
            .map(|f| format!("{}: {}", f.name, f.value))
            .collect();
        if let Some(codes) = codes_text(&item) {
            fields.push(format!("Recovery codes: {}", codes.replace('\n', " ")));
        }
        let is_login = matches!(item.kind, ItemKind::Login | ItemKind::Passkey);
        let mut record = Zeroizing::new(vec![
            folder.unwrap_or_default(),
            if item.favorite { "1" } else { "" }.to_owned(),
            if is_login { "login" } else { "note" }.to_owned(),
            item.title.clone(),
            item.notes.clone(),
            fields.join("\n"),
            if item.reprompt { "1" } else { "" }.to_owned(),
            item.urls.first().cloned().unwrap_or_default(),
            item.username.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{import_csv, import_json};
    use vault_core::{CustomField, KdfParams, RecoveryCode, SecretKey};

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
        assert!(
            item.custom_fields.iter().any(|f| f.name == "Recovery codes"
                && f.value == "aaaa (used)\nbbbb"
                && f.sensitive)
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
    fn dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20.000Z");
    }
}
