//! Unencrypted JSON exports (the layout most password managers read and write).

use serde::Deserialize;
use serde_json::Value;
use vault_core::{CustomField, ItemData, ItemKind};

use crate::{ImportError, ImportReport, dates::iso8601_to_unix, host_of, non_empty};

#[derive(Deserialize)]
struct Export {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    items: Vec<Item>,
    #[serde(default)]
    folders: Vec<ExportFolder>,
}

#[derive(Deserialize)]
struct ExportFolder {
    id: String,
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    #[serde(rename = "type")]
    kind: u8,
    name: Option<String>,
    folder_id: Option<String>,
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    /// 1 = ask for the master password again before showing the item.
    #[serde(default)]
    reprompt: u8,
    #[serde(default)]
    fields: Option<Vec<Field>>,
    login: Option<Login>,
    card: Option<Card>,
    identity: Option<serde_json::Map<String, Value>>,
    ssh_key: Option<serde_json::Map<String, Value>>,
    creation_date: Option<String>,
    revision_date: Option<String>,
    password_history: Option<Vec<OldPassword>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OldPassword {
    password: Option<String>,
    last_used_date: Option<String>,
}

#[derive(Deserialize)]
struct Field {
    name: Option<String>,
    value: Option<String>,
    /// 0 text, 1 hidden, 2 boolean, 3 linked
    #[serde(rename = "type", default)]
    kind: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    uris: Option<Vec<Uri>>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    fido2_credentials: Option<Vec<Value>>,
    password_revision_date: Option<String>,
}

#[derive(Deserialize)]
struct Uri {
    uri: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Card {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

/// Imports an unencrypted JSON export (not the encrypted variant).
pub(crate) fn import_json(bytes: &[u8]) -> Result<ImportReport, ImportError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let export: Export = serde_json::from_slice(bytes)?;
    if export.encrypted {
        return Err(ImportError::EncryptedExport);
    }

    let mut report = ImportReport::default();
    for source in export.items {
        let folder = source.folder_id.as_ref().and_then(|id| {
            export
                .folders
                .iter()
                .find(|f| &f.id == id)
                .and_then(|f| non_empty(f.name.clone()))
        });
        let title = non_empty(source.name.clone()).unwrap_or_else(|| "Untitled".into());
        let kind = match source.kind {
            1 => ItemKind::Login,
            3 => ItemKind::Card,
            5 => ItemKind::SshKey,
            2 | 4 => ItemKind::SecureNote,
            other => {
                report.warnings.push(format!(
                    "\"{title}\": unknown item type {other}, imported as a note"
                ));
                ItemKind::SecureNote
            }
        };
        let mut item = ItemData::new(kind, &title);
        item.notes = source.notes.unwrap_or_default();
        item.favorite = source.favorite;
        item.reprompt = source.reprompt != 0;
        if let Some(created) = source.creation_date.as_deref().and_then(iso8601_to_unix) {
            item.created_at = created;
        }
        if let Some(updated) = source.revision_date.as_deref().and_then(iso8601_to_unix) {
            item.updated_at = updated;
        }

        if let Some(login) = source.login {
            item.username = login.username.unwrap_or_default();
            item.password = login.password.unwrap_or_default();
            item.totp = login.totp.unwrap_or_default();
            if let Some(changed) = login
                .password_revision_date
                .as_deref()
                .and_then(iso8601_to_unix)
            {
                item.password_changed_at = changed;
            }
            item.urls = login
                .uris
                .unwrap_or_default()
                .into_iter()
                .filter_map(|u| non_empty(u.uri))
                .collect();
            if login.fido2_credentials.is_some_and(|c| !c.is_empty()) {
                report.warnings.push(format!(
                    "\"{title}\": its passkey was not exported; register a new passkey for that site"
                ));
            }
            if title == "Untitled"
                && let Some(host) = item.urls.first().and_then(|u| host_of(u))
            {
                item.title = host;
            }
        }

        for old in source.password_history.unwrap_or_default() {
            if let Some(password) = non_empty(old.password) {
                item.password_history.push(vault_core::PasswordChange {
                    password,
                    replaced_at: old
                        .last_used_date
                        .as_deref()
                        .and_then(iso8601_to_unix)
                        .unwrap_or(0),
                });
            }
        }
        item.password_history.sort_by_key(|c| c.replaced_at);

        if let Some(card) = source.card {
            item.username = card.cardholder_name.unwrap_or_default();
            push_field(&mut item, "Number", card.number, true);
            let expiry = match (non_empty(card.exp_month), non_empty(card.exp_year)) {
                (Some(m), Some(y)) => Some(format!("{m:0>2}/{y}")),
                (None, Some(y)) => Some(y),
                (Some(m), None) => Some(m),
                (None, None) => None,
            };
            push_field(&mut item, "Expiry", expiry, false);
            push_field(&mut item, "Security code", card.code, true);
            push_field(&mut item, "Brand", card.brand, false);
        }

        // An SSH key: the private key where a login keeps its password, the public key and
        // its fingerprint in their fields (worked out from the private key when missing).
        if let Some(mut ssh) = source.ssh_key.filter(|_| kind == ItemKind::SshKey) {
            let mut take = |key: &str| match ssh.remove(key) {
                Some(Value::String(text)) => non_empty(Some(text)),
                _ => None,
            };
            item.password = take("privateKey").unwrap_or_default();
            let public =
                take("publicKey").or_else(|| vault_core::ssh::public_key_of(&item.password));
            let fingerprint = take("keyFingerprint")
                .or_else(|| public.as_deref().and_then(vault_core::ssh::fingerprint));
            push_field(&mut item, vault_core::ssh::PUBLIC_KEY_FIELD, public, false);
            push_field(
                &mut item,
                vault_core::ssh::FINGERPRINT_FIELD,
                fingerprint,
                false,
            );
        }

        for (map, sensitive_keys) in [(
            source.identity,
            &["ssn", "passportNumber", "licenseNumber"][..],
        )] {
            for (key, value) in map.into_iter().flatten() {
                if let Value::String(text) = value {
                    let sensitive = sensitive_keys.contains(&key.as_str());
                    push_field(&mut item, &humanize(&key), Some(text), sensitive);
                }
            }
        }

        for field in source.fields.unwrap_or_default() {
            if field.kind == 3 {
                continue; // "linked" fields only point at other fields
            }
            let name = non_empty(field.name).unwrap_or_else(|| "Field".into());
            push_field(&mut item, &name, field.value, field.kind == 1);
        }

        report.push(item, folder);
    }
    Ok(report)
}

fn push_field(item: &mut ItemData, name: &str, value: Option<String>, sensitive: bool) {
    if let Some(value) = non_empty(value) {
        item.custom_fields.push(CustomField {
            name: name.to_owned(),
            value,
            sensitive,
        });
    }
}

/// `passportNumber` → `Passport number`
fn humanize(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    for (i, c) in key.chars().enumerate() {
        if i == 0 {
            out.extend(c.to_uppercase());
        } else if c.is_uppercase() {
            out.push(' ');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "encrypted": false,
      "folders": [{"id": "f1", "name": "Work"}],
      "items": [
        {
          "id": "1", "folderId": "f1", "type": 1, "reprompt": 0,
          "name": "GitHub", "notes": "2FA on phone", "favorite": true,
          "fields": [
            {"name": "PIN", "value": "1234", "type": 1, "linkedId": null},
            {"name": "Plan", "value": "pro", "type": 0, "linkedId": null},
            {"name": "Linked", "value": null, "type": 3, "linkedId": 101}
          ],
          "login": {
            "uris": [{"match": null, "uri": "https://github.com/login"}, {"match": null, "uri": "https://gist.github.com"}],
            "username": "octocat", "password": "s3cret", "totp": "JBSWY3DPEHPK3PXP",
            "fido2Credentials": [{"credentialId": "abc"}]
          },
          "creationDate": "2023-11-14T22:13:20.000Z", "revisionDate": "2023-11-14T22:13:21.000Z"
        },
        {
          "id": "2", "type": 3, "name": "Visa", "notes": null, "favorite": false,
          "card": {"cardholderName": "A Person", "brand": "Visa", "number": "4111111111111111",
                   "expMonth": "7", "expYear": "2030", "code": "123"}
        },
        {
          "id": "3", "type": 2, "name": "Wi-Fi", "notes": "router password: x", "favorite": false,
          "secureNote": {"type": 0}
        },
        {
          "id": "4", "type": 4, "name": "Me", "notes": null, "favorite": false,
          "identity": {"firstName": "Ana", "passportNumber": "X123", "address1": null}
        },
        {
          "id": "5", "type": 1, "name": "", "login": {"uris": [{"uri": "https://www.example.org/x"}], "username": "u", "password": "p"}
        }
      ]
    }"#;

    #[test]
    fn imports_all_item_types() {
        let report = import_json(SAMPLE.as_bytes()).unwrap();
        assert_eq!(report.items.len(), 5);
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings); // the passkey

        let github = &report.items[0];
        assert_eq!(github.kind, ItemKind::Login);
        assert_eq!(
            (github.username.as_str(), github.password.as_str()),
            ("octocat", "s3cret")
        );
        assert_eq!(github.urls.len(), 2);
        assert_eq!(github.totp, "JBSWY3DPEHPK3PXP");
        assert!(github.favorite);
        assert_eq!(github.created_at, 1_700_000_000);
        assert_eq!(github.custom_fields.len(), 2, "linked field skipped");
        assert!(github.custom_fields[0].sensitive && !github.custom_fields[1].sensitive);

        let card = &report.items[1];
        assert_eq!(card.kind, ItemKind::Card);
        let value = |name: &str| {
            card.custom_fields
                .iter()
                .find(|f| f.name == name)
                .map(|f| (f.value.as_str(), f.sensitive))
        };
        assert_eq!(value("Number"), Some(("4111111111111111", true)));
        assert_eq!(value("Expiry"), Some(("07/2030", false)));
        assert_eq!(value("Security code"), Some(("123", true)));

        assert_eq!(report.items[2].kind, ItemKind::SecureNote);
        assert_eq!(report.items[2].notes, "router password: x");

        let identity = &report.items[3];
        assert!(
            identity
                .custom_fields
                .iter()
                .any(|f| f.name == "Passport number" && f.sensitive)
        );
        assert!(
            identity
                .custom_fields
                .iter()
                .any(|f| f.name == "First name" && f.value == "Ana")
        );

        assert_eq!(
            report.items[4].title, "example.org",
            "untitled login named after its host"
        );
    }

    #[test]
    fn rejects_encrypted_exports() {
        let encrypted = r#"{"encrypted": true, "passwordProtected": true, "data": "..."}"#;
        assert!(matches!(
            import_json(encrypted.as_bytes()),
            Err(ImportError::EncryptedExport)
        ));
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(matches!(
            import_json(b"{not json"),
            Err(ImportError::Json(_))
        ));
    }
}
