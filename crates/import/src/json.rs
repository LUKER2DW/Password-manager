//! Unencrypted JSON exports (the layout most password managers read and write).

use serde::Deserialize;
use serde_json::Value;
use vault_core::{CustomField, ItemData, ItemKind, RecoveryCode};

use crate::{
    ImportError, ImportReport, dates::iso8601_to_unix, export, host_of, left_out_list, non_empty,
};

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
    /// This app's own exports: the recovery codes as codes, `[{"code", "used"}]`, next to the
    /// hidden field "Recovery codes" written for other managers. Read leniently: anything
    /// else leaves that field as it is.
    recovery_codes: Option<Value>,
    /// This app's own exports: how many attachments, passkeys and earlier passwords the item
    /// had that the file leaves out, `{"attachments": n, …}`.
    left_out: Option<Value>,
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
    /// How the website is matched for autofill: null or 0 base domain, 1 host, 2 starts
    /// with, 3 exact, 4 regular expression, 5 never.
    #[serde(rename = "match", default)]
    matching: Option<Value>,
}

/// What becomes of a website with its autofill rule. The vault fills a login into pages of
/// its websites' exact origin (scheme, host and port), any path: a rule narrower than that
/// can't be kept, so such a website is kept for reference only, out of autofill, and the
/// person is told. A rule wider than the origin (base domain, host) only narrows.
enum UriRule {
    /// Filled on the website's origin.
    Fill,
    /// Kept, never filled: the owner said never, or a rule this vault can't keep.
    Reference(&'static str),
}

fn uri_rule(uri: &str, matching: Option<&Value>) -> UriRule {
    let rule = match matching {
        None | Some(Value::Null) => return UriRule::Fill,
        Some(value) => value.as_u64(),
    };
    match rule {
        Some(0 | 1) => UriRule::Fill,
        // "Starts with" a whole origin is the origin; with a path, narrower.
        Some(2) if url_path_is_root(uri) => UriRule::Fill,
        Some(2) => UriRule::Reference("only addresses starting with it"),
        Some(3) => UriRule::Reference("only that exact address"),
        Some(4) => UriRule::Reference("a regular expression"),
        Some(5) => UriRule::Reference("never filled"),
        _ => UriRule::Reference("an unknown rule"),
    }
}

/// Whether `uri` names a whole site: nothing after the host and port but "/".
fn url_path_is_root(uri: &str) -> bool {
    let Some((_, rest)) = uri.split_once("://") else {
        return false;
    };
    match rest.find(['/', '?', '#']) {
        None => true,
        Some(at) => &rest[at..] == "/",
    }
}

/// The name of the field a website kept for reference only goes into.
pub(crate) const REFERENCE_FIELD: &str = "Website (not filled)";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Card {
    cardholder_name: Option<String>,
    brand: Option<String>,
    /// `None` when the key isn't there at all: only this app's own exports leave it out (the
    /// card's details are fields there), and their `code` is the card's PIN.
    #[serde(default, deserialize_with = "present")]
    number: Option<Option<String>>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

/// A key that is there, even as `null`.
fn present<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::deserialize(deserializer).map(Some)
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
            let mut narrowed = Vec::new();
            for uri in login.uris.unwrap_or_default() {
                let Some(address) = non_empty(uri.uri) else {
                    continue;
                };
                match uri_rule(&address, uri.matching.as_ref()) {
                    UriRule::Fill => item.urls.push(address),
                    UriRule::Reference(rule) => {
                        narrowed.push(rule);
                        item.custom_fields.push(CustomField {
                            name: REFERENCE_FIELD.into(),
                            value: address,
                            sensitive: false,
                        });
                    }
                }
            }
            for rule in narrowed {
                report.warnings.push(format!(
                    "\"{title}\": a website set to {rule} was kept in the field \"{REFERENCE_FIELD}\" and is not filled (this vault fills a whole website or nothing)"
                ));
            }
            // The file has them (with their keys), but this reader doesn't bring them in.
            let passkeys = login.fido2_credentials.map_or(0, |c| c.len());
            if let Some((what, verb)) = left_out_list(&[(passkeys, "passkey", "passkeys")]) {
                report.warnings.push(format!(
                    "\"{title}\": {what} in this file {verb} not imported (passkeys are not read from an export); register a new passkey for that site"
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
            let own_export = card.number.is_none()
                && card.brand.is_none()
                && card.exp_month.is_none()
                && card.exp_year.is_none();
            push_field(&mut item, "Number", card.number.flatten(), true);
            let expiry = match (non_empty(card.exp_month), non_empty(card.exp_year)) {
                (Some(m), Some(y)) => Some(format!("{m:0>2}/{y}")),
                (None, Some(y)) => Some(y),
                (Some(m), None) => Some(m),
                (None, None) => None,
            };
            push_field(&mut item, "Expiry", expiry, false);
            if own_export {
                item.password = card.code.unwrap_or_default();
            } else {
                push_field(&mut item, "Security code", card.code, true);
            }
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

        let codes = recovery_codes(source.recovery_codes);
        if let Some(text) = export::codes_text(&codes) {
            // The hidden field written next to them for other managers holds the same codes
            // again: it goes, unless someone changed it (then it is kept as it is).
            if let Some(at) = item.custom_fields.iter().position(|f| {
                f.name == export::RECOVERY_CODES_FIELD && f.sensitive && f.value == *text
            }) {
                item.custom_fields.remove(at);
            }
            item.recovery_codes = codes;
        }

        if let Some(left_out) = source.left_out {
            let count = |key: &str| {
                left_out
                    .get(key)
                    .and_then(Value::as_u64)
                    .and_then(|n| usize::try_from(n).ok())
                    .unwrap_or(0)
            };
            if let Some((what, verb)) = left_out_list(&[
                (count("attachments"), "attached file", "attached files"),
                (count("passkeys"), "passkey", "passkeys"),
                (
                    count("passwordHistory"),
                    "earlier password",
                    "earlier passwords",
                ),
            ]) {
                let still = if verb == "was" { "it is" } else { "they are" };
                report.warnings.push(format!(
                    "\"{title}\": {what} {verb} not in this export; {still} only in the vault it was made from"
                ));
            }
        }

        report.push(item, folder);
    }
    Ok(report)
}

/// The `recoveryCodes` of this app's exports; empty for anything else. Each code is moved out
/// of the document, so that no copy of it stays behind.
fn recovery_codes(value: Option<Value>) -> Vec<RecoveryCode> {
    let Some(Value::Array(entries)) = value else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter_map(|mut entry| {
            let Value::String(code) = entry.get_mut("code")?.take() else {
                return None;
            };
            let code = non_empty(Some(code))?;
            let used = entry.get("used").and_then(Value::as_bool).unwrap_or(false);
            Some(RecoveryCode { code, used })
        })
        .collect()
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

    #[test]
    fn a_websites_autofill_rule_is_never_widened() {
        let export = r#"{"encrypted": false, "items": [{
            "type": 1, "name": "Bank",
            "login": {"username": "me", "password": "pw", "uris": [
              {"match": null, "uri": "https://bank.example"},
              {"match": 1, "uri": "https://host.bank.example"},
              {"match": 5, "uri": "https://never.bank.example"},
              {"match": 3, "uri": "https://bank.example/login/exact"},
              {"match": 2, "uri": "https://bank.example/app/"},
              {"match": 2, "uri": "https://starts.bank.example/"},
              {"match": 4, "uri": "^https://.*\\.bank\\.example/"}
            ]}
        }]}"#;
        let report = import_json(export.as_bytes()).unwrap();
        let item = &report.items[0];
        // Filled: the whole site, as before, and rules no narrower than a whole site.
        assert_eq!(
            item.urls,
            [
                "https://bank.example",
                "https://host.bank.example",
                "https://starts.bank.example/"
            ]
        );
        // "Never", "exact", a path prefix and an expression: kept, but never filled.
        let kept: Vec<&str> = item
            .custom_fields
            .iter()
            .filter(|f| f.name == REFERENCE_FIELD)
            .map(|f| f.value.as_str())
            .collect();
        assert_eq!(
            kept,
            [
                "https://never.bank.example",
                "https://bank.example/login/exact",
                "https://bank.example/app/",
                "^https://.*\\.bank\\.example/"
            ]
        );
        assert!(item.custom_fields.iter().all(|f| !f.sensitive));
        // And the person is told, once per website.
        let told = report
            .warnings
            .iter()
            .filter(|w| w.contains(REFERENCE_FIELD))
            .count();
        assert_eq!(told, 4, "{:?}", report.warnings);
        assert!(report.warnings.iter().any(|w| w.contains("never filled")));
    }

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
    fn passkeys_the_file_holds_are_counted_in_the_warning() {
        let report = import_json(SAMPLE.as_bytes()).unwrap();
        assert_eq!(
            report.warnings,
            [
                "\"GitHub\": 1 passkey in this file was not imported (passkeys are not read from an export); register a new passkey for that site"
            ]
        );
        let two = r#"{"items": [{"type": 1, "name": "Shop", "login": {
            "username": "me", "fido2Credentials": [{"credentialId": "a"}, {"credentialId": "b"}]
        }}]}"#;
        let report = import_json(two.as_bytes()).unwrap();
        assert!(
            report.warnings[0].starts_with("\"Shop\": 2 passkeys in this file were not imported"),
            "{:?}",
            report.warnings
        );
        let none = r#"{"items": [{"type": 1, "name": "Shop", "login": {"fido2Credentials": []}}]}"#;
        assert!(import_json(none.as_bytes()).unwrap().warnings.is_empty());
    }

    #[test]
    fn recovery_codes_come_back_as_codes_only_from_this_apps_own_keys() {
        let field =
            |value: &str| format!(r#"{{"name": "Recovery codes", "value": "{value}", "type": 1}}"#);
        let item = |codes: &str, value: &str| {
            format!(
                r#"{{"items": [{{"type": 1, "name": "Mail", "login": {{"username": "me"}},
                   "fields": [{}]{codes}}}]}}"#,
                field(value)
            )
        };
        let first = |json: String| import_json(json.as_bytes()).unwrap().items.remove(0);
        let codes_field = |item: &ItemData| {
            item.custom_fields
                .iter()
                .find(|f| f.name == "Recovery codes" && f.sensitive)
                .map(|f| f.value.clone())
        };

        // This app's export: codes again, the field for other managers dropped.
        let ours = first(item(
            r#", "recoveryCodes": [{"code": "aaaa", "used": true}, {"code": "bbbb"}]"#,
            r"aaaa (used)\nbbbb",
        ));
        assert_eq!(
            ours.recovery_codes,
            [
                RecoveryCode {
                    code: "aaaa".into(),
                    used: true
                },
                RecoveryCode {
                    code: "bbbb".into(),
                    used: false
                }
            ]
        );
        assert_eq!(codes_field(&ours), None);

        // An older export, or another manager's file: the hidden field, as before.
        let older = first(item("", r"aaaa (used)\nbbbb"));
        assert!(older.recovery_codes.is_empty());
        assert_eq!(codes_field(&older).as_deref(), Some("aaaa (used)\nbbbb"));

        // A field that says more than the codes is kept next to them.
        let edited = first(item(
            r#", "recoveryCodes": [{"code": "aaaa", "used": true}]"#,
            r"aaaa (used)\nwritten by hand",
        ));
        assert_eq!(edited.recovery_codes.len(), 1);
        assert_eq!(
            codes_field(&edited).as_deref(),
            Some("aaaa (used)\nwritten by hand")
        );

        // Codes in another shape are not codes: the field stays, the import goes on.
        let odd = first(item(r#", "recoveryCodes": "aaaa""#, r"aaaa"));
        assert!(odd.recovery_codes.is_empty());
        assert_eq!(codes_field(&odd).as_deref(), Some("aaaa"));
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
