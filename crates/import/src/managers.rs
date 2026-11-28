//! Other managers' own JSON exports, each told by its shape (never by a product's name):
//!
//! - **vaults of typed items**: `{"vaults": {id: {"name", "items": [{"data": {"metadata",
//!   "type", "content", "extraFields"}}]}}}`, logins with `itemUsername`, `itemEmail`,
//!   `urls` and `totpUri`, notes, cards, identities;
//! - **items of labelled fields**: `{"items": [{"title", "category", "fields": [{"label",
//!   "type", "value", "sensitive"}]}], "folders"}`, each field's `type` saying what it is
//!   (`username`, `password`, `url`, `totp`, `ccNumber`…);
//! - **records**: `{"records": [{"title", "login", "password", "login_url", "notes",
//!   "custom_fields", "folders"}]}`, the one-time code under `$oneTimeCode` among the custom
//!   fields.
//!
//! Items in a trash or archive of the export are left out, and the review told how many.

use serde_json::Value;
use vault_core::{CustomField, ItemData, ItemKind, card};

use crate::export::wipe;
use crate::{ImportError, ImportReport, counted, host_of, non_empty};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    Vaults,
    LabelledFields,
    Records,
}

pub(crate) fn shape(document: &Value) -> Option<Shape> {
    if document.get("vaults").is_some_and(Value::is_object) {
        return Some(Shape::Vaults);
    }
    let items = document.get("items").and_then(Value::as_array);
    if items.is_some_and(|items| {
        items
            .iter()
            .any(|i| i.get("fields").is_some_and(Value::is_array) && i.get("category").is_some())
    }) {
        return Some(Shape::LabelledFields);
    }
    if document.get("records").is_some_and(Value::is_array) {
        return Some(Shape::Records);
    }
    None
}

pub(crate) fn import_shape(mut document: Value, shape: Shape) -> Result<ImportReport, ImportError> {
    if document.get("encrypted").and_then(Value::as_bool) == Some(true) {
        wipe(&mut document);
        return Err(ImportError::EncryptedExport);
    }
    let mut report = ImportReport::default();
    let mut binned = 0;
    match shape {
        Shape::Vaults => vaults(&document, &mut report, &mut binned),
        Shape::LabelledFields => labelled_fields(&document, &mut report, &mut binned),
        Shape::Records => records(&document, &mut report),
    }
    if binned > 0 {
        report.warnings.insert(
            0,
            format!(
                "{} in the trash or the archive of the export {} left out",
                counted(binned, "item", "items"),
                if binned == 1 { "was" } else { "were" }
            ),
        );
    }
    wipe(&mut document);
    Ok(report)
}

fn text(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(|t| t.trim().to_owned())
        .unwrap_or_default()
}

fn time(value: &Value, pointer: &str) -> Option<i64> {
    let value = value.pointer(pointer)?;
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(crate::dates::iso8601_to_unix))
}

fn field(item: &mut ItemData, name: &str, value: String, sensitive: bool) {
    if !value.trim().is_empty() {
        item.custom_fields.push(CustomField {
            name: name.to_owned(),
            value,
            sensitive,
        });
    }
}

fn finish(item: &mut ItemData) {
    if item.title == "Untitled"
        && let Some(host) = item.urls.first().and_then(|u| host_of(u))
    {
        item.title = host;
    }
}

/// `passportNumber` → `Passport number`
fn humanize(key: &str) -> String {
    let mut out = String::new();
    for (at, c) in key.chars().enumerate() {
        if at == 0 {
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

fn vaults(document: &Value, report: &mut ImportReport, binned: &mut usize) {
    let Some(vaults) = document.get("vaults").and_then(Value::as_object) else {
        return;
    };
    for vault in vaults.values() {
        let folder = non_empty(Some(text(vault, "/name")));
        for entry in vault
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            // 1 active, 2 trashed.
            if entry.get("state").and_then(Value::as_u64) == Some(2) {
                *binned += 1;
                continue;
            }
            let data = &entry["data"];
            let title =
                non_empty(Some(text(data, "/metadata/name"))).unwrap_or_else(|| "Untitled".into());
            let content = &data["content"];
            let kind = match text(data, "/type").as_str() {
                "login" | "alias" => ItemKind::Login,
                "creditCard" => ItemKind::Card,
                "sshKey" => ItemKind::SshKey,
                _ => ItemKind::SecureNote,
            };
            let mut item = ItemData::new(kind, &title);
            item.notes = text(data, "/metadata/note");
            item.favorite = entry.get("pinned").and_then(Value::as_bool) == Some(true);
            if let Some(at) = time(entry, "/createTime") {
                item.created_at = at;
            }
            if let Some(at) = time(entry, "/modifyTime") {
                item.updated_at = at;
            }
            match kind {
                ItemKind::Login => {
                    let username = text(content, "/itemUsername");
                    let email = text(content, "/itemEmail");
                    if username.is_empty() {
                        item.username = email;
                    } else {
                        item.username = username;
                        field(&mut item, "Email", email, false);
                    }
                    item.password = text(content, "/password");
                    item.totp = text(content, "/totpUri");
                    item.urls = content
                        .get("urls")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|u| non_empty(u.as_str().map(str::to_owned)))
                        .collect();
                    let passkeys = content
                        .get("passkeys")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len);
                    if passkeys > 0 {
                        report.warnings.push(format!(
                            "\"{title}\": {} in this file {} not imported (passkeys are not read from this export); register a new one for that site",
                            counted(passkeys, "passkey", "passkeys"),
                            if passkeys == 1 { "was" } else { "were" }
                        ));
                    }
                }
                ItemKind::Card => {
                    item.username = text(content, "/cardholderName");
                    item.password = text(content, "/pin");
                    field(&mut item, card::NUMBER, text(content, "/number"), true);
                    let expiry = text(content, "/expirationDate");
                    let expiry = card::parse_expiry(&expiry)
                        .or_else(|| {
                            // "2029-08"
                            let (y, m) = expiry.split_once('-')?;
                            Some((m.parse().ok()?, y.parse().ok()?))
                        })
                        .map(card::format_expiry)
                        .unwrap_or(expiry);
                    field(&mut item, card::EXPIRY, expiry, false);
                    field(
                        &mut item,
                        card::SECURITY_CODE,
                        text(content, "/verificationNumber"),
                        true,
                    );
                }
                ItemKind::SshKey => {
                    item.password = text(content, "/privateKey");
                    let public = non_empty(Some(text(content, "/publicKey")))
                        .or_else(|| vault_core::ssh::public_key_of(&item.password));
                    if let Some(public) = public {
                        field(&mut item, vault_core::ssh::PUBLIC_KEY_FIELD, public, false);
                    }
                }
                _ => {
                    // An identity and other kinds: their texts as fields.
                    if let Some(map) = content.as_object() {
                        let mut keys: Vec<&String> = map.keys().collect();
                        keys.sort();
                        for key in keys {
                            if let Some(value) = map[key].as_str() {
                                let secret = key.contains("Number") || key.contains("password");
                                field(&mut item, &humanize(key), value.trim().to_owned(), secret);
                            }
                        }
                    }
                }
            }
            for extra in data
                .get("extraFields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let name =
                    non_empty(Some(text(extra, "/fieldName"))).unwrap_or_else(|| "Field".into());
                let value = text(extra, "/data/content");
                match text(extra, "/type").as_str() {
                    "totp" if item.totp.is_empty() => item.totp = value,
                    "hidden" | "totp" => field(&mut item, &name, value, true),
                    _ => field(&mut item, &name, value, false),
                }
            }
            finish(&mut item);
            report.push(item, folder.clone());
        }
    }
}

fn labelled_fields(document: &Value, report: &mut ImportReport, binned: &mut usize) {
    let folder_names: Vec<(String, String)> = document
        .get("folders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|f| (text(f, "/uuid"), text(f, "/title")))
        .collect();
    for entry in document
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let flag = |key: &str| {
            entry
                .get(key)
                .is_some_and(|v| v.as_u64() == Some(1) || v.as_bool() == Some(true))
        };
        if flag("trashed") || flag("archived") {
            *binned += 1;
            continue;
        }
        let title = non_empty(Some(text(entry, "/title"))).unwrap_or_else(|| "Untitled".into());
        let kind = match text(entry, "/category").as_str() {
            "login" | "password" | "computer" => ItemKind::Login,
            "creditcard" => ItemKind::Card,
            _ => ItemKind::SecureNote,
        };
        let mut item = ItemData::new(kind, &title);
        item.notes = text(entry, "/note");
        item.favorite = flag("favorite");
        if let Some(at) = time(entry, "/createdAt") {
            item.created_at = at;
        }
        if let Some(at) = time(entry, "/updated_at") {
            item.updated_at = at;
        }
        for f in entry
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if f.get("deleted").and_then(Value::as_u64) == Some(1) {
                continue;
            }
            let label = non_empty(Some(text(f, "/label"))).unwrap_or_else(|| "Field".into());
            let value = text(f, "/value");
            if value.is_empty() {
                continue;
            }
            let sensitive = f.get("sensitive").and_then(Value::as_u64) == Some(1);
            match text(f, "/type").as_str() {
                "username" if item.username.is_empty() => item.username = value,
                "email" if item.username.is_empty() => item.username = value,
                "password" if item.password.is_empty() && kind != ItemKind::Card => {
                    item.password = value;
                }
                "url" => item.urls.push(value),
                "totp" if item.totp.is_empty() => item.totp = value,
                "ccName" if kind == ItemKind::Card => item.username = value,
                "ccNumber" => field(&mut item, card::NUMBER, value, true),
                "ccCvc" => field(&mut item, card::SECURITY_CODE, value, true),
                "ccExpiry" => field(&mut item, card::EXPIRY, value, false),
                "ccPin" | "pin" if kind == ItemKind::Card && item.password.is_empty() => {
                    item.password = value;
                }
                "ccType" => field(&mut item, card::BRAND, value, false),
                "password" | "pin" | "totp" | "ccPin" => field(&mut item, &label, value, true),
                _ => field(&mut item, &label, value, sensitive),
            }
        }
        let folder = entry
            .get("folders")
            .and_then(Value::as_array)
            .and_then(|ids| ids.first())
            .and_then(Value::as_str)
            .and_then(|id| folder_names.iter().find(|(uuid, _)| uuid == id))
            .and_then(|(_, name)| non_empty(Some(name.clone())));
        finish(&mut item);
        report.push(item, folder);
    }
}

fn records(document: &Value, report: &mut ImportReport) {
    for entry in document
        .get("records")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let title = non_empty(Some(text(entry, "/title"))).unwrap_or_else(|| "Untitled".into());
        let login = text(entry, "/login");
        let password = text(entry, "/password");
        let url = text(entry, "/login_url");
        let kind = if login.is_empty() && password.is_empty() && url.is_empty() {
            ItemKind::SecureNote
        } else {
            ItemKind::Login
        };
        let mut item = ItemData::new(kind, &title);
        item.username = login;
        item.password = password;
        item.urls = non_empty(Some(url)).into_iter().collect();
        item.notes = text(entry, "/notes");
        if let Some(fields) = entry.get("custom_fields").and_then(Value::as_object) {
            let mut names: Vec<&String> = fields.keys().collect();
            names.sort();
            for name in names {
                let value = match &fields[name] {
                    Value::String(text) => text.trim().to_owned(),
                    Value::Null => continue,
                    other => other.to_string(),
                };
                if name.starts_with("$oneTimeCode") && item.totp.is_empty() {
                    item.totp = value;
                    continue;
                }
                // "$type:Label" names a typed field; the label is what the person sees.
                let shown = name
                    .strip_prefix('$')
                    .map(|rest| rest.split_once(':').map_or(rest, |(_, label)| label))
                    .unwrap_or(name);
                let secret = name.starts_with("$secret")
                    || name.starts_with("$pinCode")
                    || name.starts_with("$oneTimeCode");
                field(&mut item, &humanize(shown), value, secret);
            }
        }
        let folder = entry
            .get("folders")
            .and_then(Value::as_array)
            .and_then(|f| f.first())
            .map(|f| {
                let name = text(f, "/folder");
                let shared = text(f, "/shared_folder");
                let path = if shared.is_empty() || !name.is_empty() && shared == name {
                    name
                } else if name.is_empty() {
                    shared
                } else {
                    format!("{shared}/{name}")
                };
                path.replace('\\', "/")
            })
            .and_then(|f| non_empty(Some(f)));
        finish(&mut item);
        report.push(item, folder);
    }
}

#[cfg(test)]
mod tests {
    use crate::{Format, detect_format, import};
    use vault_core::ItemKind;

    // Every export below is made up for these tests from the layouts' published shapes.

    #[test]
    fn vaults_of_typed_items() {
        let json = r#"{"version": "1.21.2", "userId": "u", "encrypted": false, "vaults": {
          "v1": {"name": "Personal", "description": "", "items": [
            {"itemId": "a", "state": 1, "pinned": true, "createTime": 1700000000, "modifyTime": 1700000100,
             "data": {"metadata": {"name": "Mail", "note": "work mail"}, "type": "login",
               "extraFields": [{"fieldName": "PIN", "type": "hidden", "data": {"content": "4321"}},
                               {"fieldName": "Plan", "type": "text", "data": {"content": "family"}}],
               "content": {"itemEmail": "me@example.com", "itemUsername": "", "password": "mgr-test-pw",
                 "urls": ["https://mail.example", "https://webmail.example"],
                 "totpUri": "otpauth://totp/Mail?secret=JBSWY3DPEHPK3PXP", "passkeys": [{"keyId": "k"}]}}},
            {"itemId": "b", "state": 2, "data": {"metadata": {"name": "Old"}, "type": "login", "content": {}}},
            {"itemId": "c", "state": 1,
             "data": {"metadata": {"name": "Visa", "note": ""}, "type": "creditCard",
               "content": {"cardholderName": "M E Tester", "number": "4111111111111111",
                 "verificationNumber": "737", "expirationDate": "2029-08", "pin": "1234"}}},
            {"itemId": "d", "state": 1,
             "data": {"metadata": {"name": "Me", "note": ""}, "type": "identity",
               "content": {"fullName": "M E Tester", "passportNumber": "X1234567"}}}
          ]}}}"#;
        assert_eq!(detect_format(json.as_bytes()), Format::Json);
        let report = import(json.as_bytes(), Format::Json, "", None).unwrap();
        assert_eq!(report.items.len(), 3);
        let mail = &report.items[0];
        assert_eq!(
            (mail.username.as_str(), mail.password.as_str()),
            ("me@example.com", "mgr-test-pw")
        );
        assert_eq!(mail.urls.len(), 2);
        assert!(mail.favorite && mail.totp.starts_with("otpauth://"));
        assert_eq!(mail.created_at, 1_700_000_000);
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
        assert_eq!(report.folders[0].as_deref(), Some("Personal"));
        let card = &report.items[1];
        assert_eq!(card.kind, ItemKind::Card);
        let details = vault_core::card::CardDetails::from_item(card);
        assert_eq!(
            (details.number.as_str(), details.expiry.as_str()),
            ("4111111111111111", "08/29")
        );
        let me = &report.items[2];
        assert_eq!(me.kind, ItemKind::SecureNote);
        assert!(
            me.custom_fields
                .iter()
                .any(|f| f.name == "Passport number" && f.sensitive)
        );
        assert!(report.warnings[0].starts_with("1 item in the trash"));
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("1 passkey in this file was not imported"))
        );
        assert!(!report.warnings.join(" ").contains("mgr-test-pw"));
        // The encrypted variant is refused.
        let sealed = r#"{"version": "1", "encrypted": true, "vaults": {}}"#;
        assert!(import(sealed.as_bytes(), Format::Json, "", None).is_err());
    }

    #[test]
    fn items_of_labelled_fields() {
        let json = r#"{"folders": [{"uuid": "f1", "title": "Work"}], "items": [
          {"title": "Mail", "category": "login", "favorite": 1, "folders": ["f1"], "note": "n",
           "createdAt": 1700000000, "trashed": 0, "archived": 0, "fields": [
             {"label": "Username", "type": "username", "value": "me", "sensitive": 0},
             {"label": "E-mail", "type": "email", "value": "me@example.com", "sensitive": 0},
             {"label": "Password", "type": "password", "value": "mgr-test-pw", "sensitive": 1},
             {"label": "Website", "type": "url", "value": "https://mail.example", "sensitive": 0},
             {"label": "TOTP", "type": "totp", "value": "JBSWY3DPEHPK3PXP", "sensitive": 1},
             {"label": "Security answer", "type": "text", "value": "blue", "sensitive": 1},
             {"label": "Gone", "type": "text", "value": "x", "sensitive": 0, "deleted": 1}]},
          {"title": "Visa", "category": "creditcard", "fields": [
             {"label": "Cardholder", "type": "ccName", "value": "M E Tester"},
             {"label": "Number", "type": "ccNumber", "value": "4111111111111111", "sensitive": 1},
             {"label": "CVC", "type": "ccCvc", "value": "737", "sensitive": 1},
             {"label": "Expiry", "type": "ccExpiry", "value": "08/29"},
             {"label": "PIN", "type": "pin", "value": "1234", "sensitive": 1}]},
          {"title": "Old", "category": "login", "trashed": 1, "fields": []}]}"#;
        let report = import(json.as_bytes(), Format::Json, "", None).unwrap();
        assert_eq!(report.items.len(), 2);
        let mail = &report.items[0];
        assert_eq!(
            (mail.username.as_str(), mail.password.as_str()),
            ("me", "mgr-test-pw")
        );
        assert_eq!(mail.urls, ["https://mail.example"]);
        assert_eq!(mail.totp, "JBSWY3DPEHPK3PXP");
        assert!(mail.favorite);
        assert!(
            mail.custom_fields
                .iter()
                .any(|f| f.name == "E-mail" && f.value == "me@example.com")
        );
        assert!(
            mail.custom_fields
                .iter()
                .any(|f| f.name == "Security answer" && f.sensitive)
        );
        assert!(!mail.custom_fields.iter().any(|f| f.name == "Gone"));
        assert_eq!(report.folders[0].as_deref(), Some("Work"));
        let card = &report.items[1];
        assert_eq!(card.kind, ItemKind::Card);
        assert_eq!(
            (card.username.as_str(), card.password.as_str()),
            ("M E Tester", "1234")
        );
        let details = vault_core::card::CardDetails::from_item(card);
        assert_eq!(
            (details.number.as_str(), details.security_code.as_str()),
            ("4111111111111111", "737")
        );
        assert!(report.warnings[0].starts_with("1 item in the trash"));
    }

    #[test]
    fn records_with_custom_fields() {
        let json = r#"{"shared_folders": [], "records": [
          {"title": "Mail", "$type": "login", "login": "me", "password": "mgr-test-pw",
           "login_url": "https://mail.example", "notes": "n",
           "custom_fields": {"$oneTimeCode::1": "otpauth://totp/Mail?secret=JBSWY3DPEHPK3PXP",
                             "$pinCode:Door": "2468", "Plan": "family"},
           "folders": [{"folder": "Work\\Mail"}]},
          {"title": "Note", "$type": "encryptedNotes", "notes": "only text"}]}"#;
        let report = import(json.as_bytes(), Format::Json, "", None).unwrap();
        assert_eq!(report.items.len(), 2);
        let mail = &report.items[0];
        assert_eq!(mail.password, "mgr-test-pw");
        assert!(mail.totp.starts_with("otpauth://"));
        assert!(
            mail.custom_fields
                .iter()
                .any(|f| f.name == "Door" && f.sensitive)
        );
        assert!(
            mail.custom_fields
                .iter()
                .any(|f| f.name == "Plan" && !f.sensitive)
        );
        assert_eq!(report.folders[0].as_deref(), Some("Work/Mail"));
        assert_eq!(report.items[1].kind, ItemKind::SecureNote);
    }

    #[test]
    fn more_csv_layouts_are_read_by_their_headers() {
        // Columns as each layout names them; the values made up.
        let layouts: [(&str, &str); 6] = [
            (
                "Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2\n",
                "Mail,https://mail.example,,me,mgr-test-pw,n,Work,\n",
            ),
            (
                "Password Name,Password URL,Login Name,Password,Notes,Favorite,Tags,Folder Name\n",
                "Mail,https://mail.example,me,mgr-test-pw,n,1,a b,Work\n",
            ),
            (
                "nickname,url,username,password,additionalInfo,twofaSecret,createdDate\n",
                "Mail,https://mail.example,me,mgr-test-pw,n,JBSWY3DPEHPK3PXP,\n",
            ),
            (
                "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n",
                "\"Root/Work\",\"Mail\",\"me\",\"mgr-test-pw\",\"https://mail.example\",\"n\",\"\",\"0\",\"2024-05-02T10:00:00Z\",\"2024-05-01T10:00:00Z\"\n",
            ),
            (
                "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n",
                "login,Mail,https://mail.example,me@example.com,me,mgr-test-pw,n,,1700000000,1700000100,Work\n",
            ),
            (
                "name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,pin,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields\n",
                "Mail,https://mail.example,\"[\"\"https://webmail.example\"\"]\",me,mgr-test-pw,n,,,,,,,Work,,,,,,,,,password,\n",
            ),
        ];
        for (header, row) in layouts {
            let csv = format!("{header}{row}");
            let report = import(csv.as_bytes(), Format::Csv, "", None).unwrap();
            assert_eq!(report.items.len(), 1, "{header}");
            let item = &report.items[0];
            assert_eq!(item.title, "Mail", "{header}");
            assert_eq!(item.password, "mgr-test-pw", "{header}");
            assert_eq!(item.urls[0], "https://mail.example", "{header}");
            assert_eq!(item.notes, "n", "{header}");
            assert_eq!(
                report.folders[0].as_deref().unwrap_or("Work"),
                "Work",
                "{header}"
            );
        }
        let created = |csv: &str| {
            let report = import(csv.as_bytes(), Format::Csv, "", None).unwrap();
            report.items[0].created_at
        };
        assert_eq!(
            created(&format!("{}{}", layouts[3].0, layouts[3].1)),
            1_714_557_600
        );
        assert_eq!(
            created(&format!("{}{}", layouts[4].0, layouts[4].1)),
            1_700_000_000
        );
        let more = import(
            format!("{}{}", layouts[5].0, layouts[5].1).as_bytes(),
            Format::Csv,
            "",
            None,
        )
        .unwrap();
        assert_eq!(
            more.items[0].urls,
            ["https://mail.example", "https://webmail.example"]
        );
        let tags = import(
            format!("{}{}", layouts[1].0, layouts[1].1).as_bytes(),
            Format::Csv,
            "",
            None,
        )
        .unwrap();
        assert!(
            tags.items[0]
                .custom_fields
                .iter()
                .any(|f| f.name == "Tags" && f.value == "a b")
        );
        assert!(tags.items[0].favorite);
    }

    #[test]
    fn a_card_row_of_a_mixed_csv_is_a_card() {
        let csv = "name,url,username,password,note,cardholdername,cardnumber,cvc,pin,expirydate,folder,type\n\
                   Visa,,,,,M E Tester,4111111111111111,737,1234,08/29,,credit_card\n";
        let report = import(csv.as_bytes(), Format::Csv, "", None).unwrap();
        let card = &report.items[0];
        assert_eq!(card.kind, ItemKind::Card);
        assert_eq!(
            (card.username.as_str(), card.password.as_str()),
            ("M E Tester", "1234")
        );
        let details = vault_core::card::CardDetails::from_item(card);
        assert_eq!(details.number, "4111111111111111");
        assert_eq!(details.expiry, "08/29");
        assert_eq!(details.security_code, "737");
    }
}
