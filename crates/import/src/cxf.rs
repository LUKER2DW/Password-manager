//! The Credential Exchange Format (CXF) of the FIDO Alliance: version 1.0, Proposed Standard
//! of 14 August 2025 (`cxf-v1.0-ps-20250814`), the JSON one manager hands another.
//!
//! [`import_cxf`] reads a document (a `Header` with its accounts, their items and
//! collections); [`export_cxf`] writes one. Logins (`basic-auth`), passkeys, one-time codes
//! (`totp`), notes, cards (`credit-card`), SSH keys and custom fields map onto this vault's
//! items. What the vault has no place for (an address, an identity document, a Wi-Fi network,
//! an API key…) becomes fields of a note, with the review told; files are not in the JSON
//! (CXP carries them apart) and are counted as left out.
//!
//! The document is not encrypted: it holds every password and, for passkeys, their private
//! keys (PKCS#8), as the format requires.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use vault_core::totp::Totp;
use vault_core::totp::{LinkParts, TotpAlgorithm};
use vault_core::{CustomField, ItemData, ItemKind, Passkey, RecoveryCode, Vault};
use zeroize::Zeroizing;

use crate::export::{export_items, to_text, wipe};
use crate::{ImportError, ImportReport, counted, host_of, left_out_list, non_empty};

/// The exporter's relying party id, which the format asks for. This app has no domain of
/// its own: a name under `.invalid` (RFC 6761), reserved so that it names no one.
pub(crate) const EXPORTER_RP_ID: &str = "vault.invalid";
const EXPORTER_NAME: &str = "Vault";
/// The custom fields an item's recovery codes go out in (one hidden field per code, "(used)"
/// after a spent one), read back as codes from this app's own documents.
const CODES_LABEL: &str = crate::export::RECOVERY_CODES_FIELD;

/// Whether a JSON document is a CXF header: it names its exporter and has accounts.
pub(crate) fn is_cxf(document: &Value) -> bool {
    document.get("exporterRpId").is_some_and(Value::is_string)
        && document.get("accounts").is_some_and(Value::is_array)
}

/// Bytes of a `b64url` value: URL-safe Base64, read with or without padding (and, leniently,
/// in the standard alphabet some exporters write).
fn binary(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let text = text.trim().trim_end_matches('=');
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 3 / 4 + 3));
    if URL_SAFE_NO_PAD.decode_vec(text, &mut out).is_ok() {
        return Some(out);
    }
    out.clear();
    STANDARD_NO_PAD.decode_vec(text, &mut out).ok()?;
    Some(out)
}

fn b64url(bytes: &[u8]) -> Value {
    Value::String(URL_SAFE_NO_PAD.encode(bytes))
}

/// The text under `key`, moved out of the document.
fn take(entry: &mut Value, key: &str) -> Option<String> {
    match entry.get_mut(key)?.take() {
        Value::String(text) => non_empty(Some(text)),
        _ => None,
    }
}

/// An `EditableField` under `key`: its value, whether it is concealed, and its label.
struct Field {
    value: String,
    concealed: bool,
    label: Option<String>,
}

fn take_field(entry: &mut Value, key: &str) -> Option<Field> {
    let field = entry.get_mut(key)?;
    field_of(field)
}

fn field_of(field: &mut Value) -> Option<Field> {
    let concealed = field.get("fieldType").and_then(Value::as_str) == Some("concealed-string");
    let label = take(field, "label");
    let value = take(field, "value")?;
    Some(Field {
        value,
        concealed,
        label,
    })
}

/// `passportNumber` → `Passport number`
fn humanize(key: &str) -> String {
    let mut out = String::new();
    for (at, c) in key.chars().enumerate() {
        if c.is_uppercase() && at > 0 {
            out.push(' ');
            out.extend(c.to_lowercase());
        } else if at == 0 {
            out.extend(c.to_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The parts of a credential the vault keeps as fields: each `EditableField` of it, named by
/// its label or its key. Identity numbers are hidden.
fn fields_of(credential: &mut Value, item: &mut ItemData, prefix: &str) -> usize {
    const SECRET_KEYS: [&str; 6] = [
        "documentNumber",
        "identificationNumber",
        "passportNumber",
        "nationalIdentificationNumber",
        "licenseNumber",
        "key",
    ];
    let Some(map) = credential.as_object_mut() else {
        return 0;
    };
    let mut keys: Vec<String> = map.keys().filter(|k| *k != "type").cloned().collect();
    keys.sort();
    let mut added = 0;
    for key in keys {
        let Some(value) = map.get_mut(&key) else {
            continue;
        };
        let Some(field) = field_of(value) else {
            continue;
        };
        let name = field.label.unwrap_or_else(|| humanize(&key));
        let name = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}: {name}")
        };
        item.custom_fields.push(CustomField {
            name,
            value: field.value,
            sensitive: field.concealed || SECRET_KEYS.contains(&key.as_str()),
        });
        added += 1;
    }
    added
}

/// What a document left out or couldn't hand over, counted for the review.
#[derive(Default)]
struct Unread {
    files: usize,
    passkeys: usize,
    passkey_extensions: usize,
    codes: usize,
    references: usize,
    unknown: usize,
    as_fields: Vec<&'static str>,
}

/// Reads a CXF document (unencrypted JSON).
pub(crate) fn import_cxf(mut document: Value) -> Result<ImportReport, ImportError> {
    let result = read(&mut document);
    wipe(&mut document);
    result
}

fn read(document: &mut Value) -> Result<ImportReport, ImportError> {
    let major = document
        .pointer("/version/major")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if major != 1 {
        return Err(ImportError::Json(format!(
            "a Credential Exchange document of version {major}, which this app doesn't read (it reads 1.x)"
        )));
    }
    let ours = document.get("exporterRpId").and_then(Value::as_str) == Some(EXPORTER_RP_ID);
    let mut report = ImportReport::default();
    let Some(Value::Array(accounts)) = document.get_mut("accounts").map(Value::take) else {
        return Ok(report);
    };
    let several = accounts.len() > 1;
    for mut account in accounts {
        let account_name = take(&mut account, "username")
            .or_else(|| take(&mut account, "email"))
            .unwrap_or_default();
        // Each item's folder: the first collection that holds it ("Parent/Child").
        let mut folders: HashMap<String, String> = HashMap::new();
        if let Some(Value::Array(collections)) = account.get_mut("collections").map(Value::take) {
            for collection in &collections {
                collect_folders(collection, "", &mut folders);
            }
        }
        let Some(Value::Array(items)) = account.get_mut("items").map(Value::take) else {
            continue;
        };
        for mut entry in items {
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let mut unread = Unread::default();
            let item = item_of(&mut entry, ours, &mut unread);
            warn(&mut report, &item.title, &unread);
            let folder = folders
                .get(&id)
                .cloned()
                .or_else(|| (several && !account_name.is_empty()).then(|| account_name.clone()));
            report.push(item, folder);
            wipe(&mut entry);
        }
    }
    Ok(report)
}

fn collect_folders(collection: &Value, parent: &str, out: &mut HashMap<String, String>) {
    let title = collection
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let path = match (parent.is_empty(), title.is_empty()) {
        (_, true) => parent.to_owned(),
        (true, false) => title.to_owned(),
        (false, false) => format!("{parent}/{title}"),
    };
    for linked in collection
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        // An item of another account is not in this one.
        if linked.get("account").is_some() {
            continue;
        }
        if let Some(id) = linked.get("item").and_then(Value::as_str)
            && !path.is_empty()
        {
            out.entry(id.to_owned()).or_insert_with(|| path.clone());
        }
    }
    for child in collection
        .get("subCollections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        collect_folders(child, &path, out);
    }
}

fn warn(report: &mut ImportReport, title: &str, unread: &Unread) {
    if let Some((what, verb)) = left_out_list(&[
        (unread.files, "attached file", "attached files"),
        (
            unread.references,
            "link to another item",
            "links to other items",
        ),
        (
            unread.unknown,
            "credential of a kind this app doesn't know",
            "credentials of kinds this app doesn't know",
        ),
    ]) {
        report.warnings.push(format!(
            "\"{title}\": {what} {verb} not in this file or not imported"
        ));
    }
    if unread.passkeys > 0 {
        report.warnings.push(format!(
            "\"{title}\": {} not imported (damaged, not a P-256 key, or past what an item keeps)",
            counted(unread.passkeys, "passkey was", "passkeys were")
        ));
    }
    if unread.passkey_extensions > 0 {
        report.warnings.push(format!(
            "\"{title}\": the data of {} (large blob, credential blob, PRF secrets) was left out; sites that use it may ask again",
            counted(unread.passkey_extensions, "passkey's extension", "passkeys' extensions")
        ));
    }
    if unread.codes > 0 {
        report.warnings.push(format!(
            "\"{title}\": {} with an algorithm this app doesn't know {} not imported",
            counted(unread.codes, "one-time code", "one-time codes"),
            if unread.codes == 1 { "was" } else { "were" }
        ));
    }
    if !unread.as_fields.is_empty() {
        let mut kinds = unread.as_fields.clone();
        kinds.sort_unstable();
        kinds.dedup();
        report.warnings.push(format!(
            "\"{title}\": its {} kept as fields (this vault has no item of that kind yet)",
            kinds.join(", ")
        ));
    }
}

/// One CXF item as an item of the vault.
fn item_of(entry: &mut Value, ours: bool, unread: &mut Unread) -> ItemData {
    let title = take(entry, "title");
    let mut item = ItemData::new(ItemKind::Login, title.as_deref().unwrap_or("Untitled"));
    item.favorite = entry.get("favorite").and_then(Value::as_bool) == Some(true);
    if let Some(at) = entry.get("creationAt").and_then(Value::as_i64) {
        item.created_at = at;
    }
    if let Some(at) = entry.get("modifiedAt").and_then(Value::as_i64) {
        item.updated_at = at;
    }
    if let Some(subtitle) = take(entry, "subtitle") {
        push_field(&mut item, "Subtitle", subtitle, false);
    }
    if let Some(scope) = entry.get_mut("scope") {
        for url in scope
            .get_mut("urls")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if let Value::String(url) = url.take()
                && let Some(url) = non_empty(Some(url))
            {
                item.urls.push(url);
            }
        }
        for app in scope
            .get("androidApps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = app.get("bundleId").and_then(Value::as_str) {
                push_field(&mut item, "Android app", id.to_owned(), false);
            }
        }
    }
    if let Some(tags) = entry.get("tags").and_then(Value::as_array) {
        let tags: Vec<&str> = tags.iter().filter_map(Value::as_str).collect();
        if !tags.is_empty() {
            push_field(&mut item, "Tags", tags.join(", "), false);
        }
    }

    let mut kinds: Vec<ItemKind> = Vec::new();
    let mut logins = 0;
    let credentials = match entry.get_mut("credentials").map(Value::take) {
        Some(Value::Array(credentials)) => credentials,
        _ => Vec::new(),
    };
    for mut credential in credentials {
        let kind = credential
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        match kind.as_str() {
            "basic-auth" => {
                logins += 1;
                let username = take_field(&mut credential, "username").map(|f| f.value);
                let password = take_field(&mut credential, "password").map(|f| f.value);
                if logins == 1 {
                    item.username = username.unwrap_or_default();
                    item.password = password.unwrap_or_default();
                } else {
                    if let Some(username) = username {
                        push_field(&mut item, &format!("Username ({logins})"), username, false);
                    }
                    if let Some(password) = password {
                        push_field(&mut item, &format!("Password ({logins})"), password, true);
                    }
                }
                kinds.push(ItemKind::Login);
            }
            "passkey" => {
                if credential.get("fido2Extensions").is_some() {
                    unread.passkey_extensions += 1;
                }
                match passkey_of(&mut credential, item.created_at) {
                    Some(passkey) if item.passkeys.len() < Passkey::MAX_PER_ITEM => {
                        item.passkeys.push(passkey)
                    }
                    _ => unread.passkeys += 1,
                }
                kinds.push(ItemKind::Passkey);
            }
            "totp" => match totp_of(&mut credential) {
                Some(link) if item.totp.is_empty() => item.totp = link.to_string(),
                Some(link) => {
                    let n = 1 + item
                        .custom_fields
                        .iter()
                        .filter(|f| f.name.starts_with("One-time code"))
                        .count();
                    push_field(
                        &mut item,
                        &format!("One-time code ({})", n + 1),
                        link.to_string(),
                        true,
                    );
                }
                None => unread.codes += 1,
            },
            "note" => {
                if let Some(content) = take_field(&mut credential, "content") {
                    if !item.notes.is_empty() {
                        item.notes.push_str("\n\n");
                    }
                    item.notes.push_str(&content.value);
                }
                kinds.push(ItemKind::SecureNote);
            }
            "credit-card" => {
                card_of(&mut credential, &mut item);
                kinds.push(ItemKind::Card);
            }
            "ssh-key" => {
                if ssh_of(&mut credential, &mut item) {
                    kinds.push(ItemKind::SshKey);
                } else {
                    unread.unknown += 1;
                }
            }
            "custom-fields" => {
                let label = take(&mut credential, "label");
                let fields = match credential.get_mut("fields").map(Value::take) {
                    Some(Value::Array(fields)) => fields,
                    _ => Vec::new(),
                };
                if ours && label.as_deref() == Some(CODES_LABEL) {
                    for mut field in fields {
                        if let Some(field) = field_of(&mut field) {
                            let (code, used) =
                                match field.value.strip_suffix(crate::export::USED_MARK) {
                                    Some(code) => (code.to_owned(), true),
                                    None => (field.value.clone(), false),
                                };
                            item.recovery_codes.push(RecoveryCode { code, used });
                        }
                    }
                    continue;
                }
                for mut field in fields {
                    if let Some(field) = field_of(&mut field) {
                        let name = field
                            .label
                            .or_else(|| label.clone())
                            .unwrap_or_else(|| "Field".into());
                        push_field(&mut item, &name, field.value, field.concealed);
                    }
                }
            }
            "generated-password" => {
                if let Some(password) = take(&mut credential, "password") {
                    push_field(&mut item, "Generated password", password, true);
                }
            }
            "file" => unread.files += 1,
            "item-reference" => unread.references += 1,
            "address" | "api-key" | "drivers-license" | "identity-document" | "passport"
            | "person-name" | "wifi" => {
                // No item of these kinds yet: their fields, named after the kind when the
                // item holds more than this credential.
                let (name, prefix) = match kind.as_str() {
                    "address" => ("address", "Address"),
                    "api-key" => ("API key", "API key"),
                    "drivers-license" => ("driver's licence", "Driver's licence"),
                    "identity-document" => ("identity document", "Identity document"),
                    "passport" => ("passport", "Passport"),
                    "person-name" => ("name", "Name"),
                    _ => ("Wi-Fi network", "Wi-Fi"),
                };
                if fields_of(&mut credential, &mut item, prefix) > 0 {
                    unread.as_fields.push(name);
                }
                kinds.push(ItemKind::SecureNote);
            }
            _ => unread.unknown += 1,
        }
        wipe(&mut credential);
    }

    // The item's kind: a card or an SSH key by what it holds; a login when it signs in with
    // a password; a passkey item when its passkeys are all it signs in with; else a note.
    item.kind = if kinds.contains(&ItemKind::Card) {
        ItemKind::Card
    } else if kinds.contains(&ItemKind::SshKey) {
        ItemKind::SshKey
    } else if kinds.contains(&ItemKind::Login) || !item.totp.is_empty() {
        ItemKind::Login
    } else if !item.passkeys.is_empty() {
        ItemKind::Passkey
    } else if kinds.is_empty() && !item.urls.is_empty() {
        ItemKind::Login
    } else {
        ItemKind::SecureNote
    };
    if item.kind == ItemKind::Passkey && item.username.is_empty() {
        item.username = item.passkeys[0].user_name.clone();
    }
    if title.is_none()
        && let Some(host) = item.urls.first().and_then(|u| host_of(u))
    {
        item.title = host;
    }
    item
}

fn push_field(item: &mut ItemData, name: &str, value: String, sensitive: bool) {
    if !value.is_empty() {
        item.custom_fields.push(CustomField {
            name: name.to_owned(),
            value,
            sensitive,
        });
    }
}

fn passkey_of(credential: &mut Value, created_at: i64) -> Option<Passkey> {
    let credential_id = binary(&take(credential, "credentialId")?)?;
    let user_handle = take(credential, "userHandle")
        .and_then(|h| binary(&h))
        .unwrap_or_default();
    let key = Zeroizing::new(take(credential, "key")?);
    let der = binary(&key)?;
    let scalar = Passkey::scalar_from_pkcs8(&der)?;
    let rp_id = take(credential, "rpId")?;
    let user_name = take(credential, "username").unwrap_or_default();
    let display_name = take(credential, "userDisplayName").unwrap_or_else(|| user_name.clone());
    Passkey::from_parts(
        &credential_id,
        &rp_id,
        &user_handle,
        &user_name,
        &display_name,
        created_at,
        &scalar,
    )
    .ok()
}

/// A `totp` credential as the item's `otpauth://` link; `None` for an algorithm this app
/// doesn't know (the format says to leave those out) or a key that gives no codes.
fn totp_of(credential: &mut Value) -> Option<Zeroizing<String>> {
    let algorithm = match credential
        .get("algorithm")
        .and_then(Value::as_str)
        .unwrap_or("sha1")
        .to_ascii_lowercase()
        .as_str()
    {
        "sha1" => TotpAlgorithm::Sha1,
        "sha256" => TotpAlgorithm::Sha256,
        "sha512" => TotpAlgorithm::Sha512,
        _ => return None,
    };
    let number = |key: &str| credential.get(key).and_then(Value::as_u64).unwrap_or(0);
    let (digits, period) = (number("digits"), number("period"));
    let secret = Zeroizing::new(take(credential, "secret")?);
    let issuer = take(credential, "issuer").unwrap_or_default();
    let account = take(credential, "username").unwrap_or_default();
    LinkParts {
        issuer: &issuer,
        account: &account,
        secret: &secret,
        algorithm,
        digits: u32::try_from(digits).ok()?,
        period,
        counter: None,
        characters: false,
    }
    .link()
}

/// A `credit-card` credential into the card's place in the item: the holder as its user,
/// the PIN as its password, the rest as the card's fields.
fn card_of(credential: &mut Value, item: &mut ItemData) {
    use vault_core::card;
    if let Some(holder) = take_field(credential, "fullName") {
        item.username = holder.value;
    }
    if let Some(pin) = take_field(credential, "pin") {
        item.password = pin.value;
    }
    if let Some(number) = take_field(credential, "number") {
        push_field(item, card::NUMBER, number.value, true);
    }
    if let Some(expiry) = take_field(credential, "expiryDate") {
        let value = year_month(&expiry.value).unwrap_or(expiry.value);
        push_field(item, card::EXPIRY, value, false);
    }
    if let Some(code) = take_field(credential, "verificationNumber") {
        push_field(item, card::SECURITY_CODE, code.value, true);
    }
    if let Some(brand) = take_field(credential, "cardType") {
        push_field(item, card::BRAND, brand.value, false);
    }
    if let Some(from) = take_field(credential, "validFrom") {
        let value = year_month(&from.value).unwrap_or(from.value);
        push_field(item, "Valid from", value, false);
    }
}

/// `2029-08` → `08/29`, as the vault writes a card's expiry.
fn year_month(text: &str) -> Option<String> {
    let (year, month) = text.trim().split_once('-')?;
    let month: u32 = month.parse().ok()?;
    let year: u32 = year.parse().ok()?;
    ((1..=12).contains(&month) && year >= 2000)
        .then(|| vault_core::card::format_expiry((month, year)))
}

/// An `ssh-key` credential into the vault's SSH key: the private key in OpenSSH's form, its
/// public half and fingerprint worked out. `false` when the key can't be read.
fn ssh_of(credential: &mut Value, item: &mut ItemData) -> bool {
    use vault_core::ssh;
    let comment = take(credential, "keyComment").unwrap_or_default();
    let Some(key) = take(credential, "privateKey").map(Zeroizing::new) else {
        return false;
    };
    let Some(der) = binary(&key) else {
        return false;
    };
    let Ok(pair) = ssh::from_pkcs8_der(&der, &comment) else {
        return false;
    };
    item.password = pair.private_key.to_string();
    if item.username.is_empty() {
        item.username = comment;
    }
    push_field(item, ssh::PUBLIC_KEY_FIELD, pair.public_key.clone(), false);
    push_field(
        item,
        ssh::FINGERPRINT_FIELD,
        pair.fingerprint.clone(),
        false,
    );
    push_field(item, ssh::KEY_TYPE_FIELD, pair.key_type.clone(), false);
    for (key, name) in [
        ("creationDate", "Created"),
        ("expiryDate", "Expires"),
        ("keyGenerationSource", "Made by"),
    ] {
        if let Some(field) = take_field(credential, key) {
            push_field(item, name, field.value, false);
        }
    }
    true
}

// ---------------------------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------------------------

/// The vault as a CXF document (unencrypted JSON). Passkeys go out with their private keys,
/// as the format carries them; attached files and earlier passwords stay behind
/// ([`crate::export_report`] counts them).
pub fn export_cxf(vault: &Vault) -> Result<Zeroizing<String>, vault_core::Error> {
    let now = web_time_now();
    let mut collections: Vec<Value> = Vec::new();
    for folder in vault.folders() {
        collections.push(json!({
            "id": b64url(&hex_bytes(&folder.id.to_hex())),
            "title": folder.name,
            "items": [],
        }));
    }
    let mut items = Vec::new();
    for (index, (item, _)) in export_items(vault)?.iter().enumerate() {
        // An id of no meaning: the item's place in the file.
        let id = b64url(format!("item-{index}").as_bytes());
        if let Some(folder) = item.folder
            && let Some(at) = vault.folders().iter().position(|f| f.id == folder)
            && let Some(Value::Array(linked)) = collections[at].get_mut("items")
        {
            linked.push(json!({ "item": id.clone() }));
        }
        items.push(item_json(item, id)?);
    }
    let mut document = json!({
        "version": { "major": 1, "minor": 0 },
        "exporterRpId": EXPORTER_RP_ID,
        "exporterDisplayName": EXPORTER_NAME,
        "timestamp": now,
        "accounts": [{
            "id": b64url(b"vault"),
            "username": "",
            "email": "",
            "collections": collections,
            "items": null,
        }],
    });
    document["accounts"][0]["items"] = Value::Array(items);
    let text = to_text(&document);
    wipe(&mut document);
    text
}

fn web_time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .filter_map(|at| u8::from_str_radix(hex.get(at * 2..at * 2 + 2)?, 16).ok())
        .collect()
}

/// An `EditableField`, its text moved in.
fn editable(kind: &str, value: String) -> Value {
    let mut field = Map::new();
    field.insert("fieldType".into(), Value::String(kind.to_owned()));
    field.insert("value".into(), Value::String(value));
    Value::Object(field)
}

fn labelled(kind: &str, label: &str, value: String) -> Value {
    let mut field = editable(kind, value);
    field["label"] = Value::String(label.to_owned());
    field
}

fn item_json(item: &ItemData, id: Value) -> Result<Value, vault_core::Error> {
    use vault_core::{card, ssh};
    let mut credentials: Vec<Value> = Vec::new();
    let mut entry = Map::new();
    entry.insert("id".into(), id);
    if item.created_at > 0 {
        entry.insert("creationAt".into(), item.created_at.into());
    }
    if item.updated_at > 0 {
        entry.insert("modifiedAt".into(), item.updated_at.into());
    }
    entry.insert("title".into(), Value::String(item.title.clone()));
    if item.favorite {
        entry.insert("favorite".into(), Value::Bool(true));
    }
    if !item.urls.is_empty() {
        entry.insert(
            "scope".into(),
            json!({ "urls": item.urls, "androidApps": [] }),
        );
    }
    // The fields that are the card's or the SSH key's own, written in their credential.
    let mut own: Vec<&str> = Vec::new();
    match item.kind {
        ItemKind::Login => {
            credentials.push(basic_auth(item));
        }
        ItemKind::Passkey => {
            if !item.password.is_empty() {
                credentials.push(basic_auth(item));
            }
        }
        ItemKind::SecureNote => {
            if !item.username.is_empty() || !item.password.is_empty() {
                credentials.push(basic_auth(item));
            }
        }
        ItemKind::Card => {
            let field = |name: &str| {
                item.custom_fields
                    .iter()
                    .find(|f| f.name == name)
                    .map(|f| f.value.clone())
            };
            let mut credential = Map::new();
            credential.insert("type".into(), "credit-card".into());
            if let Some(number) = field(card::NUMBER) {
                credential.insert("number".into(), editable("concealed-string", number));
            }
            if !item.username.is_empty() {
                credential.insert("fullName".into(), editable("string", item.username.clone()));
            }
            if let Some(brand) = field(card::BRAND) {
                credential.insert("cardType".into(), editable("string", brand));
            }
            if let Some(code) = field(card::SECURITY_CODE) {
                credential.insert(
                    "verificationNumber".into(),
                    editable("concealed-string", code),
                );
            }
            if !item.password.is_empty() {
                credential.insert(
                    "pin".into(),
                    editable("concealed-string", item.password.clone()),
                );
            }
            if let Some((month, year)) = field(card::EXPIRY).and_then(|e| card::parse_expiry(&e)) {
                credential.insert(
                    "expiryDate".into(),
                    editable("year-month", format!("{year:04}-{month:02}")),
                );
                own.push(card::EXPIRY);
            }
            own.extend([card::NUMBER, card::BRAND, card::SECURITY_CODE]);
            credentials.push(Value::Object(credential));
        }
        ItemKind::SshKey => {
            if let Some((der, algorithm)) = ssh::pkcs8_der(&item.password) {
                let mut credential = Map::new();
                credential.insert("type".into(), "ssh-key".into());
                credential.insert("keyType".into(), Value::String(algorithm));
                credential.insert("privateKey".into(), b64url(&der));
                // The comment: the item's user, else the one in its public key.
                let comment = if item.username.is_empty() {
                    item.custom_fields
                        .iter()
                        .find(|f| f.name == ssh::PUBLIC_KEY_FIELD)
                        .and_then(|f| f.value.split_whitespace().nth(2))
                        .unwrap_or_default()
                        .to_owned()
                } else {
                    item.username.clone()
                };
                if !comment.is_empty() {
                    credential.insert("keyComment".into(), Value::String(comment));
                }
                credentials.push(Value::Object(credential));
                own.extend([
                    ssh::PUBLIC_KEY_FIELD,
                    ssh::FINGERPRINT_FIELD,
                    ssh::KEY_TYPE_FIELD,
                ]);
            } else {
                // A key this can't write as PKCS#8 (P-521, or one with a passphrase): its text,
                // hidden, so that it isn't lost.
                credentials.push(json!({
                    "type": "custom-fields",
                    "fields": [labelled("concealed-string", "Private key", item.password.clone())],
                }));
            }
        }
    }
    for passkey in &item.passkeys {
        let key = passkey.private_key_pkcs8()?;
        credentials.push(json!({
            "type": "passkey",
            "credentialId": b64url(&passkey.credential_id),
            "rpId": passkey.rp_id,
            "username": passkey.user_name,
            "userDisplayName": passkey.display_name,
            "userHandle": b64url(&passkey.user_handle),
            "key": b64url(&key),
        }));
    }
    if !item.totp.trim().is_empty()
        && let Some(credential) = totp_json(item)
    {
        credentials.push(credential);
    }
    if !item.notes.is_empty() {
        credentials.push(json!({
            "type": "note",
            "content": editable("string", item.notes.clone()),
        }));
    }
    let fields: Vec<Value> = item
        .custom_fields
        .iter()
        .filter(|f| !own.contains(&f.name.as_str()))
        .map(|f| {
            let kind = if f.sensitive {
                "concealed-string"
            } else {
                "string"
            };
            labelled(kind, &f.name, f.value.clone())
        })
        .collect();
    if !fields.is_empty() {
        let mut credential = json!({ "type": "custom-fields", "fields": null });
        credential["fields"] = Value::Array(fields);
        credentials.push(credential);
    }
    if !item.recovery_codes.is_empty() {
        let codes: Vec<Value> = item
            .recovery_codes
            .iter()
            .map(|c| {
                let text = if c.used {
                    format!("{}{}", c.code, crate::export::USED_MARK)
                } else {
                    c.code.clone()
                };
                labelled("concealed-string", "Recovery code", text)
            })
            .collect();
        let mut credential =
            json!({ "type": "custom-fields", "label": CODES_LABEL, "fields": null });
        credential["fields"] = Value::Array(codes);
        credentials.push(credential);
    }
    entry.insert("credentials".into(), Value::Array(credentials));
    Ok(Value::Object(entry))
}

fn basic_auth(item: &ItemData) -> Value {
    let mut credential = Map::new();
    credential.insert("type".into(), "basic-auth".into());
    if !item.username.is_empty() {
        let kind = if item.username.contains('@') {
            "email"
        } else {
            "string"
        };
        credential.insert("username".into(), editable(kind, item.username.clone()));
    }
    if !item.password.is_empty() {
        credential.insert(
            "password".into(),
            editable("concealed-string", item.password.clone()),
        );
    }
    Value::Object(credential)
}

/// The item's one-time code as a `totp` credential; `None` for a counter-based key or a
/// five-character one, which the format has no place for (they go as a hidden field).
fn totp_json(item: &ItemData) -> Option<Value> {
    let totp = Totp::parse(&item.totp).ok();
    let names = vault_core::totp::names(&item.totp);
    match totp {
        Some(parsed) if !parsed.is_counter_based() && !parsed.is_characters() => {
            let secret = secret_of(&item.totp)?;
            let mut credential = json!({
                "type": "totp",
                "secret": null,
                "period": parsed.period(),
                "digits": parsed.digits(),
                "algorithm": match parsed.algorithm() {
                    TotpAlgorithm::Sha1 => "sha1",
                    TotpAlgorithm::Sha256 => "sha256",
                    TotpAlgorithm::Sha512 => "sha512",
                },
            });
            credential["secret"] = Value::String(secret.to_string());
            let issuer = if names.issuer.is_empty() {
                item.title.clone()
            } else {
                names.issuer
            };
            credential["issuer"] = Value::String(issuer);
            let account = if names.account.is_empty() {
                item.username.clone()
            } else {
                names.account
            };
            if !account.is_empty() {
                credential["username"] = Value::String(account);
            }
            Some(credential)
        }
        _ => Some(json!({
            "type": "custom-fields",
            "fields": [labelled("concealed-string", "One-time code", item.totp.clone())],
        })),
    }
}

/// The Base32 key of a bare key or an `otpauth://` link, capitals and no spaces.
fn secret_of(totp: &str) -> Option<Zeroizing<String>> {
    let totp = totp.trim();
    let raw = if totp.to_ascii_lowercase().starts_with("otpauth://") {
        let query = totp.split_once('?')?.1;
        query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            name.eq_ignore_ascii_case("secret").then_some(value)
        })?
    } else {
        totp
    };
    Some(Zeroizing::new(
        raw.chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdbx_export::tests::full_vault;
    use crate::{Format, import};

    #[test]
    fn the_vault_comes_back_from_its_own_document() {
        let vault = full_vault();
        let text = export_cxf(&vault).unwrap();
        let document: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(document["version"], json!({ "major": 1, "minor": 0 }));
        assert_eq!(document["exporterRpId"], EXPORTER_RP_ID);
        assert!(document["timestamp"].as_u64().unwrap() > 1_700_000_000);
        // Required arrays are there; ids are b64url.
        let account = &document["accounts"][0];
        assert!(account["collections"].is_array() && account["items"].is_array());
        for item in account["items"].as_array().unwrap() {
            assert!(binary(item["id"].as_str().unwrap()).is_some());
            assert!(item["credentials"].is_array());
        }
        let counted = crate::export_report(&vault, crate::ExportFormat::Cxf).unwrap();
        assert_eq!(counted.left_out.attachments, 1);
        assert_eq!(counted.left_out.earlier_passwords, 2);
        assert_eq!(counted.left_out.kinds_changed, 0);
        assert_eq!(counted.in_clear.passkeys, 2);
        assert_eq!(counted.affected, ["Mail"]);
        let report = import(text.as_bytes(), Format::Json, "", None).unwrap();
        // Only the attached file and the earlier passwords stay behind (said by the export
        // report, not the import).
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.items.len(), vault.len());
        for id in vault.item_ids() {
            let original = vault.get_item(&id).unwrap();
            let at = report
                .items
                .iter()
                .position(|i| i.title == original.title)
                .unwrap();
            let back = &report.items[at];
            assert_eq!(back.kind, original.kind, "{}", original.title);
            if original.kind == ItemKind::SshKey {
                // The same key, written again in OpenSSH form with its comment.
                let public = |item: &ItemData| {
                    let key = vault_core::ssh::public_key_of(&item.password).unwrap();
                    key.split(' ').take(2).collect::<Vec<_>>().join(" ")
                };
                assert_eq!(public(back), public(&original));
                assert_eq!(back.username, "me@test", "the key's comment");
                continue;
            }
            assert_eq!(back.username, original.username, "{}", original.title);
            assert_eq!(back.password, original.password, "{}", original.title);
            assert_eq!(back.urls, original.urls);
            assert_eq!(back.notes, original.notes);
            assert_eq!(back.favorite, original.favorite);
            assert_eq!(back.created_at, original.created_at);
            assert_eq!(back.passkeys, original.passkeys, "{}", original.title);
            assert_eq!(back.recovery_codes, original.recovery_codes);
            assert_eq!(
                report.folders[at].is_some(),
                original.folder.is_some(),
                "{}",
                original.title
            );
            for field in &original.custom_fields {
                assert!(
                    back.custom_fields.iter().any(|f| f.name == field.name
                        && f.value == field.value
                        && f.sensitive == field.sensitive),
                    "{}: {}",
                    original.title,
                    field.name
                );
            }
            if !original.totp.is_empty() {
                let code = |t: &str| Totp::parse(t).unwrap().code_at(59);
                assert_eq!(code(&back.totp), code(&original.totp));
            }
        }
    }

    /// A document of another exporter, with every kind of credential the format names, made
    /// for this test from the specification's structures.
    fn foreign() -> String {
        let passkey = Passkey::new("shop.example", b"user-9", "me@example.com", "Me").unwrap();
        let pkcs8 = passkey.private_key_pkcs8().unwrap();
        let ssh = vault_core::ssh::generate_ed25519("").unwrap();
        let (ssh_der, _) = vault_core::ssh::pkcs8_der(&ssh.private_key).unwrap();
        json!({
            "version": { "major": 1, "minor": 0 },
            "exporterRpId": "exporter.example",
            "exporterDisplayName": "Example exporter",
            "timestamp": 1_760_000_000u64,
            "accounts": [{
                "id": "YWNjb3VudA",
                "username": "",
                "email": "me@example.com",
                "collections": [{
                    "id": "Y29sbA",
                    "title": "Personal",
                    "items": [],
                    "subCollections": [{
                        "id": "c3Vi",
                        "title": "Shopping",
                        "items": [{ "item": "c2hvcA" }]
                    }]
                }],
                "items": [
                    {
                        "id": "c2hvcA",
                        "creationAt": 1_700_000_000u64,
                        "title": "Shop",
                        "favorite": true,
                        "scope": { "urls": ["https://shop.example"], "androidApps": [{ "bundleId": "com.example.shop" }] },
                        "tags": ["money"],
                        "credentials": [
                            { "type": "basic-auth",
                              "username": { "fieldType": "email", "value": "me@example.com" },
                              "password": { "fieldType": "concealed-string", "value": "cxf-test-pw" } },
                            { "type": "passkey",
                              "credentialId": URL_SAFE_NO_PAD.encode(&passkey.credential_id),
                              "rpId": "shop.example", "username": "me@example.com",
                              "userDisplayName": "Me",
                              "userHandle": URL_SAFE_NO_PAD.encode(b"user-9"),
                              "key": URL_SAFE_NO_PAD.encode(pkcs8.as_slice()),
                              "fido2Extensions": { "credBlob": "AAAA" } },
                            { "type": "totp", "secret": "JBSWY3DPEHPK3PXP", "period": 30,
                              "digits": 6, "algorithm": "sha1", "issuer": "Shop" },
                            { "type": "totp", "secret": "JBSWY3DPEHPK3PXP", "period": 30,
                              "digits": 6, "algorithm": "md5" },
                            { "type": "file", "id": "Zg", "name": "receipt.pdf",
                              "decryptedSize": 10, "integrityHash": "AAAA" },
                            { "type": "some-future-kind" }
                        ]
                    },
                    {
                        "id": "Y2FyZA",
                        "title": "Visa",
                        "credentials": [{ "type": "credit-card",
                            "number": { "fieldType": "concealed-string", "value": "4111111111111111" },
                            "fullName": { "fieldType": "string", "value": "M E Tester" },
                            "cardType": { "fieldType": "string", "value": "Visa" },
                            "verificationNumber": { "fieldType": "concealed-string", "value": "737" },
                            "pin": { "fieldType": "concealed-string", "value": "1234" },
                            "expiryDate": { "fieldType": "year-month", "value": "2029-08" } }]
                    },
                    {
                        "id": "c3No",
                        "title": "Server",
                        "credentials": [{ "type": "ssh-key", "keyType": "ssh-ed25519",
                            "privateKey": URL_SAFE_NO_PAD.encode(ssh_der.as_slice()),
                            "keyComment": "deploy@example" }]
                    },
                    {
                        "id": "aWQ",
                        "title": "Passport",
                        "credentials": [
                            { "type": "passport",
                              "passportNumber": { "fieldType": "string", "value": "X1234567" },
                              "fullName": { "fieldType": "string", "value": "M E Tester" },
                              "expiryDate": { "fieldType": "date", "value": "2031-01-31" } },
                            { "type": "note", "content": { "fieldType": "string", "value": "kept in the drawer" } }
                        ]
                    },
                    {
                        "id": "d2lmaQ",
                        "title": "Home Wi-Fi",
                        "credentials": [{ "type": "wifi",
                            "ssid": { "fieldType": "string", "value": "home" },
                            "passphrase": { "fieldType": "concealed-string", "value": "wifi-test-pass" } }]
                    }
                ]
            }]
        })
        .to_string()
    }

    #[test]
    fn another_exporters_document_maps_onto_the_vaults_items() {
        let text = foreign();
        assert_eq!(crate::detect_format(text.as_bytes()), Format::Json);
        let report = import(text.as_bytes(), Format::Json, "", None).unwrap();
        assert_eq!(report.items.len(), 5);
        let find = |title: &str| {
            let at = report.items.iter().position(|i| i.title == title).unwrap();
            (&report.items[at], report.folders[at].as_deref())
        };
        let (shop, folder) = find("Shop");
        assert_eq!(folder, Some("Personal/Shopping"));
        assert_eq!(shop.kind, ItemKind::Login);
        assert_eq!(
            (shop.username.as_str(), shop.password.as_str()),
            ("me@example.com", "cxf-test-pw")
        );
        assert_eq!(shop.urls, ["https://shop.example"]);
        assert!(shop.favorite);
        assert_eq!(shop.passkeys.len(), 1);
        assert_eq!(shop.passkeys[0].user_handle, b"user-9");
        assert_eq!(shop.passkeys[0].created_at, 1_700_000_000);
        assert!(Totp::parse(&shop.totp).is_ok());
        assert!(
            shop.custom_fields
                .iter()
                .any(|f| f.name == "Android app" && f.value == "com.example.shop")
        );
        assert!(
            shop.custom_fields
                .iter()
                .any(|f| f.name == "Tags" && f.value == "money")
        );
        let (card, _) = find("Visa");
        assert_eq!(card.kind, ItemKind::Card);
        let details = vault_core::card::CardDetails::from_item(card);
        assert_eq!(details.number, "4111111111111111");
        assert_eq!(details.expiry, "08/29");
        assert_eq!(details.security_code, "737");
        assert_eq!(
            (card.username.as_str(), card.password.as_str()),
            ("M E Tester", "1234")
        );
        let (server, _) = find("Server");
        assert_eq!(server.kind, ItemKind::SshKey);
        assert!(
            server
                .password
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert_eq!(server.username, "deploy@example");
        let (passport, _) = find("Passport");
        assert_eq!(passport.kind, ItemKind::SecureNote);
        assert_eq!(passport.notes, "kept in the drawer");
        assert!(
            passport
                .custom_fields
                .iter()
                .any(|f| f.name == "Passport: Passport number" && f.sensitive)
        );
        let (wifi, _) = find("Home Wi-Fi");
        assert!(
            wifi.custom_fields
                .iter()
                .any(|f| f.name == "Wi-Fi: Passphrase" && f.sensitive)
        );

        let warnings = report.warnings.join("\n");
        assert!(
            warnings.contains("1 attached file and 1 credential of a kind"),
            "{warnings}"
        );
        assert!(warnings.contains("1 passkey's extension"), "{warnings}");
        assert!(
            warnings.contains("1 one-time code with an algorithm"),
            "{warnings}"
        );
        assert!(
            warnings.contains("its passport kept as fields"),
            "{warnings}"
        );
        for secret in [
            "cxf-test-pw",
            "4111111111111111",
            "wifi-test-pass",
            "JBSWY3DP",
        ] {
            assert!(!warnings.contains(secret));
        }
    }

    #[test]
    fn a_document_of_another_version_or_a_broken_passkey_is_told() {
        let newer = foreign().replace("\"major\":1", "\"major\":2");
        let err = import(newer.as_bytes(), Format::Json, "", None).unwrap_err();
        assert!(err.to_string().contains("version 2"), "{err}");
        let mut document: Value = serde_json::from_str(&foreign()).unwrap();
        document["accounts"][0]["items"][0]["credentials"][1]["key"] = "AAAA".into();
        let report = import(document.to_string().as_bytes(), Format::Json, "", None).unwrap();
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("1 passkey was not imported"))
        );
        assert!(report.items[0].passkeys.is_empty());
    }
}
