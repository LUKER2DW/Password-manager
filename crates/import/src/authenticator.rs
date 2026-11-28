//! One-time code keys from authenticator apps: what they export and what their QR codes hold.
//!
//! - `otpauth://` links, one per line (the plain-text export most apps offer);
//! - `otpauth-migration://offline?data=…`, the QR codes an app shows to move its keys to
//!   another phone: a protocol buffer (`MigrationPayload`) in Base64, read by [`migration`];
//! - the JSON exports of the common apps, each told by its shape: a database of `entries`
//!   with an `info` block (unencrypted), a list of `services` with an `otp` block, a list of
//!   tokens whose secret is an array of bytes, an array of keys with `secret` and `type`, and a
//!   list of `entries` that hold a link each.
//!
//! Each key becomes a login holding the code: the issuer as its title, the account as its
//! user. An encrypted export is refused with a word on how to make a plain one.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use serde_json::Value;
use vault_core::totp::{LinkParts, TotpAlgorithm};
use vault_core::{ItemData, ItemKind};
use zeroize::Zeroizing;

use crate::export::wipe;
use crate::{ImportError, ImportReport, counted, non_empty};

/// Whether a text is a list of `otpauth://` or `otpauth-migration://` links.
pub(crate) fn is_link_list(bytes: &[u8]) -> bool {
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let start = text
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(text.len());
    text[start..]
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"otpauth"))
}

/// One key read, before it is an item.
struct Key {
    issuer: String,
    account: String,
    link: Zeroizing<String>,
    notes: String,
    folder: Option<String>,
}

impl Key {
    fn into_item(self) -> (ItemData, Option<String>) {
        let names = vault_core::totp::names(&self.link);
        let issuer = non_empty(Some(self.issuer)).unwrap_or(names.issuer);
        let account = non_empty(Some(self.account)).unwrap_or(names.account);
        let title = non_empty(Some(issuer))
            .or_else(|| non_empty(Some(account.clone())))
            .unwrap_or_else(|| "One-time code".into());
        let mut item = ItemData::new(ItemKind::Login, &title);
        item.username = account;
        item.totp = self.link.to_string();
        item.notes = self.notes;
        (item, self.folder)
    }
}

fn push(report: &mut ImportReport, key: Key) {
    let (item, folder) = key.into_item();
    report.push(item, folder);
}

fn skipped(report: &mut ImportReport, n: usize, why: &str) {
    if n > 0 {
        report
            .warnings
            .push(format!("{} {why}, not imported", counted(n, "key", "keys")));
    }
}

/// A list of links, one per line: `otpauth://` keys and `otpauth-migration://` batches.
pub(crate) fn import_links(bytes: &[u8]) -> Result<ImportReport, ImportError> {
    let text = std::str::from_utf8(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes))
        .map_err(|_| ImportError::Json("the file is not text".into()))?;
    let mut report = ImportReport::default();
    let mut unread = 0;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let starts = |prefix: &str| {
            line.get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        };
        if starts("otpauth-migration:") {
            match migration(line) {
                Some(batch) => {
                    report.warnings.extend(batch.warnings);
                    report.items.extend(batch.items);
                    report.folders.extend(batch.folders);
                }
                None => unread += 1,
            }
        } else if starts("otpauth://") && vault_core::totp::Totp::parse(line).is_ok() {
            push(
                &mut report,
                Key {
                    issuer: String::new(),
                    account: String::new(),
                    link: Zeroizing::new(line.to_owned()),
                    notes: String::new(),
                    folder: None,
                },
            );
        } else {
            unread += 1;
        }
    }
    if unread > 0 {
        report.warnings.push(format!(
            "{} that {} no key this app can read {} skipped",
            counted(unread, "line", "lines"),
            if unread == 1 { "holds" } else { "hold" },
            if unread == 1 { "was" } else { "were" }
        ));
    }
    Ok(report)
}

/// The keys of an `otpauth-migration://offline?data=…` link. `None` when it isn't one.
pub fn migration(link: &str) -> Option<ImportReport> {
    let query = link.trim().split_once('?')?.1;
    let data = query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        name.eq_ignore_ascii_case("data").then_some(value)
    })?;
    let data = Zeroizing::new(percent_decode(data));
    let unpadded = data.trim_end_matches('=');
    let mut payload = Zeroizing::new(Vec::with_capacity(unpadded.len() * 3 / 4 + 3));
    let padded = Zeroizing::new(format!(
        "{unpadded}{}",
        "=".repeat((4 - unpadded.len() % 4) % 4)
    ));
    if STANDARD
        .decode_vec(padded.as_bytes(), &mut payload)
        .is_err()
    {
        payload.clear();
        URL_SAFE.decode_vec(padded.as_bytes(), &mut payload).ok()?;
    }
    let mut report = ImportReport::default();
    let (mut unknown, mut damaged) = (0, 0);
    for field in Message::new(&payload) {
        let (1, Wire::Bytes(parameters)) = field? else {
            continue; // version, batch size and index, batch id
        };
        match otp_parameters(parameters) {
            Ok(key) => push(&mut report, key),
            Err(Unread::Unknown) => unknown += 1,
            Err(Unread::Damaged) => damaged += 1,
        }
    }
    skipped(
        &mut report,
        unknown,
        "of a kind this app doesn't know (MD5, or no type)",
    );
    skipped(&mut report, damaged, "damaged");
    Some(report)
}

enum Unread {
    Unknown,
    Damaged,
}

/// One `OtpParameters` of a migration payload: 1 secret (bytes), 2 name, 3 issuer,
/// 4 algorithm (1 SHA-1, 2 SHA-256, 3 SHA-512, 4 MD5), 5 digits (1 six, 2 eight), 6 type
/// (1 counter-based, 2 time-based), 7 counter.
fn otp_parameters(bytes: &[u8]) -> Result<Key, Unread> {
    let mut secret: &[u8] = &[];
    let (mut name, mut issuer) = (String::new(), String::new());
    let (mut algorithm, mut digits, mut kind, mut counter) = (1, 1, 2, 0);
    for field in Message::new(bytes) {
        match field.ok_or(Unread::Damaged)? {
            (1, Wire::Bytes(b)) => secret = b,
            (2, Wire::Bytes(b)) => name = String::from_utf8_lossy(b).into_owned(),
            (3, Wire::Bytes(b)) => issuer = String::from_utf8_lossy(b).into_owned(),
            (4, Wire::Varint(n)) => algorithm = n,
            (5, Wire::Varint(n)) => digits = n,
            (6, Wire::Varint(n)) => kind = n,
            (7, Wire::Varint(n)) => counter = n,
            _ => {}
        }
    }
    let algorithm = match algorithm {
        0 | 1 => TotpAlgorithm::Sha1,
        2 => TotpAlgorithm::Sha256,
        3 => TotpAlgorithm::Sha512,
        _ => return Err(Unread::Unknown),
    };
    let digits = match digits {
        0 | 1 => 6,
        2 => 8,
        _ => return Err(Unread::Unknown),
    };
    let counter = match kind {
        1 => Some(counter),
        2 => None,
        _ => return Err(Unread::Unknown),
    };
    // The name is "Issuer:account" or the account alone.
    let account = match name.split_once(':') {
        Some((before, after)) if issuer.is_empty() || before.trim() == issuer.trim() => {
            if issuer.is_empty() {
                issuer = before.trim().to_owned();
            }
            after.trim().to_owned()
        }
        _ => name.trim().to_owned(),
    };
    let secret = vault_core::totp::base32_encode(secret);
    let link = LinkParts {
        issuer: &issuer,
        account: &account,
        secret: &secret,
        algorithm,
        digits,
        period: 30,
        counter,
        characters: false,
    }
    .link()
    .ok_or(Unread::Damaged)?;
    Ok(Key {
        issuer,
        account,
        link,
        notes: String::new(),
        folder: None,
    })
}

/// A field of a protocol buffer: its number and value (the wire types this format uses).
enum Wire<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Other,
}

/// The fields of a protocol buffer message, in order; `None` for a field that runs past the
/// end or can't be read (and nothing after it).
struct Message<'a> {
    rest: &'a [u8],
    broken: bool,
}

impl<'a> Message<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            rest: bytes,
            broken: false,
        }
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = self.rest.split_first()?;
            self.rest = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn field(&mut self) -> Option<(u64, Wire<'a>)> {
        let tag = self.varint()?;
        let number = tag >> 3;
        let value = match tag & 7 {
            0 => Wire::Varint(self.varint()?),
            1 => {
                self.rest = self.rest.get(8..)?;
                Wire::Other
            }
            2 => {
                let length = usize::try_from(self.varint()?).ok()?;
                let bytes = self.rest.get(..length)?;
                self.rest = &self.rest[length..];
                Wire::Bytes(bytes)
            }
            5 => {
                self.rest = self.rest.get(4..)?;
                Wire::Other
            }
            _ => return None,
        };
        (number > 0).then_some((number, value))
    }
}

impl<'a> Iterator for Message<'a> {
    type Item = Option<(u64, Wire<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.broken || self.rest.is_empty() {
            return None;
        }
        let field = self.field();
        self.broken = field.is_none();
        Some(field)
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%'
            && let Some(byte) = text
                .get(at + 1..at + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(byte);
            at += 3;
            continue;
        }
        out.push(if bytes[at] == b'+' { b' ' } else { bytes[at] });
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------------------------
// The JSON exports
// ---------------------------------------------------------------------------------------------

/// Which authenticator export a JSON document is, by its shape. `None` for anything else.
pub(crate) fn shape(document: &Value) -> Option<Shape> {
    if let Some(db) = document.get("db")
        && document.get("header").is_some()
    {
        return Some(if db.is_string() {
            Shape::Encrypted
        } else {
            Shape::Database
        });
    }
    if document.get("services").is_some_and(Value::is_array) {
        let encrypted = document
            .get("servicesEncrypted")
            .is_some_and(|s| s.as_str().is_some_and(|s| !s.is_empty()));
        return Some(if encrypted {
            Shape::Encrypted
        } else {
            Shape::Services
        });
    }
    if document.get("tokens").is_some_and(Value::is_array) {
        return Some(Shape::Tokens);
    }
    if let Some(entries) = document.get("entries").and_then(Value::as_array)
        && entries
            .iter()
            .any(|e| e.pointer("/content/uri").is_some_and(Value::is_string))
    {
        return Some(Shape::Links);
    }
    if let Some(list) = document.as_array()
        && !list.is_empty()
        && list.iter().all(|e| e.get("secret").is_some())
    {
        return Some(Shape::List);
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    /// `{"header", "db": {"entries": [{"type", "name", "issuer", "info": {…}}]}}`
    Database,
    /// `{"services": [{"name", "secret", "otp": {…}}]}`
    Services,
    /// `{"tokens": [{"secret": [bytes], "issuerExt", "label", …}]}`
    Tokens,
    /// `{"entries": [{"content": {"uri"}, "note"}]}`
    Links,
    /// `[{"secret", "issuer", "label", "type", …}]`
    List,
    /// One of these, encrypted.
    Encrypted,
}

fn text(entry: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|k| entry.pointer(k).and_then(Value::as_str))
        .map(|t| t.trim().to_owned())
        .unwrap_or_default()
}

fn number(entry: &Value, keys: &[&str]) -> u64 {
    keys.iter()
        .find_map(|k| {
            let value = entry.pointer(k)?;
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
        })
        .unwrap_or(0)
}

/// Reads an authenticator's JSON export of the given shape.
pub(crate) fn import_shape(mut document: Value, shape: Shape) -> Result<ImportReport, ImportError> {
    let result = read_shape(&document, shape);
    wipe(&mut document);
    result
}

fn read_shape(document: &Value, shape: Shape) -> Result<ImportReport, ImportError> {
    let mut report = ImportReport::default();
    let mut unknown = 0;
    let entries: Vec<&Value> = match shape {
        Shape::Encrypted => {
            return Err(ImportError::Json(
                "this authenticator export is encrypted; export it again without a password (or as plain text)".into(),
            ));
        }
        Shape::Database => document
            .pointer("/db/entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .collect(),
        Shape::Services => document["services"]
            .as_array()
            .into_iter()
            .flatten()
            .collect(),
        Shape::Tokens => document["tokens"]
            .as_array()
            .into_iter()
            .flatten()
            .collect(),
        Shape::Links => document["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .collect(),
        Shape::List => document.as_array().into_iter().flatten().collect(),
    };
    for entry in entries {
        let key = match shape {
            Shape::Database => database_key(entry),
            Shape::Services => services_key(entry),
            Shape::Tokens => tokens_key(entry),
            Shape::Links => links_key(entry),
            Shape::List => list_key(entry),
            Shape::Encrypted => None,
        };
        match key {
            Some(key) => push(&mut report, key),
            None => unknown += 1,
        }
    }
    skipped(
        &mut report,
        unknown,
        "of a kind this app doesn't know, or damaged",
    );
    Ok(report)
}

/// The kind of code a key gives, as these exports name it.
fn kind_of(name: &str) -> Option<(bool, bool)> {
    // (counter-based, five characters)
    match name.trim().to_ascii_lowercase().as_str() {
        "" | "totp" => Some((false, false)),
        "hotp" => Some((true, false)),
        "steam" => Some((false, true)),
        _ => None,
    }
}

fn algorithm_of(name: &str) -> Option<TotpAlgorithm> {
    match name.trim().to_ascii_uppercase().replace('-', "").as_str() {
        "" | "SHA1" => Some(TotpAlgorithm::Sha1),
        "SHA256" => Some(TotpAlgorithm::Sha256),
        "SHA512" => Some(TotpAlgorithm::Sha512),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn key_of(
    issuer: String,
    account: String,
    secret: &str,
    kind: &str,
    algorithm: &str,
    digits: u64,
    period: u64,
    counter: u64,
    notes: String,
    folder: Option<String>,
) -> Option<Key> {
    let (counter_based, characters) = kind_of(kind)?;
    let link = LinkParts {
        issuer: &issuer,
        account: &account,
        secret,
        algorithm: algorithm_of(algorithm)?,
        digits: u32::try_from(digits).ok()?,
        period,
        counter: counter_based.then_some(counter),
        characters,
    }
    .link()?;
    Some(Key {
        issuer,
        account,
        link,
        notes,
        folder,
    })
}

fn database_key(entry: &Value) -> Option<Key> {
    let secret = Zeroizing::new(text(entry, &["/info/secret"]));
    key_of(
        text(entry, &["/issuer"]),
        text(entry, &["/name"]),
        &secret,
        &text(entry, &["/type"]),
        &text(entry, &["/info/algo"]),
        number(entry, &["/info/digits"]),
        number(entry, &["/info/period"]),
        number(entry, &["/info/counter"]),
        text(entry, &["/note"]),
        non_empty(Some(text(entry, &["/group"]))),
    )
}

fn services_key(entry: &Value) -> Option<Key> {
    let secret = Zeroizing::new(text(entry, &["/secret"]));
    key_of(
        text(entry, &["/otp/issuer", "/name"]),
        text(entry, &["/otp/account", "/otp/label"]),
        &secret,
        &text(entry, &["/otp/tokenType"]),
        &text(entry, &["/otp/algorithm"]),
        number(entry, &["/otp/digits"]),
        number(entry, &["/otp/period"]),
        number(entry, &["/otp/counter"]),
        text(entry, &["/otp/notes", "/notes"]),
        None,
    )
}

fn tokens_key(entry: &Value) -> Option<Key> {
    // The secret as signed bytes.
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        entry
            .get("secret")?
            .as_array()?
            .iter()
            .map(|b| b.as_i64().map(|b| b as u8))
            .collect::<Option<Vec<u8>>>()?,
    );
    let secret = vault_core::totp::base32_encode(&bytes);
    key_of(
        text(entry, &["/issuerExt", "/issuerInt"]),
        text(entry, &["/label"]),
        &secret,
        &text(entry, &["/type"]),
        &text(entry, &["/algo"]),
        number(entry, &["/digits"]),
        number(entry, &["/period"]),
        number(entry, &["/counter"]),
        String::new(),
        None,
    )
}

fn links_key(entry: &Value) -> Option<Key> {
    let link = Zeroizing::new(text(entry, &["/content/uri"]));
    vault_core::totp::Totp::parse(&link).ok()?;
    Some(Key {
        issuer: String::new(),
        account: text(entry, &["/content/name"]),
        link,
        notes: text(entry, &["/note"]),
        folder: None,
    })
}

fn list_key(entry: &Value) -> Option<Key> {
    let secret = Zeroizing::new(text(entry, &["/secret"]));
    let mut issuer = text(entry, &["/issuer"]);
    let mut account = text(entry, &["/account", "/label"]);
    if issuer.is_empty()
        && let Some((before, after)) = account.clone().split_once(':')
    {
        issuer = before.trim().to_owned();
        account = after.trim().to_owned();
    }
    key_of(
        issuer,
        account,
        &secret,
        &text(entry, &["/type", "/kind"]),
        &text(entry, &["/algorithm"]),
        number(entry, &["/digits"]),
        number(entry, &["/period", "/timer"]),
        number(entry, &["/counter"]),
        String::new(),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Format, detect_format, import};
    use vault_core::totp::Totp;

    /// A protocol buffer field (test data is written here, the reader is the code above).
    fn tag(out: &mut Vec<u8>, number: u64, wire: u64) {
        varint(out, number << 3 | wire);
    }

    fn varint(out: &mut Vec<u8>, mut n: u64) {
        while n >= 0x80 {
            out.push((n as u8) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
    }

    fn bytes(out: &mut Vec<u8>, number: u64, value: &[u8]) {
        tag(out, number, 2);
        varint(out, value.len() as u64);
        out.extend_from_slice(value);
    }

    fn number(out: &mut Vec<u8>, number: u64, value: u64) {
        tag(out, number, 0);
        varint(out, value);
    }

    /// `OtpParameters` with the fields given.
    fn parameters(
        secret: &[u8],
        name: &str,
        issuer: &str,
        algorithm: u64,
        digits: u64,
        kind: u64,
        counter: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        bytes(&mut out, 1, secret);
        bytes(&mut out, 2, name.as_bytes());
        bytes(&mut out, 3, issuer.as_bytes());
        number(&mut out, 4, algorithm);
        number(&mut out, 5, digits);
        number(&mut out, 6, kind);
        if counter > 0 {
            number(&mut out, 7, counter);
        }
        out
    }

    fn migration_link(keys: &[Vec<u8>]) -> String {
        let mut payload = Vec::new();
        for key in keys {
            bytes(&mut payload, 1, key);
        }
        number(&mut payload, 2, 1); // version
        number(&mut payload, 3, 1); // batch size
        number(&mut payload, 4, 0); // batch index
        number(&mut payload, 5, 12345); // batch id
        let data = STANDARD
            .encode(&payload)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        format!("otpauth-migration://offline?data={data}")
    }

    const RFC_KEY: &[u8] = b"12345678901234567890";

    #[test]
    fn a_migration_payload_gives_each_key_as_an_item() {
        let link = migration_link(&[
            parameters(
                RFC_KEY,
                "Example Co:me@example.com",
                "Example Co",
                1,
                1,
                2,
                0,
            ),
            parameters(RFC_KEY, "backup@example.com", "Bank", 2, 2, 1, 7),
            parameters(RFC_KEY, "old", "Legacy", 4, 1, 2, 0), // MD5: not taken
        ]);
        let report = migration(&link).unwrap();
        assert_eq!(report.items.len(), 2);
        let first = &report.items[0];
        assert_eq!(
            (first.title.as_str(), first.username.as_str()),
            ("Example Co", "me@example.com")
        );
        let totp = Totp::parse(&first.totp).unwrap();
        // RFC 6238's SHA-1 vector, 6 digits.
        assert_eq!(totp.code_at(59).as_str(), "287082");
        let bank = Totp::parse(&report.items[1].totp).unwrap();
        assert_eq!(bank.counter(), Some(7));
        assert_eq!(bank.digits(), 8);
        assert_eq!(report.items[1].title, "Bank");
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(report.warnings[0].contains("1 key of a kind"));
        // Not a migration link, or a payload cut short: nothing, or what came before.
        assert!(migration("otpauth-migration://offline").is_none());
        let cut = &link[..link.len() - 12];
        assert!(migration(cut).is_none_or(|r| r.items.len() <= 2));
    }

    #[test]
    fn a_list_of_links_is_read_line_by_line() {
        let text = format!(
            "otpauth://totp/Mail:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Mail\n\
             \n\
             otpauth://totp/Game:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&encoder=steam\n\
             not a link, éééééééééé\n\
             {}\n",
            migration_link(&[parameters(RFC_KEY, "chat", "Chat", 1, 1, 2, 0)])
        );
        assert_eq!(detect_format(text.as_bytes()), Format::OtpLinks);
        let report = import(text.as_bytes(), Format::OtpLinks, "", None).unwrap();
        let titles: Vec<&str> = report.items.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(titles, ["Mail", "Game", "Chat"]);
        assert!(Totp::parse(&report.items[1].totp).unwrap().is_characters());
        assert_eq!(
            report.warnings,
            ["1 line that holds no key this app can read was skipped"]
        );
    }

    #[test]
    fn the_common_json_exports_are_told_by_their_shape() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let database = format!(
            r#"{{"version": 1, "header": {{"slots": null, "params": null}},
            "db": {{"version": 3, "entries": [
              {{"type": "totp", "name": "me@example.com", "issuer": "Mail", "note": "work",
                "info": {{"secret": "{secret}", "algo": "SHA1", "digits": 6, "period": 30}}}},
              {{"type": "steam", "name": "me", "issuer": "Game",
                "info": {{"secret": "{secret}", "algo": "SHA1", "digits": 5, "period": 30}}}},
              {{"type": "yandex", "name": "x", "issuer": "Y", "info": {{"secret": "{secret}"}}}}]}}}}"#
        );
        let services = format!(
            r#"{{"schemaVersion": 4, "services": [
              {{"name": "Mail", "secret": "{secret}", "otp": {{"account": "me", "issuer": "Mail",
                "digits": 8, "period": 60, "algorithm": "SHA256", "tokenType": "TOTP"}}}},
              {{"name": "Bank", "secret": "{secret}", "otp": {{"label": "me", "tokenType": "HOTP", "counter": 3}}}}]}}"#
        );
        // The secret as signed bytes (RFC 6238's key).
        let signed: Vec<String> = RFC_KEY.iter().map(|b| (*b as i8).to_string()).collect();
        let tokens = format!(
            r#"{{"tokenOrder": ["Mail:me"], "tokens": [
              {{"algo": "SHA1", "counter": 0, "digits": 6, "issuerExt": "Mail", "label": "me",
                "period": 30, "secret": [{}], "type": "TOTP"}}]}}"#,
            signed.join(",")
        );
        let links = format!(
            r#"{{"version": 1, "entries": [
              {{"id": "1", "content": {{"uri": "otpauth://totp/Mail:me?secret={secret}", "entry_type": "Totp", "name": "Mail"}}, "note": "n"}}]}}"#
        );
        let list = format!(
            r#"[{{"secret": "{secret}", "issuer": "Mail", "label": "me", "digits": 6,
              "type": "TOTP", "algorithm": "SHA1", "period": 30, "tags": []}},
              {{"secret": "{secret}", "label": "Game:me", "type": "STEAM"}}]"#
        );
        for (text, expected) in [
            (&database, 2),
            (&services, 2),
            (&tokens, 1),
            (&links, 1),
            (&list, 2),
        ] {
            assert_eq!(detect_format(text.as_bytes()), Format::Json);
            let report = import(text.as_bytes(), Format::Json, "", None).unwrap();
            assert_eq!(report.items.len(), expected, "{text}");
            for item in &report.items {
                assert_eq!(item.kind, ItemKind::Login);
                assert!(Totp::parse(&item.totp).is_ok(), "{}", item.totp);
                assert!(!item.title.is_empty());
            }
        }
        let report = import(database.as_bytes(), Format::Json, "", None).unwrap();
        assert_eq!(report.items[0].notes, "work");
        assert!(Totp::parse(&report.items[1].totp).unwrap().is_characters());
        assert!(report.warnings[0].contains("1 key of a kind"));
        let report = import(services.as_bytes(), Format::Json, "", None).unwrap();
        let mail = Totp::parse(&report.items[0].totp).unwrap();
        assert_eq!(
            (mail.digits(), mail.period(), mail.algorithm()),
            (8, 60, TotpAlgorithm::Sha256)
        );
        assert_eq!(
            Totp::parse(&report.items[1].totp).unwrap().counter(),
            Some(3)
        );
        let report = import(tokens.as_bytes(), Format::Json, "", None).unwrap();
        assert_eq!(
            Totp::parse(&report.items[0].totp)
                .unwrap()
                .code_at(59)
                .as_str(),
            "287082"
        );
        let report = import(list.as_bytes(), Format::Json, "", None).unwrap();
        assert_eq!(
            (
                report.items[1].title.as_str(),
                report.items[1].username.as_str()
            ),
            ("Game", "me")
        );
    }

    #[test]
    fn an_encrypted_export_is_refused_with_how_to_make_a_plain_one() {
        for text in [
            r#"{"version": 1, "header": {"slots": [{}], "params": {}}, "db": "c2VhbGVk"}"#,
            r#"{"schemaVersion": 4, "services": [], "servicesEncrypted": "c2VhbGVk"}"#,
        ] {
            let err = import(text.as_bytes(), Format::Json, "", None).unwrap_err();
            assert!(err.to_string().contains("without a password"), "{err}");
        }
    }

    #[test]
    fn a_broken_protocol_buffer_stops_where_it_breaks() {
        // A length past the end, a wire type that doesn't exist, a varint that never ends.
        for bytes in [
            &[0x0a, 0x05, 0x01][..],
            &[0x0f, 0x00],
            &[
                0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        ] {
            let fields: Vec<_> = Message::new(bytes).collect();
            assert!(fields.last().unwrap().is_none());
        }
    }
}
