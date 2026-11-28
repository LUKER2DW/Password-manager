//! Export as a KeePass database (KDBX 4), encrypted with a password of the person's and,
//! if they choose, a keyfile.
//!
//! Written by the `keepass` crate (the same one [`crate::kdbx`] reads with): KDBX 4.1 with
//! ChaCha20 for the file and for its protected values, HMAC-SHA-256 over each block, GZip, and
//! the key derived with Argon2id at [`KDF`] (CRYPTO.md §3.11). Every item goes in whole, in the
//! places KeePassXC and KeePass2Android use: extra websites as `KP2A_URL_n`, the one-time
//! code as `otp`, passkeys as `KPEX_PASSKEY_*` (one per entry: more become entries of their
//! own), attached files as attachments, earlier passwords as the entry's history. What only
//! this app has (the item's kind, favourite, recovery codes as codes, a passkey's display
//! name) goes in the entry's custom data as one JSON object under `vault.item`, which other
//! programs keep and ignore, so that an import here gives the same items back.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::DateTime;
use keepass::config::{
    CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig,
};
use keepass::db::{CustomDataItem, CustomDataValue, Entry, History, Value, fields};
use keepass::{Database, DatabaseKey};
use vault_core::{ItemData, Passkey, Vault};
use zeroize::Zeroizing;

use crate::export::{RECOVERY_CODES_FIELD, codes_text, export_items};
use crate::kdbx::{
    CODES_DATA, DISPLAY_NAME_DATA, FAVORITE_DATA, ITEM_DATA, KIND_DATA, PASSKEY_CREATED_DATA,
    PASSKEY_ID, PASSKEY_KEY, PASSKEY_RP, PASSKEY_USER, PASSKEY_USER_HANDLE, REPROMPT_DATA,
    URL_PREFIX, kind_name,
};

/// The key derivation of an exported database: Argon2id (version 1.3) with the vault's own
/// standard level (CRYPTO.md §4): 256 MiB, 3 passes, 4 lanes. KeePass, KeePassXC and
/// KeePassDX open it; it is well within what this app's importer accepts.
pub const KDF: KdfParams = KdfParams {
    memory_bytes: 256 * 1024 * 1024,
    passes: 3,
    lanes: 4,
};

/// Argon2id parameters of a KDBX file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_bytes: u64,
    pub passes: u64,
    pub lanes: u32,
}

/// The vault as a KDBX 4 database, opened with `password` (and `keyfile`, the bytes of any
/// file, when given). Fails with [`vault_core::Error::SecretsLocked`] while an item's secrets
/// are locked, like every export.
pub fn export_kdbx(
    vault: &Vault,
    password: &str,
    keyfile: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, vault_core::Error> {
    write(vault, password, keyfile, KDF)
}

pub(crate) fn write(
    vault: &Vault,
    password: &str,
    keyfile: Option<&[u8]>,
    kdf: KdfParams,
) -> Result<Zeroizing<Vec<u8>>, vault_core::Error> {
    if password.is_empty() && keyfile.is_none() {
        return Err(vault_core::Error::Malformed);
    }
    let mut config = DatabaseConfig::default();
    config.outer_cipher_config = OuterCipherConfig::ChaCha20;
    config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    config.compression_config = CompressionConfig::GZip;
    config.kdf_config = KdfConfig::Argon2id {
        iterations: kdf.passes,
        memory: kdf.memory_bytes,
        parallelism: kdf.lanes,
        version: kdbx_argon2::Version::Version13,
    };
    let mut db = Database::with_config(config);
    let name = vault.settings().name.clone();
    db.meta.database_name = Some(if name.trim().is_empty() {
        "Vault".into()
    } else {
        name
    });

    for (item, folder) in export_items(vault)? {
        let group = match folder {
            Some(name) => {
                let found = db.root().groups().find(|g| g.name == name).map(|g| g.id());
                match found {
                    Some(id) => id,
                    None => db.root_mut().add_group().edit(|g| g.name = name).id(),
                }
            }
            None => db.root().id(),
        };
        let mut entries = entries_of(&item);
        for entry in entries.drain(..) {
            let mut group = db.group_mut(group).ok_or(vault_core::Error::Malformed)?;
            let mut added = group.add_entry();
            let id = added.id();
            added.edit(|e| fill(e, &entry));
            for (name, data) in &entry.attachments {
                added.add_attachment(name.clone(), Value::protected(data.to_vec()));
            }
            let _ = id;
        }
    }

    let mut key = DatabaseKey::new();
    if !password.is_empty() {
        key = key.with_password(password);
    }
    if let Some(mut keyfile) = keyfile {
        key = key
            .with_keyfile(&mut keyfile)
            .map_err(|_| vault_core::Error::Malformed)?;
    }
    // Written into a buffer reserved up front, so that most of it never moves (the rest is
    // wiped by the program's allocator when it is freed).
    let mut out = Zeroizing::new(Vec::with_capacity(64 * 1024));
    db.save(&mut *out, key)
        .map_err(|_| vault_core::Error::Malformed)?;
    Ok(out)
}

/// An entry's fields: name, value, protected.
type Fields = Vec<(String, Zeroizing<String>, bool)>;
/// This app's own data of an entry: key and text.
type OwnData = Vec<(&'static str, String)>;

/// What one entry holds before it is put in the database.
struct EntryParts {
    fields: Fields,
    data: OwnData,
    attachments: Vec<(String, Zeroizing<Vec<u8>>)>,
    history: Vec<(Zeroizing<String>, i64)>,
    created: i64,
    modified: i64,
}

/// The entries of an item: one, and one more for each passkey after its first (an entry
/// holds one passkey in KeePassXC's fields).
fn entries_of(item: &ItemData) -> Vec<EntryParts> {
    let mut fields: Fields = Vec::new();
    fn put(fields: &mut Fields, name: &str, value: &str, protected: bool) {
        if !value.is_empty() {
            fields.push((name.to_owned(), Zeroizing::new(value.to_owned()), protected));
        }
    }
    put(&mut fields, fields::TITLE, &item.title, false);
    put(&mut fields, fields::USERNAME, &item.username, false);
    put(&mut fields, fields::PASSWORD, &item.password, true);
    if let Some(first) = item.urls.first() {
        put(&mut fields, fields::URL, first, false);
    }
    for (n, url) in item.urls.iter().skip(1).enumerate() {
        put(&mut fields, &format!("{URL_PREFIX}_{}", n + 1), url, false);
    }
    put(&mut fields, fields::NOTES, &item.notes, false);
    if !item.totp.trim().is_empty() {
        let link = otp_link(item);
        put(&mut fields, fields::OTP, &link, true);
    }
    let standard = fields.len();
    let mut data = Vec::new();
    if let Some(kind) = kind_name(item.kind) {
        data.push((KIND_DATA, kind.to_owned()));
    }
    if item.favorite {
        data.push((FAVORITE_DATA, "1".to_owned()));
    }
    if item.reprompt {
        data.push((REPROMPT_DATA, "1".to_owned()));
    }
    for field in &item.custom_fields {
        put(&mut fields, &field.name, &field.value, field.sensitive);
    }
    if let Some(codes) = codes_text(&item.recovery_codes) {
        put(&mut fields, RECOVERY_CODES_FIELD, &codes, true);
        data.push((CODES_DATA, "1".to_owned()));
    }
    let fields = unique_names(fields, standard);
    let base = EntryParts {
        fields,
        data,
        attachments: item
            .attachments
            .iter()
            .map(|file| (file.name.clone(), Zeroizing::new(file.data.clone())))
            .collect(),
        history: item
            .password_history
            .iter()
            .map(|old| (Zeroizing::new(old.password.clone()), old.replaced_at))
            .collect(),
        created: item.created_at,
        modified: item.updated_at,
    };
    let mut entries = vec![base];
    for (n, passkey) in item.passkeys.iter().enumerate() {
        let Some((passkey_fields, passkey_data)) = passkey_parts(passkey) else {
            continue;
        };
        if n > 0 {
            // A passkey of its own: the item's name, user and websites, and the passkey.
            let mut fields: Fields = entries[0]
                .fields
                .iter()
                .filter(|(name, ..)| {
                    [fields::USERNAME, fields::URL].contains(&name.as_str())
                        || name.starts_with(URL_PREFIX)
                })
                .map(|(name, value, protected)| (name.clone(), value.clone(), *protected))
                .collect();
            fields.push((
                fields::TITLE.into(),
                Zeroizing::new(format!("{} (passkey {})", item.title, n + 1)),
                false,
            ));
            entries.push(EntryParts {
                fields,
                data: vec![(KIND_DATA, "passkey".to_owned())],
                attachments: Vec::new(),
                history: Vec::new(),
                created: item.created_at,
                modified: item.updated_at,
            });
        }
        let entry = entries.last_mut().unwrap_or_else(|| unreachable!());
        entry.fields.extend(passkey_fields);
        entry.data.extend(passkey_data);
    }
    entries
}

/// Two fields of one name would be one in KeePass (a map by name), and a name of its own
/// (Title, otp, a passkey's) would replace that: such a field gets a number after its name.
/// The first `standard` are KeePass's own (Title … otp), put first in `entries_of`.
fn unique_names(fields: Fields, standard: usize) -> Fields {
    let mut out: Fields = Vec::with_capacity(fields.len());
    for (at, (name, value, protected)) in fields.into_iter().enumerate() {
        let taken = |name: &str, out: &[(String, Zeroizing<String>, bool)]| {
            out.iter().any(|(n, ..)| n.eq_ignore_ascii_case(name))
                || (at >= standard
                    && (name.starts_with("KPEX_")
                        || name.starts_with(URL_PREFIX)
                        || fields::KNOWN_FIELDS
                            .iter()
                            .chain(&[fields::OTP])
                            .any(|known| known.eq_ignore_ascii_case(name))))
        };
        let mut unique = name.clone();
        let mut n = 2;
        while taken(&unique, &out) {
            unique = format!("{name} ({n})");
            n += 1;
        }
        out.push((unique, value, protected));
    }
    out
}

/// A passkey as KeePassXC keeps it in an entry, and what it has that KeePassXC has no field
/// for (the display name, when it was made) as custom data. `None` for a passkey without its
/// key (a locked item, which never gets this far).
fn passkey_parts(passkey: &Passkey) -> Option<(Fields, OwnData)> {
    let der = passkey.private_key_pkcs8().ok()?;
    let body = Zeroizing::new(STANDARD.encode(der.as_slice()));
    let mut pem = Zeroizing::new(String::with_capacity(body.len() + body.len() / 64 + 64));
    pem.push_str("-----BEGIN PRIVATE KEY-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----");
    let plain = |name: &str, value: String| (name.to_owned(), Zeroizing::new(value), false);
    let fields = vec![
        plain(PASSKEY_ID, URL_SAFE_NO_PAD.encode(&passkey.credential_id)),
        plain(PASSKEY_RP, passkey.rp_id.clone()),
        plain(PASSKEY_USER, passkey.user_name.clone()),
        plain(
            PASSKEY_USER_HANDLE,
            URL_SAFE_NO_PAD.encode(&passkey.user_handle),
        ),
        (PASSKEY_KEY.to_owned(), pem, true),
    ];
    let data = vec![
        (DISPLAY_NAME_DATA, passkey.display_name.clone()),
        (PASSKEY_CREATED_DATA, passkey.created_at.to_string()),
    ];
    Some((fields, data))
}

/// The one-time code as KeePassXC's `otp` field holds it: an `otpauth://` link (a bare key
/// becomes one, time-based with the defaults).
fn otp_link(item: &ItemData) -> Zeroizing<String> {
    let totp = item.totp.trim();
    if totp.to_ascii_lowercase().starts_with("otpauth://") {
        return Zeroizing::new(totp.to_owned());
    }
    vault_core::totp::LinkParts {
        issuer: &item.title,
        account: &item.username,
        secret: totp,
        ..Default::default()
    }
    .link()
    .unwrap_or_else(|| Zeroizing::new(totp.to_owned()))
}

fn time(unix: i64) -> Option<chrono::NaiveDateTime> {
    (unix > 0).then(|| DateTime::from_timestamp(unix, 0).map(|t| t.naive_utc()))?
}

/// Puts the parts in an entry the database made.
fn fill(entry: &mut Entry, parts: &EntryParts) {
    for (name, value, protected) in &parts.fields {
        let value = value.to_string();
        if *protected {
            entry.set_protected(name.clone(), value);
        } else {
            entry.set_unprotected(name.clone(), value);
        }
    }
    if !parts.data.is_empty() {
        let data: serde_json::Map<String, serde_json::Value> = parts
            .data
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone().into()))
            .collect();
        entry.custom_data.insert(
            ITEM_DATA.to_owned(),
            CustomDataItem {
                value: Some(CustomDataValue::String(
                    serde_json::Value::Object(data).to_string(),
                )),
                last_modification_time: None,
            },
        );
    }
    if let Some(created) = time(parts.created) {
        entry.times.creation = Some(created);
    }
    if let Some(modified) = time(parts.modified) {
        entry.times.last_modification = Some(modified);
    }
    if !parts.history.is_empty() {
        let mut history = History::default();
        // Oldest first: each is put in front of those before it.
        for (password, replaced_at) in parts.history.iter().rev() {
            let mut old = entry.clone();
            old.history = None;
            old.custom_data.clear();
            old.fields.clear();
            for (name, value, _) in parts.fields.iter().filter(|(name, ..)| {
                [fields::TITLE, fields::USERNAME, fields::URL].contains(&name.as_str())
            }) {
                old.set_unprotected(name.clone(), value.to_string());
            }
            old.set_protected(fields::PASSWORD, password.to_string());
            if let Some(at) = time(*replaced_at) {
                old.times.last_modification = Some(at);
            }
            history.add_entry(old);
        }
        entry.history = Some(history);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{Format, import};
    use vault_core::ItemKind;
    use vault_core::{
        Attachment, CustomField, GuardCheck, KdfParams as VaultKdf, PasswordChange, RecoveryCode,
        SecretKey,
    };

    /// Quick to open in tests; the export itself uses [`KDF`].
    pub(crate) const TEST_KDF: KdfParams = KdfParams {
        memory_bytes: 1024 * 1024,
        passes: 1,
        lanes: 1,
    };

    pub(crate) const PASSPHRASE: &str = "kdbx export test passphrase";

    /// A vault with one item of each kind, holding everything an item holds.
    pub(crate) fn full_vault() -> Vault {
        let mut vault = Vault::create(
            PASSPHRASE,
            &SecretKey::generate().unwrap(),
            None,
            VaultKdf::minimum().unwrap(),
        )
        .unwrap();
        let work = vault.add_folder("Work").unwrap();
        let mut mail = ItemData::login("Mail", "me@example.com", "pw-now", "https://mail.example");
        mail.urls.push("https://webmail.example".into());
        mail.folder = Some(work);
        mail.favorite = true;
        mail.reprompt = true;
        mail.notes = "two lines\nof notes".into();
        mail.totp = "JBSWY3DPEHPK3PXP".into();
        mail.custom_fields = vec![
            CustomField {
                name: "PIN".into(),
                value: "4321".into(),
                sensitive: true,
            },
            CustomField {
                name: "Title".into(),
                value: "a field named like a KeePass field".into(),
                sensitive: false,
            },
        ];
        mail.recovery_codes = RecoveryCode::parse_list("aaaa-1111\nbbbb-2222");
        mail.recovery_codes[0].used = true;
        mail.password_history = vec![
            PasswordChange {
                password: "pw-first".into(),
                replaced_at: 1_600_000_000,
            },
            PasswordChange {
                password: "pw-second".into(),
                replaced_at: 1_700_000_000,
            },
        ];
        mail.attachments
            .push(Attachment::new("scan.pdf", b"%PDF-1.7 test".to_vec()).unwrap());
        vault.add_item(&mail).unwrap();

        let mut shop = ItemData::new(ItemKind::Passkey, "Shop");
        shop.username = "me".into();
        shop.urls.push("https://shop.example".into());
        shop.passkeys
            .push(Passkey::new("shop.example", b"user-1", "me", "Me Myself").unwrap());
        shop.passkeys
            .push(Passkey::new("shop.example", b"user-2", "other", "Other").unwrap());
        vault.add_item(&shop).unwrap();

        let mut card = ItemData::new(ItemKind::Card, "Visa");
        vault_core::card::CardDetails {
            number: "4111111111111111".into(),
            expiry: "08/29".into(),
            security_code: "737".into(),
        }
        .apply(&mut card);
        card.username = "M E Tester".into();
        card.password = "1234".into();
        vault.add_item(&card).unwrap();

        let pair = vault_core::ssh::generate_ed25519("me@test").unwrap();
        let mut ssh = ItemData::new(ItemKind::SshKey, "Server");
        ssh.password = pair.private_key.to_string();
        ssh.custom_fields.push(CustomField {
            name: vault_core::ssh::PUBLIC_KEY_FIELD.into(),
            value: pair.public_key.clone(),
            sensitive: false,
        });
        vault.add_item(&ssh).unwrap();

        let mut note = ItemData::new(ItemKind::SecureNote, "Alarm");
        note.notes = "code 1234".into();
        vault.add_item(&note).unwrap();
        vault
    }

    #[test]
    fn every_item_comes_back_whole_from_our_reader() {
        let vault = full_vault();
        let bytes = write(&vault, "kdbx file password", None, TEST_KDF).unwrap();
        assert_eq!(crate::detect_format(&bytes), Format::Kdbx);
        let report = import(&bytes, Format::Kdbx, "kdbx file password", None).unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        // One entry more: Shop's second passkey is an entry of its own.
        assert_eq!(report.items.len(), vault.len() + 1);
        let find = |title: &str| {
            let at = report.items.iter().position(|i| i.title == title).unwrap();
            (&report.items[at], report.folders[at].as_deref())
        };
        let originals: Vec<ItemData> = vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .collect();
        for original in &originals {
            let (back, folder) = find(&original.title);
            assert_eq!(back.kind, original.kind, "{}", original.title);
            assert_eq!(back.username, original.username);
            assert_eq!(back.password, original.password);
            assert_eq!(back.urls, original.urls);
            assert_eq!(back.notes, original.notes);
            assert_eq!(back.favorite, original.favorite);
            assert_eq!(back.reprompt, original.reprompt);
            assert_eq!(back.created_at, original.created_at);
            assert_eq!(back.recovery_codes, original.recovery_codes);
            assert_eq!(back.attachments, original.attachments);
            assert_eq!(back.password_history, original.password_history);
            let mut fields = original.custom_fields.clone();
            let mut back_fields = back.custom_fields.clone();
            for f in back_fields.iter_mut() {
                if f.name == "Title (2)" {
                    f.name = "Title".into();
                }
            }
            fields.sort_by(|a, b| a.name.cmp(&b.name));
            back_fields.sort_by(|a, b| a.name.cmp(&b.name));
            assert_eq!(back_fields, fields, "{}", original.title);
            assert_eq!(folder, original.folder.map(|_| "Work"));
        }
        let (mail, _) = find("Mail");
        let totp = vault_core::totp::Totp::parse(&mail.totp).unwrap();
        assert_eq!(
            totp.code_at(59),
            vault_core::totp::Totp::parse("JBSWY3DPEHPK3PXP")
                .unwrap()
                .code_at(59)
        );
        let (shop, _) = find("Shop");
        let (second, _) = find("Shop (passkey 2)");
        let original = &originals
            .iter()
            .find(|i| i.title == "Shop")
            .unwrap()
            .passkeys;
        assert_eq!(shop.passkeys.as_slice(), &original[..1]);
        assert_eq!(second.passkeys.as_slice(), &original[1..]);
        assert_eq!(second.kind, ItemKind::Passkey);
    }

    #[test]
    fn a_keyfile_and_a_password_are_both_needed() {
        let vault = full_vault();
        let keyfile = b"any file at all can be a keyfile";
        let bytes = write(&vault, "kdbx file password", Some(keyfile), TEST_KDF).unwrap();
        assert!(import(&bytes, Format::Kdbx, "kdbx file password", None).is_err());
        assert!(import(&bytes, Format::Kdbx, "wrong", Some(keyfile)).is_err());
        let report = import(&bytes, Format::Kdbx, "kdbx file password", Some(keyfile)).unwrap();
        assert_eq!(report.items.len(), vault.len() + 1);
        // No password and no keyfile: no file.
        assert!(write(&vault, "", None, TEST_KDF).is_err());
    }

    #[test]
    fn the_file_is_written_with_the_documented_cipher_and_key_derivation() {
        let vault = full_vault();
        let bytes = write(&vault, "pw", None, TEST_KDF).unwrap();
        // KDBX 4.x: signature, then the version.
        assert_eq!(&bytes[..4], &[0x03, 0xd9, 0xa2, 0x9a]);
        assert_eq!(u16::from_le_bytes([bytes[10], bytes[11]]), 4);
        // ChaCha20's cipher id (KDBX 4) and Argon2id's KDF uuid are in the header.
        let chacha20 = [
            0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb,
            0xb5, 0x9a,
        ];
        let argon2id = [
            0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0,
            0xa1, 0xe6,
        ];
        let header = &bytes[..400.min(bytes.len())];
        assert!(header.windows(16).any(|w| w == chacha20));
        assert!(header.windows(16).any(|w| w == argon2id));
        // Nothing of the vault is in the file in clear.
        for secret in [&b"pw-now"[..], b"4111111111111111", b"Mail", b"scan.pdf"] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret));
        }
    }

    /// Writes the test vault, at the export's own key derivation, to the file named by
    /// `KDBX_EXPORT_OUT` (password "kdbx file password"), for opening with another program
    /// (`keepassxc-cli ls -R`, `keepassxc-cli show -s -a otp`).
    #[test]
    #[ignore]
    fn write_a_file_for_another_reader() {
        let Ok(path) = std::env::var("KDBX_EXPORT_OUT") else {
            return;
        };
        let bytes = export_kdbx(&full_vault(), "kdbx file password", None).unwrap();
        std::fs::write(path, bytes.as_slice()).unwrap();
    }

    #[test]
    fn a_locked_item_stops_the_export() {
        let mut vault = full_vault();
        vault
            .set_item_guard(true, GuardCheck::Pin, Some("2468"), Some(PASSPHRASE))
            .unwrap();
        vault.lock_secrets();
        assert!(matches!(
            write(&vault, "pw", None, TEST_KDF),
            Err(vault_core::Error::SecretsLocked)
        ));
    }
}
