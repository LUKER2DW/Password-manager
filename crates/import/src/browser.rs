//! Reading the passwords a browser saved on this computer, straight from its own store, when the
//! user asks for it (Windows).
//!
//! - **Chromium browsers** (Edge, Brave, Opera, Vivaldi, older Chrome): the `Login Data` SQLite
//!   database; each password is AES-256-GCM encrypted with a key that Windows protects for the
//!   signed-in user (DPAPI, in `Local State`). Chrome 127+ adds "app-bound" encryption (`v20`)
//!   that only Chrome itself can undo; those entries are counted and the user is pointed to the
//!   CSV export instead.
//! - **Firefox**: `logins.json`, encrypted with a key kept in `key4.db` (NSS), itself protected
//!   by the profile's primary password (empty unless the user set one).
//!
//! The databases are read into memory (never copied to disk) and every decrypted value lives in
//! wiped-on-drop buffers until it becomes an [`ItemData`]. This is the same access an
//! infostealer uses, which is why the app only does it on an explicit click.
//!
//! Undoing Windows' protection (DPAPI) is the caller's [`Unprotect`] function, so this crate
//! stays free of `unsafe` code (the desktop app passes `vault_platform::dpapi::unprotect`).

use std::path::{Path, PathBuf};

use aes::cipher::{BlockModeDecrypt, KeyInit, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::{Aes256Gcm, Nonce, aead::Aead};
use base64::Engine as _;
use sha1::Digest as _;
use vault_core::ItemData;
use zeroize::Zeroizing;

use crate::{ImportError, ImportReport, Source, host_of, non_empty};

/// Undoes Windows DPAPI protection for the signed-in user; `None` when it can't.
pub type Unprotect<'a> = &'a dyn Fn(&[u8]) -> Option<Zeroizing<Vec<u8>>>;

/// One browser profile that has saved passwords.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserProfile {
    /// As the browser shows it ("Person 1", "default-release"…).
    pub name: String,
    /// The profile folder.
    pub dir: PathBuf,
}

/// Whether `source` can be read directly (all browsers but Safari, on Windows).
pub fn supports_direct(source: Source) -> bool {
    cfg!(windows) && engine(source).is_some()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Engine {
    Chromium,
    Firefox,
}

fn engine(source: Source) -> Option<Engine> {
    match source {
        Source::Chrome
        | Source::Edge
        | Source::Brave
        | Source::Opera
        | Source::OperaGx
        | Source::Vivaldi => Some(Engine::Chromium),
        Source::Firefox => Some(Engine::Firefox),
        _ => None,
    }
}

/// The folder holding `Local State` (Chromium) or `profiles.ini` (Firefox).
fn user_data_dir(source: Source) -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let roaming = std::env::var_os("APPDATA").map(PathBuf::from);
    Some(match source {
        Source::Chrome => local?.join(r"Google\Chrome\User Data"),
        Source::Edge => local?.join(r"Microsoft\Edge\User Data"),
        Source::Brave => local?.join(r"BraveSoftware\Brave-Browser\User Data"),
        Source::Vivaldi => local?.join(r"Vivaldi\User Data"),
        Source::Opera => roaming?.join(r"Opera Software\Opera Stable"),
        Source::OperaGx => roaming?.join(r"Opera Software\Opera GX Stable"),
        Source::Firefox => roaming?.join(r"Mozilla\Firefox"),
        _ => return None,
    })
}

/// Profiles of `source` on this computer that have a password store.
pub fn profiles(source: Source) -> Vec<BrowserProfile> {
    let (Some(engine), Some(root)) = (engine(source), user_data_dir(source)) else {
        return Vec::new();
    };
    match engine {
        Engine::Chromium => chromium_profiles(&root),
        Engine::Firefox => firefox_profiles(&root),
    }
}

fn chromium_profiles(root: &Path) -> Vec<BrowserProfile> {
    let mut out = Vec::new();
    // Opera keeps a single profile in the user data folder itself.
    if root.join("Login Data").is_file() {
        out.push(BrowserProfile {
            name: "Default".into(),
            dir: root.to_path_buf(),
        });
    }
    let names: Vec<(String, String)> = std::fs::read(root.join("Local State"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|state| {
            state
                .pointer("/profile/info_cache")?
                .as_object()
                .map(|cache| {
                    cache
                        .iter()
                        .map(|(dir, info)| {
                            let name = info
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or(dir)
                                .to_owned();
                            (dir.clone(), name)
                        })
                        .collect()
                })
        })
        .unwrap_or_default();
    for (dir, name) in names {
        let path = root.join(&dir);
        if path.join("Login Data").is_file() && !out.iter().any(|p| p.dir == path) {
            out.push(BrowserProfile { name, dir: path });
        }
    }
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    out
}

fn firefox_profiles(root: &Path) -> Vec<BrowserProfile> {
    let Ok(ini) = std::fs::read_to_string(root.join("profiles.ini")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut name = String::new();
    let mut path = String::new();
    let mut relative = true;
    let mut flush = |name: &mut String, path: &mut String, relative: &mut bool| {
        if !path.is_empty() {
            let dir = if *relative {
                root.join(path.replace('/', "\\"))
            } else {
                PathBuf::from(&*path)
            };
            if dir.join("logins.json").is_file() {
                out.push(BrowserProfile {
                    name: if name.is_empty() {
                        path.clone()
                    } else {
                        name.clone()
                    },
                    dir,
                });
            }
        }
        name.clear();
        path.clear();
        *relative = true;
    };
    for line in ini.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            flush(&mut name, &mut path, &mut relative);
        } else if let Some(v) = line.strip_prefix("Name=") {
            name = v.to_owned();
        } else if let Some(v) = line.strip_prefix("Path=") {
            path = v.to_owned();
        } else if let Some(v) = line.strip_prefix("IsRelative=") {
            relative = v != "0";
        }
    }
    flush(&mut name, &mut path, &mut relative);
    out
}

/// Reads every saved login of `profile`. `primary_password` is Firefox's own (empty when none
/// was set); Chromium browsers ignore it.
pub fn read(
    source: Source,
    profile: &BrowserProfile,
    primary_password: &str,
    unprotect: Unprotect<'_>,
) -> Result<ImportReport, ImportError> {
    match engine(source) {
        Some(Engine::Chromium) => {
            let root = user_data_dir(source).ok_or_else(|| browser_error("not found"))?;
            read_chromium(&root, &profile.dir, unprotect)
        }
        Some(Engine::Firefox) => read_firefox(&profile.dir, primary_password),
        None => Err(browser_error("this source has no store to read")),
    }
}

fn browser_error(text: &str) -> ImportError {
    ImportError::Browser(text.to_owned())
}

/// Reads a file the browser may hold open (SQLite allows shared reads).
fn read_store(path: &Path) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    std::fs::read(path).map(Zeroizing::new).map_err(|e| {
        browser_error(&format!(
            "couldn't read {} ({e}); close the browser and try again",
            path.file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
        ))
    })
}

/// Opens SQLite bytes in memory, read-only.
fn open_sqlite(bytes: &[u8]) -> Result<rusqlite::Connection, ImportError> {
    let mut conn = rusqlite::Connection::open_in_memory().map_err(sql_error)?;
    conn.deserialize_read_exact(rusqlite::MAIN_DB, bytes, bytes.len(), true)
        .map_err(sql_error)?;
    Ok(conn)
}

fn sql_error(err: rusqlite::Error) -> ImportError {
    browser_error(&format!("unreadable database: {err}"))
}

// ---------------------------------------------------------------------------------------------
// Chromium
// ---------------------------------------------------------------------------------------------

/// Microseconds since 1601-01-01 → Unix seconds.
fn chromium_time(micros: i64) -> i64 {
    if micros <= 0 {
        0
    } else {
        micros / 1_000_000 - 11_644_473_600
    }
}

fn read_chromium(
    root: &Path,
    profile: &Path,
    unprotect: Unprotect<'_>,
) -> Result<ImportReport, ImportError> {
    let state: serde_json::Value = serde_json::from_slice(&read_store(&root.join("Local State"))?)?;
    let key = state
        .pointer("/os_crypt/encrypted_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| browser_error("no encryption key in Local State"))
        .and_then(|b64| {
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|_| browser_error("bad encryption key"))
        })?;
    let wrapped = key
        .strip_prefix(b"DPAPI")
        .ok_or_else(|| browser_error("unknown key protection"))?;
    let key = unprotect(wrapped).ok_or_else(|| {
        browser_error("Windows couldn't unlock the browser's key for this account")
    })?;
    if key.len() != 32 {
        return Err(browser_error("unexpected key size"));
    }

    let bytes = read_store(&profile.join("Login Data"))?;
    let conn = open_sqlite(&bytes)?;
    let mut statement = conn
        .prepare(
            "SELECT origin_url, username_value, password_value, date_created, \
             date_password_modified, blacklisted_by_user FROM logins",
        )
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut report = ImportReport::default();
    let mut app_bound = 0usize;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let never_saved: i64 = row.get(5).unwrap_or(0);
        if never_saved != 0 {
            continue; // "Never save for this site": no password there
        }
        let url: String = row.get(0).unwrap_or_default();
        let username: String = row.get(1).unwrap_or_default();
        let blob: Vec<u8> = row.get(2).unwrap_or_default();
        let blob = Zeroizing::new(blob);
        let password = match decrypt_chromium(&key, &blob, unprotect) {
            Ok(password) => password,
            Err(ChromiumValue::AppBound) => {
                app_bound += 1;
                continue;
            }
            Err(ChromiumValue::Broken) => {
                report
                    .warnings
                    .push(format!("{url}: couldn't decrypt, skipped"));
                continue;
            }
        };
        if url.is_empty() && username.is_empty() && password.is_empty() {
            continue;
        }
        let title = host_of(&url).unwrap_or_else(|| "Untitled".into());
        let mut item = ItemData::login(&title, &username, &password, &url);
        let created = chromium_time(row.get(3).unwrap_or(0));
        if created > 0 {
            item.created_at = created;
        }
        let changed = chromium_time(row.get(4).unwrap_or(0));
        if changed > 0 {
            item.updated_at = changed;
            item.password_changed_at = changed;
        }
        report.push(item, None);
    }
    if app_bound > 0 {
        report.warnings.insert(
            0,
            format!(
                "{app_bound} passwords use the browser's app-bound encryption, which only the \
                 browser itself can open: export them as CSV from the browser instead"
            ),
        );
    }
    Ok(report)
}

enum ChromiumValue {
    AppBound,
    Broken,
}

fn decrypt_chromium(
    key: &[u8],
    blob: &[u8],
    unprotect: Unprotect<'_>,
) -> Result<Zeroizing<String>, ChromiumValue> {
    if blob.is_empty() {
        return Ok(Zeroizing::new(String::new()));
    }
    if blob.starts_with(b"v20") {
        return Err(ChromiumValue::AppBound);
    }
    let plain = if blob.starts_with(b"v10") || blob.starts_with(b"v11") {
        if blob.len() < 3 + 12 + 16 {
            return Err(ChromiumValue::Broken);
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ChromiumValue::Broken)?;
        Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::try_from(&blob[3..15]).map_err(|_| ChromiumValue::Broken)?,
                    &blob[15..],
                )
                .map_err(|_| ChromiumValue::Broken)?,
        )
    } else {
        // Very old entries: protected by DPAPI directly.
        unprotect(blob).ok_or(ChromiumValue::Broken)?
    };
    String::from_utf8(plain.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| ChromiumValue::Broken)
}

// ---------------------------------------------------------------------------------------------
// Firefox (NSS)
// ---------------------------------------------------------------------------------------------

const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
const OID_DES_EDE3_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07];
/// `CKA_ID` of the key that encrypts logins.
const LOGIN_KEY_ID: &[u8] = &[0xf8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// A minimal DER reader: enough for the few structures NSS uses.
#[derive(Clone, Copy)]
struct Der<'a> {
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The next element: (tag, contents).
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.rest.split_first()?;
        let (&first, mut rest) = rest.split_first()?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let len = rest[..n]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            rest = &rest[n..];
            len
        };
        if rest.len() < len {
            return None;
        }
        let (body, after) = rest.split_at(len);
        self.rest = after;
        Some((tag, body))
    }

    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        match self.next()? {
            (t, body) if t == tag => Some(body),
            _ => None,
        }
    }

    fn seq(&mut self) -> Option<Der<'a>> {
        self.expect(0x30).map(Der::new)
    }
}

fn der_int(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 5 {
        return None;
    }
    Some(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)) as u32)
}

/// Decrypts a PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC) blob from `key4.db`.
fn nss_pbe_decrypt(blob: &[u8], global_salt: &[u8], password: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut outer = Der::new(blob).seq()?;
    let mut algorithm = outer.seq()?;
    if algorithm.expect(0x06)? != OID_PBES2 {
        return None;
    }
    let mut params = algorithm.seq()?;
    let mut kdf = params.seq()?;
    let _pbkdf2_oid = kdf.expect(0x06)?;
    let mut kdf_params = kdf.seq()?;
    let salt = kdf_params.expect(0x04)?;
    let iterations = der_int(kdf_params.expect(0x02)?)?;
    let mut cipher = params.seq()?;
    if cipher.expect(0x06)? != OID_AES256_CBC {
        return None;
    }
    let iv_tail = cipher.expect(0x04)?;
    let ciphertext = outer.expect(0x04)?;
    if !(1..=10_000_000).contains(&iterations) {
        return None;
    }

    let mut hasher = sha1::Sha1::new();
    hasher.update(global_salt);
    hasher.update(password.as_bytes());
    let k = Zeroizing::new(hasher.finalize().to_vec());
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&k, salt, iterations, key.as_mut());
    // NSS stores 14 bytes of IV; the full IV is them prefixed with their DER header.
    let mut iv = [0u8; 16];
    if iv_tail.len() == 14 {
        iv[0] = 0x04;
        iv[1] = 0x0e;
        iv[2..].copy_from_slice(iv_tail);
    } else if iv_tail.len() == 16 {
        iv.copy_from_slice(iv_tail);
    } else {
        return None;
    }
    aes256_cbc_decrypt(key.as_ref(), &iv, ciphertext)
}

fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).ok()?;
    decryptor
        .decrypt_padded_vec::<Pkcs7>(data)
        .ok()
        .map(Zeroizing::new)
}

fn des3_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let decryptor = cbc::Decryptor::<des::TdesEde3>::new_from_slices(key, iv).ok()?;
    decryptor
        .decrypt_padded_vec::<Pkcs7>(data)
        .ok()
        .map(Zeroizing::new)
}

/// The key that encrypts Firefox logins, from `key4.db`.
fn firefox_key(key4: &[u8], primary_password: &str) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let conn = open_sqlite(key4)?;
    let (global_salt, check): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT item1, item2 FROM metaData WHERE id = 'password'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql_error)?;
    let checked = nss_pbe_decrypt(&check, &global_salt, primary_password)
        .ok_or(ImportError::WrongBrowserPassword)?;
    if checked.as_slice() != b"password-check" {
        return Err(ImportError::WrongBrowserPassword);
    }
    let mut statement = conn
        .prepare("SELECT a11, a102 FROM nssPrivate")
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let a11: Vec<u8> = row.get(0).unwrap_or_default();
        let a102: Vec<u8> = row.get(1).unwrap_or_default();
        if a102 == LOGIN_KEY_ID
            && let Some(key) = nss_pbe_decrypt(&a11, &global_salt, primary_password)
        {
            return Ok(key);
        }
    }
    Err(browser_error("no login key in key4.db"))
}

/// Decrypts one `encryptedUsername` / `encryptedPassword` value of `logins.json`.
fn firefox_value(key: &[u8], b64: &str) -> Option<Zeroizing<String>> {
    let blob = Zeroizing::new(base64::engine::general_purpose::STANDARD.decode(b64).ok()?);
    let mut outer = Der::new(&blob).seq()?;
    let _key_id = outer.expect(0x04)?;
    let mut algorithm = outer.seq()?;
    let oid = algorithm.expect(0x06)?;
    let iv = algorithm.expect(0x04)?;
    let ciphertext = outer.expect(0x04)?;
    let plain = if oid == OID_AES256_CBC && key.len() >= 32 {
        aes256_cbc_decrypt(&key[..32], iv, ciphertext)?
    } else if oid == OID_DES_EDE3_CBC && key.len() >= 24 {
        des3_cbc_decrypt(&key[..24], iv, ciphertext)?
    } else {
        return None;
    };
    String::from_utf8(plain.to_vec()).ok().map(Zeroizing::new)
}

fn read_firefox(profile: &Path, primary_password: &str) -> Result<ImportReport, ImportError> {
    let key = firefox_key(&read_store(&profile.join("key4.db"))?, primary_password)?;
    let logins: serde_json::Value =
        serde_json::from_slice(&read_store(&profile.join("logins.json"))?)?;
    let mut report = ImportReport::default();
    for login in logins
        .get("logins")
        .and_then(|l| l.as_array())
        .into_iter()
        .flatten()
    {
        let text = |name: &str| login.get(name).and_then(|v| v.as_str()).unwrap_or_default();
        let url = text("hostname").to_owned();
        let (Some(username), Some(password)) = (
            firefox_value(&key, text("encryptedUsername")),
            firefox_value(&key, text("encryptedPassword")),
        ) else {
            report
                .warnings
                .push(format!("{url}: couldn't decrypt, skipped"));
            continue;
        };
        let title = non_empty(host_of(&url)).unwrap_or_else(|| "Untitled".into());
        let mut item = ItemData::login(&title, &username, &password, &url);
        let ms = |name: &str| {
            login
                .get(name)
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0)
        };
        if ms("timeCreated") > 0 {
            item.created_at = ms("timeCreated") / 1000;
        }
        if ms("timePasswordChanged") > 0 {
            item.updated_at = ms("timePasswordChanged") / 1000;
            item.password_changed_at = item.updated_at;
        }
        report.push(item, None);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};

    use super::*;

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &parts.concat())
    }

    /// Builds a key4.db-style PBES2 blob, as NSS writes it.
    fn pbes2(plain: &[u8], global_salt: &[u8], password: &str) -> Vec<u8> {
        let salt = [7u8; 32];
        let iterations = 1000u32;
        let iv_tail = [9u8; 14];
        let mut hasher = sha1::Sha1::new();
        hasher.update(global_salt);
        hasher.update(password.as_bytes());
        let k = hasher.finalize();
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&k, &salt, iterations, &mut key);
        let mut iv = [0u8; 16];
        iv[0] = 4;
        iv[1] = 14;
        iv[2..].copy_from_slice(&iv_tail);
        let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_vec::<Pkcs7>(plain);
        seq(&[
            seq(&[
                der(0x06, OID_PBES2),
                seq(&[
                    seq(&[
                        der(
                            0x06,
                            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c],
                        ),
                        seq(&[
                            der(0x04, &salt),
                            der(0x02, &iterations.to_be_bytes()[2..]),
                            der(0x02, &[32]),
                        ]),
                    ]),
                    seq(&[der(0x06, OID_AES256_CBC), der(0x04, &iv_tail)]),
                ]),
            ]),
            der(0x04, &ct),
        ])
    }

    #[test]
    fn nss_key_and_firefox_values() {
        let global_salt = b"global-salt-0123";
        // The password check only opens with the right primary password.
        let check = pbes2(b"password-check", global_salt, "");
        assert_eq!(
            nss_pbe_decrypt(&check, global_salt, "").unwrap().as_slice(),
            b"password-check"
        );
        assert!(
            nss_pbe_decrypt(&check, global_salt, "wrong")
                .is_none_or(|p| p.as_slice() != b"password-check")
        );

        // A login value encrypted with the 32-byte login key (AES-256-CBC).
        let login_key = [3u8; 32];
        let iv = [5u8; 16];
        let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(&login_key, &iv)
            .unwrap()
            .encrypt_padded_vec::<Pkcs7>(b"hunter2");
        let value = seq(&[
            der(0x04, LOGIN_KEY_ID),
            seq(&[der(0x06, OID_AES256_CBC), der(0x04, &iv)]),
            der(0x04, &ct),
        ]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(value);
        assert_eq!(firefox_value(&login_key, &b64).unwrap().as_str(), "hunter2");
        assert!(firefox_value(&[4u8; 32], &b64).is_none_or(|v| v.as_str() != "hunter2"));
    }

    #[test]
    fn chromium_values() {
        let key = [1u8; 32];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = [2u8; 12];
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend(
            cipher
                .encrypt(&Nonce::from(nonce), b"s3cret".as_ref())
                .unwrap(),
        );
        let none = |_: &[u8]| None;
        assert_eq!(
            decrypt_chromium(&key, &blob, &none).ok().unwrap().as_str(),
            "s3cret"
        );
        assert!(matches!(
            decrypt_chromium(&key, b"v20xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", &none),
            Err(ChromiumValue::AppBound)
        ));
        assert!(decrypt_chromium(&[9u8; 32], &blob, &none).is_err());
        // Old entries go to DPAPI.
        let old = |data: &[u8]| (data == b"blob").then(|| Zeroizing::new(b"legacy".to_vec()));
        assert_eq!(
            decrypt_chromium(&key, b"blob", &old).ok().unwrap().as_str(),
            "legacy"
        );
        assert_eq!(chromium_time(13_340_000_000_000_000), 1_695_526_400);
    }

    #[test]
    fn profiles_ini() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("Profiles").join("abc.default-release");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(profile.join("logins.json"), "{}").unwrap();
        std::fs::write(
            dir.path().join("profiles.ini"),
            "[Install1]\nDefault=Profiles/abc.default-release\n\n[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abc.default-release\n\n[Profile1]\nName=empty\nIsRelative=1\nPath=Profiles/none\n",
        )
        .unwrap();
        let found = firefox_profiles(dir.path());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "default-release");
    }

    #[test]
    fn sqlite_from_bytes() {
        // A real SQLite file opened from bytes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Login Data");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE t (a TEXT); INSERT INTO t VALUES ('x');")
                .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        let conn = open_sqlite(&bytes).unwrap();
        let a: String = conn.query_row("SELECT a FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(a, "x");
    }
}
