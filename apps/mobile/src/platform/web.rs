//! The stand-in for the platform crate in a browser (the web preview). Everything lives in
//! this page's memory and is gone when it closes: the preview only ever holds a demo vault
//! made for it, never a real one.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    fmt,
    path::{Path, PathBuf},
};

use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::{Zeroize, Zeroizing};

thread_local! {
    static FILES: RefCell<HashMap<PathBuf, Vec<u8>>> = RefCell::new(HashMap::new());
    static SECRET_KEYS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    static REVISIONS: RefCell<BTreeMap<String, u64>> = const { RefCell::new(BTreeMap::new()) };
    static CLIPBOARD: RefCell<Option<Zeroizing<String>>> = const { RefCell::new(None) };
}

/// The vault file, in this page's memory.
pub mod files {
    use super::*;

    pub fn read(path: &Path) -> vault_core::Result<Vec<u8>> {
        read_any(path).map_err(vault_core::Error::Io)
    }

    pub fn write_atomic(path: &Path, bytes: &[u8]) -> vault_core::Result<()> {
        FILES.with(|files| files.borrow_mut().insert(path.to_owned(), bytes.to_vec()));
        Ok(())
    }

    pub fn read_any(path: &Path) -> std::io::Result<Vec<u8>> {
        FILES
            .with(|files| files.borrow().get(path).cloned())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
    }

    pub fn create_dir_all(_: &Path) -> std::io::Result<()> {
        Ok(())
    }

    pub fn remove(path: &Path) {
        FILES.with(|files| files.borrow_mut().remove(path));
    }
}

/// The leak check needs the network, which the preview doesn't use.
pub mod leak_check {
    pub fn count(_password: &str) -> Result<u64, String> {
        Err("the browser preview doesn't use the network".into())
    }

    pub fn lookup<K: Copy>(
        _queries: &[(K, vault_core::health::BreachQuery)],
    ) -> Result<Vec<(K, u64)>, String> {
        Err("the browser preview doesn't use the network".into())
    }
}

/// The browser's language (`navigator.language`, "pt-BR"): the preview follows it as the phone
/// follows Android's, when the setting says "the phone's".
#[wasm_bindgen(
    inline_js = "export function browser_language() { return navigator.language || ''; }"
)]
extern "C" {
    fn browser_language() -> String;
}

pub fn system_language() -> Option<String> {
    Some(browser_language()).filter(|tag| !tag.is_empty())
}

/// The Secret Key "remembered on this device": in this page's memory.
pub mod secret_store {
    use super::*;

    pub fn store(vault_id: &str, key: &vault_core::SecretKey) -> anyhow::Result<()> {
        SECRET_KEYS.with(|keys| {
            keys.borrow_mut()
                .insert(vault_id.to_owned(), key.to_display_string().to_string())
        });
        Ok(())
    }

    pub fn load(vault_id: &str) -> anyhow::Result<Option<vault_core::SecretKey>> {
        Ok(SECRET_KEYS
            .with(|keys| keys.borrow().get(vault_id).cloned())
            .and_then(|text| vault_core::SecretKey::parse(&text).ok()))
    }

    pub fn forget(vault_id: &str) -> anyhow::Result<bool> {
        Ok(SECRET_KEYS.with(|keys| keys.borrow_mut().remove(vault_id).is_some()))
    }
}

/// The clipboard: the page keeps what was copied (the preview can't read the computer's).
pub mod clipboard {
    use super::*;

    pub fn copy_secret(text: &str) -> anyhow::Result<()> {
        copy_plain(text)
    }

    pub fn copy_plain(text: &str) -> anyhow::Result<()> {
        CLIPBOARD.with(|c| *c.borrow_mut() = Some(Zeroizing::new(text.to_owned())));
        Ok(())
    }

    pub fn paste_text() -> Option<Zeroizing<String>> {
        CLIPBOARD.with(|c| c.borrow().clone())
    }

    pub fn clear_if(expected: &str) -> bool {
        CLIPBOARD.with(|c| {
            let mut c = c.borrow_mut();
            if c.as_deref().is_some_and(|text| text == expected) {
                *c = None;
                true
            } else {
                false
            }
        })
    }
}

/// Rollback detection, as on a device: the highest revision seen, per vault.
pub mod device {
    use super::*;

    pub fn record_revision(vault_id: &str, revision: u64) -> anyhow::Result<()> {
        REVISIONS.with(|r| {
            let mut r = r.borrow_mut();
            let seen = r.entry(vault_id.to_owned()).or_default();
            *seen = (*seen).max(revision);
        });
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFile {
    Read,
    SetAside,
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackStatus {
    Ok,
    Older { revision: u64, highest_seen: u64 },
}

#[derive(Debug, Default)]
pub struct DeviceState;

impl DeviceState {
    pub fn load_or_set_aside() -> (Self, StateFile) {
        (Self, StateFile::Read)
    }

    pub fn check_rollback(&self, vault_id: &str, revision: u64) -> RollbackStatus {
        let seen = REVISIONS.with(|r| r.borrow().get(vault_id).copied());
        match seen {
            Some(highest_seen) if revision < highest_seen => RollbackStatus::Older {
                revision,
                highest_seen,
            },
            _ => RollbackStatus::Ok,
        }
    }

    pub fn record_revision(&mut self, vault_id: &str, revision: u64) {
        let _ = device::record_revision(vault_id, revision);
    }

    pub fn save(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// A typed secret, kept out of Slint strings and wiped when cleared: the platform crate's
/// buffer, without the locked memory a browser doesn't offer.
pub const MAX_SECRET_BYTES: usize = 1024;

pub struct SecretBuffer {
    bytes: Box<[u8; MAX_SECRET_BYTES]>,
    len: usize,
    chars: usize,
}

impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuffer({} chars, <redacted>)", self.chars)
    }
}

impl Default for SecretBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBuffer {
    pub fn new() -> Self {
        Self {
            bytes: Box::new([0u8; MAX_SECRET_BYTES]),
            len: 0,
            chars: 0,
        }
    }

    /// Whether `c` can be part of a secret (the platform crate's rule): never a control
    /// character or a private-use code point.
    pub fn takes(c: char) -> bool {
        !(c.is_control() || ('\u{E000}'..='\u{F8FF}').contains(&c) || c >= '\u{F0000}')
    }

    /// Appends the characters it [takes](Self::takes) and skips the others. Returns `false`
    /// if the buffer is full.
    pub fn push_str(&mut self, text: &str) -> bool {
        for c in text.chars() {
            if !Self::takes(c) {
                continue;
            }
            let mut encoded = [0u8; 4];
            let width = c.encode_utf8(&mut encoded).len();
            if self.len + width > MAX_SECRET_BYTES {
                encoded.zeroize();
                return false;
            }
            self.bytes[self.len..self.len + width].copy_from_slice(&encoded[..width]);
            encoded.zeroize();
            self.len += width;
            self.chars += 1;
        }
        true
    }

    /// Removes the last character and wipes its bytes.
    pub fn backspace(&mut self) {
        if self.len == 0 {
            return;
        }
        let mut start = self.len - 1;
        while start > 0 && (self.bytes[start] & 0b1100_0000) == 0b1000_0000 {
            start -= 1;
        }
        self.bytes[start..self.len].zeroize();
        self.len = start;
        self.chars -= 1;
    }

    pub fn clear(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
        self.chars = 0;
    }

    pub fn char_count(&self) -> usize {
        self.chars
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The secret as text. Valid UTF-8 by construction.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len])
            .expect("only whole UTF-8 characters are stored")
    }

    /// Constant-time-ish comparison of two buffers (length leak is acceptable here).
    pub fn matches(&self, other: &SecretBuffer) -> bool {
        self.len == other.len
            && self.bytes[..self.len]
                .iter()
                .zip(&other.bytes[..other.len])
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }

    /// Replaces the contents with `text` (e.g. a generated passphrase the user accepted).
    pub fn set(&mut self, text: &str) -> bool {
        self.clear();
        self.push_str(text)
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.clear();
    }
}
