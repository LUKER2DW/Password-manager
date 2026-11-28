//! The security log: what was done with a vault on this device (unlocks and failed unlocks,
//! each use through the browser extension or autofill, exports, the emergency kit, devices,
//! the vault key renewed), so the person can notice use they didn't make (CRYPTO.md §3.11,
//! THREAT_MODEL.md §3, the security log).
//!
//! One file per vault, outside the vault file and never synced: `security-log-<vault id>.bin`
//! in the app's folder (the phone keeps it next to its vaults). Each entry is sealed on its own
//! to a public key whose private half is sealed with the vault key (the drop box's
//! construction, `vault_core::drop_box`, under a purpose of its own): the locked app can still
//! write (a failed unlock, a fill while locked), and only the open vault reads the log back, so
//! the sites and titles in it are as private as the vault's own. Entries hold no secret: what
//! happened, when, the site and the item's title, and a short detail (how it was unlocked,
//! what the extension was given, a device's name, an export's format).
//!
//! Bounded: at most [`MAX_ENTRIES`], the oldest dropped first. A file that doesn't open with
//! the vault (damaged, its key replaced) is set aside as `….unreadable` and a new log starts
//! with an entry that says so; clearing leaves one entry saying when it was cleared. Malware
//! running as the person can still delete the file or add entries of its own (the public key
//! is public): the log helps notice, it proves nothing.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use vault_core::{
    FormerKey, Vault,
    drop_box::{self, DropBoxKey, PUBLIC_KEY_LEN},
    storage,
};

/// The vault-key subkey purpose the log's private key is sealed under (CRYPTO.md §3.11).
pub const PURPOSE: &str = "security-log";
/// The most entries kept: the oldest go first.
pub const MAX_ENTRIES: usize = 500;
/// The longest site, title or detail kept, in characters.
pub const MAX_TEXT: usize = 200;
const VERSION: u8 = 1;

/// What happened. Stable numbers: they are stored, and the apps word them.
pub mod kind {
    /// The vault was unlocked (detail: how, see [`super::how`]).
    pub const UNLOCKED: u16 = 1;
    /// An unlock failed (detail: how it was tried).
    pub const UNLOCK_FAILED: u16 = 2;
    /// The browser extension was given something from an item (site, title; detail: what,
    /// see [`super::gave`]).
    pub const EXTENSION_GAVE: u16 = 3;
    /// The browser extension saved a login (site, title).
    pub const EXTENSION_SAVED: u16 = 4;
    /// The browser extension filled a login while the vault was locked (site, title).
    pub const LOCKED_FILL: u16 = 5;
    /// The vault was exported (detail: the format).
    pub const EXPORTED: u16 = 6;
    /// The emergency kit was shown on screen.
    pub const KIT_SHOWN: u16 = 7;
    /// The emergency kit was saved as a file.
    pub const KIT_SAVED: u16 = 8;
    /// The emergency kit was printed.
    pub const KIT_PRINTED: u16 = 9;
    /// A device joined the vault's sync (detail: its name).
    pub const DEVICE_JOINED: u16 = 10;
    /// A device was removed from the vault's sync (detail: its name).
    pub const DEVICE_REMOVED: u16 = 11;
    /// The vault key was renewed here (or a key renewed elsewhere taken: detail "taken").
    pub const KEY_RENEWED: u16 = 12;
    /// The log was cleared (the entries before it are gone).
    pub const CLEARED: u16 = 13;
    /// The log couldn't be read and started again (detail: why, see [`super::restarted`]).
    pub const RESTARTED: u16 = 14;
    /// The master password was changed.
    pub const PASSWORD_CHANGED: u16 = 15;
    /// Android's autofill was given a login (site or app, title; detail: what).
    pub const AUTOFILL_GAVE: u16 = 16;
    /// A passkey signed in for another app or a browser on the phone (site, title).
    pub const PASSKEY_USED: u16 = 17;
}

/// How an unlock was made or tried (an entry's detail).
pub mod how {
    pub const PASSWORD: &str = "password";
    /// Windows Hello or the phone's fingerprint.
    pub const DEVICE: &str = "device";
    /// The emergency kit's recovery parts.
    pub const RECOVERY: &str = "recovery";
}

/// What the extension or autofill was given (an entry's detail).
pub mod gave {
    pub const LOGIN: &str = "login";
    pub const PASSWORD: &str = "password";
    pub const USERNAME: &str = "username";
    pub const CODE: &str = "code";
    pub const PASSKEY: &str = "passkey";
    pub const CARD: &str = "card";
    pub const IDENTITY: &str = "identity";
}

/// Why the log started again (an entry's detail).
pub mod restarted {
    /// The file couldn't be read or opened with the vault.
    pub const UNREADABLE: &str = "unreadable";
    /// Its public key wasn't the one its sealed private key has: someone swapped it, and the
    /// entries sealed to it since couldn't be read here.
    pub const KEY_REPLACED: &str = "key";
}

/// One entry. Never a secret: no password, code, key or item contents but its title.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unix seconds.
    pub at: i64,
    /// One of [`kind`].
    pub kind: u16,
    pub site: String,
    pub title: String,
    pub detail: String,
}

impl Event {
    pub fn new(kind: u16, at: i64) -> Self {
        Self {
            at,
            kind,
            site: String::new(),
            title: String::new(),
            detail: String::new(),
        }
    }

    pub fn site(mut self, site: &str) -> Self {
        self.site = cut(site);
        self
    }

    pub fn title(mut self, title: &str) -> Self {
        self.title = cut(title);
        self
    }

    pub fn detail(mut self, detail: &str) -> Self {
        self.detail = cut(detail);
        self
    }
}

fn cut(text: &str) -> String {
    text.chars().take(MAX_TEXT).collect()
}

/// One line read back: an entry, or one that couldn't be opened (altered, or sealed to another
/// key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Event(Event),
    Unreadable,
}

#[derive(Serialize, Deserialize)]
struct LogFile {
    version: u8,
    public_key: [u8; PUBLIC_KEY_LEN],
    sealed_key: Vec<u8>,
    entries: Vec<Vec<u8>>,
}

/// A vault's security log on this device.
#[derive(Debug, Clone)]
pub struct SecurityLog {
    path: PathBuf,
    vault_id: String,
}

impl SecurityLog {
    /// The log of vault `vault_id` (its hex id) in folder `dir`.
    pub fn in_dir(dir: &Path, vault_id: &str) -> Self {
        Self {
            path: dir.join(format!("security-log-{vault_id}.bin")),
            vault_id: vault_id.to_owned(),
        }
    }

    /// The log of vault `vault_id` in the app's folder (`VAULT_HOME` in tests).
    pub fn for_vault(vault_id: &str) -> Result<Self> {
        Ok(Self::in_dir(&crate::paths::app_dir()?, vault_id))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<Option<LogFile>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).context("reading the security log"),
        };
        let file: LogFile =
            postcard::from_bytes(&bytes).map_err(|_| anyhow!("the security log is damaged"))?;
        if file.version != VERSION {
            return Err(anyhow!("the security log is of an unknown version"));
        }
        Ok(Some(file))
    }

    fn write(&self, file: &LogFile) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).context("making the app's folder")?;
        }
        let bytes = postcard::to_allocvec(file).context("writing the security log")?;
        storage::write_atomic(&self.path, &bytes).context("writing the security log")?;
        // The copy before this write isn't kept: what was cleared or dropped stays gone.
        let _ = std::fs::remove_file(storage::backup_path(&self.path));
        Ok(())
    }

    fn seal(&self, public_key: &[u8; PUBLIC_KEY_LEN], event: &Event) -> Result<Vec<u8>> {
        let plain = postcard::to_allocvec(event).context("writing an entry")?;
        drop_box::seal_entry(public_key, &self.vault_id, &plain).context("sealing an entry")
    }

    /// Adds `event` with the public key alone (the vault may be locked). `false` when there
    /// is no log yet: it starts at the first unlock ([`SecurityLog::open`]).
    pub fn record(&self, event: &Event) -> Result<bool> {
        let Some(mut file) = self.load()? else {
            return Ok(false);
        };
        let entry = self.seal(&file.public_key, event)?;
        file.entries.push(entry);
        let over = file.entries.len().saturating_sub(MAX_ENTRIES);
        file.entries.drain(..over);
        self.write(&file)?;
        Ok(true)
    }

    /// At an unlock: makes the log when there is none, and starts it again when it doesn't
    /// open with `vault` (the old file set aside, an entry saying why). Returns its key.
    pub fn open(&self, vault: &Vault, now: i64) -> Result<DropBoxKey> {
        let why = match self.load() {
            Ok(None) => None,
            Ok(Some(file)) => match DropBoxKey::open_for(vault, PURPOSE, &file.sealed_key) {
                Ok(key) if key.public_key() == file.public_key => return Ok(key),
                Ok(_) => Some(restarted::KEY_REPLACED),
                Err(_) => Some(restarted::UNREADABLE),
            },
            Err(_) => Some(restarted::UNREADABLE),
        };
        if why.is_some() {
            let aside = self.path.with_extension("bin.unreadable");
            std::fs::rename(&self.path, &aside).context("setting the security log aside")?;
        }
        let first = why.map(|why| Event::new(kind::RESTARTED, now).detail(why));
        self.start(vault, first.as_ref())
    }

    /// A new key pair and a log holding only `first`, if any.
    fn start(&self, vault: &Vault, first: Option<&Event>) -> Result<DropBoxKey> {
        let key = DropBoxKey::generate()?;
        let public_key = key.public_key();
        let mut file = LogFile {
            version: VERSION,
            public_key,
            sealed_key: key.seal_for(vault, PURPOSE)?,
            entries: Vec::new(),
        };
        if let Some(event) = first {
            file.entries.push(self.seal(&public_key, event)?);
        }
        self.write(&file)?;
        Ok(key)
    }

    /// Every entry, newest first (with the vault open). An empty list when there is no log.
    pub fn read(&self, vault: &Vault) -> Result<Vec<Line>> {
        let Some(file) = self.load()? else {
            return Ok(Vec::new());
        };
        let key = DropBoxKey::open_for(vault, PURPOSE, &file.sealed_key)
            .map_err(|_| anyhow!("the security log doesn't open with this vault"))?;
        Ok(file
            .entries
            .iter()
            .rev()
            .map(|sealed| {
                key.open_entry(vault, sealed)
                    .ok()
                    .and_then(|plain| postcard::from_bytes::<Event>(&plain).ok())
                    .map_or(Line::Unreadable, Line::Event)
            })
            .collect())
    }

    /// Empties the log: a new key pair, and one entry saying when it was cleared.
    pub fn clear(&self, vault: &Vault, now: i64) -> Result<()> {
        self.start(vault, Some(&Event::new(kind::CLEARED, now)))
            .map(drop)
    }

    /// After a renewal of the vault key: the log's private key sealed again under the new
    /// one (the key pair stays, so every entry still opens).
    pub fn reseal(&self, vault: &Vault, former: &FormerKey) -> Result<()> {
        let Some(mut file) = self.load()? else {
            return Ok(());
        };
        file.sealed_key = DropBoxKey::reseal_for(vault, former, PURPOSE, &file.sealed_key)?;
        self.write(&file)
    }

    /// The vault is gone from this device: its log goes too.
    pub fn remove(&self) {
        let _ = std::fs::remove_file(storage::backup_path(&self.path));
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The devices that joined or left the vault's sync between `before` and `after` (its
/// device list before and after a sync round merged other copies), as entries.
pub fn device_changes(
    before: &[vault_core::sync::SyncDevice],
    after: &[vault_core::sync::SyncDevice],
    now: i64,
) -> Vec<Event> {
    let joined = after
        .iter()
        .filter(|d| !before.iter().any(|b| b.id == d.id))
        .map(|d| Event::new(kind::DEVICE_JOINED, now).detail(&d.name));
    let left = before
        .iter()
        .filter(|b| !after.iter().any(|d| d.id == b.id))
        .map(|b| Event::new(kind::DEVICE_REMOVED, now).detail(&b.name));
    joined.chain(left).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{KdfParams, SecretKey};

    fn new_vault() -> Vault {
        vault_with(&SecretKey::generate().unwrap())
    }

    fn vault_with(secret_key: &SecretKey) -> Vault {
        Vault::create("pw", secret_key, None, KdfParams::minimum().unwrap()).unwrap()
    }

    fn events(lines: &[Line]) -> Vec<&Event> {
        lines
            .iter()
            .filter_map(|line| match line {
                Line::Event(event) => Some(event),
                Line::Unreadable => None,
            })
            .collect()
    }

    #[test]
    fn written_while_locked_read_only_with_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault();
        let log = SecurityLog::in_dir(dir.path(), &vault.id_hex());
        // No log before the first unlock: nothing is written.
        assert!(!log.record(&Event::new(kind::UNLOCK_FAILED, 1)).unwrap());
        assert!(!log.path().exists());

        log.open(&vault, 2).unwrap();
        assert!(log.read(&vault).unwrap().is_empty());
        let fill = Event::new(kind::EXTENSION_GAVE, 3)
            .site("https://example.com")
            .title("Example mail")
            .detail(gave::LOGIN);
        assert!(log.record(&Event::new(kind::UNLOCK_FAILED, 1)).unwrap());
        assert!(log.record(&fill).unwrap());
        // The site and title aren't in the file in the clear.
        let bytes = std::fs::read(log.path()).unwrap();
        assert!(!bytes.windows(7).any(|w| w == b"example"));
        assert!(!storage::backup_path(log.path()).exists());

        let lines = log.read(&vault).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], Line::Event(fill));
        // Another vault reads nothing of it.
        assert!(log.read(&new_vault()).is_err());
        // Opening again keeps it.
        log.open(&vault, 4).unwrap();
        assert_eq!(log.read(&vault).unwrap().len(), 2);
    }

    #[test]
    fn bounded_cut_and_cleared_with_a_line_saying_so() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault();
        let log = SecurityLog::in_dir(dir.path(), &vault.id_hex());
        log.open(&vault, 0).unwrap();
        for at in 0..(MAX_ENTRIES as i64 + 5) {
            log.record(&Event::new(kind::UNLOCKED, at).title(&"t".repeat(MAX_TEXT * 2)))
                .unwrap();
        }
        let lines = log.read(&vault).unwrap();
        assert_eq!(lines.len(), MAX_ENTRIES);
        let newest = events(&lines);
        assert_eq!(newest[0].at, MAX_ENTRIES as i64 + 4);
        assert_eq!(newest.last().unwrap().at, 5);
        assert_eq!(newest[0].title.chars().count(), MAX_TEXT);

        log.clear(&vault, 99).unwrap();
        let lines = log.read(&vault).unwrap();
        assert_eq!(lines, [Line::Event(Event::new(kind::CLEARED, 99))]);
    }

    #[test]
    fn a_damaged_or_swapped_log_starts_again_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault();
        let log = SecurityLog::in_dir(dir.path(), &vault.id_hex());
        log.open(&vault, 0).unwrap();
        log.record(&Event::new(kind::EXPORTED, 1)).unwrap();

        // An altered entry reads as such; the others still read.
        let mut file = log.load().unwrap().unwrap();
        *file.entries[0].last_mut().unwrap() ^= 1;
        log.write(&file).unwrap();
        log.record(&Event::new(kind::KIT_SHOWN, 2)).unwrap();
        let lines = log.read(&vault).unwrap();
        assert_eq!(lines[1], Line::Unreadable);
        assert!(matches!(&lines[0], Line::Event(e) if e.kind == kind::KIT_SHOWN));

        // Its public key swapped for someone else's: started again at the next unlock.
        let mut file = log.load().unwrap().unwrap();
        file.public_key = DropBoxKey::generate().unwrap().public_key();
        log.write(&file).unwrap();
        log.open(&vault, 3).unwrap();
        let lines = log.read(&vault).unwrap();
        assert_eq!(
            lines,
            [Line::Event(
                Event::new(kind::RESTARTED, 3).detail(restarted::KEY_REPLACED)
            )]
        );
        assert!(log.path().with_extension("bin.unreadable").exists());

        // Garbage: the same.
        std::fs::write(log.path(), b"not a log").unwrap();
        assert!(log.record(&Event::new(kind::UNLOCKED, 4)).is_err());
        log.open(&vault, 5).unwrap();
        assert_eq!(
            log.read(&vault).unwrap(),
            [Line::Event(
                Event::new(kind::RESTARTED, 5).detail(restarted::UNREADABLE)
            )]
        );
    }

    #[test]
    fn devices_joined_and_left_are_named() {
        use vault_core::sync::{DeviceId, SyncDevice};
        let device = |n: u8, name: &str| SyncDevice {
            id: DeviceId::from_bytes([n; 16]),
            name: name.to_owned(),
            signing_key: None,
            added_at: 0,
        };
        let before = [device(1, "Desktop"), device(2, "Phone")];
        let after = [device(1, "Desktop"), device(3, "Laptop")];
        assert_eq!(
            device_changes(&before, &after, 7),
            [
                Event::new(kind::DEVICE_JOINED, 7).detail("Laptop"),
                Event::new(kind::DEVICE_REMOVED, 7).detail("Phone"),
            ]
        );
        assert!(device_changes(&after, &after, 7).is_empty());
    }

    #[test]
    fn a_renewed_vault_key_still_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let secret_key = SecretKey::generate().unwrap();
        let mut vault = vault_with(&secret_key);
        let log = SecurityLog::in_dir(dir.path(), &vault.id_hex());
        log.open(&vault, 0).unwrap();
        log.record(&Event::new(kind::UNLOCKED, 1)).unwrap();
        let former = vault.renew_key("pw", &secret_key, None).unwrap().former;
        assert!(log.read(&vault).is_err());
        log.reseal(&vault, &former).unwrap();
        assert_eq!(log.read(&vault).unwrap().len(), 1);
    }
}
