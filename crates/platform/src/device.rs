//! Per-device state: rollback protection and local preferences (`<app dir>/state.json`).
//! Nothing secret is stored here.

use std::{collections::BTreeMap, fs};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use vault_core::{
    storage,
    sync::{DeviceId, SeenRevisions},
};

use crate::paths;

pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 5;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DeviceState {
    #[serde(default)]
    vaults: BTreeMap<String, VaultState>,
    #[serde(default)]
    pub settings: Settings,
    /// Vault files opened on this device, most recent first (paths only).
    #[serde(default)]
    recent_vaults: Vec<String>,
    /// This device's id for sync (hex), made the first time a vault is synced here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

/// How many vault files the device remembers.
pub const MAX_RECENT_VAULTS: usize = 8;

#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultState {
    highest_revision: u64,
    /// Where the vault's keyfile was last found (a location, never the key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keyfile_path: Option<String>,
    /// Sync: the folder chosen for this vault on this device (written by earlier versions;
    /// read as `sync_to` = a folder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync_folder: Option<String>,
    /// Sync: where this vault syncs on this device, if anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync_to: Option<SyncTo>,
    /// Sync: a backup place, synced too, through which the vault keeps syncing while the
    /// main one can't be reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync_backup: Option<SyncTo>,
    /// Sync: the vault revision whose copy was last put on the backup place.
    #[serde(default)]
    sync_published_backup: u64,
    /// Sync: the copies already seen from each other device (rollback and fork checks).
    #[serde(default, skip_serializing_if = "is_empty_seen")]
    sync_seen: SeenRevisions,
    /// Sync: when the last round finished (Unix seconds), and the revision last published.
    #[serde(default)]
    sync_at: i64,
    #[serde(default)]
    sync_published: u64,
}

fn is_empty_seen(seen: &SeenRevisions) -> bool {
    *seen == SeenRevisions::default()
}

/// Where a vault syncs. Nothing secret: the WebDAV password and the server key are in the
/// OS credential store (`secret_store`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SyncTo {
    /// A folder another program keeps the same everywhere.
    Folder { path: std::path::PathBuf },
    /// Our own `vault-server`, at this address.
    Server { url: String },
    /// A WebDAV collection (Nextcloud, a NAS), with this user name.
    Webdav { url: String, user: String },
}

impl SyncTo {
    /// What to show the person: the folder or the address.
    /// What to show for it: the folder, or the address without a certificate pin (a long hex
    /// string that means nothing to read and is kept for the connection only).
    pub fn describe(&self) -> String {
        match self {
            Self::Folder { path } => path.display().to_string(),
            Self::Server { url } | Self::Webdav { url, .. } => {
                let (address, pinned) = crate::sync::split_pin(url);
                if pinned.is_some() {
                    format!("{address} (pinned certificate)")
                } else {
                    address.to_owned()
                }
            }
        }
    }
}

/// What this device keeps about syncing one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPlace {
    pub to: SyncTo,
    /// A second place synced too (a backup server), if any.
    pub backup: Option<SyncTo>,
    pub seen: SeenRevisions,
    /// Unix seconds of the last finished round; 0 = never.
    pub at: i64,
    /// The vault revision whose copy was last put in the folder.
    pub published: u64,
    /// The same, for the backup place.
    pub published_backup: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Lock after this many minutes without interaction.
    pub auto_lock_minutes: u32,
    /// Seconds before a copied secret is cleared from the clipboard.
    pub clipboard_clear_seconds: u32,
    /// Desktop app appearance; dark is the default.
    pub dark_theme: bool,
    /// Download website icons (contacts each saved site once). Off by default for privacy.
    pub website_icons: bool,
    /// Let the browser extension ask this app for logins. Off by default.
    pub browser_extension: bool,
    /// Closing the window keeps the app running in the notification area. On by default.
    pub close_to_tray: bool,
    /// The browser extension can fill logins while the vault is locked, with Windows Hello
    /// for each one. On by default; it needs the item lock's Windows Hello.
    pub browser_locked_fill: bool,
    /// The generator's last options.
    pub generator: GeneratorPrefs,
    /// The app's language (`pt_BR`); empty follows the system.
    pub language: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            clipboard_clear_seconds: 20,
            dark_theme: true,
            website_icons: false,
            browser_extension: false,
            close_to_tray: true,
            browser_locked_fill: true,
            generator: GeneratorPrefs::default(),
            language: String::new(),
        }
    }
}

/// How the generator was last set up on this device. Not secret: no generated value is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneratorPrefs {
    /// 0 random characters, 1 words.
    pub mode: u8,
    pub length: u32,
    pub words: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub extended_ascii: bool,
    pub avoid_ambiguous: bool,
    pub also_use: String,
    pub never_use: String,
    /// 0 lower, 1 UPPER, 2 Title, 3 mixed.
    pub word_case: u8,
    pub add_digit: bool,
    pub separator: String,
    /// File name in the word list folder; empty = the bundled EFF list.
    pub wordlist: String,
}

impl Default for GeneratorPrefs {
    fn default() -> Self {
        Self {
            mode: 0,
            length: 24,
            words: 6,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            extended_ascii: false,
            avoid_ambiguous: false,
            also_use: String::new(),
            never_use: String::new(),
            word_case: 0,
            add_digit: false,
            separator: "-".into(),
            wordlist: String::new(),
        }
    }
}

/// What [`DeviceState::load_or_set_aside`] found in the state file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFile {
    /// Read as it was, or there was none yet.
    Read,
    /// It couldn't be read: moved to `state.json.unreadable` (kept), and a fresh state started.
    SetAside,
    /// It couldn't be read nor moved: a fresh state in memory only. Don't save it, or it
    /// would replace the file.
    Unreadable,
}

/// Outcome of comparing an opened vault with what this device has seen before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackStatus {
    Ok,
    /// The file is older than a revision this device already saw: it may have been replaced
    /// with an old copy.
    Older {
        revision: u64,
        highest_seen: u64,
    },
}

impl DeviceState {
    /// Vault files opened on this device, most recent first.
    pub fn recent_vaults(&self) -> Vec<std::path::PathBuf> {
        self.recent_vaults
            .iter()
            .map(std::path::PathBuf::from)
            .collect()
    }

    /// Puts path first in the recent list (moving it if it was already there).
    pub fn remember_vault(&mut self, path: &std::path::Path) {
        let path = path.to_string_lossy().into_owned();
        self.recent_vaults
            .retain(|p| !p.eq_ignore_ascii_case(&path));
        self.recent_vaults.insert(0, path);
        self.recent_vaults.truncate(MAX_RECENT_VAULTS);
    }

    /// Removes path from the recent list (the file itself is untouched).
    pub fn forget_vault(&mut self, path: &std::path::Path) {
        let path = path.to_string_lossy();
        self.recent_vaults
            .retain(|p| !p.eq_ignore_ascii_case(&path));
    }

    pub fn load() -> Result<Self> {
        let path = paths::app_dir()?.join("state.json");
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Like [`DeviceState::load`], for the apps: a state file that can't be read is never
    /// written over (it holds the highest revision seen of every vault) and never locks the
    /// person out. It is moved to `state.json.unreadable`, kept, and a fresh state starts;
    /// [`StateFile`] says which happened, so the app can tell the person that older copies
    /// of their vaults aren't caught until they are opened again here.
    pub fn load_or_set_aside() -> (Self, StateFile) {
        match paths::app_dir() {
            Ok(dir) => Self::load_or_set_aside_at(&dir.join("state.json")),
            Err(_) => (Self::default(), StateFile::Unreadable),
        }
    }

    fn load_or_set_aside_at(path: &std::path::Path) -> (Self, StateFile) {
        match fs::read(path) {
            Ok(bytes) => {
                if let Ok(state) = serde_json::from_slice(&bytes) {
                    return (state, StateFile::Read);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return (Self::default(), StateFile::Read);
            }
            Err(_) => {}
        }
        if fs::rename(path, path.with_file_name("state.json.unreadable")).is_ok() {
            (Self::default(), StateFile::SetAside)
        } else {
            // Still there (held by another program, say): left alone, and not saved over.
            (Self::default(), StateFile::Unreadable)
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = paths::app_dir()?.join("state.json");
        fs::create_dir_all(path.parent().expect("state path has a parent"))?;
        storage::write_atomic(&path, &serde_json::to_vec_pretty(self)?).map_err(|e| anyhow!(e))
    }

    pub fn check_rollback(&self, vault_id: &str, revision: u64) -> RollbackStatus {
        let highest_seen = self.vaults.get(vault_id).map_or(0, |v| v.highest_revision);
        if revision < highest_seen {
            RollbackStatus::Older {
                revision,
                highest_seen,
            }
        } else {
            RollbackStatus::Ok
        }
    }

    pub fn record_revision(&mut self, vault_id: &str, revision: u64) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        entry.highest_revision = entry.highest_revision.max(revision);
    }

    /// Where this device last found the vault's keyfile.
    pub fn keyfile_path(&self, vault_id: &str) -> Option<std::path::PathBuf> {
        self.vaults
            .get(vault_id)?
            .keyfile_path
            .as_deref()
            .map(std::path::PathBuf::from)
    }

    pub fn set_keyfile_path(&mut self, vault_id: &str, path: Option<&std::path::Path>) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        entry.keyfile_path = path.map(|p| p.to_string_lossy().into_owned());
    }

    /// Whether this device already has a sync id.
    pub fn has_device_id(&self) -> bool {
        self.device_id
            .as_deref()
            .and_then(DeviceId::from_hex)
            .is_some()
    }

    /// This device's sync id, made (and kept, once saved) the first time it is asked for.
    pub fn device_id(&mut self) -> vault_core::Result<DeviceId> {
        if let Some(id) = self.device_id.as_deref().and_then(DeviceId::from_hex) {
            return Ok(id);
        }
        let id = DeviceId::generate()?;
        self.device_id = Some(id.to_hex());
        Ok(id)
    }

    /// Where and how vault `vault_id` syncs on this device; `None` when it doesn't.
    pub fn sync_place(&self, vault_id: &str) -> Option<SyncPlace> {
        let state = self.vaults.get(vault_id)?;
        let to = state.sync_to.clone().or_else(|| {
            state.sync_folder.as_deref().map(|path| SyncTo::Folder {
                path: std::path::PathBuf::from(path),
            })
        })?;
        Some(SyncPlace {
            to,
            backup: state.sync_backup.clone(),
            seen: state.sync_seen.clone(),
            at: state.sync_at,
            published: state.sync_published,
            published_backup: state.sync_published_backup,
        })
    }

    /// Starts syncing vault `vault_id` through `folder`, or (with `None`) stops.
    pub fn set_sync_folder(&mut self, vault_id: &str, folder: Option<&std::path::Path>) {
        self.set_sync_to(
            vault_id,
            folder.map(|path| SyncTo::Folder {
                path: path.to_owned(),
            }),
        );
    }

    /// Starts syncing vault `vault_id` through `to`, or (with `None`) stops. Stopping forgets
    /// what was seen: syncing again later starts afresh. Moving to another place keeps it, so
    /// an older copy put back is still refused there.
    pub fn set_sync_to(&mut self, vault_id: &str, to: Option<SyncTo>) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        entry.sync_folder = None;
        let stopped = to.is_none();
        if entry.sync_to != to {
            entry.sync_published = 0;
        }
        entry.sync_to = to;
        if stopped {
            entry.sync_seen = SeenRevisions::default();
            entry.sync_at = 0;
            entry.sync_published = 0;
            entry.sync_backup = None;
            entry.sync_published_backup = 0;
        }
    }

    /// Adds (or with `None` removes) a backup place for vault `vault_id`: synced every round
    /// too, so the vault keeps syncing while the main place can't be reached.
    pub fn set_sync_backup(&mut self, vault_id: &str, backup: Option<SyncTo>) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        if entry.sync_backup != backup {
            entry.sync_published_backup = 0;
        }
        entry.sync_backup = backup;
    }

    /// Records that `revision`'s copy is on the place in `role`.
    pub fn record_published(&mut self, vault_id: &str, role: crate::sync::Role, revision: u64) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        let published = match role {
            crate::sync::Role::Main => &mut entry.sync_published,
            crate::sync::Role::Backup => &mut entry.sync_published_backup,
        };
        *published = (*published).max(revision);
    }

    /// Records a finished round.
    pub fn record_sync(&mut self, vault_id: &str, seen: &SeenRevisions, at: i64, published: u64) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        entry.sync_seen = seen.clone();
        entry.sync_at = at;
        entry.sync_published = entry.sync_published.max(published);
    }
}

/// Loads, records and saves in one step.
pub fn record_revision(vault_id: &str, revision: u64) -> Result<()> {
    let mut state = DeviceState::load()?;
    state.record_revision(vault_id, revision);
    state.save()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreadable_state_file_is_set_aside_not_written_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert_eq!(DeviceState::load_or_set_aside_at(&path).1, StateFile::Read);

        let mut state = DeviceState::default();
        state.record_revision("v", 7);
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        let (read, file) = DeviceState::load_or_set_aside_at(&path);
        assert_eq!(file, StateFile::Read);
        assert_eq!(
            read.check_rollback("v", 6),
            RollbackStatus::Older {
                revision: 6,
                highest_seen: 7
            }
        );

        fs::write(&path, b"{ damaged").unwrap();
        let (fresh, file) = DeviceState::load_or_set_aside_at(&path);
        assert_eq!(file, StateFile::SetAside);
        assert_eq!(fresh.check_rollback("v", 0), RollbackStatus::Ok);
        assert!(!path.exists());
        assert_eq!(
            fs::read(dir.path().join("state.json.unreadable")).unwrap(),
            b"{ damaged"
        );
    }

    #[test]
    fn rollback_detection() {
        let mut state = DeviceState::default();
        assert_eq!(state.check_rollback("v", 1), RollbackStatus::Ok);
        state.record_revision("v", 5);
        state.record_revision("v", 3); // never goes down
        assert_eq!(state.check_rollback("v", 5), RollbackStatus::Ok);
        assert_eq!(
            state.check_rollback("v", 4),
            RollbackStatus::Older {
                revision: 4,
                highest_seen: 5
            }
        );
        assert_eq!(state.check_rollback("other", 0), RollbackStatus::Ok);
    }

    #[test]
    fn recent_vaults_most_recent_first() {
        let mut state = DeviceState::default();
        for i in 0..10 {
            state.remember_vault(std::path::Path::new(&format!("C:/v{i}.vault")));
        }
        state.remember_vault(std::path::Path::new("C:/V5.vault")); // same file, other case
        let recent = state.recent_vaults();
        assert_eq!(recent.len(), MAX_RECENT_VAULTS);
        assert_eq!(recent[0], std::path::PathBuf::from("C:/V5.vault"));
        assert_eq!(
            recent
                .iter()
                .filter(|p| p.to_string_lossy().to_lowercase() == "c:/v5.vault")
                .count(),
            1
        );
        state.forget_vault(std::path::Path::new("c:/v5.vault"));
        assert!(
            !state
                .recent_vaults()
                .iter()
                .any(|p| p.ends_with("V5.vault"))
        );
    }

    #[test]
    fn old_state_files_still_load() {
        let json = r#"{"vaults": {"abc": {"highest_revision": 7}}}"#;
        let state: DeviceState = serde_json::from_str(json).unwrap();
        assert_eq!(state.settings, Settings::default());
        // A settings block written before `dark_theme` existed still loads, with the default.
        let partial = r#"{"settings": {"auto_lock_minutes": 9, "clipboard_clear_seconds": 30}}"#;
        let older: DeviceState = serde_json::from_str(partial).unwrap();
        assert_eq!(older.settings.auto_lock_minutes, 9);
        assert!(older.settings.dark_theme);
        assert_eq!(
            state.check_rollback("abc", 6),
            RollbackStatus::Older {
                revision: 6,
                highest_seen: 7
            }
        );
    }
}
