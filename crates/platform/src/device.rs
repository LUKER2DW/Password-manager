//! Per-device state: rollback protection and local preferences (`<app dir>/state.json`).
//! Nothing secret is stored here.

use std::{collections::BTreeMap, fs};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use vault_core::storage;

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
}

/// How many vault files the device remembers.
pub const MAX_RECENT_VAULTS: usize = 8;

#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultState {
    highest_revision: u64,
    /// Where the vault's keyfile was last found (a location, never the key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keyfile_path: Option<String>,
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
    /// The generator's last options.
    pub generator: GeneratorPrefs,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            clipboard_clear_seconds: 20,
            dark_theme: true,
            website_icons: false,
            generator: GeneratorPrefs::default(),
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
