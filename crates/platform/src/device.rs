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
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultState {
    highest_revision: u64,
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
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            clipboard_clear_seconds: 20,
            dark_theme: true,
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
