//! A vault's fingerprint unlock on this phone (`unlock-<vault id>.json`, next to the vault): the
//! vault key sealed under a device secret (`Vault::seal_for_device`, CRYPTO.md §3.1), that
//! secret sealed by the phone's secure hardware (opened only right after a fingerprint), and
//! when the master password was last typed. Nothing in it opens the vault without the
//! hardware's key. Read by the controller and by autofill (`crate::autofill`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::platform::files;

/// Fingerprint unlock asks for the master password again after this long, as Windows Hello
/// does on the desktop.
pub(crate) const PASSWORD_EVERY: i64 = 14 * 86_400;

#[derive(Serialize, Deserialize)]
pub(crate) struct BioUnlock {
    pub(crate) sealed_key: Vec<u8>,
    pub(crate) hardware: Vec<u8>,
    pub(crate) password_at: i64,
}

impl BioUnlock {
    /// The master password was typed within the last 14 days.
    pub(crate) fn fresh(&self, now: i64) -> bool {
        now - self.password_at < PASSWORD_EVERY
    }
}

pub(crate) fn path(folder: &Path, vault_id: &str) -> PathBuf {
    folder.join(format!("unlock-{vault_id}.json"))
}

pub(crate) fn read(folder: &Path, vault_id: &str) -> Option<BioUnlock> {
    files::read_any(&path(folder, vault_id))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

pub(crate) fn write(folder: &Path, vault_id: &str, bio: &BioUnlock) -> Result<(), String> {
    let bytes = serde_json::to_vec(bio).map_err(|e| e.to_string())?;
    files::write_atomic(&path(folder, vault_id), &bytes).map_err(|e| e.to_string())
}
