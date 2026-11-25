//! A vault's fingerprint unlock on this phone (`unlock-<vault id>.json`, next to the vault): the
//! vault key sealed under a device secret (`Vault::seal_for_device`, CRYPTO.md §3.1), that
//! secret sealed by the phone's secure hardware (opened only right after a fingerprint), and
//! when the master password was last typed. Nothing in it opens the vault without the
//! hardware's key. Read by the controller and by autofill (`crate::autofill`).
//!
//! When the master password was last typed is the phone's settings' to know too
//! (`Prefs::password_typed_at`): turning fingerprint unlock off and on again starts from that
//! time, never from the moment it was turned on.

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
    /// When the master password was last typed (checked against the vault) on this phone, in
    /// Unix seconds.
    pub(crate) password_at: i64,
}

impl BioUnlock {
    /// The master password was typed within the last 14 days.
    pub(crate) fn fresh(&self, now: i64) -> bool {
        password_fresh(self.password_at, now)
    }
}

/// Whether a master password typed at `typed_at` still lets the fingerprint open the vault at
/// `now`. A time after `now` (the clock was moved back since, or the file was changed) proves
/// nothing and counts as too long ago: the master password is asked.
pub(crate) fn password_fresh(typed_at: i64, now: i64) -> bool {
    typed_at <= now && now.saturating_sub(typed_at) < PASSWORD_EVERY
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_master_password_is_asked_every_14_days_and_for_a_time_to_come() {
        let now = 1_800_000_000;
        assert!(password_fresh(now, now));
        assert!(password_fresh(now - PASSWORD_EVERY + 1, now));
        assert!(!password_fresh(now - PASSWORD_EVERY, now), "14 days ago");
        assert!(!password_fresh(0, now));
        // The clock moved back since, or a time written ahead: not fresh.
        assert!(!password_fresh(now + 1, now));
        assert!(!password_fresh(now + PASSWORD_EVERY, now));
        assert!(!password_fresh(i64::MAX, now));
        assert!(!password_fresh(i64::MIN, now), "no overflow either way");
    }
}
