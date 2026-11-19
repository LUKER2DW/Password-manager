//! Locating, unlocking and saving the vault. Device integration lives in `vault-platform`.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use vault_core::{Error as CoreError, Keyfile, SecretKey, Unlock, Vault, storage};
use vault_platform::{DeviceState, RollbackStatus, device, keyfile, paths, secret_store};
use zeroize::Zeroizing;

use crate::prompt::Prompter;

pub fn default_vault_path() -> Result<PathBuf> {
    paths::default_vault_path()
}

/// Turns core errors into messages a person can act on.
pub fn explain(error: CoreError) -> anyhow::Error {
    match error {
        CoreError::DecryptionFailed => {
            anyhow!("wrong master password or Secret Key, or the vault file was modified")
        }
        CoreError::KeyChecksumMismatch => anyhow!("that key has a typo (checksum mismatch)"),
        CoreError::InvalidKeyFormat => anyhow!("that does not look like a valid key"),
        CoreError::KeyfileRequired => anyhow!(
            "this vault also needs its keyfile: pass --vault-keyfile <PATH> (or set VAULT_KEYFILE)"
        ),
        other => anyhow!(other),
    }
}

pub fn store_secret_key(vault_id: &str, key: &SecretKey) -> Result<()> {
    secret_store::store(vault_id, key)
}

pub fn load_secret_key(vault_id: &str) -> Result<Option<SecretKey>> {
    secret_store::load(vault_id)
}

pub fn forget_secret_key(vault_id: &str) -> Result<bool> {
    secret_store::forget(vault_id)
}

pub fn record_new_vault(vault: &Vault) -> Result<()> {
    device::record_revision(&vault.id_hex(), vault.revision())
}

/// An unlocked vault bound to its file.
pub struct Session {
    pub path: PathBuf,
    pub vault: Vault,
    pub secret_key: SecretKey,
    /// The keyfile the vault was opened with, when it uses one.
    pub keyfile: Option<Keyfile>,
    /// The master password just typed, kept (wiped on drop) for commands that rewrite the
    /// password lock without changing the password.
    pub password: Zeroizing<String>,
    /// The file as it was read or last written, to refuse a save over someone else's changes.
    file_hash: [u8; 32],
}

impl Session {
    /// Unlocks with master password + Secret Key (from the OS store, or typed from the kit),
    /// plus the keyfile when the vault uses one (`keyfile_path`, else where it was last found).
    pub fn unlock(
        path: &Path,
        prompter: &mut Prompter,
        allow_rollback: bool,
        keyfile_path: Option<&Path>,
    ) -> Result<Self> {
        let bytes = read_vault_file(path)?;
        let info = Vault::inspect(&bytes).map_err(explain)?;
        let keyfile = if info.needs_keyfile {
            let path = keyfile_path
                .map(Path::to_owned)
                .or_else(|| keyfile::remembered_path(&info.id_hex))
                .ok_or_else(|| explain(CoreError::KeyfileRequired))?;
            let key = keyfile::read(&path)?;
            Some((key, path))
        } else {
            None
        };

        let (secret_key, typed) = match secret_store::load(&info.id_hex)? {
            Some(key) => (key, false),
            None => {
                eprintln!("This device does not know the Secret Key for this vault yet.");
                let text = prompter.secret("Secret Key (from your emergency kit)")?;
                (SecretKey::parse(&text).map_err(explain)?, true)
            }
        };
        let password = prompter.secret("Master password")?;
        let unlock = match &keyfile {
            Some((keyfile, _)) => Unlock::PasswordAndKeyfile {
                password: &password,
                secret_key: &secret_key,
                keyfile,
            },
            None => Unlock::Password {
                password: &password,
                secret_key: &secret_key,
            },
        };
        let vault = Vault::open(&bytes, unlock).map_err(explain)?;
        if let Some((_, path)) = &keyfile {
            // It worked: next time the path needn't be typed.
            let _ = keyfile::remember_path(&info.id_hex, Some(path));
        }

        if typed {
            secret_store::store(&info.id_hex, &secret_key)?;
            eprintln!("Secret Key saved in this device's credential store.");
        }

        let mut state = DeviceState::load()?;
        if let RollbackStatus::Older {
            revision,
            highest_seen,
        } = state.check_rollback(&info.id_hex, vault.revision())
        {
            let message = format!(
                "this vault file is OLDER than one this device has already seen \
                 (revision {revision} < {highest_seen}). Someone may have replaced it with an old copy."
            );
            if !allow_rollback {
                bail!(
                    "{message}\nIf you restored a backup on purpose, re-run with --allow-rollback."
                );
            }
            eprintln!("warning: {message}");
        }
        state.record_revision(&info.id_hex, vault.revision());
        state.save()?;

        Ok(Self {
            path: path.to_owned(),
            vault,
            secret_key,
            keyfile: keyfile.map(|(key, _)| key),
            password,
            file_hash: storage::fingerprint(&bytes),
        })
    }

    /// Opens the secrets the item lock encrypts: asks for its PIN or password, three tries.
    /// Does nothing when the vault has no such lock or the secrets are open already.
    pub fn open_secrets(&mut self, prompter: &mut Prompter) -> Result<()> {
        let guard = self.vault.item_guard();
        if !guard.encrypts() || self.vault.secrets_open() {
            return Ok(());
        }
        let label = if guard.check == vault_core::GuardCheck::Pin {
            "Item PIN"
        } else {
            "Item password"
        };
        for _ in 0..3 {
            let typed = prompter.secret(label)?;
            if self.vault.unlock_secrets(&typed).map_err(explain)? {
                // Items added while it was closed are sealed under it now.
                if self.vault.seal_pending().map_err(explain)? > 0 {
                    self.save()?;
                }
                return Ok(());
            }
            eprintln!("That isn't it.");
        }
        anyhow::bail!("wrong three times: the item's secrets stay locked")
    }

    /// One item, asking for the item PIN or password first when its secrets are locked.
    pub fn open_item(
        &mut self,
        id: &vault_core::ItemId,
        prompter: &mut Prompter,
    ) -> Result<vault_core::ItemData> {
        let item = self.vault.get_item(id).map_err(explain)?;
        // An item added while the item lock was closed is not sealed under it yet, so it reads
        // in full: the check is asked for all the same (and seals it).
        let waits = self.vault.item_guard().encrypts()
            && self.vault.guards(&item)
            && !self.vault.secrets_open();
        if !item.is_locked() && !waits {
            return Ok(item);
        }
        self.open_secrets(prompter)?;
        self.vault.get_item(id).map_err(explain)
    }

    /// Encrypts and writes the vault, unless the file changed since this session read it.
    pub fn save(&mut self) -> Result<()> {
        ensure_unchanged(&self.path, &self.file_hash)?;
        let bytes = self.vault.to_bytes().map_err(explain)?;
        storage::write_atomic(&self.path, &bytes).map_err(explain)?;
        self.file_hash = storage::fingerprint(&bytes);
        device::record_revision(&self.vault.id_hex(), self.vault.revision())
    }
}

/// Refuses to go on when the vault file no longer holds what was read: someone else (the
/// app, another device's sync, another command) wrote it in the meantime, and saving now
/// would throw their changes away (AGENTS.md §4.1, rule 7).
pub fn ensure_unchanged(path: &Path, read: &[u8; 32]) -> Result<()> {
    let now = storage::read(path).map_err(explain)?;
    if storage::fingerprint(&now) != *read {
        bail!(
            "{} changed while this command was running (another app or device saved it). \
             Nothing was written: run the command again.",
            path.display()
        );
    }
    Ok(())
}

pub fn read_vault_file(path: &Path) -> Result<Vec<u8>> {
    if !path.exists() {
        bail!(
            "no vault at {} (create one with `vault init`, or pass --vault)",
            path.display()
        );
    }
    storage::read(path).map_err(explain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_changed_by_someone_else_is_not_written_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        storage::write_atomic(&path, b"as read").unwrap();
        let read = storage::fingerprint(b"as read");
        ensure_unchanged(&path, &read).unwrap();

        // The app (or a sync tool) saves in the meantime.
        storage::write_atomic(&path, b"saved elsewhere").unwrap();
        let refused = ensure_unchanged(&path, &read).unwrap_err().to_string();
        assert!(
            refused.contains("changed while this command was running"),
            "{refused}"
        );
    }
}
