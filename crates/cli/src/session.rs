//! Locating, unlocking and saving the vault. Device integration lives in `vault-platform`.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use vault_core::{Error as CoreError, SecretKey, Unlock, Vault, storage};
use vault_platform::{DeviceState, RollbackStatus, device, paths, secret_store};

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
}

impl Session {
    /// Unlocks with master password + Secret Key (from the OS store, or typed from the kit).
    pub fn unlock(path: &Path, prompter: &mut Prompter, allow_rollback: bool) -> Result<Self> {
        let bytes = read_vault_file(path)?;
        let info = Vault::inspect(&bytes).map_err(explain)?;

        let (secret_key, typed) = match secret_store::load(&info.id_hex)? {
            Some(key) => (key, false),
            None => {
                eprintln!("This device does not know the Secret Key for this vault yet.");
                let text = prompter.secret("Secret Key (from your emergency kit)")?;
                (SecretKey::parse(&text).map_err(explain)?, true)
            }
        };
        let password = prompter.secret("Master password")?;
        let vault = Vault::open(
            &bytes,
            Unlock::Password {
                password: &password,
                secret_key: &secret_key,
            },
        )
        .map_err(explain)?;

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
        })
    }

    /// Encrypts and writes the vault (atomic write + `.bak`).
    pub fn save(&mut self) -> Result<()> {
        let bytes = self.vault.to_bytes().map_err(explain)?;
        storage::write_atomic(&self.path, &bytes).map_err(explain)?;
        device::record_revision(&self.vault.id_hex(), self.vault.revision())
    }
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
