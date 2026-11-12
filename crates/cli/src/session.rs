//! Locating, unlocking and saving the vault; per-device state.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use vault_core::{Error as CoreError, SecretKey, Unlock, Vault, storage};
use zeroize::Zeroizing;

use crate::prompt::Prompter;

const KEYRING_SERVICE: &str = "vault-cli";
const APP_DIR: &str = "vault";

/// Default vault location: `<local data dir>/vault/default.vault`.
pub fn default_vault_path() -> Result<PathBuf> {
    Ok(app_dir()?.join("default.vault"))
}

/// App data directory. `VAULT_HOME` overrides it (portable installs, tests).
fn app_dir() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("VAULT_HOME") {
        return Ok(PathBuf::from(home));
    }
    let base = dirs::data_local_dir().context("cannot determine the local data directory")?;
    Ok(base.join(APP_DIR))
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

// ---------------------------------------------------------------------------------------------
// Secret Key storage in the OS credential store (Windows Credential Manager, macOS Keychain,
// Secret Service on Linux). The Secret Key never touches the vault file or plain files.
// ---------------------------------------------------------------------------------------------

fn keyring_entry(vault_id: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, &format!("secret-key:{vault_id}"))
        .context("opening the OS credential store")
}

pub fn store_secret_key(vault_id: &str, key: &SecretKey) -> Result<()> {
    keyring_entry(vault_id)?
        .set_password(&key.to_display_string())
        .context("saving the Secret Key in the OS credential store")
}

pub fn load_secret_key(vault_id: &str) -> Result<Option<SecretKey>> {
    match keyring_entry(vault_id)?.get_password() {
        Ok(text) => {
            let text = Zeroizing::new(text);
            Ok(Some(SecretKey::parse(&text).map_err(explain)?))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(anyhow!(error).context("reading the OS credential store")),
    }
}

pub fn forget_secret_key(vault_id: &str) -> Result<bool> {
    match keyring_entry(vault_id)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(error) => Err(anyhow!(error).context("deleting from the OS credential store")),
    }
}

// ---------------------------------------------------------------------------------------------
// Rollback protection: remember the highest revision seen for each vault on this device.
// ---------------------------------------------------------------------------------------------

#[derive(Default, Serialize, Deserialize)]
struct DeviceState {
    #[serde(default)]
    vaults: BTreeMap<String, VaultState>,
}

#[derive(Default, Serialize, Deserialize)]
struct VaultState {
    highest_revision: u64,
}

fn state_path() -> Result<PathBuf> {
    Ok(app_dir()?.join("state.json"))
}

fn load_state() -> Result<DeviceState> {
    let path = state_path()?;
    match fs::read(&path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DeviceState::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn record_revision(vault_id: &str, revision: u64) -> Result<()> {
    let mut state = load_state()?;
    let entry = state.vaults.entry(vault_id.to_owned()).or_default();
    entry.highest_revision = entry.highest_revision.max(revision);
    let path = state_path()?;
    fs::create_dir_all(path.parent().expect("state path has a parent"))?;
    storage::write_atomic(&path, &serde_json::to_vec_pretty(&state)?).map_err(explain)
}

// ---------------------------------------------------------------------------------------------

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

        let (secret_key, typed) = match load_secret_key(&info.id_hex)? {
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
            store_secret_key(&info.id_hex, &secret_key)?;
            eprintln!("Secret Key saved in this device's credential store.");
        }
        check_rollback(&info.id_hex, vault.revision(), allow_rollback)?;
        record_revision(&info.id_hex, vault.revision())?;

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
        record_revision(&self.vault.id_hex(), self.vault.revision())
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

fn check_rollback(vault_id: &str, revision: u64, allow_rollback: bool) -> Result<()> {
    let highest = load_state()?
        .vaults
        .get(vault_id)
        .map_or(0, |state| state.highest_revision);
    if revision < highest {
        let message = format!(
            "this vault file is OLDER than one this device has already seen \
             (revision {revision} < {highest}). Someone may have replaced it with an old copy."
        );
        if !allow_rollback {
            bail!("{message}\nIf you restored a backup on purpose, re-run with --allow-rollback.");
        }
        eprintln!("warning: {message}");
    }
    Ok(())
}

pub fn record_new_vault(vault: &Vault) -> Result<()> {
    record_revision(&vault.id_hex(), vault.revision())
}
