//! The Secret Key lives in the OS credential store (Windows Credential Manager, macOS Keychain,
//! Secret Service on Linux) — never in the vault file or in plain files.

use anyhow::{Context, Result, anyhow};
use vault_core::SecretKey;
use zeroize::Zeroizing;

const SERVICE: &str = "vault-cli";

fn entry(vault_id: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, &format!("secret-key:{vault_id}"))
        .context("opening the OS credential store")
}

pub fn store(vault_id: &str, key: &SecretKey) -> Result<()> {
    entry(vault_id)?
        .set_password(&key.to_display_string())
        .context("saving the Secret Key in the OS credential store")
}

pub fn load(vault_id: &str) -> Result<Option<SecretKey>> {
    match entry(vault_id)?.get_password() {
        Ok(text) => {
            let text = Zeroizing::new(text);
            Ok(Some(SecretKey::parse(&text).map_err(|e| anyhow!(e))?))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(anyhow!(error).context("reading the OS credential store")),
    }
}

/// Returns whether a key was stored.
pub fn forget(vault_id: &str) -> Result<bool> {
    match entry(vault_id)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(error) => Err(anyhow!(error).context("deleting from the OS credential store")),
    }
}
