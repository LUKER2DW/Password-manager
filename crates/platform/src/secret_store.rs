//! The Secret Key lives in the OS credential store (Windows Credential Manager, macOS Keychain,
//! Secret Service on Linux; on Android, SharedPreferences encrypted with a key held in the
//! Android Keystore) — never in the vault file or in plain files.

use anyhow::{Context, Result, anyhow};
#[cfg(not(target_os = "android"))]
use keyring::{Entry, Error as StoreError};
#[cfg(target_os = "android")]
use keyring_core::{Entry, Error as StoreError};
use vault_core::SecretKey;
use zeroize::Zeroizing;

const SERVICE: &str = "vault-cli";

/// On Android, the Keystore-backed store becomes the default once, before the first entry.
#[cfg(target_os = "android")]
fn ready() -> Result<()> {
    static STORE: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    STORE
        .get_or_init(|| {
            let store = android_native_keyring_store::Store::new().map_err(|e| e.to_string())?;
            keyring_core::set_default_store(store);
            Ok(())
        })
        .clone()
        .map_err(|e| anyhow!(e).context("opening the Android Keystore"))
}

#[cfg(not(target_os = "android"))]
fn ready() -> Result<()> {
    Ok(())
}

fn entry(vault_id: &str) -> Result<Entry> {
    text_entry(&format!("secret-key:{vault_id}"))
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
        Err(StoreError::NoEntry) => Ok(None),
        Err(error) => Err(anyhow!(error).context("reading the OS credential store")),
    }
}

/// Returns whether a key was stored.
pub fn forget(vault_id: &str) -> Result<bool> {
    match entry(vault_id)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(StoreError::NoEntry) => Ok(false),
        Err(error) => Err(anyhow!(error).context("deleting from the OS credential store")),
    }
}

fn text_entry(account: &str) -> Result<Entry> {
    ready()?;
    Entry::new(SERVICE, account).context("opening the OS credential store")
}

fn store_text(account: &str, text: &str) -> Result<()> {
    text_entry(account)?
        .set_password(text)
        .context("saving in the OS credential store")
}

fn load_text(account: &str) -> Result<Option<Zeroizing<String>>> {
    match text_entry(account)?.get_password() {
        Ok(text) => Ok(Some(Zeroizing::new(text))),
        Err(StoreError::NoEntry) => Ok(None),
        Err(error) => Err(anyhow!(error).context("reading the OS credential store")),
    }
}

fn forget_text(account: &str) -> Result<bool> {
    match text_entry(account)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(StoreError::NoEntry) => Ok(false),
        Err(error) => Err(anyhow!(error).context("deleting from the OS credential store")),
    }
}

/// The key device `device` (hex) signs its requests to a sync server with (its secret
/// seed), per vault. Never in the vault file or in device state.
pub fn store_sync_key(vault_id: &str, device: &str, seed: &[u8; 32]) -> Result<()> {
    let text = Zeroizing::new(vault_sync_wire::hex(seed));
    store_text(&format!("sync-key:{vault_id}:{device}"), &text)
}

pub fn load_sync_key(vault_id: &str, device: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let Some(text) = load_text(&format!("sync-key:{vault_id}:{device}"))? else {
        return Ok(None);
    };
    let seed = vault_sync_wire::unhex::<32>(&text)
        .ok_or_else(|| anyhow!("the sync key in the OS credential store is damaged"))?;
    Ok(Some(Zeroizing::new(seed)))
}

pub fn forget_sync_key(vault_id: &str, device: &str) -> Result<bool> {
    forget_text(&format!("sync-key:{vault_id}:{device}"))
}

/// The WebDAV password for a vault's sync.
pub fn store_webdav_password(vault_id: &str, password: &str) -> Result<()> {
    store_text(&format!("webdav:{vault_id}"), password)
}

pub fn load_webdav_password(vault_id: &str) -> Result<Option<Zeroizing<String>>> {
    load_text(&format!("webdav:{vault_id}"))
}

pub fn forget_webdav_password(vault_id: &str) -> Result<bool> {
    forget_text(&format!("webdav:{vault_id}"))
}
