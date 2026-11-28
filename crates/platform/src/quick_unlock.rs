//! Quick unlock: open the vault after the OS verifies the user (Windows Hello today) instead of
//! typing the master password.
//!
//! How it works (spec: CRYPTO.md §3.1):
//! - The OS creates a key pair for this vault inside the security chip (TPM). The private key
//!   never leaves it and is only usable after Windows Hello verifies the user (face, fingerprint
//!   or Windows PIN).
//! - The chip signs a fixed, vault-specific challenge. The signature (RSA PKCS#1 v1.5, so the same
//!   every time) is the *device secret*; `vault-core` turns it into a key that wraps the vault key.
//! - Only the wrapped vault key is stored on disk (`quick-unlock-<vault id>.bin`). Copied to another
//!   computer it is useless; on this computer it needs the user to pass Windows Hello.
//! - It is bound to the current master password: changing the password revokes it.
//! - Every [`PASSWORD_INTERVAL_DAYS`] days (the person may choose 1 to
//!   [`MAX_PASSWORD_INTERVAL_DAYS`]) the master password is asked once, so it isn't forgotten.
//!   That date is sealed with the vault key, so it cannot be pushed forward.

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use vault_core::{Vault, storage};
use zeroize::Zeroizing;

use crate::paths;

/// How often the master password is asked even when quick unlock is on, unless the person
/// chose another interval.
pub const PASSWORD_INTERVAL_DAYS: u64 = 14;

/// The longest interval that may be chosen: a month.
pub const MAX_PASSWORD_INTERVAL_DAYS: u64 = 30;

const LAST_PASSWORD_PURPOSE: &str = "last-password-unlock";

/// Why quick unlock did not produce a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuickUnlockError {
    /// The device has no Windows Hello (or equivalent) set up.
    Unavailable,
    /// The person closed the prompt or chose to use a password.
    Cancelled,
    /// This vault has no device key on this computer (anymore).
    NotEnrolled,
    /// Anything else, with the OS's description.
    Failed(String),
}

impl std::fmt::Display for QuickUnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => f.write_str("not available on this device"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::NotEnrolled => f.write_str("not set up for this vault"),
            Self::Failed(detail) => f.write_str(detail),
        }
    }
}

/// Verifies the person at the device and then produces a stable secret for one vault.
pub trait DeviceVerifier: Send + Sync + std::fmt::Debug {
    /// Name shown to the user ("Windows Hello").
    fn name(&self) -> &'static str;
    /// Whether the device can verify the user right now (e.g. Windows Hello is set up).
    fn is_available(&self) -> bool;
    /// Creates (or replaces) this vault's device key after verifying the user; returns the secret.
    fn enroll(&self, vault_id: &str) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError>;
    /// Verifies the user and returns the same secret `enroll` returned.
    fn secret(&self, vault_id: &str) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError>;
    /// Deletes this vault's device key. Best effort.
    fn remove(&self, vault_id: &str);
}

/// The verifier for this OS, if there is one.
pub fn system_verifier() -> Option<std::sync::Arc<dyn DeviceVerifier>> {
    #[cfg(windows)]
    {
        Some(std::sync::Arc::new(windows_hello::WindowsHello))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn blob_path(vault_id: &str) -> Result<PathBuf> {
    Ok(paths::app_dir()?.join(format!("quick-unlock-{vault_id}.bin")))
}

fn last_password_path(vault_id: &str) -> Result<PathBuf> {
    Ok(paths::app_dir()?.join(format!("last-password-{vault_id}.bin")))
}

/// Whether quick unlock is set up for this vault on this device.
pub fn is_enrolled(vault_id: &str) -> bool {
    blob_path(vault_id).is_ok_and(|path| path.exists())
}

/// The wrapped vault key for this device, if quick unlock is set up.
pub fn load(vault_id: &str) -> Option<Vec<u8>> {
    std::fs::read(blob_path(vault_id).ok()?).ok()
}

/// Turns quick unlock on: wraps the vault key with the device secret and stores it.
pub fn enroll(vault: &Vault, device_secret: &[u8]) -> Result<()> {
    let sealed = vault.seal_for_device(device_secret)?;
    let path = blob_path(&vault.id_hex())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    storage::write_atomic(&path, &sealed)?;
    Ok(())
}

/// Turns quick unlock off on this device (the wrapped key file; the OS key is removed by the
/// verifier).
pub fn forget(vault_id: &str) {
    if let Ok(path) = blob_path(vault_id) {
        let _ = std::fs::remove_file(storage::backup_path(&path));
        let _ = std::fs::remove_file(path);
    }
}

// ---- the item lock: Windows Hello in place of its PIN or password ----

/// The name of the device key that opens the item lock (apart from the one that opens the
/// vault, so turning one off leaves the other alone).
pub fn item_lock_key_id(vault_id: &str) -> String {
    format!("{vault_id}-items")
}

fn item_lock_path(vault_id: &str) -> Result<PathBuf> {
    Ok(paths::app_dir()?.join(format!("item-lock-{vault_id}.bin")))
}

/// Whether the device's user verification can open this vault's item lock here.
pub fn item_lock_enrolled(vault_id: &str) -> bool {
    item_lock_path(vault_id).is_ok_and(|path| path.exists())
}

/// The wrapped item guard key for this device.
pub fn item_lock_load(vault_id: &str) -> Option<Vec<u8>> {
    std::fs::read(item_lock_path(vault_id).ok()?).ok()
}

/// Wraps the item guard key (which must be open) with the device secret and stores it.
pub fn item_lock_enroll(vault: &Vault, device_secret: &[u8]) -> Result<()> {
    let sealed = vault.seal_guard_for_device(device_secret)?;
    let path = item_lock_path(&vault.id_hex())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    storage::write_atomic(&path, &sealed)?;
    Ok(())
}

/// Forgets the wrapped item guard key on this device.
pub fn item_lock_forget(vault_id: &str) {
    if let Ok(path) = item_lock_path(vault_id) {
        let _ = std::fs::remove_file(storage::backup_path(&path));
        let _ = std::fs::remove_file(path);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Records that the master password was just used to open this vault.
pub fn record_password_unlock(vault: &Vault) -> Result<()> {
    record_password_unlock_at(vault, now_unix())
}

fn record_password_unlock_at(vault: &Vault, now: u64) -> Result<()> {
    let sealed = vault.seal_local(LAST_PASSWORD_PURPOSE, &now.to_le_bytes())?;
    let path = last_password_path(&vault.id_hex())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    storage::write_atomic(&path, &sealed)?;
    Ok(())
}

/// Whether the master password was used in the last `days` days (1 to
/// [`MAX_PASSWORD_INTERVAL_DAYS`]), recently enough for quick unlock to be allowed. Missing,
/// unreadable or future dates count as "not recently".
pub fn password_is_recent(vault: &Vault, days: u64) -> bool {
    password_is_recent_at(vault, now_unix(), days)
}

/// `days` kept between 1 and [`MAX_PASSWORD_INTERVAL_DAYS`].
pub fn interval_days(days: u64) -> u64 {
    days.clamp(1, MAX_PASSWORD_INTERVAL_DAYS)
}

fn password_is_recent_at(vault: &Vault, now: u64, days: u64) -> bool {
    let Some(sealed) = last_password_path(&vault.id_hex())
        .ok()
        .and_then(|path| std::fs::read(path).ok())
    else {
        return false;
    };
    let Ok(plain) = vault.open_local(LAST_PASSWORD_PURPOSE, &sealed) else {
        return false;
    };
    let Ok(bytes) = <[u8; 8]>::try_from(plain.as_slice()) else {
        return false;
    };
    let then = u64::from_le_bytes(bytes);
    then <= now && now - then < interval_days(days) * 24 * 60 * 60
}

#[cfg(windows)]
mod windows_hello {
    //! Windows Hello through WinRT `KeyCredentialManager` (TPM-backed when the PC has a TPM).

    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use windows::{
        Security::{
            Credentials::{
                KeyCredential, KeyCredentialCreationOption, KeyCredentialManager,
                KeyCredentialStatus,
            },
            Cryptography::CryptographicBuffer,
        },
        core::{Array, HSTRING},
    };
    use zeroize::Zeroizing;

    use super::{DeviceVerifier, QuickUnlockError};

    #[derive(Debug)]
    pub struct WindowsHello;

    fn credential_name(vault_id: &str) -> HSTRING {
        HSTRING::from(format!("vault-quick-unlock-{vault_id}"))
    }

    fn challenge(vault_id: &str) -> Vec<u8> {
        [b"vault-v0/windows-hello/".as_slice(), vault_id.as_bytes()].concat()
    }

    fn failed(err: windows::core::Error) -> QuickUnlockError {
        QuickUnlockError::Failed(err.message())
    }

    fn status_error(status: KeyCredentialStatus) -> QuickUnlockError {
        match status {
            KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
                QuickUnlockError::Cancelled
            }
            KeyCredentialStatus::NotFound => QuickUnlockError::NotEnrolled,
            KeyCredentialStatus::SecurityDeviceLocked => {
                QuickUnlockError::Failed("the security chip is locked for now".into())
            }
            other => QuickUnlockError::Failed(format!("Windows Hello status {}", other.0)),
        }
    }

    /// The Windows Hello dialog can open behind the app window when a desktop app asks for it;
    /// while waiting, keep bringing it to the front.
    struct PromptFocus(Arc<AtomicBool>);

    impl PromptFocus {
        #[allow(unsafe_code)]
        fn start() -> Self {
            let done = Arc::new(AtomicBool::new(false));
            let flag = done.clone();
            std::thread::spawn(move || {
                use windows_sys::Win32::UI::WindowsAndMessaging::{
                    FindWindowW, SetForegroundWindow,
                };
                let class: Vec<u16> = "Credential Dialog Xaml Host\0".encode_utf16().collect();
                for _ in 0..40 {
                    if flag.load(Ordering::Relaxed) {
                        return;
                    }
                    // SAFETY: `class` is a NUL-terminated UTF-16 string that outlives the call;
                    // a null window name matches any title.
                    let hwnd = unsafe { FindWindowW(class.as_ptr(), std::ptr::null()) };
                    if !hwnd.is_null() {
                        // SAFETY: `hwnd` was just returned by FindWindowW; a stale handle only
                        // makes the call fail.
                        unsafe { SetForegroundWindow(hwnd) };
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
            Self(done)
        }
    }

    impl Drop for PromptFocus {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    fn sign(
        credential: &KeyCredential,
        vault_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError> {
        let data =
            CryptographicBuffer::CreateFromByteArray(&challenge(vault_id)).map_err(failed)?;
        let _focus = PromptFocus::start();
        let result = credential
            .RequestSignAsync(&data)
            .and_then(|op| op.join())
            .map_err(failed)?;
        let status = result.Status().map_err(failed)?;
        if status != KeyCredentialStatus::Success {
            return Err(status_error(status));
        }
        let buffer = result.Result().map_err(failed)?;
        let mut bytes = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&buffer, &mut bytes).map_err(failed)?;
        let secret = Zeroizing::new(bytes.to_vec());
        // The WinRT array is freed by its own allocator; wipe our view of it first.
        for byte in bytes.iter_mut() {
            *byte = 0;
        }
        Ok(secret)
    }

    impl DeviceVerifier for WindowsHello {
        fn name(&self) -> &'static str {
            "Windows Hello"
        }

        fn is_available(&self) -> bool {
            KeyCredentialManager::IsSupportedAsync()
                .and_then(|op| op.join())
                .unwrap_or(false)
        }

        fn enroll(&self, vault_id: &str) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError> {
            if !self.is_available() {
                return Err(QuickUnlockError::Unavailable);
            }
            let result = {
                let _focus = PromptFocus::start();
                KeyCredentialManager::RequestCreateAsync(
                    &credential_name(vault_id),
                    KeyCredentialCreationOption::ReplaceExisting,
                )
                .and_then(|op| op.join())
                .map_err(failed)?
            };
            let status = result.Status().map_err(failed)?;
            if status != KeyCredentialStatus::Success {
                return Err(status_error(status));
            }
            let credential = result.Credential().map_err(failed)?;
            sign(&credential, vault_id)
        }

        fn secret(&self, vault_id: &str) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError> {
            // No IsSupported round trip first: OpenAsync reports the same problems itself.
            let result = KeyCredentialManager::OpenAsync(&credential_name(vault_id))
                .and_then(|op| op.join())
                .map_err(failed)?;
            let status = result.Status().map_err(failed)?;
            if status != KeyCredentialStatus::Success {
                return Err(status_error(status));
            }
            let credential = result.Credential().map_err(failed)?;
            sign(&credential, vault_id)
        }

        fn remove(&self, vault_id: &str) {
            let _ = KeyCredentialManager::DeleteAsync(&credential_name(vault_id))
                .and_then(|op| op.join());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{KdfParams, SecretKey};

    fn new_vault() -> Vault {
        Vault::create(
            "quick unlock test passphrase",
            &SecretKey::generate().unwrap(),
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap()
    }

    /// Asks Windows whether Hello is set up (no prompt). `cargo test -- --ignored hello`
    #[test]
    #[ignore = "depends on this machine's Windows Hello setup"]
    fn hello_availability() {
        let verifier = system_verifier().expect("a verifier on this OS");
        println!("{} available: {}", verifier.name(), verifier.is_available());
    }

    #[test]
    fn password_interval_is_enforced_and_sealed() {
        let home = tempfile::tempdir().unwrap();
        // SAFETY: tests in this crate that touch VAULT_HOME run in this one test only.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("VAULT_HOME", home.path());
        }
        let vault = new_vault();
        let day = 24 * 60 * 60;
        let now = 1_900_000_000;
        let every = PASSWORD_INTERVAL_DAYS;
        assert!(
            !password_is_recent_at(&vault, now, every),
            "never used: not recent"
        );

        record_password_unlock_at(&vault, now).unwrap();
        assert!(password_is_recent_at(&vault, now + day, every));
        assert!(!password_is_recent_at(&vault, now + every * day, every));
        assert!(
            !password_is_recent_at(&vault, now - day, every),
            "future date"
        );
        // Another interval chosen: a day, a month; outside those, the nearest.
        assert!(!password_is_recent_at(&vault, now + day, 1));
        assert!(password_is_recent_at(&vault, now + 29 * day, 30));
        assert!(
            !password_is_recent_at(&vault, now + day, 0),
            "at least a day"
        );
        assert!(
            !password_is_recent_at(&vault, now + 30 * day, 365),
            "at most a month"
        );

        // Another vault cannot read (or forge) this vault's date.
        let other = new_vault();
        let path = last_password_path(&vault.id_hex()).unwrap();
        std::fs::copy(&path, last_password_path(&other.id_hex()).unwrap()).unwrap();
        assert!(!password_is_recent_at(&other, now + day, every));

        // Enrollment file round trip.
        let secret = [3u8; 256];
        enroll(&vault, &secret).unwrap();
        assert!(is_enrolled(&vault.id_hex()));
        assert!(load(&vault.id_hex()).is_some());
        forget(&vault.id_hex());
        assert!(!is_enrolled(&vault.id_hex()));
    }
}
