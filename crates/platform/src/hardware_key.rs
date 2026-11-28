//! A hardware security key, asked through FIDO2's `hmac-secret` (CRYPTO.md §3.13, M10 F6;
//! designed, not used by the apps yet: the vault's header carries it from a later format).
//!
//! On Windows the key is reached through Windows' own WebAuthn API (`webauthn.dll`), which
//! needs no administrator (since Windows 10 1903 only an administrator may talk to a FIDO key
//! over USB HID) and shows Windows' prompt for the touch and the key's PIN. Its
//! `makeCredential` with `hmac-secret` enrols a key; its `getAssertion` with the salt values
//! returns the answer. Both are behind [`HardwareKey`], so the apps' tests use
//! [`MemoryKey`] and never need a real key.
//!
//! Only the API's version is read here so far ([`windows_api_version`]): the two calls that
//! touch a key are written once they can be tried against a real one.

use anyhow::Result;
use zeroize::Zeroizing;

/// A credential made on a key for this vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    /// The credential's id, as the key gave it (kept in the header).
    pub credential_id: Vec<u8>,
    /// Whether the key asked for its PIN (user verification) when it was made.
    pub verified: bool,
}

/// What the apps ask of a hardware key.
pub trait HardwareKey {
    /// Makes a credential with `hmac-secret` for `rp_id` (one touch).
    fn enroll(&self, rp_id: &str, user_name: &str) -> Result<Enrolled>;
    /// The key's `hmac-secret` answer for `salt` with credential `credential_id` (one touch).
    fn answer(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>>;
}

/// The oldest `webauthn.dll` API version that passes an `hmac-secret` salt to the key
/// (`pHmacSecretSaltValues` in the assertion's options). To be confirmed against a real key.
pub const MIN_WINDOWS_API_VERSION: u32 = 3;

/// The version of Windows' WebAuthn API on this computer (`None` without `webauthn.dll`,
/// before Windows 10 1903, or off Windows).
pub fn windows_api_version() -> Option<u32> {
    imp::api_version()
}

/// Whether this Windows can ask a hardware key for its `hmac-secret` answer.
pub fn windows_can_answer() -> bool {
    windows_api_version().is_some_and(|version| version >= MIN_WINDOWS_API_VERSION)
}

/// A stand-in for a key, in memory: its secret is random, each credential's answer is
/// HMAC-SHA-256(secret, credential id ‖ salt), as a real key's is an HMAC of a secret only it
/// holds. For the apps' tests only.
#[derive(Debug)]
pub struct MemoryKey {
    secret: Zeroizing<[u8; 32]>,
    /// Refuses every request (a key pulled out, a touch never made).
    pub absent: std::sync::atomic::AtomicBool,
}

impl MemoryKey {
    pub fn new() -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(secret.as_mut()).map_err(|_| anyhow::anyhow!("no randomness"))?;
        Ok(Self {
            secret,
            absent: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

impl HardwareKey for MemoryKey {
    fn enroll(&self, rp_id: &str, user_name: &str) -> Result<Enrolled> {
        if self.absent.load(std::sync::atomic::Ordering::Relaxed) {
            anyhow::bail!("no key");
        }
        let mut id = vec![0u8; 16];
        getrandom::fill(&mut id).map_err(|_| anyhow::anyhow!("no randomness"))?;
        id.extend_from_slice(rp_id.as_bytes());
        id.extend_from_slice(user_name.as_bytes());
        Ok(Enrolled {
            credential_id: id,
            verified: true,
        })
    }

    fn answer(
        &self,
        _rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>> {
        use hmac::{KeyInit, Mac};
        if self.absent.load(std::sync::atomic::Ordering::Relaxed) {
            anyhow::bail!("no key");
        }
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(self.secret.as_ref())
            .map_err(|_| anyhow::anyhow!("bad key"))?;
        mac.update(credential_id);
        mac.update(salt);
        let outer = mac.finalize().into_bytes();
        let mut answer = Zeroizing::new([0u8; 32]);
        answer.copy_from_slice(&outer);
        Ok(answer)
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Networking::WindowsWebServices::WebAuthNGetApiVersionNumber;

    pub(super) fn api_version() -> Option<u32> {
        // `webauthn.dll` is loaded from System32 only (process.rs); a Windows without it
        // fails to load it, which this call can't survive: look for the file first.
        let system = std::env::var_os("SystemRoot")?;
        if !std::path::Path::new(&system)
            .join("System32")
            .join("webauthn.dll")
            .exists()
        {
            return None;
        }
        // SAFETY: a plain call without arguments, in a DLL found above.
        #[allow(unsafe_code)]
        let version = unsafe { WebAuthNGetApiVersionNumber() };
        (version > 0).then_some(version)
    }
}

#[cfg(not(windows))]
mod imp {
    pub(super) fn api_version() -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stand_in_answers_like_a_key_and_its_slot_opens() {
        let key = MemoryKey::new().unwrap();
        let enrolled = key.enroll("vault.local", "test").unwrap();
        let salt = [9u8; 32];
        let answer = key
            .answer("vault.local", &enrolled.credential_id, &salt)
            .unwrap();
        // The same question, the same answer; another salt or credential, another one.
        assert_eq!(
            *answer,
            *key.answer("vault.local", &enrolled.credential_id, &salt)
                .unwrap()
        );
        assert_ne!(
            *answer,
            *key.answer("vault.local", &enrolled.credential_id, &[8u8; 32])
                .unwrap()
        );
        assert_ne!(
            *answer,
            *MemoryKey::new()
                .unwrap()
                .answer("vault.local", &enrolled.credential_id, &salt)
                .unwrap()
        );
        // The vault's slot (CRYPTO.md §3.13) opens with that answer only.
        let factor = vault_core::hardware_key::random_32().unwrap();
        let vault_id = [5u8; 16];
        let slot = vault_core::hardware_key::seal_factor(
            &answer,
            &vault_id,
            &enrolled.credential_id,
            &factor,
        )
        .unwrap();
        let again = key
            .answer("vault.local", &enrolled.credential_id, &salt)
            .unwrap();
        assert_eq!(
            *vault_core::hardware_key::open_factor(
                &again,
                &vault_id,
                &enrolled.credential_id,
                &slot
            )
            .unwrap(),
            *factor
        );
        // A key pulled out answers nothing.
        key.absent.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            key.answer("vault.local", &enrolled.credential_id, &salt)
                .is_err()
        );
    }

    /// Reads this Windows' WebAuthn API version (no prompt, no key needed) and prints it.
    #[cfg(windows)]
    #[test]
    fn windows_tells_its_webauthn_version() {
        let version = windows_api_version();
        println!("webauthn.dll API version: {version:?}");
        assert!(version.is_none_or(|v| v >= 1));
    }
}
