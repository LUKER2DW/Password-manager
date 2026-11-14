//! Logins the browser extension may fill while the vault is locked.
//!
//! A locked vault has no key in memory. For this one purpose the app keeps the passwords of
//! logins in a blob of their own, encrypted (XChaCha20-Poly1305, padded) under a random
//! [`LockedFillKey`]. That key is stored twice:
//! - wrapped by a key derived (HKDF-SHA-256) from the device's user verification — on
//!   Windows a Windows Hello signature made by the security chip, only after the person is
//!   verified — so the locked app can open it with Windows Hello and nothing else;
//! - sealed with the vault key (`Vault::seal_local`), so the open app keeps the blob current
//!   without asking.
//!
//! Nothing typed opens it. A PIN would be weak here: whoever copies the file could try every
//! PIN away from the app, while each Windows Hello try needs the person and the chip.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result, aead, keys, padding, random};

/// The key of the locked-fill blob. Wiped when dropped.
pub struct LockedFillKey(Zeroizing<aead::Key>);

impl std::fmt::Debug for LockedFillKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockedFillKey(<redacted>)")
    }
}

fn aad(part: &[u8], vault_id: &str) -> Vec<u8> {
    [
        b"vault-v0/locked-fill/".as_slice(),
        part,
        b"/",
        vault_id.as_bytes(),
    ]
    .concat()
}

impl LockedFillKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random::secret_array::<{ aead::KEY_LEN }>()?))
    }

    /// The key as it was sealed with the vault key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key: aead::Key = bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self(Zeroizing::new(key)))
    }

    /// The raw key, to be sealed with the vault key. Never store it as is.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Wraps the key for the device's user verification. `device_secret` comes from the
    /// device's secure hardware after the person is verified, and is never stored.
    pub fn wrap_for_device(&self, device_secret: &[u8], vault_id: &str) -> Result<Vec<u8>> {
        let kek = keys::locked_fill_kek(device_secret, vault_id)?;
        aead::seal(&kek, self.0.as_ref(), &aad(b"key", vault_id))
    }

    /// Opens what [`LockedFillKey::wrap_for_device`] made. Fails with another device secret.
    pub fn unwrap_for_device(device_secret: &[u8], vault_id: &str, sealed: &[u8]) -> Result<Self> {
        let kek = keys::locked_fill_kek(device_secret, vault_id)?;
        let bytes = aead::open(&kek, sealed, &aad(b"key", vault_id))?;
        Self::from_bytes(&bytes)
    }

    pub fn seal_passwords(&self, vault_id: &str, passwords: &LockedPasswords) -> Result<Vec<u8>> {
        // Sized up front so the plain bytes are never copied by a growing buffer.
        let size = 16
            + passwords
                .entries
                .iter()
                .map(|entry| entry.id.len() + entry.password.len() + 8)
                .sum::<usize>();
        let mut buffer = Zeroizing::new(vec![0u8; size]);
        let used = postcard::to_slice(passwords, &mut buffer)
            .map_err(|_| Error::Malformed)?
            .len();
        let padded = padding::pad(&buffer[..used], padding::body_bucket)?;
        aead::seal(&self.0, &padded, &aad(b"passwords", vault_id))
    }

    pub fn open_passwords(&self, vault_id: &str, sealed: &[u8]) -> Result<LockedPasswords> {
        let padded = aead::open(&self.0, sealed, &aad(b"passwords", vault_id))?;
        postcard::from_bytes(padding::unpad(&padded)?).map_err(|_| Error::Malformed)
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct LockedPassword {
    id: String,
    password: String,
}

/// The passwords the locked app may fill, by item id (hex). Wiped when dropped.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct LockedPasswords {
    entries: Vec<LockedPassword>,
}

impl std::fmt::Debug for LockedPasswords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedPasswords")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl LockedPasswords {
    pub fn get(&self, id: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.password.as_str())
    }

    /// Adds or replaces the password of `id`; an empty one removes it.
    pub fn set(&mut self, id: &str, password: &str) {
        self.entries.retain(|entry| entry.id != id);
        if !password.is_empty() {
            self.entries.push(LockedPassword {
                id: id.to_owned(),
                password: password.to_owned(),
            });
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: [u8; 32] = [7; 32];

    #[test]
    fn passwords_open_with_the_device_only() {
        let key = LockedFillKey::generate().unwrap();
        let mut passwords = LockedPasswords::default();
        passwords.set("aa", "first-secret");
        passwords.set("bb", "second-secret");
        passwords.set("aa", "changed");
        passwords.set("cc", "");
        let sealed = key.seal_passwords("v1", &passwords).unwrap();
        assert!(!sealed.windows(7).any(|w| w == b"changed"));

        let wrapped = key.wrap_for_device(&DEVICE, "v1").unwrap();
        let again = LockedFillKey::unwrap_for_device(&DEVICE, "v1", &wrapped).unwrap();
        let opened = again.open_passwords("v1", &sealed).unwrap();
        assert_eq!(opened.get("aa"), Some("changed"));
        assert_eq!(opened.get("bb"), Some("second-secret"));
        assert_eq!(opened.get("cc"), None);
        assert_eq!(opened.len(), 2);

        // Another device, another vault, or a tampered blob opens nothing.
        assert!(LockedFillKey::unwrap_for_device(&[8; 32], "v1", &wrapped).is_err());
        assert!(LockedFillKey::unwrap_for_device(&DEVICE, "v2", &wrapped).is_err());
        assert!(again.open_passwords("v2", &sealed).is_err());
        let mut broken = sealed.clone();
        let last = broken.len() - 1;
        broken[last] ^= 1;
        assert!(again.open_passwords("v1", &broken).is_err());
        // A device secret too short to be one is refused.
        assert!(key.wrap_for_device(&[1; 8], "v1").is_err());
        // The raw key round-trips (for the copy sealed with the vault key).
        let copy = LockedFillKey::from_bytes(key.as_bytes()).unwrap();
        assert_eq!(copy.open_passwords("v1", &sealed).unwrap().len(), 2);
        assert!(LockedFillKey::from_bytes(&[1; 5]).is_err());
    }
}
