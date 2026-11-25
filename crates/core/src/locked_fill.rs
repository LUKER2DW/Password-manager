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

use crypto_box::{PublicKey, SecretKey as BoxSecret, aead::OsRng};
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

/// The key of the passwords of logins behind the item lock (CRYPTO.md §3.4): an X25519 key
/// pair. Its private half is kept only wrapped for the device's user verification, never
/// with the vault key, so whoever holds the vault key (malware reading an open vault from
/// memory) still can't read a locked login's password from the locked-fill file: the item
/// lock keeps its meaning there too. The open app adds a password with the public half
/// alone (libsodium's sealed box), so keeping the file current asks for nothing.
pub struct GuardedFillKey {
    secret: BoxSecret,
}

impl std::fmt::Debug for GuardedFillKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuardedFillKey(<redacted>)")
    }
}

/// Bytes of a [`GuardedFillKey`]'s public half.
pub const GUARDED_PUBLIC_KEY_LEN: usize = 32;

impl GuardedFillKey {
    pub fn generate() -> Result<Self> {
        let bytes = random::secret_array::<32>()?;
        Ok(Self {
            secret: BoxSecret::from_bytes(*bytes),
        })
    }

    /// The public half, which passwords are sealed to ([`seal_guarded`]).
    pub fn public_key(&self) -> [u8; GUARDED_PUBLIC_KEY_LEN] {
        self.secret.public_key().to_bytes()
    }

    /// Wraps the private half for the device's user verification (as
    /// [`LockedFillKey::wrap_for_device`]).
    pub fn wrap_for_device(&self, device_secret: &[u8], vault_id: &str) -> Result<Vec<u8>> {
        let kek = keys::locked_fill_kek(device_secret, vault_id)?;
        let bytes = Zeroizing::new(self.secret.to_bytes());
        aead::seal(&kek, bytes.as_ref(), &aad(b"guarded-key", vault_id))
    }

    /// Opens what [`GuardedFillKey::wrap_for_device`] made.
    pub fn unwrap_for_device(device_secret: &[u8], vault_id: &str, sealed: &[u8]) -> Result<Self> {
        let kek = keys::locked_fill_kek(device_secret, vault_id)?;
        let bytes = aead::open(&kek, sealed, &aad(b"guarded-key", vault_id))?;
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| Error::Malformed)?;
        let array = Zeroizing::new(array);
        Ok(Self {
            secret: BoxSecret::from_bytes(*array),
        })
    }

    /// Opens one password sealed by [`seal_guarded`], for login `item_id` as it was when
    /// `stamp` was taken. Fails for another vault, another login or another stamp: a password
    /// kept for one version of a login is never handed out for another (another website, say).
    pub fn open_guarded(
        &self,
        vault_id: &str,
        item_id: &str,
        stamp: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Zeroizing<String>> {
        let plain = Zeroizing::new(
            self.secret
                .unseal(sealed)
                .map_err(|_| Error::DecryptionFailed)?,
        );
        let prefix = guarded_prefix(vault_id, item_id, stamp);
        let rest = plain
            .strip_prefix(prefix.as_slice())
            .ok_or(Error::DecryptionFailed)?;
        let password = padding::unpad(rest)?;
        let text = std::str::from_utf8(password).map_err(|_| Error::Malformed)?;
        Ok(Zeroizing::new(text.to_owned()))
    }
}

fn guarded_prefix(vault_id: &str, item_id: &str, stamp: &[u8; 32]) -> Vec<u8> {
    [
        aad(b"guarded", vault_id).as_slice(),
        b"/",
        item_id.as_bytes(),
        b"/",
        stamp,
    ]
    .concat()
}

/// Seals the password of login `item_id` (as of `stamp`, see `Vault::item_stamp`) to a
/// [`GuardedFillKey`]'s public half. Padded like an item.
pub fn seal_guarded(
    public_key: &[u8; GUARDED_PUBLIC_KEY_LEN],
    vault_id: &str,
    item_id: &str,
    stamp: &[u8; 32],
    password: &str,
) -> Result<Vec<u8>> {
    let prefix = guarded_prefix(vault_id, item_id, stamp);
    let padded = padding::pad(password.as_bytes(), padding::item_bucket)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(prefix.len() + padded.len()));
    plain.extend_from_slice(&prefix);
    plain.extend_from_slice(&padded);
    PublicKey::from_bytes(*public_key)
        .seal(&mut OsRng, &plain)
        .map_err(|_| Error::Rng)
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

    #[test]
    fn a_locked_logins_password_opens_with_the_device_and_for_that_version_only() {
        let key = GuardedFillKey::generate().unwrap();
        let public = key.public_key();
        let stamp = [3; 32];
        // Sealed with the public half alone (the open app, asking nothing).
        let sealed = seal_guarded(&public, "v1", "aa", &stamp, "locked-secret").unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"locked"));
        let wrapped = key.wrap_for_device(&DEVICE, "v1").unwrap();
        drop(key);
        let key = GuardedFillKey::unwrap_for_device(&DEVICE, "v1", &wrapped).unwrap();
        assert_eq!(key.public_key(), public);
        assert_eq!(
            key.open_guarded("v1", "aa", &stamp, &sealed)
                .unwrap()
                .as_str(),
            "locked-secret"
        );
        // Another version of the login, another login, another vault: nothing.
        assert!(key.open_guarded("v1", "aa", &[4; 32], &sealed).is_err());
        assert!(key.open_guarded("v1", "bb", &stamp, &sealed).is_err());
        assert!(key.open_guarded("v2", "aa", &stamp, &sealed).is_err());
        // Only the device opens the private half.
        assert!(GuardedFillKey::unwrap_for_device(&[8; 32], "v1", &wrapped).is_err());
        assert!(GuardedFillKey::unwrap_for_device(&DEVICE, "v2", &wrapped).is_err());
        // The blob key's wrap is another one: neither stands in for the other.
        let blob = LockedFillKey::generate().unwrap();
        let blob_wrapped = blob.wrap_for_device(&DEVICE, "v1").unwrap();
        assert!(GuardedFillKey::unwrap_for_device(&DEVICE, "v1", &blob_wrapped).is_err());
        assert!(LockedFillKey::unwrap_for_device(&DEVICE, "v1", &wrapped).is_err());
    }
}
