//! The browser drop box: logins saved from the browser while the vault is locked.
//!
//! The locked app has no vault key, so it can't add an item. Instead each login is sealed to a
//! public key whose private half only the open vault can read (libsodium's sealed box:
//! X25519 with an ephemeral key, XSalsa20-Poly1305; spec/CRYPTO.md §3.5), and kept until the
//! next unlock, when the app opens them and adds them as items.
//!
//! - The private key is kept sealed with the vault key ([`Vault::seal_local`]): a copy of the
//!   files without the vault opens nothing.
//! - Writing needs only the public key, so the locked app asks for nothing (no PIN, no Windows
//!   Hello) and still can't read back what it wrote.
//! - Each entry carries the vault's id and is padded like an item, so entries can't be moved to
//!   another vault and their size says little about the password.
//! - The public key isn't authenticated while locked (nothing secret is available then): a
//!   program running as the user could swap it and read later saves. Such a program already
//!   sees the password where it is typed, in the browser; the threat model says so.

use crypto_box::{PublicKey, SecretKey as BoxSecret, aead::OsRng};
use zeroize::Zeroizing;

use crate::{Error, Result, Vault, padding};

const PURPOSE: &str = "browser-drop-box";
/// Bytes of a public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// The drop box's private key, read with the open vault. Wiped on drop.
pub struct DropBoxKey {
    secret: BoxSecret,
}

impl std::fmt::Debug for DropBoxKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DropBoxKey(<redacted>)")
    }
}

impl DropBoxKey {
    /// A new key pair from the OS random generator.
    pub fn generate() -> Result<Self> {
        let bytes = crate::random::secret_array::<32>()?;
        Ok(Self {
            secret: BoxSecret::from_bytes(*bytes),
        })
    }

    /// The public half, which the locked app seals entries to.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.secret.public_key().to_bytes()
    }

    /// The private key sealed with the vault key, to keep next to the vault.
    pub fn seal_with(&self, vault: &Vault) -> Result<Vec<u8>> {
        let bytes = Zeroizing::new(self.secret.to_bytes());
        vault.seal_local(PURPOSE, bytes.as_ref())
    }

    /// The key kept by [`DropBoxKey::seal_with`].
    pub fn open_with(vault: &Vault, sealed: &[u8]) -> Result<Self> {
        let bytes = vault.open_local(PURPOSE, sealed)?;
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| Error::Malformed)?;
        let array = Zeroizing::new(array);
        Ok(Self {
            secret: BoxSecret::from_bytes(*array),
        })
    }

    /// Opens one entry written by [`seal_entry`] for this vault.
    pub fn open_entry(&self, vault: &Vault, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let plain = Zeroizing::new(
            self.secret
                .unseal(sealed)
                .map_err(|_| Error::DecryptionFailed)?,
        );
        let id = vault.id_hex();
        let rest = plain
            .strip_prefix(id.as_bytes())
            .ok_or(Error::DecryptionFailed)?;
        Ok(Zeroizing::new(padding::unpad(rest)?.to_vec()))
    }
}

/// Seals `data` for vault `vault_id` (its hex id) to the drop box's public key.
pub fn seal_entry(
    public_key: &[u8; PUBLIC_KEY_LEN],
    vault_id: &str,
    data: &[u8],
) -> Result<Vec<u8>> {
    let padded = padding::pad(data, padding::item_bucket)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(vault_id.len() + padded.len()));
    plain.extend_from_slice(vault_id.as_bytes());
    plain.extend_from_slice(&padded);
    PublicKey::from_bytes(*public_key)
        .seal(&mut OsRng, &plain)
        .map_err(|_| Error::Rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KdfParams, SecretKey};

    fn new_vault() -> Vault {
        Vault::create(
            "pw",
            &SecretKey::generate().unwrap(),
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn only_the_open_vault_reads_what_was_dropped() {
        let vault = new_vault();
        let key = DropBoxKey::generate().unwrap();
        let sealed_key = key.seal_with(&vault).unwrap();
        let public = key.public_key();
        drop(key);

        // Written with the public key alone (the locked app).
        let entry = seal_entry(&public, &vault.id_hex(), b"login bytes").unwrap();
        assert!(!entry.windows(5).any(|w| w == b"login"));
        let again = seal_entry(&public, &vault.id_hex(), b"login bytes").unwrap();
        assert_ne!(entry, again, "a fresh ephemeral key each time");
        // Padded: short and long entries of one bucket have the same size.
        assert_eq!(
            entry.len(),
            seal_entry(&public, &vault.id_hex(), b"x").unwrap().len()
        );

        let key = DropBoxKey::open_with(&vault, &sealed_key).unwrap();
        assert_eq!(key.public_key(), public);
        assert_eq!(
            key.open_entry(&vault, &entry).unwrap().as_slice(),
            b"login bytes"
        );

        // Another vault can't open the key, nor take an entry meant for this one.
        let other = new_vault();
        assert!(DropBoxKey::open_with(&other, &sealed_key).is_err());
        let moved = seal_entry(&public, &other.id_hex(), b"login bytes").unwrap();
        assert!(key.open_entry(&vault, &moved).is_err());
        // Tampering is caught.
        let mut bad = entry.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(key.open_entry(&vault, &bad).is_err());
        assert!(!format!("{key:?}").contains(&format!("{:?}", &public[..4])));
    }
}
