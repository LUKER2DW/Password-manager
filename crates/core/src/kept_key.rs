//! The Secret Key as a device keeps it under a key that never leaves a chip (spec:
//! CRYPTO.md §2.2.1).
//!
//! A new random key-encryption key seals the Secret Key with the vault's AEAD; the chip (the
//! TPM on Windows, reached by `vault-platform`) wraps only that key-encryption key, with
//! RSA-OAEP under [`WRAP_LABEL`]. This module makes the key-encryption key, seals and opens
//! the Secret Key, and writes and reads the stored form:
//! `version (0x01) ‖ wrapped key-encryption key (256 bytes) ‖ sealed Secret Key`.

use zeroize::Zeroizing;

use crate::{Error, Result, SecretKey, aead, random};

/// Length of the key-encryption key the chip wraps.
pub const KEK_LEN: usize = aead::KEY_LEN;
/// Length of the wrapped key-encryption key: one RSA-2048 block.
pub const WRAPPED_LEN: usize = 256;

const VERSION: u8 = 0x01;
const AAD: &[u8] = b"vault-v0/secret-key-at-rest";
/// The Secret Key's own length, sealed as it is (no padding: it never changes).
const SECRET_KEY_LEN: usize = 16;

/// The OAEP label the chip binds the wrapped key-encryption key to. Short and ending in a
/// zero byte, as a TPM requires: it takes only zero-terminated labels, of at most its largest
/// hash's size (about 34 bytes on one with SHA-256 only). The vault is named by the chip's key
/// (one per vault) and by the seal's associated data.
pub const WRAP_LABEL: &[u8] = b"vault-v0/secret-key-at-rest\0";

fn aad(vault_id_hex: &str) -> Vec<u8> {
    [AAD, vault_id_hex.as_bytes()].concat()
}

/// A new key-encryption key, and `key` sealed under it for the vault `vault_id_hex`. The
/// caller has the chip wrap the first and keeps the second (see [`encode`]). The Secret Key
/// leaves the key shield only into a wiped copy, and the stack the seal used is cleared.
pub fn seal(key: &SecretKey, vault_id_hex: &str) -> Result<(Zeroizing<[u8; KEK_LEN]>, Vec<u8>)> {
    let sealed = seal_in_frame(key, vault_id_hex);
    crate::memory::clear_stack();
    sealed
}

/// [`seal`]'s work, in a frame of its own below the one that clears the stack.
#[inline(never)]
fn seal_in_frame(
    key: &SecretKey,
    vault_id_hex: &str,
) -> Result<(Zeroizing<[u8; KEK_LEN]>, Vec<u8>)> {
    let kek = random::secret_array::<KEK_LEN>()?;
    let sealed = aead::seal(&kek, key.open().as_ref(), &aad(vault_id_hex))?;
    Ok((kek, sealed))
}

/// Opens what [`seal`] sealed, with the key-encryption key the chip unwrapped. Any failure
/// (a key of another length, another vault, a changed byte) is one error. The Secret Key goes
/// straight into the key shield, and the stack the opening used is cleared.
pub fn open(kek: &[u8], vault_id_hex: &str, sealed: &[u8]) -> Result<SecretKey> {
    let key = open_in_frame(kek, vault_id_hex, sealed);
    crate::memory::clear_stack();
    key
}

/// [`open`]'s work, in a frame of its own below the one that clears the stack.
#[inline(never)]
fn open_in_frame(kek: &[u8], vault_id_hex: &str, sealed: &[u8]) -> Result<SecretKey> {
    let kek: &[u8; KEK_LEN] = kek.try_into().map_err(|_| Error::DecryptionFailed)?;
    let bytes = aead::open(kek, sealed, &aad(vault_id_hex))?;
    if bytes.len() != SECRET_KEY_LEN {
        return Err(Error::DecryptionFailed);
    }
    SecretKey::from_slice(&bytes)
}

/// The stored form: the version, the chip's wrapped key-encryption key, the sealed key.
pub fn encode(wrapped_kek: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if wrapped_kek.len() != WRAPPED_LEN {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(1 + WRAPPED_LEN + sealed.len());
    out.push(VERSION);
    out.extend_from_slice(wrapped_kek);
    out.extend_from_slice(sealed);
    Ok(out)
}

/// Splits a stored form into the wrapped key-encryption key and the sealed key. Another
/// version or a form too short for both is refused.
pub fn decode(kept: &[u8]) -> Result<(&[u8], &[u8])> {
    match kept.split_first() {
        Some((&VERSION, rest)) if rest.len() > WRAPPED_LEN + aead::OVERHEAD => {
            Ok(rest.split_at(WRAPPED_LEN))
        }
        Some((&VERSION, _)) => Err(Error::Malformed),
        Some((&version, _)) => Err(Error::UnsupportedVersion(u16::from(version))),
        None => Err(Error::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn seals_and_opens_for_one_vault_only() {
        let key = SecretKey::generate().unwrap();
        let (kek, sealed) = seal(&key, ID).unwrap();
        assert_eq!(open(kek.as_ref(), ID, &sealed).unwrap(), key);
        // Another vault's id, another key, a changed byte, a short key: all one error.
        let other = "ffeeddccbbaa99887766554433221100";
        assert!(matches!(
            open(kek.as_ref(), other, &sealed),
            Err(Error::DecryptionFailed)
        ));
        let mut wrong = *kek;
        wrong[0] ^= 1;
        assert!(open(&wrong, ID, &sealed).is_err());
        let mut changed = sealed.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(open(kek.as_ref(), ID, &changed).is_err());
        assert!(open(&kek[..16], ID, &sealed).is_err());
        // A new key-encryption key every time.
        let (again, _) = seal(&key, ID).unwrap();
        assert_ne!(*again, *kek);
    }

    #[test]
    fn stored_form_round_trips_and_refuses_the_unexpected() {
        let key = SecretKey::generate().unwrap();
        let (_, sealed) = seal(&key, ID).unwrap();
        let wrapped = [7u8; WRAPPED_LEN];
        let kept = encode(&wrapped, &sealed).unwrap();
        assert_eq!(kept[0], VERSION);
        assert_eq!(kept.len(), 1 + WRAPPED_LEN + sealed.len());
        let (w, s) = decode(&kept).unwrap();
        assert_eq!(w, wrapped);
        assert_eq!(s, sealed);

        assert!(encode(&wrapped[..255], &sealed).is_err());
        let mut future = kept.clone();
        future[0] = 2;
        assert!(matches!(decode(&future), Err(Error::UnsupportedVersion(2))));
        assert!(decode(&[]).is_err());
        assert!(decode(&kept[..1 + WRAPPED_LEN]).is_err());
    }

    #[test]
    fn label_fits_a_tpm() {
        assert!(WRAP_LABEL.len() <= 32);
        assert_eq!(WRAP_LABEL.last(), Some(&0));
        assert_eq!(&WRAP_LABEL[..WRAP_LABEL.len() - 1], AAD);
    }
}
