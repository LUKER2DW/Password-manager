//! A hardware security key as a factor of the vault (CRYPTO.md §3.13, M10 F6; designed).
//!
//! The key answers through FIDO2's `hmac-secret`: 32 bytes for a salt, after a touch
//! (`vault_platform::hardware_key` asks it). Each enrolled key wraps the vault's one
//! `hardware_factor`, and the factor's key joins the password slot's KEK. This module is that
//! arithmetic, on the existing primitives only (HKDF-SHA-256 and the key-committing AEAD);
//! the header's fields that carry the slots come with a format version of their own, so
//! nothing here is written to a vault file yet.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Result, aead, random};

/// What a key's `hmac-secret` answers, and the factor every enrolled key wraps.
pub const ANSWER_LEN: usize = 32;
pub const FACTOR_LEN: usize = 32;
/// The longest credential id CTAP 2.1 allows.
pub const MAX_CREDENTIAL_ID: usize = 1023;

/// The relying party id the vault's credentials are made for (no website: only this app asks
/// for it).
pub const RP_ID: &str = "vault.local";

fn hkdf32(ikm: &[u8], vault_id: &[u8; 16], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(vault_id), ikm)
        .expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    out
}

/// A new random salt for an enrolled key, or a new `hardware_factor`.
pub fn random_32() -> Result<Zeroizing<[u8; 32]>> {
    random::secret_array::<32>()
}

/// The slot's AAD: the label, the vault, and the credential it belongs to.
fn slot_aad(vault_id: &[u8; 16], credential_id: &[u8]) -> Vec<u8> {
    let label = b"vault-v0/hardware-key";
    let mut aad = Vec::with_capacity(label.len() + 16 + 32);
    aad.extend_from_slice(label);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&Sha256::digest(credential_id));
    aad
}

/// `hardware_slot_i`: the factor sealed under what key *i* answered for its salt.
pub fn seal_factor(
    answer: &[u8; ANSWER_LEN],
    vault_id: &[u8; 16],
    credential_id: &[u8],
    factor: &[u8; FACTOR_LEN],
) -> Result<Vec<u8>> {
    if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID {
        return Err(crate::Error::InvalidKeyFormat);
    }
    let wrap = hkdf32(answer, vault_id, b"vault-v0/hardware-key/wrap");
    aead::seal(&wrap, factor, &slot_aad(vault_id, credential_id))
}

/// The factor back from a slot, with what its key answered. Any change to the slot, the
/// vault id, the credential id or the answer fails (fail closed).
pub fn open_factor(
    answer: &[u8; ANSWER_LEN],
    vault_id: &[u8; 16],
    credential_id: &[u8],
    slot: &[u8],
) -> Result<Zeroizing<[u8; FACTOR_LEN]>> {
    let wrap = hkdf32(answer, vault_id, b"vault-v0/hardware-key/wrap");
    let opened = aead::open(&wrap, slot, &slot_aad(vault_id, credential_id))?;
    let mut factor = Zeroizing::new([0u8; FACTOR_LEN]);
    if opened.len() != FACTOR_LEN {
        return Err(crate::Error::InvalidKeyFormat);
    }
    factor.copy_from_slice(&opened);
    Ok(factor)
}

/// `hardware_factor_key`: what joins the password slot's KEK (CRYPTO.md §3.13), after the
/// password key, the Secret Key and the keyfile's digest.
pub fn factor_key(factor: &[u8; FACTOR_LEN], vault_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    hkdf32(factor, vault_id, b"vault-v0/hardware-key/factor")
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: [u8; 16] = [7; 16];
    const CREDENTIAL: &[u8] = b"a test credential id";

    #[test]
    fn any_enrolled_key_opens_the_same_factor_and_nothing_else_does() {
        let factor = random_32().unwrap();
        let first = [1u8; 32];
        let spare = [2u8; 32];
        let slot = seal_factor(&first, &VAULT, CREDENTIAL, &factor).unwrap();
        let spare_slot = seal_factor(&spare, &VAULT, b"the spare", &factor).unwrap();
        assert_eq!(
            *open_factor(&first, &VAULT, CREDENTIAL, &slot).unwrap(),
            *factor
        );
        assert_eq!(
            *open_factor(&spare, &VAULT, b"the spare", &spare_slot).unwrap(),
            *factor
        );
        // Another answer, another vault, another credential, a changed byte: nothing.
        assert!(open_factor(&spare, &VAULT, CREDENTIAL, &slot).is_err());
        assert!(open_factor(&first, &[8; 16], CREDENTIAL, &slot).is_err());
        assert!(open_factor(&first, &VAULT, b"another", &slot).is_err());
        for i in 0..slot.len() {
            let mut changed = slot.clone();
            changed[i] ^= 1;
            assert!(open_factor(&first, &VAULT, CREDENTIAL, &changed).is_err());
        }
        assert!(seal_factor(&first, &VAULT, b"", &factor).is_err());
        assert!(seal_factor(&first, &VAULT, &[0; MAX_CREDENTIAL_ID + 1], &factor).is_err());
    }

    #[test]
    fn the_factor_key_is_hkdf_with_its_own_label() {
        // RFC 5869 HKDF-SHA-256 computed apart, with Python's hmac and hashlib alone:
        // prk = HMAC(salt = 07 × 16, 03 × 32); okm = HMAC(prk, info ‖ 01).
        let key = factor_key(&[3; 32], &VAULT);
        let expected = "0b3e9a5fcb67c88a11779f373f4a761627dfb3ebcf264d3ad3a4228596bb14c8";
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
        let again = factor_key(&[3; 32], &VAULT);
        assert_eq!(*key, *again);
        assert_ne!(*key, *factor_key(&[3; 32], &[8; 16]));
        assert_ne!(
            *key,
            *hkdf32(&[3; 32], &VAULT, b"vault-v0/hardware-key/wrap")
        );
    }
}
