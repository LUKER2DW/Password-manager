//! Key-committing authenticated encryption (spec: CRYPTO.md §5).
//!
//! `seal` output layout: `version (1) ‖ nonce (24) ‖ commitment (32) ‖ ciphertext ‖ tag (16)`.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, Result, random};

pub(crate) const KEY_LEN: usize = 32;
const VERSION: u8 = 0x01;
const NONCE_LEN: usize = 24;
const COMMIT_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 1 + NONCE_LEN + COMMIT_LEN;
/// Bytes added by `seal` on top of the plaintext.
pub(crate) const OVERHEAD: usize = HEADER_LEN + TAG_LEN;

const LABEL_ENC: &[u8] = b"vault-v0/aead/enc";
const LABEL_COMMIT: &[u8] = b"vault-v0/aead/commit";

pub(crate) type Key = [u8; KEY_LEN];

/// Derives the per-message encryption key and the key commitment.
fn derive(key: &Key, nonce: &[u8; NONCE_LEN]) -> (Zeroizing<Key>, [u8; COMMIT_LEN]) {
    let hkdf = Hkdf::<Sha256>::new(Some(nonce), key);
    let mut enc_key = Zeroizing::new([0u8; KEY_LEN]);
    let mut commitment = [0u8; COMMIT_LEN];
    hkdf.expand(LABEL_ENC, enc_key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    hkdf.expand(LABEL_COMMIT, &mut commitment)
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    (enc_key, commitment)
}

fn cipher(enc_key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(enc_key).expect("key length is fixed at 32 bytes")
}

/// Encrypts and authenticates `plaintext`, binding it to `key` and `aad`.
pub(crate) fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; NONCE_LEN] = random::array()?;
    let (enc_key, commitment) = derive(key, &nonce);
    let ciphertext = cipher(&enc_key)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Malformed)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&commitment);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Verifies and decrypts a value produced by [`seal`]. Every failure is reported as
/// [`Error::DecryptionFailed`], without saying which check failed.
pub(crate) fn open(key: &Key, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < OVERHEAD || sealed[0] != VERSION {
        return Err(Error::DecryptionFailed);
    }
    let nonce: [u8; NONCE_LEN] = sealed[1..1 + NONCE_LEN]
        .try_into()
        .expect("slice length checked above");
    let stored_commitment = &sealed[1 + NONCE_LEN..HEADER_LEN];
    let ciphertext = &sealed[HEADER_LEN..];

    let (enc_key, commitment) = derive(key, &nonce);
    if !bool::from(commitment.as_slice().ct_eq(stored_commitment)) {
        return Err(Error::DecryptionFailed);
    }
    cipher(&enc_key)
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Key = [7u8; 32];
    const OTHER_KEY: Key = [8u8; 32];

    #[test]
    fn round_trip() {
        let sealed = seal(&KEY, b"hello vault", b"aad").unwrap();
        assert_eq!(sealed.len(), b"hello vault".len() + OVERHEAD);
        assert_eq!(
            open(&KEY, &sealed, b"aad").unwrap().as_slice(),
            b"hello vault"
        );
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let sealed = seal(&KEY, b"", b"").unwrap();
        assert!(open(&KEY, &sealed, b"").unwrap().is_empty());
    }

    #[test]
    fn nonces_are_unique() {
        let a = seal(&KEY, b"same", b"").unwrap();
        let b = seal(&KEY, b"same", b"").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&KEY, b"secret", b"").unwrap();
        assert!(matches!(
            open(&OTHER_KEY, &sealed, b""),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let sealed = seal(&KEY, b"secret", b"item-1").unwrap();
        assert!(matches!(
            open(&KEY, &sealed, b"item-2"),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn any_flipped_byte_fails() {
        let sealed = seal(&KEY, b"tamper me", b"aad").unwrap();
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 0x01;
            assert!(
                open(&KEY, &tampered, b"aad").is_err(),
                "flipping byte {i} was not detected"
            );
        }
    }

    #[test]
    fn truncated_input_fails() {
        let sealed = seal(&KEY, b"x", b"").unwrap();
        for len in 0..sealed.len() {
            assert!(open(&KEY, &sealed[..len], b"").is_err());
        }
    }
}
