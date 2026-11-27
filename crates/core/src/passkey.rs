//! Passkeys: WebAuthn credentials kept in login items (format v10).
//!
//! A passkey is a P-256 key pair made for one site, named by its relying party id (`rp_id`,
//! a domain such as `example.com`). The private half stays in the vault, with the item's
//! secrets, so the item lock covers it like a password. When the person signs in, it signs
//! the site's challenge with ES256 (ECDSA over P-256 with SHA-256, deterministic nonces per
//! RFC 6979, from the RustCrypto `p256` crate). The site keeps only the public half.
//!
//! This module makes the bytes an authenticator hands a site (WebAuthn Level 3 §6.1, §6.5):
//! authenticator data, the COSE public key, a `none` attestation object, and the assertion
//! signature. Which page may use which `rp_id` is decided by the browser link
//! (`vault-browser`), not here.
//!
//! Passkeys made here carry no sign counter (always 0, which tells the site there is none):
//! the same passkey lives in every synced copy of the vault, so a counter could never be kept
//! in step, and signing never has to write the vault.

use std::fmt;

use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// The COSE number of ES256, the only algorithm passkeys are made with here.
pub const ES256: i64 = -7;

/// Authenticator data flags (WebAuthn §6.1).
pub mod flags {
    /// The person was there (clicked to allow it).
    pub const USER_PRESENT: u8 = 0x01;
    /// The person was verified (the vault was unlocked, and the item lock passed when it
    /// covers the login).
    pub const USER_VERIFIED: u8 = 0x04;
    /// The passkey can be backed up (it lives in a vault file that is copied and synced).
    pub const BACKUP_ELIGIBLE: u8 = 0x08;
    /// It is backed up.
    pub const BACKED_UP: u8 = 0x10;
    /// Attested credential data follows (only when the passkey is made).
    pub const ATTESTED: u8 = 0x40;
}

/// What a passkey made here tells the site about itself: present, verified, backed up.
pub const FLAGS: u8 =
    flags::USER_PRESENT | flags::USER_VERIFIED | flags::BACKUP_ELIGIBLE | flags::BACKED_UP;

/// One passkey of a login. Wiped from memory when dropped.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Passkey {
    /// The credential's id, as the site knows it (16 random bytes for passkeys made here).
    pub credential_id: Vec<u8>,
    /// The site it belongs to (the relying party id: a domain, in its ASCII form).
    pub rp_id: String,
    /// The site's id for the account (opaque bytes, at most 64).
    pub user_handle: Vec<u8>,
    /// The account's name at the site (often an email address).
    pub user_name: String,
    /// The name the site shows for the account.
    pub display_name: String,
    /// Unix seconds.
    pub created_at: i64,
    /// The P-256 private key (a 32-byte big-endian scalar). Empty while the item is locked.
    pub(crate) key: Vec<u8>,
}

impl Passkey {
    /// At most this many passkeys per login.
    pub const MAX_PER_ITEM: usize = 16;
    /// Longest credential id (WebAuthn §5.1: 1023 bytes).
    pub const MAX_CREDENTIAL_ID: usize = 1023;
    /// Longest user handle (WebAuthn §5.4.3: 64 bytes).
    pub const MAX_USER_HANDLE: usize = 64;
    /// Longest relying party id (a domain name).
    pub const MAX_RP_ID: usize = 253;
    /// Longest user name or display name, in characters.
    pub const MAX_NAME_CHARS: usize = 256;

    /// A new passkey for `rp_id` and the account `user_handle`, with a fresh key pair and a
    /// random 16-byte credential id.
    pub fn new(
        rp_id: &str,
        user_handle: &[u8],
        user_name: &str,
        display_name: &str,
    ) -> Result<Self> {
        // A random 32-byte string is a valid P-256 scalar except with a chance of about 2^-32.
        let mut key = None;
        for _ in 0..8 {
            let bytes = crate::random::secret_array::<32>()?;
            if SigningKey::from_slice(bytes.as_ref()).is_ok() {
                key = Some(bytes.to_vec());
                break;
            }
        }
        let passkey = Self {
            credential_id: crate::random::array::<16>()?.to_vec(),
            rp_id: rp_id.to_owned(),
            user_handle: user_handle.to_vec(),
            user_name: user_name.to_owned(),
            display_name: display_name.to_owned(),
            created_at: crate::item::unix_now(),
            key: key.ok_or(Error::Rng)?,
        };
        if !passkey.fits() {
            return Err(Error::Malformed);
        }
        Ok(passkey)
    }

    /// A passkey from its parts, such as one kept by another manager: `key` is its 32-byte
    /// P-256 private scalar.
    pub fn from_parts(
        credential_id: &[u8],
        rp_id: &str,
        user_handle: &[u8],
        user_name: &str,
        display_name: &str,
        created_at: i64,
        key: &[u8],
    ) -> Result<Self> {
        let passkey = Self {
            credential_id: credential_id.to_vec(),
            rp_id: rp_id.to_owned(),
            user_handle: user_handle.to_vec(),
            user_name: user_name.to_owned(),
            display_name: display_name.to_owned(),
            created_at,
            key: key.to_vec(),
        };
        if key.is_empty() || !passkey.fits() {
            return Err(Error::Malformed);
        }
        Ok(passkey)
    }

    /// Whether its private key is here (not while the item is locked).
    pub fn has_key(&self) -> bool {
        !self.key.is_empty()
    }

    /// Its private key, the 32-byte P-256 scalar (empty while the item is locked). Only for
    /// sealing it again under another key, as the export under a password of its own does
    /// (CRYPTO.md §3.3); [`Passkey::from_parts`] takes it back.
    pub fn private_key(&self) -> &[u8] {
        &self.key
    }

    /// Whether it keeps to the limits above, and its key (when there) is a P-256 key.
    pub(crate) fn fits(&self) -> bool {
        !self.credential_id.is_empty()
            && self.credential_id.len() <= Self::MAX_CREDENTIAL_ID
            && self.user_handle.len() <= Self::MAX_USER_HANDLE
            && !self.rp_id.is_empty()
            && self.rp_id.len() <= Self::MAX_RP_ID
            && self.user_name.chars().count() <= Self::MAX_NAME_CHARS
            && self.display_name.chars().count() <= Self::MAX_NAME_CHARS
            && (self.key.is_empty() || SigningKey::from_slice(&self.key).is_ok())
    }

    fn signing_key(&self) -> Result<SigningKey> {
        if self.key.is_empty() {
            return Err(Error::SecretsLocked);
        }
        SigningKey::from_slice(&self.key).map_err(|_| Error::Malformed)
    }

    /// The public key as an uncompressed SEC1 point (`04 || x || y`).
    pub fn public_key(&self) -> Result<[u8; 65]> {
        let point = self.signing_key()?.verifying_key().to_sec1_point(false);
        point.as_bytes().try_into().map_err(|_| Error::Malformed)
    }

    /// The public key as a COSE key (RFC 9053 §7.1.1), the form the site stores.
    pub fn cose_key(&self) -> Result<Vec<u8>> {
        let point = self.public_key()?;
        let mut out = Vec::with_capacity(77);
        cbor::map(&mut out, 5);
        // Keys in CTAP2's canonical order: 1, 3, -1, -2, -3.
        cbor::int(&mut out, 1); // kty
        cbor::int(&mut out, 2); // EC2
        cbor::int(&mut out, 3); // alg
        cbor::int(&mut out, ES256);
        cbor::int(&mut out, -1); // crv
        cbor::int(&mut out, 1); // P-256
        cbor::int(&mut out, -2); // x
        cbor::bytes(&mut out, &point[1..33]);
        cbor::int(&mut out, -3); // y
        cbor::bytes(&mut out, &point[33..65]);
        Ok(out)
    }

    /// The public key as a DER SubjectPublicKeyInfo (what `getPublicKey()` gives a page).
    pub fn spki(&self) -> Result<Vec<u8>> {
        // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (point) }
        const PREFIX: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let mut out = PREFIX.to_vec();
        out.extend_from_slice(&self.public_key()?);
        Ok(out)
    }

    /// The authenticator data for this passkey, with the attested credential data when it is
    /// being made (`attest`).
    pub fn authenticator_data(&self, attest: bool) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(if attest { 140 } else { 37 });
        out.extend_from_slice(&Sha256::digest(self.rp_id.as_bytes()));
        out.push(if attest {
            FLAGS | flags::ATTESTED
        } else {
            FLAGS
        });
        out.extend_from_slice(&0u32.to_be_bytes());
        if attest {
            // No attestation: the authenticator's model id (AAGUID) is all zeros.
            out.extend_from_slice(&[0; 16]);
            let length = u16::try_from(self.credential_id.len()).map_err(|_| Error::Malformed)?;
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(&self.credential_id);
            out.extend_from_slice(&self.cose_key()?);
        }
        Ok(out)
    }

    /// The signature a site checks: ES256 over `authenticator_data || client_data_hash`,
    /// DER-encoded.
    pub fn sign(&self, authenticator_data: &[u8], client_data_hash: &[u8; 32]) -> Result<Vec<u8>> {
        let key = self.signing_key()?;
        let mut message = Vec::with_capacity(authenticator_data.len() + 32);
        message.extend_from_slice(authenticator_data);
        message.extend_from_slice(client_data_hash);
        let signature: Signature = key.sign(&message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

impl fmt::Debug for Passkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passkey")
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("created_at", &self.created_at)
            .field(
                "key",
                &if self.key.is_empty() {
                    ""
                } else {
                    "<redacted>"
                },
            )
            .finish_non_exhaustive()
    }
}

/// The attestation object of a passkey being made: no attestation (`fmt` "none"), only the
/// authenticator data.
pub fn attestation_object(authenticator_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(authenticator_data.len() + 32);
    cbor::map(&mut out, 3);
    // Canonical order: shorter keys first.
    cbor::text(&mut out, "fmt");
    cbor::text(&mut out, "none");
    cbor::text(&mut out, "attStmt");
    cbor::map(&mut out, 0);
    cbor::text(&mut out, "authData");
    cbor::bytes(&mut out, authenticator_data);
    out
}

/// Whether `signature` (DER) is a valid ES256 signature of `message` by the SEC1 public key
/// `public_key`, as a site would check it.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(public_key),
        Signature::from_der(signature),
    ) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

/// The few CBOR items (RFC 8949) the bytes above need, written in their shortest form.
mod cbor {
    fn head(out: &mut Vec<u8>, major: u8, value: u64) {
        let major = major << 5;
        if let Ok(small) = u8::try_from(value) {
            if small < 24 {
                out.push(major | small);
            } else {
                out.extend_from_slice(&[major | 24, small]);
            }
        } else if let Ok(value) = u16::try_from(value) {
            out.push(major | 25);
            out.extend_from_slice(&value.to_be_bytes());
        } else if let Ok(value) = u32::try_from(value) {
            out.push(major | 26);
            out.extend_from_slice(&value.to_be_bytes());
        } else {
            out.push(major | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }

    pub(super) fn int(out: &mut Vec<u8>, value: i64) {
        match u64::try_from(value) {
            Ok(positive) => head(out, 0, positive),
            // -1 - n is written as n.
            Err(_) => head(out, 1, value.unsigned_abs() - 1),
        }
    }

    pub(super) fn bytes(out: &mut Vec<u8>, data: &[u8]) {
        head(out, 2, data.len() as u64);
        out.extend_from_slice(data);
    }

    pub(super) fn text(out: &mut Vec<u8>, text: &str) {
        head(out, 3, text.len() as u64);
        out.extend_from_slice(text.as_bytes());
    }

    pub(super) fn map(out: &mut Vec<u8>, pairs: u64) {
        head(out, 5, pairs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_is_written_in_its_shortest_form() {
        let mut out = Vec::new();
        for value in [0, 23, 24, 255, 256, -1, -7, -24, -25] {
            cbor::int(&mut out, value);
        }
        assert_eq!(
            out,
            [
                0x00, 0x17, 0x18, 0x18, 0x18, 0xff, 0x19, 0x01, 0x00, 0x20, 0x26, 0x37, 0x38, 0x18
            ]
        );
        let mut text = Vec::new();
        cbor::text(&mut text, "fmt");
        assert_eq!(text, b"\x63fmt");
    }

    #[test]
    fn a_new_passkey_signs_what_a_site_checks() {
        let passkey = Passkey::new("example.com", b"user-1", "me@example.com", "Me").unwrap();
        assert_eq!(passkey.credential_id.len(), 16);
        assert!(passkey.has_key() && passkey.fits());
        let public = passkey.public_key().unwrap();
        assert_eq!(public[0], 0x04);

        // The COSE key holds the same point.
        let cose = passkey.cose_key().unwrap();
        assert_eq!(
            &cose[..10],
            &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        assert_eq!(&cose[10..42], &public[1..33]);
        assert_eq!(&cose[42..45], &[0x22, 0x58, 0x20]);
        assert_eq!(&cose[45..], &public[33..]);
        let spki = passkey.spki().unwrap();
        assert_eq!((spki.len(), &spki[26..]), (91, &public[..]));

        // Made: attested data with the credential id and key; signing in: 37 bytes.
        let made = passkey.authenticator_data(true).unwrap();
        assert_eq!(&made[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(made[32], 0x5d);
        assert_eq!(&made[33..37], &[0, 0, 0, 0], "no sign counter");
        assert_eq!(&made[53..55], &[0, 16]);
        assert_eq!(&made[55..71], passkey.credential_id.as_slice());
        assert_eq!(&made[71..], cose.as_slice());
        let attestation = attestation_object(&made);
        assert!(attestation.starts_with(b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58"));
        assert!(attestation.ends_with(&made));

        let data = passkey.authenticator_data(false).unwrap();
        assert_eq!((data.len(), data[32]), (37, 0x1d));
        let hash: [u8; 32] = Sha256::digest(b"{\"type\":\"webauthn.get\"}").into();
        let signature = passkey.sign(&data, &hash).unwrap();
        let mut message = data.clone();
        message.extend_from_slice(&hash);
        assert!(verify(&public, &message, &signature));
        message[0] ^= 1;
        assert!(!verify(&public, &message, &signature), "another message");
        let other = Passkey::new("example.com", b"user-1", "me", "").unwrap();
        assert_ne!(other.credential_id, passkey.credential_id);
        assert!(!verify(&other.public_key().unwrap(), &message, &signature));
    }

    #[test]
    fn a_locked_passkey_signs_nothing_and_says_nothing_of_its_key() {
        let mut passkey = Passkey::new("example.com", b"u", "me", "").unwrap();
        assert!(format!("{passkey:?}").contains("<redacted>"));
        passkey.key.clear();
        assert!(!passkey.has_key());
        assert!(matches!(
            passkey.sign(&[], &[0; 32]),
            Err(Error::SecretsLocked)
        ));
        assert!(passkey.public_key().is_err());
    }

    #[test]
    fn limits_are_kept() {
        let ok = Passkey::new("example.com", &[1; 64], "me", "").unwrap();
        assert!(ok.fits());
        assert!(Passkey::new("example.com", &[1; 65], "me", "").is_err());
        assert!(Passkey::new("", b"u", "me", "").is_err());
        let mut bad = ok.clone();
        bad.key = vec![0; 32]; // zero is not a valid scalar
        assert!(!bad.fits());
        let mut long = ok;
        long.user_name = "x".repeat(257);
        assert!(!long.fits());
    }
}
