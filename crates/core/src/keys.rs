//! User-held keys (Secret Key, Recovery Key) and the internal key hierarchy
//! (spec: CRYPTO.md §2–§3).

use std::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, KdfParams, Result, aead, encoding, kdf, random};

const SECRET_KEY_LEN: usize = 16;
const RECOVERY_KEY_LEN: usize = 32;
const SECRET_KEY_PREFIX: &str = "S0";
const RECOVERY_KEY_PREFIX: &str = "R0";
const SECRET_KEY_GROUP: usize = 7;
const RECOVERY_KEY_GROUP: usize = 6;
const CHECKSUM_CHARS: usize = 2;

/// 128-bit Secret Key, combined with the master password to derive the vault's
/// key-encryption key. Without it, the master password alone cannot open the vault.
pub struct SecretKey(Zeroizing<[u8; SECRET_KEY_LEN]>);

/// 256-bit Recovery Key printed in the emergency kit. Opens the vault on its own.
pub struct RecoveryKey(Zeroizing<[u8; RECOVERY_KEY_LEN]>);

macro_rules! user_key_impl {
    ($ty:ident, $len:expr, $prefix:expr, $group:expr) => {
        impl $ty {
            /// Generates a new random key.
            pub fn generate() -> Result<Self> {
                random::secret_array::<$len>().map(Self)
            }

            /// Parses the printed form. Case-insensitive; spaces and dashes are ignored.
            pub fn parse(text: &str) -> Result<Self> {
                parse_user_key::<$len>(text, $prefix).map(Self)
            }

            /// The printable form, e.g. for the emergency kit. Wiped on drop.
            pub fn to_display_string(&self) -> Zeroizing<String> {
                format_user_key(self.0.as_ref(), $prefix, $group)
            }

            #[cfg(test)]
            #[allow(dead_code, reason = "not every key type needs it in tests")]
            pub(crate) fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            pub(crate) fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }

        impl PartialEq for $ty {
            fn eq(&self, other: &Self) -> bool {
                self.0.as_slice().ct_eq(other.0.as_slice()).into()
            }
        }

        impl Eq for $ty {}
    };
}

user_key_impl!(
    SecretKey,
    SECRET_KEY_LEN,
    SECRET_KEY_PREFIX,
    SECRET_KEY_GROUP
);
user_key_impl!(
    RecoveryKey,
    RECOVERY_KEY_LEN,
    RECOVERY_KEY_PREFIX,
    RECOVERY_KEY_GROUP
);

impl RecoveryKey {
    /// The printed form is always `R0` followed by this many groups…
    pub const GROUPS: usize =
        (encoding::encoded_len(RECOVERY_KEY_LEN) + CHECKSUM_CHARS) / RECOVERY_KEY_GROUP;
    /// …of this many characters, so it can be written into boxes on paper.
    pub const GROUP_LEN: usize = RECOVERY_KEY_GROUP;
    pub const PREFIX: &'static str = RECOVERY_KEY_PREFIX;
}

/// Top 10 bits of SHA-256("vault-v0/key-checksum" ‖ prefix ‖ key).
fn checksum(prefix: &str, key: &[u8]) -> u16 {
    let digest = Sha256::new()
        .chain_update(b"vault-v0/key-checksum")
        .chain_update(prefix.as_bytes())
        .chain_update(key)
        .finalize();
    (u16::from(digest[0]) << 2) | (u16::from(digest[1]) >> 6)
}

fn format_user_key(key: &[u8], prefix: &str, group: usize) -> Zeroizing<String> {
    let symbols = encoding::encoded_len(key.len()) + CHECKSUM_CHARS;
    let mut body = Zeroizing::new(String::with_capacity(symbols));
    encoding::encode_into(key, &mut body);
    let sum = checksum(prefix, key);
    encoding::push_symbol((sum >> 5) as u8, &mut body);
    encoding::push_symbol((sum & 31) as u8, &mut body);

    let mut out = Zeroizing::new(String::with_capacity(
        prefix.len() + symbols + symbols.div_ceil(group),
    ));
    out.push_str(prefix);
    for (i, c) in body.chars().enumerate() {
        if i % group == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

fn parse_user_key<const N: usize>(text: &str, prefix: &str) -> Result<Zeroizing<[u8; N]>> {
    let mut cleaned = Zeroizing::new(Vec::with_capacity(text.len()));
    for byte in text.bytes() {
        if byte == b'-' || byte.is_ascii_whitespace() {
            continue;
        }
        cleaned.push(byte.to_ascii_uppercase());
    }
    let rest = cleaned
        .strip_prefix(prefix.as_bytes())
        .ok_or(Error::InvalidKeyFormat)?;
    let data_chars = encoding::encoded_len(N);
    if rest.len() != data_chars + CHECKSUM_CHARS {
        return Err(Error::InvalidKeyFormat);
    }
    let bytes = encoding::decode(&rest[..data_chars], N)?;
    let hi = encoding::decode_symbol(rest[data_chars]).ok_or(Error::InvalidKeyFormat)?;
    let lo = encoding::decode_symbol(rest[data_chars + 1]).ok_or(Error::InvalidKeyFormat)?;
    if (u16::from(hi) << 5 | u16::from(lo)) != checksum(prefix, &bytes) {
        return Err(Error::KeyChecksumMismatch);
    }
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// HKDF-SHA-256 with a 32-byte output.
fn hkdf32(ikm: &[u8], salt: &[u8], info: &[&[u8]]) -> Zeroizing<aead::Key> {
    let mut out = Zeroizing::new([0u8; aead::KEY_LEN]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand_multi_info(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    out
}

/// KEK for the password slot: Argon2id(password) combined with the Secret Key.
pub(crate) fn password_kek(
    password: &str,
    secret_key: &SecretKey,
    kdf_params: &KdfParams,
    vault_id: &[u8; 16],
) -> Result<Zeroizing<aead::Key>> {
    let password_key = kdf::derive_password_key(password, kdf_params)?;
    let mut ikm = Zeroizing::new([0u8; 32 + SECRET_KEY_LEN]);
    ikm[..32].copy_from_slice(password_key.as_ref());
    ikm[32..].copy_from_slice(secret_key.as_bytes());
    Ok(hkdf32(ikm.as_ref(), vault_id, &[b"vault-v0/kek/password"]))
}

/// KEK for the recovery slot. No Argon2: the Recovery Key already has 256 bits of entropy.
pub(crate) fn recovery_kek(
    recovery_key: &RecoveryKey,
    vault_id: &[u8; 16],
) -> Zeroizing<aead::Key> {
    hkdf32(
        recovery_key.as_bytes(),
        vault_id,
        &[b"vault-v0/kek/recovery"],
    )
}

/// KEK for a device unlock (Windows Hello and similar). `device_secret` is produced by the
/// device's secure hardware after the user is verified (e.g. a deterministic TPM signature) and
/// is never stored.
pub(crate) fn device_kek(
    device_secret: &[u8],
    vault_id: &[u8; 16],
) -> Result<Zeroizing<aead::Key>> {
    if device_secret.len() < 32 {
        return Err(Error::InvalidKeyFormat);
    }
    Ok(hkdf32(device_secret, vault_id, &[b"vault-v0/kek/device"]))
}

/// The random key that protects the vault contents. Never leaves the process unwrapped.
pub(crate) struct VaultKey(Zeroizing<aead::Key>);

impl VaultKey {
    pub(crate) fn generate() -> Result<Self> {
        random::secret_array().map(Self)
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; aead::KEY_LEN]);
        if bytes.len() != aead::KEY_LEN {
            return Err(Error::Malformed);
        }
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    pub(crate) fn as_bytes(&self) -> &aead::Key {
        &self.0
    }

    /// Purpose-bound subkey: HKDF(vault_key, salt = vault_id, info = "vault-v0/subkey/" ‖ purpose).
    pub(crate) fn subkey(&self, purpose: &[u8], vault_id: &[u8; 16]) -> Zeroizing<aead::Key> {
        hkdf32(self.0.as_ref(), vault_id, &[b"vault-v0/subkey/", purpose])
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_text_round_trip() {
        let key = SecretKey::generate().unwrap();
        let text = key.to_display_string();
        assert!(text.starts_with("S0-"));
        // "S0" + 4 groups of (dash + 7 chars)
        assert_eq!(text.len(), 2 + 4 * 8);
        assert_eq!(SecretKey::parse(&text).unwrap(), key);
        assert_eq!(SecretKey::parse(&text.to_lowercase()).unwrap(), key);
        assert_eq!(SecretKey::parse(&text.replace('-', " ")).unwrap(), key);
    }

    #[test]
    fn recovery_key_text_round_trip() {
        let key = RecoveryKey::generate().unwrap();
        let text = key.to_display_string();
        assert!(text.starts_with("R0-"));
        // "R0" + 9 groups of (dash + 6 chars)
        assert_eq!(text.len(), 2 + 9 * 7);
        assert_eq!(RecoveryKey::parse(&text).unwrap(), key);
    }

    #[test]
    fn typo_is_caught_by_checksum() {
        let key = SecretKey::from_bytes([0x5A; 16]);
        let text = key.to_display_string();
        // Change one data character (position 3 is the first char after "S0-").
        let mut typo = text.to_string().into_bytes();
        typo[3] = if typo[3] == b'A' { b'B' } else { b'A' };
        let typo = String::from_utf8(typo).unwrap();
        assert!(matches!(
            SecretKey::parse(&typo),
            Err(Error::KeyChecksumMismatch)
        ));
    }

    #[test]
    fn wrong_kind_or_length_is_rejected() {
        let secret = SecretKey::generate().unwrap().to_display_string();
        assert!(matches!(
            RecoveryKey::parse(&secret),
            Err(Error::InvalidKeyFormat)
        ));
        assert!(matches!(
            SecretKey::parse("S0-ABC"),
            Err(Error::InvalidKeyFormat)
        ));
        assert!(matches!(SecretKey::parse(""), Err(Error::InvalidKeyFormat)));
    }

    #[test]
    fn debug_does_not_leak() {
        let key = SecretKey::from_bytes([0xAA; 16]);
        assert_eq!(format!("{key:?}"), "SecretKey(<redacted>)");
    }

    #[test]
    fn subkeys_are_purpose_and_vault_bound() {
        let vault_key = VaultKey::from_slice(&[1u8; 32]).unwrap();
        let a = vault_key.subkey(b"body", &[0u8; 16]);
        let b = vault_key.subkey(b"item-wrap", &[0u8; 16]);
        let c = vault_key.subkey(b"body", &[1u8; 16]);
        assert_ne!(*a, *b);
        assert_ne!(*a, *c);
    }
}
