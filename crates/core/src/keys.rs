//! User-held keys (Secret Key, recovery parts, Recovery Key) and the internal key hierarchy
//! (spec: CRYPTO.md §2–§3).

use std::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, PasswordKdf, Result, aead, encoding, memory::ShieldedKey, random};

const SECRET_KEY_LEN: usize = 16;
const RECOVERY_KEY_LEN: usize = 32;
const SECRET_KEY_PREFIX: &str = "S0";
const RECOVERY_KEY_PREFIX: &str = "R0";
const SECRET_KEY_GROUP: usize = 7;
const PART_LEN: usize = 16;
const PART_GROUP: usize = 7;
const RECOVERY_KEY_GROUP: usize = 6;
const CHECKSUM_CHARS: usize = 2;

/// 128-bit Secret Key, combined with the master password to derive the vault's
/// key-encryption key. Without it, the master password alone cannot open the vault.
pub struct SecretKey(Zeroizing<[u8; SECRET_KEY_LEN]>);

/// 256-bit Recovery Key printed in emergency kits made before format v8. Opens the vault on
/// its own. New kits use [`RecoveryParts`] instead.
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

impl SecretKey {
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; SECRET_KEY_LEN]);
        if bytes.len() != SECRET_KEY_LEN {
            return Err(Error::Malformed);
        }
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// Which of the three recovery parts (CRYPTO.md §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PartLabel {
    A,
    B,
    C,
}

impl PartLabel {
    pub const ALL: [PartLabel; 3] = [PartLabel::A, PartLabel::B, PartLabel::C];

    /// The printed prefix: the part's letter and the scheme's version, e.g. `A0`.
    pub fn prefix(self) -> &'static str {
        match self {
            PartLabel::A => "A0",
            PartLabel::B => "B0",
            PartLabel::C => "C0",
        }
    }

    pub fn letter(self) -> char {
        match self {
            PartLabel::A => 'A',
            PartLabel::B => 'B',
            PartLabel::C => 'C',
        }
    }
}

/// One of the three recovery parts of an emergency kit (format v8): 128 random bits. One part
/// alone reveals nothing; any two bring back the Secret Key; all three open the vault, so a
/// forgotten master password can be replaced.
pub struct RecoveryPart {
    label: PartLabel,
    key: Zeroizing<[u8; PART_LEN]>,
}

impl RecoveryPart {
    /// The printed form is the prefix followed by this many groups…
    pub const GROUPS: usize = (encoding::encoded_len(PART_LEN) + CHECKSUM_CHARS) / PART_GROUP;
    /// …of this many characters.
    pub const GROUP_LEN: usize = PART_GROUP;
    /// Bytes of a part, as kept in a file of its own (the picture).
    pub const LEN: usize = PART_LEN;

    fn generate(label: PartLabel) -> Result<Self> {
        Ok(Self {
            label,
            key: random::secret_array::<PART_LEN>()?,
        })
    }

    /// Parses the printed form (`A0-…`, `B0-…` or `C0-…`). Case-insensitive; spaces and
    /// dashes are ignored; a typo is caught by the checksum.
    pub fn parse(text: &str) -> Result<Self> {
        let first = text
            .bytes()
            .find(|b| *b != b'-' && !b.is_ascii_whitespace())
            .map(|b| b.to_ascii_uppercase());
        let label = match first {
            Some(b'A') => PartLabel::A,
            Some(b'B') => PartLabel::B,
            Some(b'C') => PartLabel::C,
            _ => return Err(Error::InvalidKeyFormat),
        };
        parse_user_key::<PART_LEN>(text, label.prefix()).map(|key| Self { label, key })
    }

    /// The printable form, e.g. for the emergency kit. Wiped on drop.
    pub fn to_display_string(&self) -> Zeroizing<String> {
        format_user_key(self.key.as_ref(), self.label.prefix(), PART_GROUP)
    }

    pub fn label(&self) -> PartLabel {
        self.label
    }

    /// The part's bytes, to keep it in a file of its own. Wiped on drop.
    pub fn to_bytes(&self) -> Zeroizing<[u8; PART_LEN]> {
        self.key.clone()
    }

    /// A part read back from a file of its own.
    pub fn from_bytes(label: PartLabel, bytes: &[u8]) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; PART_LEN]);
        if bytes.len() != PART_LEN {
            return Err(Error::InvalidKeyFormat);
        }
        key.copy_from_slice(bytes);
        Ok(Self { label, key })
    }

    fn as_bytes(&self) -> &[u8; PART_LEN] {
        &self.key
    }
}

impl fmt::Debug for RecoveryPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoveryPart({}, <redacted>)", self.label.letter())
    }
}

impl PartialEq for RecoveryPart {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label && bool::from(self.key.as_slice().ct_eq(other.key.as_slice()))
    }
}

impl Eq for RecoveryPart {}

/// The three recovery parts of one kit, A, B and C.
#[derive(Debug)]
pub struct RecoveryParts([RecoveryPart; 3]);

impl RecoveryParts {
    pub fn generate() -> Result<Self> {
        Ok(Self([
            RecoveryPart::generate(PartLabel::A)?,
            RecoveryPart::generate(PartLabel::B)?,
            RecoveryPart::generate(PartLabel::C)?,
        ]))
    }

    pub fn part(&self, label: PartLabel) -> &RecoveryPart {
        &self.0[label as usize]
    }

    pub(crate) fn all(&self) -> [&RecoveryPart; 3] {
        [&self.0[0], &self.0[1], &self.0[2]]
    }
}

/// The three parts in order A, B, C; refused unless there is exactly one of each.
pub(crate) fn ordered_parts(parts: [&RecoveryPart; 3]) -> Result<[&RecoveryPart; 3]> {
    let mut sorted = parts;
    sorted.sort_by_key(|part| part.label);
    if sorted.iter().map(|part| part.label).ne(PartLabel::ALL) {
        return Err(Error::InvalidKeyFormat);
    }
    Ok(sorted)
}

/// Which pair two parts are, as an index into the header's pair wraps (AB 0, AC 1, BC 2), and
/// the two in order; refused when both are the same part.
pub(crate) fn ordered_pair<'a>(
    first: &'a RecoveryPart,
    second: &'a RecoveryPart,
) -> Result<(usize, &'a RecoveryPart, &'a RecoveryPart)> {
    let (x, y) = if first.label <= second.label {
        (first, second)
    } else {
        (second, first)
    };
    let index = match (x.label, y.label) {
        (PartLabel::A, PartLabel::B) => 0,
        (PartLabel::A, PartLabel::C) => 1,
        (PartLabel::B, PartLabel::C) => 2,
        _ => return Err(Error::InvalidKeyFormat),
    };
    Ok((index, x, y))
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

/// A keyfile: an optional third factor next to the master password and the Secret Key. Any
/// file works; what counts is a SHA-256 of its exact bytes, so the file must never change.
/// Kept apart from the vault (a USB stick), it means a stolen vault file, password and Secret
/// Key still open nothing.
#[derive(Clone)]
pub struct Keyfile(Zeroizing<[u8; 32]>);

impl Keyfile {
    /// Largest file accepted (1 MiB): a keyfile is a key, not a document.
    pub const MAX_LEN: usize = 1024 * 1024;
    /// Smallest file accepted: fewer bytes can't hold a key worth having.
    pub const MIN_LEN: usize = 16;

    /// Reads a keyfile's bytes (the whole file, unchanged).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if !(Self::MIN_LEN..=Self::MAX_LEN).contains(&bytes.len()) {
            return Err(Error::InvalidKeyFormat);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"vault-v0/keyfile");
        hasher.update(bytes);
        Ok(Self(Zeroizing::new(hasher.finalize().into())))
    }

    /// A new keyfile: the key and the bytes to write to the file (a line of text holding 256
    /// random bits, so it can also be printed and typed back into a file).
    pub fn generate() -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let random: Zeroizing<[u8; 32]> = Zeroizing::new(crate::random::array()?);
        let mut text = Zeroizing::new(String::with_capacity(96));
        text.push_str("vault-keyfile-v1 ");
        for byte in random.iter() {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
        }
        text.push('\n');
        let bytes = Zeroizing::new(text.as_bytes().to_vec());
        Ok((Self::from_bytes(&bytes)?, bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Keyfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keyfile(<redacted>)")
    }
}

/// KEK for the password slot: Argon2id(password) combined with the Secret Key, and with the
/// keyfile when the vault uses one (a different HKDF label, so the two can't be confused).
pub(crate) fn password_kek(
    password: &str,
    secret_key: &SecretKey,
    keyfile: Option<&Keyfile>,
    kdf: &PasswordKdf,
    vault_id: &[u8; 16],
) -> Result<Zeroizing<aead::Key>> {
    let password_key = kdf.derive(password)?;
    let mut ikm = Zeroizing::new([0u8; 32 + SECRET_KEY_LEN + 32]);
    ikm[..32].copy_from_slice(password_key.as_ref());
    ikm[32..32 + SECRET_KEY_LEN].copy_from_slice(secret_key.as_bytes());
    match keyfile {
        None => Ok(hkdf32(
            &ikm[..32 + SECRET_KEY_LEN],
            vault_id,
            &[b"vault-v0/kek/password"],
        )),
        Some(keyfile) => {
            ikm[32 + SECRET_KEY_LEN..].copy_from_slice(keyfile.as_bytes());
            Ok(hkdf32(
                ikm.as_ref(),
                vault_id,
                &[b"vault-v0/kek/password+keyfile"],
            ))
        }
    }
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

/// KEK for the vault key from all three recovery parts (A ‖ B ‖ C, 384 random bits, so no
/// Argon2), bound to this vault and this kit.
pub(crate) fn parts_kek(
    parts: [&RecoveryPart; 3],
    vault_id: &[u8; 16],
    kit_id: &[u8; 16],
) -> Zeroizing<aead::Key> {
    let mut ikm = Zeroizing::new([0u8; 3 * PART_LEN]);
    for (index, part) in parts.iter().enumerate() {
        ikm[index * PART_LEN..(index + 1) * PART_LEN].copy_from_slice(part.as_bytes());
    }
    hkdf32(ikm.as_ref(), vault_id, &[b"vault-v0/kek/parts", kit_id])
}

/// KEK that one pair of parts opens (`first` before `second`, as [`ordered_pair`] gives them).
pub(crate) fn pair_kek(
    first: &RecoveryPart,
    second: &RecoveryPart,
    vault_id: &[u8; 16],
    kit_id: &[u8; 16],
) -> Zeroizing<aead::Key> {
    let mut ikm = Zeroizing::new([0u8; 2 * PART_LEN]);
    ikm[..PART_LEN].copy_from_slice(first.as_bytes());
    ikm[PART_LEN..].copy_from_slice(second.as_bytes());
    let pair = [first.label.letter() as u8, second.label.letter() as u8];
    hkdf32(
        ikm.as_ref(),
        vault_id,
        &[b"vault-v0/kek/parts-pair/", &pair, kit_id],
    )
}

/// Key that seals the Secret Key in the header, from the random pair key every pair opens.
pub(crate) fn parts_secret_key_key(
    pair_key: &[u8],
    vault_id: &[u8; 16],
    kit_id: &[u8; 16],
) -> Zeroizing<aead::Key> {
    hkdf32(
        pair_key,
        vault_id,
        &[b"vault-v0/key/parts-secret-key", kit_id],
    )
}

/// KEK that wraps the item guard key. `stretched` is Argon2id of the PIN, guard password or
/// master password, with the wrapped key's own salt.
pub(crate) fn guard_kek(stretched: &[u8; 32], vault_id: &[u8; 16]) -> Zeroizing<aead::Key> {
    hkdf32(stretched, vault_id, &[b"vault-v0/kek/guard"])
}

/// Key of a password-protected export, from Argon2id of its password.
pub(crate) fn export_key(stretched: &[u8; 32]) -> Zeroizing<aead::Key> {
    hkdf32(stretched, b"vault-v0/export", &[b"vault-v0/key/export"])
}

/// KEK that wraps the item guard key for this device (Windows Hello and similar), from the
/// secret the device's secure hardware produces after verifying the user.
pub(crate) fn guard_device_kek(
    device_secret: &[u8],
    vault_id: &[u8; 16],
) -> Result<Zeroizing<aead::Key>> {
    if device_secret.len() < 32 {
        return Err(Error::InvalidKeyFormat);
    }
    Ok(hkdf32(
        device_secret,
        vault_id,
        &[b"vault-v0/kek/guard-device"],
    ))
}

/// KEK for the blob the browser extension fills from while the vault is locked
/// (`locked_fill`), from the device's user verification (Windows Hello).
pub(crate) fn locked_fill_kek(
    device_secret: &[u8],
    vault_id: &str,
) -> Result<Zeroizing<aead::Key>> {
    if device_secret.len() < 32 {
        return Err(Error::InvalidKeyFormat);
    }
    Ok(hkdf32(
        device_secret,
        vault_id.as_bytes(),
        &[b"vault-v0/kek/locked-fill"],
    ))
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

/// The random key that protects the vault contents. Never leaves the process unwrapped, and
/// stays encrypted between uses when the program installed a key shield (`memory.rs`).
pub(crate) struct VaultKey(ShieldedKey);

impl VaultKey {
    pub(crate) fn generate() -> Result<Self> {
        random::secret_array().map(|key| Self(ShieldedKey::new(key)))
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; aead::KEY_LEN]);
        if bytes.len() != aead::KEY_LEN {
            return Err(Error::Malformed);
        }
        key.copy_from_slice(bytes);
        Ok(Self(ShieldedKey::new(key)))
    }

    /// The key itself, in a copy wiped when dropped: for the moment it is used.
    pub(crate) fn open(&self) -> Zeroizing<aead::Key> {
        self.0.open()
    }

    /// A second copy, to open another copy of the same vault with (sync).
    pub(crate) fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }

    /// Purpose-bound subkey: HKDF(vault_key, salt = vault_id, info = "vault-v0/subkey/" ‖ purpose).
    pub(crate) fn subkey(&self, purpose: &[u8], vault_id: &[u8; 16]) -> Zeroizing<aead::Key> {
        hkdf32(
            self.open().as_ref(),
            vault_id,
            &[b"vault-v0/subkey/", purpose],
        )
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
    fn recovery_parts_text_round_trip() {
        let parts = RecoveryParts::generate().unwrap();
        for label in PartLabel::ALL {
            let part = parts.part(label);
            let text = part.to_display_string();
            assert!(text.starts_with(&format!("{}-", label.prefix())));
            // prefix + 4 groups of (dash + 7 chars), like the Secret Key
            assert_eq!(text.len(), 2 + 4 * 8);
            assert_eq!(RecoveryPart::GROUPS, 4);
            let parsed = RecoveryPart::parse(&text.to_lowercase()).unwrap();
            assert_eq!(&parsed, part);
            assert_eq!(parsed.label(), label);
            let back = RecoveryPart::from_bytes(label, part.to_bytes().as_ref()).unwrap();
            assert_eq!(&back, part);
        }
        assert_ne!(parts.part(PartLabel::A), parts.part(PartLabel::B));
        // A part relabelled as another fails its checksum.
        let a = parts.part(PartLabel::A).to_display_string();
        assert!(RecoveryPart::parse(&a.replacen('A', "B", 1)).is_err());
        assert!(matches!(
            RecoveryPart::parse("S0-ABC"),
            Err(Error::InvalidKeyFormat)
        ));
        assert_eq!(
            format!("{:?}", parts.part(PartLabel::C)),
            "RecoveryPart(C, <redacted>)"
        );
    }

    #[test]
    fn parts_are_taken_in_any_order_but_once_each() {
        let parts = RecoveryParts::generate().unwrap();
        let [a, b, c] = parts.all();
        assert_eq!(ordered_parts([c, a, b]).unwrap(), [a, b, c]);
        assert!(ordered_parts([a, a, b]).is_err());
        assert_eq!(ordered_pair(c, a).unwrap().0, 1);
        assert_eq!(ordered_pair(b, c).unwrap().0, 2);
        assert!(ordered_pair(b, b).is_err());
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
