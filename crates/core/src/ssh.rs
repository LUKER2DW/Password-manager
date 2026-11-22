//! SSH keys kept as items (format v9, [`ItemKind::SshKey`](crate::ItemKind::SshKey)): the
//! private key where a login keeps its password, the public key and its fingerprint in fields.
//!
//! A new key is Ed25519, made with `ed25519-dalek` and written in OpenSSH's own format,
//! without a passphrase (the vault is its protection). A key brought in (pasted or read from a
//! file) is kept exactly as it is: only its public half is read, which OpenSSH stores in the
//! clear even in an encrypted key, to show the public key and the fingerprint.

use zeroize::Zeroizing;

use crate::{Result, random};

/// The fields an SSH key item keeps besides its private key.
pub const PUBLIC_KEY_FIELD: &str = "Public key";
pub const FINGERPRINT_FIELD: &str = "Fingerprint";

const MAGIC: &[u8] = b"openssh-key-v1\0";
const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";
const ED25519: &str = "ssh-ed25519";

/// A key pair as text, the way OpenSSH writes it.
pub struct SshKeyPair {
    /// `-----BEGIN OPENSSH PRIVATE KEY-----` …
    pub private_key: Zeroizing<String>,
    /// `ssh-ed25519 AAAA… comment`
    pub public_key: String,
    /// `SHA256:…`, as `ssh-keygen -l` shows it.
    pub fingerprint: String,
}

impl std::fmt::Debug for SshKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKeyPair")
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A new Ed25519 key, with `comment` (often `user@host`) in both halves.
pub fn generate_ed25519(comment: &str) -> Result<SshKeyPair> {
    let seed = random::secret_array::<32>()?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public = signing.verifying_key().to_bytes();

    let mut blob = Vec::new();
    put_string(&mut blob, ED25519.as_bytes());
    put_string(&mut blob, &public);

    // The private section: a check number twice, the key, the comment, padding to 8 bytes.
    let check: [u8; 4] = random::array()?;
    let mut private = Zeroizing::new(Vec::with_capacity(256));
    private.extend_from_slice(&check);
    private.extend_from_slice(&check);
    put_string(&mut private, ED25519.as_bytes());
    put_string(&mut private, &public);
    let mut pair = Zeroizing::new([0u8; 64]);
    pair[..32].copy_from_slice(seed.as_ref());
    pair[32..].copy_from_slice(&public);
    put_string(&mut private, pair.as_ref());
    put_string(&mut private, comment.as_bytes());
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }

    let mut file = Zeroizing::new(Vec::with_capacity(512));
    file.extend_from_slice(MAGIC);
    put_string(&mut file, b"none");
    put_string(&mut file, b"none");
    put_string(&mut file, b"");
    file.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut file, &blob);
    put_string(&mut file, &private);

    let encoded = Zeroizing::new(base64::encode(&file));
    let mut text = Zeroizing::new(String::with_capacity(encoded.len() + 128));
    text.push_str(BEGIN);
    text.push('\n');
    for line in encoded.as_bytes().chunks(70) {
        text.push_str(std::str::from_utf8(line).unwrap_or_default());
        text.push('\n');
    }
    text.push_str(END);
    text.push('\n');

    let public_key = public_line(&blob, comment);
    let fingerprint = fingerprint_of_blob(&blob);
    Ok(SshKeyPair {
        private_key: text,
        public_key,
        fingerprint,
    })
}

fn public_line(blob: &[u8], comment: &str) -> String {
    let kind = read_string(blob, &mut 0)
        .and_then(|kind| std::str::from_utf8(kind).ok())
        .unwrap_or(ED25519);
    let mut line = format!("{kind} {}", base64::encode(blob));
    if !comment.trim().is_empty() {
        line.push(' ');
        line.push_str(comment.trim());
    }
    line
}

fn fingerprint_of_blob(blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("SHA256:{}", base64::encode_unpadded(&Sha256::digest(blob)))
}

fn read_string<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let len = bytes.get(*at..*at + 4)?;
    let len = u32::from_be_bytes(len.try_into().ok()?) as usize;
    let start = *at + 4;
    let value = bytes.get(start..start.checked_add(len)?)?;
    *at = start + len;
    Some(value)
}

/// The public key of a private key in OpenSSH's format (any key type, encrypted or not),
/// without its comment, which an encrypted key keeps secret. `None` for anything else.
pub fn public_key_of(private_key: &str) -> Option<String> {
    let body: String = private_key
        .trim()
        .strip_prefix(BEGIN)?
        .trim()
        .strip_suffix(END)?
        .split_whitespace()
        .collect();
    let file = Zeroizing::new(base64::decode(&body)?);
    let rest = file.strip_prefix(MAGIC)?;
    let mut at = 0;
    for _ in 0..3 {
        read_string(rest, &mut at)?; // cipher, kdf, kdf options
    }
    let count = u32::from_be_bytes(rest.get(at..at + 4)?.try_into().ok()?);
    at += 4;
    if count == 0 {
        return None;
    }
    let blob = read_string(rest, &mut at)?;
    Some(public_line(blob, ""))
}

/// The fingerprint of a public key line (`ssh-ed25519 AAAA… comment`), as `ssh-keygen -l`
/// shows it. `None` when it isn't one.
pub fn fingerprint(public_key: &str) -> Option<String> {
    let mut words = public_key.split_whitespace();
    let kind = words.next()?;
    let blob = base64::decode(words.next()?)?;
    let mut at = 0;
    let named = read_string(&blob, &mut at)?;
    (named == kind.as_bytes()).then(|| fingerprint_of_blob(&blob))
}

/// Standard Base64 (RFC 4648), as OpenSSH uses it.
mod base64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(bytes: &[u8]) -> String {
        let mut out = encode_unpadded(bytes);
        while out.len() % 4 != 0 {
            out.push('=');
        }
        out
    }

    pub fn encode_unpadded(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
            }
        }
        out
    }

    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let text = text.trim_end_matches('=');
        let mut out = Vec::with_capacity(text.len() * 3 / 4);
        let (mut acc, mut bits) = (0u32, 0u32);
        for c in text.bytes() {
            let value = ALPHABET.iter().position(|a| *a == c)? as u32;
            acc = (acc << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_key_reads_back_its_own_public_half() {
        let pair = generate_ed25519("me@test").unwrap();
        assert!(pair.private_key.starts_with(BEGIN));
        assert!(pair.private_key.trim_end().ends_with(END));
        assert!(
            pair.public_key
                .starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA")
        );
        assert!(pair.public_key.ends_with(" me@test"));
        assert!(pair.fingerprint.starts_with("SHA256:"));
        assert_eq!(pair.fingerprint.len(), "SHA256:".len() + 43);
        let read = public_key_of(&pair.private_key).unwrap();
        assert!(pair.public_key.starts_with(&read));
        assert_eq!(fingerprint(&read).unwrap(), pair.fingerprint);
        assert_eq!(fingerprint(&pair.public_key).unwrap(), pair.fingerprint);
        // Every line of the key's body is at most 70 characters, as OpenSSH writes it.
        assert!(
            pair.private_key
                .lines()
                .all(|line| line.len() <= 70 || line.starts_with("-----"))
        );
        assert!(format!("{pair:?}").contains("<redacted>"));
    }

    #[test]
    fn a_known_public_key_has_its_known_fingerprint() {
        // RFC 8709's Ed25519 test key 1 (the public key bytes), wrapped as OpenSSH does.
        let public = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let mut blob = Vec::new();
        put_string(&mut blob, ED25519.as_bytes());
        put_string(&mut blob, &public);
        let line = public_line(&blob, "");
        assert_eq!(
            line,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
        );
        use sha2::{Digest, Sha256};
        assert_eq!(
            fingerprint(&line).unwrap(),
            format!("SHA256:{}", base64::encode_unpadded(&Sha256::digest(&blob)))
        );
    }

    #[test]
    fn other_text_is_not_a_key() {
        assert!(public_key_of("hello").is_none());
        assert!(public_key_of(&format!("{BEGIN}\nAAAA\n{END}")).is_none());
        assert!(fingerprint("ssh-ed25519 not-base64!").is_none());
        assert!(
            fingerprint(
                "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
            )
            .is_none()
        );
        assert_eq!(
            base64::decode(&base64::encode(b"any bytes \0\xff")).unwrap(),
            b"any bytes \0\xff"
        );
    }
}
