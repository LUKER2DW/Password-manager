//! SSH keys kept as items (format v9, [`ItemKind::SshKey`](crate::ItemKind::SshKey)): the
//! private key where a login keeps its password, its public key, fingerprint and type in
//! fields.
//!
//! The private key is always kept the way OpenSSH writes it, without a passphrase: the vault
//! is its protection (as other managers keep them). A new key is Ed25519. A key brought in
//! (pasted or read from a file) is read in each common form: OpenSSH's own, with or without
//! a passphrase (asked for, used once to open it, never kept), PKCS#8 (`BEGIN PRIVATE KEY`),
//! PKCS#1 for RSA and SEC1 for ECDSA; anything but OpenSSH's own form is written in it. The
//! reading and writing is RustCrypto's `ssh-key`; nothing here parses key bytes by hand.

use ssh_key::{
    HashAlg, LineEnding, PrivateKey, PublicKey,
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair},
};
use zeroize::Zeroizing;

use crate::{Result, random};

/// The fields an SSH key item keeps besides its private key.
pub const PUBLIC_KEY_FIELD: &str = "Public key";
pub const FINGERPRINT_FIELD: &str = "Fingerprint";
pub const KEY_TYPE_FIELD: &str = "Key type";

/// The most work a passphrase may ask for (bcrypt rounds): `ssh-keygen` uses 16 and people
/// raise it to a few hundred. A key that asks for more is refused rather than left to freeze
/// the app.
const MAX_ROUNDS: u32 = 2_000;

/// A key pair as text, the way OpenSSH writes it.
pub struct SshKeyPair {
    /// `-----BEGIN OPENSSH PRIVATE KEY-----` …, without a passphrase.
    pub private_key: Zeroizing<String>,
    /// `ssh-ed25519 AAAA… comment`
    pub public_key: String,
    /// `SHA256:…`, as `ssh-keygen -l` shows it.
    pub fingerprint: String,
    /// "Ed25519", "RSA 4096", "ECDSA P-256".
    pub key_type: String,
}

impl std::fmt::Debug for SshKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKeyPair")
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .field("fingerprint", &self.fingerprint)
            .field("key_type", &self.key_type)
            .finish()
    }
}

/// Why a text brought in as a private key wasn't taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProblem {
    /// Nothing that looks like a key.
    NotAKey,
    /// A public key (`ssh-ed25519 AAAA…`): the private one is the file without `.pub`.
    PublicOnly,
    /// The key has a passphrase: ask for it and try again.
    NeedsPassphrase,
    /// The passphrase given doesn't open it.
    WrongPassphrase,
    /// A form or kind of key that isn't read here (PuTTY's, an old OpenSSL-encrypted PEM, an
    /// encrypted PKCS#8, DSA): `ssh-keygen -p` writes it in OpenSSH's form.
    Unsupported,
}

impl std::fmt::Display for KeyProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotAKey => "not a private key",
            Self::PublicOnly => "a public key, not the private one",
            Self::NeedsPassphrase => "the key has a passphrase",
            Self::WrongPassphrase => "wrong passphrase",
            Self::Unsupported => "a form of key that isn't read here",
        })
    }
}

/// A new Ed25519 key, with `comment` (often `user@host`) in both halves.
pub fn generate_ed25519(comment: &str) -> Result<SshKeyPair> {
    let seed = random::secret_array::<32>()?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    let private = PrivateKey::new(KeypairData::Ed25519(keypair), comment.trim())
        .map_err(|_| crate::Error::InvalidKeyFormat)?;
    pair_of(&private).ok_or(crate::Error::InvalidKeyFormat)
}

/// The text written for `private`, and its public half.
fn pair_of(private: &PrivateKey) -> Option<SshKeyPair> {
    Some(SshKeyPair {
        private_key: private.to_openssh(LineEnding::LF).ok()?,
        public_key: private.public_key().to_openssh().ok()?,
        fingerprint: private.fingerprint(HashAlg::Sha256).to_string(),
        key_type: key_type(private.key_data()),
    })
}

/// "Ed25519", "RSA 3072", "ECDSA P-256" …
fn key_type(data: &KeypairData) -> String {
    match data {
        KeypairData::Ed25519(_) => "Ed25519".into(),
        KeypairData::Rsa(rsa) => {
            let bits = rsa.public.n.as_positive_bytes().map_or(0, |n| {
                n.len() * 8 - n.first().map_or(0, |b| b.leading_zeros() as usize)
            });
            format!("RSA {bits}")
        }
        KeypairData::Ecdsa(ecdsa) => format!("ECDSA {}", curve_name(ecdsa)),
        other => other
            .algorithm()
            .map(|a| a.as_str().to_owned())
            .unwrap_or_default(),
    }
}

fn curve_name(ecdsa: &EcdsaKeypair) -> &'static str {
    match ecdsa {
        EcdsaKeypair::NistP256 { .. } => "P-256",
        EcdsaKeypair::NistP384 { .. } => "P-384",
        EcdsaKeypair::NistP521 { .. } => "P-521",
    }
}

/// Reads a private key brought in (pasted, or a file's text) in any of the forms this module
/// takes, opening it with `passphrase` when it has one, and gives it back as kept: in
/// OpenSSH's form without a passphrase, with its public half. `comment` (the item's user
/// field) goes in the public key when the key has none of its own.
pub fn import(
    text: &str,
    passphrase: Option<&str>,
    comment: &str,
) -> std::result::Result<SshKeyPair, KeyProblem> {
    let text = text.trim();
    let first = text.lines().next().unwrap_or_default().trim();
    // A key in OpenSSH's form without a passphrase is kept exactly as it came.
    let mut kept_as_is = false;
    let mut private = if first == "-----BEGIN OPENSSH PRIVATE KEY-----" {
        let (key, had_passphrase) = openssh(text, passphrase)?;
        kept_as_is = !had_passphrase;
        key
    } else if first == "-----BEGIN PRIVATE KEY-----" {
        PrivateKey::new(pkcs8(text)?, "").map_err(|_| KeyProblem::NotAKey)?
    } else if first == "-----BEGIN RSA PRIVATE KEY-----" {
        if text.contains("Proc-Type: 4,ENCRYPTED") {
            return Err(KeyProblem::Unsupported);
        }
        use rsa::pkcs1::DecodeRsaPrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs1_pem(text).map_err(|_| KeyProblem::NotAKey)?;
        rsa_key(&key)?
    } else if first == "-----BEGIN EC PRIVATE KEY-----" {
        if text.contains("Proc-Type: 4,ENCRYPTED") {
            return Err(KeyProblem::Unsupported);
        }
        let keypair = if let Ok(key) = p256::SecretKey::from_sec1_pem(text) {
            EcdsaKeypair::NistP256 {
                public: key.public_key().into(),
                private: key.into(),
            }
        } else if let Ok(key) = p384::SecretKey::from_sec1_pem(text) {
            EcdsaKeypair::NistP384 {
                public: key.public_key().into(),
                private: key.into(),
            }
        } else {
            return Err(KeyProblem::Unsupported);
        };
        PrivateKey::new(KeypairData::Ecdsa(keypair), "").map_err(|_| KeyProblem::NotAKey)?
    } else if first == "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        || first.starts_with("PuTTY-User-Key-File")
        || first == "-----BEGIN DSA PRIVATE KEY-----"
    {
        return Err(KeyProblem::Unsupported);
    } else if PublicKey::from_openssh(first).is_ok() {
        return Err(KeyProblem::PublicOnly);
    } else {
        return Err(KeyProblem::NotAKey);
    };
    if private.comment().is_empty() && !comment.trim().is_empty() {
        private.set_comment(comment.trim());
    }
    let mut pair = pair_of(&private).ok_or(KeyProblem::NotAKey)?;
    if kept_as_is {
        pair.private_key = Zeroizing::new(format!("{text}\n"));
    }
    Ok(pair)
}

/// A key in OpenSSH's own form, opened with `passphrase` if it has one; and whether it had.
fn openssh(
    text: &str,
    passphrase: Option<&str>,
) -> std::result::Result<(PrivateKey, bool), KeyProblem> {
    let key = PrivateKey::from_openssh(text).map_err(|_| KeyProblem::NotAKey)?;
    if !key.is_encrypted() {
        return Ok((key, false));
    }
    let Some(passphrase) = passphrase.filter(|p| !p.is_empty()) else {
        return Err(KeyProblem::NeedsPassphrase);
    };
    match key.kdf() {
        ssh_key::Kdf::Bcrypt { rounds, .. } if *rounds <= MAX_ROUNDS => {}
        _ => return Err(KeyProblem::Unsupported),
    }
    key.decrypt(passphrase.as_bytes())
        .map(|key| (key, true))
        .map_err(|_| KeyProblem::WrongPassphrase)
}

/// `BEGIN PRIVATE KEY`: Ed25519, RSA or ECDSA, whichever it is.
fn pkcs8(text: &str) -> std::result::Result<KeypairData, KeyProblem> {
    use p256::pkcs8::DecodePrivateKey;
    if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_pem(text) {
        return Ok(KeypairData::Ed25519(Ed25519Keypair::from(key)));
    }
    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_pem(text) {
        return RsaKeypair::try_from(&key)
            .map(KeypairData::Rsa)
            .map_err(|_| KeyProblem::Unsupported);
    }
    if let Ok(key) = p256::SecretKey::from_pkcs8_pem(text) {
        return Ok(KeypairData::Ecdsa(EcdsaKeypair::NistP256 {
            public: key.public_key().into(),
            private: key.into(),
        }));
    }
    if let Ok(key) = p384::SecretKey::from_pkcs8_pem(text) {
        return Ok(KeypairData::Ecdsa(EcdsaKeypair::NistP384 {
            public: key.public_key().into(),
            private: key.into(),
        }));
    }
    Err(KeyProblem::Unsupported)
}

fn rsa_key(key: &rsa::RsaPrivateKey) -> std::result::Result<PrivateKey, KeyProblem> {
    let keypair = RsaKeypair::try_from(key).map_err(|_| KeyProblem::Unsupported)?;
    PrivateKey::new(KeypairData::Rsa(keypair), "").map_err(|_| KeyProblem::NotAKey)
}

/// The public key of a private key in OpenSSH's form (any key type, with a passphrase or
/// not), without its comment, which a key with a passphrase keeps secret. `None` for anything
/// else.
pub fn public_key_of(private_key: &str) -> Option<String> {
    let key = PrivateKey::from_openssh(private_key.trim()).ok()?;
    let mut public = key.public_key().clone();
    public.set_comment("");
    public.to_openssh().ok()
}

/// The type of a private key in OpenSSH's form ("Ed25519", "RSA 4096"), when it has no
/// passphrase. `None` otherwise.
pub fn key_type_of(private_key: &str) -> Option<String> {
    let key = PrivateKey::from_openssh(private_key.trim()).ok()?;
    (!key.is_encrypted()).then(|| key_type(key.key_data()))
}

/// The fingerprint of a public key line (`ssh-ed25519 AAAA… comment`), as `ssh-keygen -l`
/// shows it. `None` when it isn't one.
pub fn fingerprint(public_key: &str) -> Option<String> {
    PublicKey::from_openssh(public_key.trim())
        .ok()
        .map(|key| key.fingerprint(HashAlg::Sha256).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keys made for these tests only (`ssh-keygen` and `openssl`), never used anywhere.
    const ED25519_PASSPHRASE: &str = "correct horse";

    #[test]
    fn a_new_key_reads_back_its_own_public_half() {
        let pair = generate_ed25519("me@test").unwrap();
        assert!(
            pair.private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert!(
            pair.private_key
                .trim_end()
                .ends_with("-----END OPENSSH PRIVATE KEY-----")
        );
        assert!(
            pair.public_key
                .starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA")
        );
        assert!(pair.public_key.ends_with(" me@test"));
        assert!(pair.fingerprint.starts_with("SHA256:"));
        assert_eq!(pair.fingerprint.len(), "SHA256:".len() + 43);
        assert_eq!(pair.key_type, "Ed25519");
        let read = public_key_of(&pair.private_key).unwrap();
        assert!(pair.public_key.starts_with(&read));
        assert_eq!(fingerprint(&read).unwrap(), pair.fingerprint);
        assert_eq!(fingerprint(&pair.public_key).unwrap(), pair.fingerprint);
        assert_eq!(key_type_of(&pair.private_key).unwrap(), "Ed25519");
        // Every line of the key's body is at most 70 characters, as OpenSSH writes it.
        assert!(
            pair.private_key
                .lines()
                .all(|line| line.len() <= 70 || line.starts_with("-----"))
        );
        assert!(format!("{pair:?}").contains("<redacted>"));
        // Brought back in, it is the same key, kept exactly as it was.
        let again = import(&pair.private_key, None, "").unwrap();
        assert_eq!(again.private_key.as_str(), pair.private_key.as_str());
        assert_eq!(again.fingerprint, pair.fingerprint);
    }

    #[test]
    fn a_key_with_a_passphrase_is_opened_once_and_kept_without_it() {
        let pair = generate_ed25519("me@test").unwrap();
        let key = PrivateKey::from_openssh(pair.private_key.as_str()).unwrap();
        let mut rng = TestRng(7);
        let locked = key.encrypt(&mut rng, ED25519_PASSPHRASE).unwrap();
        let locked = locked.to_openssh(LineEnding::LF).unwrap();
        // Its public half reads without the passphrase (OpenSSH keeps it in the clear).
        assert!(
            pair.public_key
                .starts_with(&public_key_of(&locked).unwrap())
        );
        assert_eq!(key_type_of(&locked), None);
        assert_eq!(
            import(&locked, None, "").unwrap_err(),
            KeyProblem::NeedsPassphrase
        );
        assert_eq!(
            import(&locked, Some("not it"), "").unwrap_err(),
            KeyProblem::WrongPassphrase
        );
        let opened = import(&locked, Some(ED25519_PASSPHRASE), "").unwrap();
        assert_eq!(opened.fingerprint, pair.fingerprint);
        assert!(
            !PrivateKey::from_openssh(opened.private_key.as_str())
                .unwrap()
                .is_encrypted()
        );
    }

    #[test]
    fn other_forms_are_written_as_openssh() {
        // PKCS#8 (`openssl genpkey -algorithm ed25519`): RFC 8410's example key.
        let pkcs8 = "-----BEGIN PRIVATE KEY-----\n\
                     MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n\
                     -----END PRIVATE KEY-----";
        let pair = import(pkcs8, None, "work laptop").unwrap();
        assert_eq!(pair.key_type, "Ed25519");
        assert!(
            pair.private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        // RFC 8410's public key for it.
        let public: [u8; 32] = [
            0x19, 0xbf, 0x44, 0x09, 0x69, 0x84, 0xcd, 0xfe, 0x85, 0x41, 0xba, 0xc1, 0x67, 0xdc,
            0x3b, 0x96, 0xc8, 0x50, 0x86, 0xaa, 0x30, 0xb6, 0xb6, 0xcb, 0x0c, 0x5c, 0x38, 0xad,
            0x70, 0x31, 0x66, 0xe1,
        ];
        let expected = PublicKey::new(
            ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(public)),
            "work laptop",
        );
        assert_eq!(pair.public_key, expected.to_openssh().unwrap());
        // A P-256 key in SEC1 (`openssl ecparam -genkey -name prime256v1`).
        let secret = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let sec1 = secret.to_sec1_pem(p256::pkcs8::LineEnding::LF).unwrap();
        let pair = import(&sec1, None, "").unwrap();
        assert_eq!(pair.key_type, "ECDSA P-256");
        assert!(pair.public_key.starts_with("ecdsa-sha2-nistp256 "));
    }

    #[test]
    fn what_isnt_a_private_key_says_why() {
        let pair = generate_ed25519("").unwrap();
        assert_eq!(
            import(&pair.public_key, None, "").unwrap_err(),
            KeyProblem::PublicOnly
        );
        assert_eq!(import("hello", None, "").unwrap_err(), KeyProblem::NotAKey);
        assert_eq!(
            import("PuTTY-User-Key-File-3: ssh-ed25519\n…", None, "").unwrap_err(),
            KeyProblem::Unsupported
        );
        assert_eq!(
            import(
                "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n…\n-----END RSA PRIVATE KEY-----",
                None,
                ""
            )
            .unwrap_err(),
            KeyProblem::Unsupported
        );
        assert!(public_key_of("hello").is_none());
        assert!(fingerprint("ssh-ed25519 not-base64!").is_none());
    }

    /// A predictable source for the passphrase's salt in a test (never for keys).
    struct TestRng(u64);
    impl rand_core::RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            u32::try_from(self.next_u64() >> 32).unwrap_or(0)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = u8::try_from(self.next_u32() & 0xFF).unwrap_or(0);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for TestRng {}
}
