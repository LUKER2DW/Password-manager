//! SSH keys kept as items (format v9, [`ItemKind::SshKey`](crate::ItemKind::SshKey)): the
//! private key where a login keeps its password, its public key, fingerprint and type in
//! fields.
//!
//! The private key is always kept the way OpenSSH writes it, without a passphrase: the vault
//! is its protection (as other managers keep them). A new key is Ed25519. A key brought in
//! (pasted or read from a file) is read in each common form: OpenSSH's own, with or without
//! a passphrase (asked for, used once to open it, never kept), PKCS#8 (`BEGIN PRIVATE KEY`),
//! PKCS#1 for RSA and SEC1 for ECDSA; anything but OpenSSH's own form is written in it.
//! OpenSSH's form is read and written by RustCrypto's `ssh-key`, the others by the key types'
//! own crates (`rsa`, `p256`, `p384`, `ed25519-dalek`), whose numbers are handed to `ssh-key`;
//! nothing here parses key bytes by hand.

use ssh_encoding::{Decode, Encode};
use ssh_key::{
    HashAlg, LineEnding, Mpint, PrivateKey, PublicKey,
    private::{EcdsaKeypair, EcdsaPrivateKey, Ed25519Keypair, KeypairData, RsaKeypair},
    public::{EcdsaPublicKey, RsaPublicKey},
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
        let key = rsa::PrivateKey::from_pkcs1_pem(text).map_err(|_| KeyProblem::NotAKey)?;
        rsa_key(&key)?
    } else if first == "-----BEGIN EC PRIVATE KEY-----" {
        if text.contains("Proc-Type: 4,ENCRYPTED") {
            return Err(KeyProblem::Unsupported);
        }
        let keypair = if let Ok(key) = p256::SecretKey::from_sec1_pem(text) {
            p256_keypair(&key)?
        } else if let Ok(key) = p384::SecretKey::from_sec1_pem(text) {
            p384_keypair(&key)?
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
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    use p256::pkcs8::DecodePrivateKey;
    if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_pem(text) {
        return Ok(KeypairData::Ed25519(Ed25519Keypair::from(key)));
    }
    if let Ok(key) = rsa::PrivateKey::from_pkcs8_pem(text) {
        return rsa_keypair(&key).map(KeypairData::Rsa);
    }
    if let Ok(key) = p256::SecretKey::from_pkcs8_pem(text) {
        return p256_keypair(&key).map(KeypairData::Ecdsa);
    }
    if let Ok(key) = p384::SecretKey::from_pkcs8_pem(text) {
        return p384_keypair(&key).map(KeypairData::Ecdsa);
    }
    Err(KeyProblem::Unsupported)
}

fn rsa_key(key: &rsa::PrivateKey) -> std::result::Result<PrivateKey, KeyProblem> {
    let keypair = rsa_keypair(key)?;
    PrivateKey::new(KeypairData::Rsa(keypair), "").map_err(|_| KeyProblem::NotAKey)
}

/// The smallest RSA key OpenSSH (and `ssh-key`, reading it back) takes, in bits.
const MIN_RSA_BITS: usize = 2048;

/// An RSA key read (and checked) by the `rsa` crate, as `ssh-key` keeps it: its numbers.
/// Keys of more than two primes, or under 2048 bits, aren't taken.
fn rsa_keypair(key: &rsa::PrivateKey) -> std::result::Result<RsaKeypair, KeyProblem> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let [p, q] = key.primes() else {
        return Err(KeyProblem::Unsupported);
    };
    if key.size().saturating_mul(8) < MIN_RSA_BITS {
        return Err(KeyProblem::Unsupported);
    }
    let iqmp = key.crt_coefficient().ok_or(KeyProblem::Unsupported)?;
    let number = |value: &rsa::BoxedUint| {
        let bytes = Zeroizing::new(value.to_be_bytes());
        Mpint::from_positive_bytes(&bytes).map_err(|_| KeyProblem::NotAKey)
    };
    Ok(RsaKeypair {
        public: RsaPublicKey {
            e: number(key.e())?,
            n: number(key.n().as_ref())?,
        },
        private: ssh_key::private::RsaPrivateKey {
            d: number(key.d())?,
            iqmp: number(&iqmp)?,
            p: number(p)?,
            q: number(q)?,
        },
    })
}

/// A P-256 key read by the `p256` crate, with its public point worked out from it.
fn p256_keypair(key: &p256::SecretKey) -> std::result::Result<EcdsaKeypair, KeyProblem> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let point = key.public_key().to_sec1_point(false);
    let EcdsaPublicKey::NistP256(public) = ecdsa_public(point.as_bytes())? else {
        return Err(KeyProblem::NotAKey);
    };
    Ok(EcdsaKeypair::NistP256 {
        public,
        private: ecdsa_private(&key.to_bytes())?,
    })
}

/// A P-384 key read by the `p384` crate, with its public point worked out from it.
fn p384_keypair(key: &p384::SecretKey) -> std::result::Result<EcdsaKeypair, KeyProblem> {
    use p384::elliptic_curve::sec1::ToSec1Point;
    let point = key.public_key().to_sec1_point(false);
    let EcdsaPublicKey::NistP384(public) = ecdsa_public(point.as_bytes())? else {
        return Err(KeyProblem::NotAKey);
    };
    Ok(EcdsaKeypair::NistP384 {
        public,
        private: ecdsa_private(&key.to_bytes())?,
    })
}

fn ecdsa_public(sec1: &[u8]) -> std::result::Result<EcdsaPublicKey, KeyProblem> {
    EcdsaPublicKey::from_sec1_bytes(sec1).map_err(|_| KeyProblem::NotAKey)
}

/// An ECDSA private scalar as `ssh-key` keeps it. It makes one only from the curve crates of
/// its own release or from its wire form, a length and the bytes, which is what is given
/// here.
fn ecdsa_private<const SIZE: usize>(
    scalar: &[u8],
) -> std::result::Result<EcdsaPrivateKey<SIZE>, KeyProblem> {
    if scalar.len() != SIZE {
        return Err(KeyProblem::NotAKey);
    }
    let mut wire = Zeroizing::new(Vec::with_capacity(4 + SIZE));
    wire.extend_from_slice(&u32::try_from(SIZE).unwrap_or(0).to_be_bytes());
    wire.extend_from_slice(scalar);
    EcdsaPrivateKey::<SIZE>::decode(&mut wire.as_slice()).map_err(|_| KeyProblem::NotAKey)
}

/// A private key in OpenSSH's form (no passphrase) as PKCS#8 DER, with the name of its
/// algorithm as SSH writes it (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`): the form
/// the Credential Exchange Format carries SSH keys in. `None` for a key with a passphrase,
/// anything that isn't a key, or a type with no PKCS#8 form here (P-521).
pub fn pkcs8_der(private_key: &str) -> Option<(Zeroizing<Vec<u8>>, String)> {
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;
    use p256::pkcs8::EncodePrivateKey;
    let key = PrivateKey::from_openssh(private_key.trim()).ok()?;
    if key.is_encrypted() {
        return None;
    }
    let algorithm = key.algorithm().as_str().to_owned();
    // Each arm copies its document out (the crates' documents are of two `der` releases);
    // the documents wipe themselves when dropped.
    let der = match key.key_data() {
        KeypairData::Ed25519(pair) => {
            let secret = Zeroizing::new(pair.private.to_bytes());
            let document = ed25519_dalek::SigningKey::from_bytes(&secret)
                .to_pkcs8_der()
                .ok()?;
            document.as_bytes().to_vec()
        }
        KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) => {
            let document = p256::SecretKey::from_slice(private.as_slice())
                .ok()?
                .to_pkcs8_der()
                .ok()?;
            document.as_bytes().to_vec()
        }
        KeypairData::Ecdsa(EcdsaKeypair::NistP384 { private, .. }) => {
            let document = p384::SecretKey::from_slice(private.as_slice())
                .ok()?
                .to_pkcs8_der()
                .ok()?;
            document.as_bytes().to_vec()
        }
        KeypairData::Rsa(pair) => {
            let number = |value: &Mpint| {
                let bytes = value.as_positive_bytes()?;
                let bits = u32::try_from((bytes.len() * 8).next_multiple_of(64)).ok()?;
                rsa::BoxedUint::from_be_slice(bytes, bits).ok()
            };
            let rsa = rsa::PrivateKey::from_components(
                number(&pair.public.n)?,
                number(&pair.public.e)?,
                number(&pair.private.d)?,
                vec![number(&pair.private.p)?, number(&pair.private.q)?],
            )
            .ok()?;
            let document = rsa.to_pkcs8_der().ok()?;
            document.as_bytes().to_vec()
        }
        _ => return None,
    };
    Some((Zeroizing::new(der), algorithm))
}

/// A private key in PKCS#8 DER (as [`pkcs8_der`] writes it) in OpenSSH's form, with its
/// public half. `comment` goes in the public key.
pub fn from_pkcs8_der(der: &[u8], comment: &str) -> std::result::Result<SshKeyPair, KeyProblem> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    use p256::pkcs8::DecodePrivateKey;
    let data = if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
        KeypairData::Ed25519(Ed25519Keypair::from(key))
    } else if let Ok(key) = rsa::PrivateKey::from_pkcs8_der(der) {
        KeypairData::Rsa(rsa_keypair(&key)?)
    } else if let Ok(key) = p256::SecretKey::from_pkcs8_der(der) {
        KeypairData::Ecdsa(p256_keypair(&key)?)
    } else if let Ok(key) = p384::SecretKey::from_pkcs8_der(der) {
        KeypairData::Ecdsa(p384_keypair(&key)?)
    } else {
        return Err(KeyProblem::Unsupported);
    };
    let private = PrivateKey::new(data, comment.trim()).map_err(|_| KeyProblem::NotAKey)?;
    pair_of(&private).ok_or(KeyProblem::NotAKey)
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

/// What an SSH agent calls a key: its public half in SSH's wire form (the "key blob" the
/// agent protocol lists and a client names when it asks for a signature). `None` when
/// `public_key` isn't a public key line.
pub fn public_key_blob(public_key: &str) -> Option<Vec<u8>> {
    let key = PublicKey::from_openssh(public_key.trim()).ok()?;
    let mut blob = Vec::new();
    key.key_data().encode(&mut blob).ok()?;
    Some(blob)
}

/// The agent protocol's flags on a sign request for an RSA key: which hash the client wants
/// (draft-miller-ssh-agent §3.6.1). Without either, a client asks for `ssh-rsa` (SHA-1),
/// which is refused.
pub const AGENT_RSA_SHA2_256: u32 = 2;
pub const AGENT_RSA_SHA2_512: u32 = 4;

/// Why an SSH key item's key didn't sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignProblem {
    /// The item's private key doesn't read as one (or has a passphrase, which a kept key
    /// never has).
    NotAKey,
    /// A key or a signature this app doesn't make: P-521, DSA, a security key's (`sk-`), or
    /// RSA with SHA-1.
    Unsupported,
}

/// Signs `data` with an SSH key item's private key (`private_key`, in OpenSSH's form), the
/// way an SSH agent answers a sign request: the signature in SSH's wire form (the
/// algorithm's name, then the signature), as the agent's answer carries it.
///
/// Each key type signs through its own crate (`ed25519-dalek`; `p256` and `p384`, RFC 6979
/// nonces, SHA-256 and SHA-384 as RFC 5656 asks; `rsa`, PKCS #1 v1.5 with SHA-256 or
/// SHA-512 as RFC 8332 asks, blinded), and `ssh-key` writes the result; nothing here signs by
/// hand. `flags` are the agent protocol's (`AGENT_RSA_SHA2_*`); other key types ignore them.
pub fn agent_sign(
    private_key: &str,
    data: &[u8],
    flags: u32,
) -> std::result::Result<Vec<u8>, SignProblem> {
    use ssh_key::{Algorithm, EcdsaCurve, Signature};
    let key = PrivateKey::from_openssh(private_key.trim()).map_err(|_| SignProblem::NotAKey)?;
    if key.is_encrypted() {
        return Err(SignProblem::NotAKey);
    }
    let signature = match key.key_data() {
        KeypairData::Ed25519(pair) => {
            use ed25519_dalek::Signer;
            let seed = Zeroizing::new(pair.private.to_bytes());
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
            let signed = signing.sign(data);
            Signature::new(Algorithm::Ed25519, signed.to_bytes().to_vec())
        }
        KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) => {
            use p256::ecdsa::signature::Signer;
            let signing = p256::ecdsa::SigningKey::from_slice(private.as_slice())
                .map_err(|_| SignProblem::NotAKey)?;
            let signed: p256::ecdsa::Signature = signing.sign(data);
            let (r, s) = signed.split_bytes();
            Signature::new(
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256,
                },
                ecdsa_signature(&r, &s)?,
            )
        }
        KeypairData::Ecdsa(EcdsaKeypair::NistP384 { private, .. }) => {
            use p384::ecdsa::signature::Signer;
            let signing = p384::ecdsa::SigningKey::from_slice(private.as_slice())
                .map_err(|_| SignProblem::NotAKey)?;
            let signed: p384::ecdsa::Signature = signing.sign(data);
            let (r, s) = signed.split_bytes();
            Signature::new(
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP384,
                },
                ecdsa_signature(&r, &s)?,
            )
        }
        KeypairData::Rsa(pair) => {
            let (hash, signed) = rsa_sign(pair, data, flags)?;
            Signature::new(Algorithm::Rsa { hash: Some(hash) }, signed)
        }
        _ => return Err(SignProblem::Unsupported),
    }
    .map_err(|_| SignProblem::Unsupported)?;
    let mut blob = Vec::new();
    signature
        .encode(&mut blob)
        .map_err(|_| SignProblem::Unsupported)?;
    Ok(blob)
}

/// An ECDSA signature as SSH writes it inside the signature (RFC 5656 §3.1.2): r and s as
/// two `mpint`s.
fn ecdsa_signature(r: &[u8], s: &[u8]) -> std::result::Result<Vec<u8>, SignProblem> {
    let mut blob = Vec::new();
    for number in [r, s] {
        let mpint = Mpint::from_positive_bytes(number).map_err(|_| SignProblem::Unsupported)?;
        mpint
            .encode(&mut blob)
            .map_err(|_| SignProblem::Unsupported)?;
    }
    Ok(blob)
}

/// RSA, PKCS #1 v1.5 with the hash the client asked for (SHA-512 when it takes both).
fn rsa_sign(
    pair: &RsaKeypair,
    data: &[u8],
    flags: u32,
) -> std::result::Result<(HashAlg, Vec<u8>), SignProblem> {
    use rsa::signature::{SignatureEncoding, Signer};
    let hash = if flags & AGENT_RSA_SHA2_512 != 0 {
        HashAlg::Sha512
    } else if flags & AGENT_RSA_SHA2_256 != 0 {
        HashAlg::Sha256
    } else {
        return Err(SignProblem::Unsupported);
    };
    let n = pair
        .public
        .n
        .as_positive_bytes()
        .ok_or(SignProblem::NotAKey)?;
    let bits = u32::try_from(n.len() * 8).map_err(|_| SignProblem::NotAKey)?;
    let number = |value: &Mpint, bits: u32| {
        let bytes = value.as_positive_bytes().ok_or(SignProblem::NotAKey)?;
        rsa::BoxedUint::from_be_slice(bytes, bits).map_err(|_| SignProblem::NotAKey)
    };
    let e_bytes = pair
        .public
        .e
        .as_positive_bytes()
        .ok_or(SignProblem::NotAKey)?;
    let e_bits = u32::try_from(e_bytes.len() * 8).map_err(|_| SignProblem::NotAKey)?;
    let key = rsa::PrivateKey::from_components(
        number(&pair.public.n, bits)?,
        number(&pair.public.e, e_bits)?,
        number(&pair.private.d, bits)?,
        vec![
            number(&pair.private.p, bits)?,
            number(&pair.private.q, bits)?,
        ],
    )
    .map_err(|_| SignProblem::NotAKey)?;
    let signed = match hash {
        HashAlg::Sha512 => rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(key)
            .try_sign(data)
            .map(|s| s.to_vec()),
        _ => rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key)
            .try_sign(data)
            .map(|s| s.to_vec()),
    }
    .map_err(|_| SignProblem::Unsupported)?;
    Ok((hash, signed))
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
    fn rsa_and_p384_keys_are_read_as_ssh_keygen_reads_them() {
        // Test keys from crates/core/testdata/ssh; the fingerprints are `ssh-keygen -l`'s.
        let pkcs1 = include_str!("../testdata/ssh/rsa-2048-pkcs1.txt");
        let pkcs8 = include_str!("../testdata/ssh/rsa-2048-pkcs8.txt");
        // The same key, converted by `ssh-keygen -p`.
        let rsa_openssh = include_str!("../testdata/ssh/rsa-2048-openssh.txt");
        let rsa_fingerprint = "SHA256:NxwueWLNUr4Lhdr0JybEzeMoO8DMejewxuWsY0/J8Ac";
        for text in [pkcs1, pkcs8] {
            let pair = import(text, None, "build server").unwrap();
            assert_eq!(pair.key_type, "RSA 2048");
            assert_eq!(pair.fingerprint, rsa_fingerprint);
            assert!(pair.public_key.starts_with("ssh-rsa AAAAB3NzaC1yc2E"));
            assert!(pair.public_key.ends_with(" build server"));
            // What is kept reads back as the same key.
            assert_eq!(key_type_of(&pair.private_key).unwrap(), "RSA 2048");
            let public = public_key_of(&pair.private_key).unwrap();
            assert_eq!(fingerprint(&public).unwrap(), rsa_fingerprint);
            // Every number of the private key is the one ssh-keygen writes for it.
            assert_eq!(key_data_of(&pair.private_key), key_data_of(rsa_openssh));
        }
        let sec1 = include_str!("../testdata/ssh/p384-sec1.txt");
        let pair = import(sec1, None, "").unwrap();
        assert_eq!(pair.key_type, "ECDSA P-384");
        assert_eq!(
            pair.fingerprint,
            "SHA256:oc6bQHkyKIxg5bhb3CJ0VnnQBiTcb/d/PMQjuiF+MR4"
        );
        assert!(pair.public_key.starts_with("ecdsa-sha2-nistp384 "));
        assert_eq!(key_type_of(&pair.private_key).unwrap(), "ECDSA P-384");
        let p384_openssh = include_str!("../testdata/ssh/p384-openssh.txt");
        assert_eq!(key_data_of(&pair.private_key), key_data_of(p384_openssh));
    }

    #[test]
    fn every_kept_key_type_goes_to_pkcs8_and_back_the_same() {
        let ed25519 = generate_ed25519("me@test").unwrap().private_key;
        let p256 = import(
            &p256::SecretKey::from_slice(&[7u8; 32])
                .unwrap()
                .to_sec1_pem(p256::pkcs8::LineEnding::LF)
                .unwrap(),
            None,
            "",
        )
        .unwrap()
        .private_key;
        let rsa = include_str!("../testdata/ssh/rsa-2048-openssh.txt");
        let p384 = include_str!("../testdata/ssh/p384-openssh.txt");
        for (key, algorithm) in [
            (ed25519.as_str(), "ssh-ed25519"),
            (p256.as_str(), "ecdsa-sha2-nistp256"),
            (rsa, "ssh-rsa"),
            (p384, "ecdsa-sha2-nistp384"),
        ] {
            let (der, name) = pkcs8_der(key).unwrap();
            assert_eq!(name, algorithm);
            assert_eq!(der[0], 0x30, "a DER sequence");
            let back = from_pkcs8_der(&der, "laptop").unwrap();
            assert_eq!(
                key_data_of(&back.private_key),
                key_data_of(key),
                "{algorithm}"
            );
            assert!(back.public_key.ends_with(" laptop"));
        }
        assert!(pkcs8_der("not a key").is_none());
        assert_eq!(
            from_pkcs8_der(b"\x30\x00", "").err(),
            Some(KeyProblem::Unsupported)
        );
    }

    /// The signature an agent answers with, read back and checked by each key type's own
    /// verifier against the item's public key.
    #[test]
    fn the_agent_signs_with_each_kind_of_key_and_each_signature_verifies() {
        use ssh_key::{Algorithm, Signature};
        let data = b"a session id and a userauth request, as ssh sends them";
        let signed = |private: &str, flags: u32| {
            let blob = agent_sign(private, data, flags).unwrap();
            Signature::decode(&mut blob.as_slice()).unwrap()
        };
        let public_of = |private: &str| {
            PublicKey::from_openssh(&public_key_of(private).unwrap())
                .unwrap()
                .key_data()
                .clone()
        };
        let mpints = |bytes: &[u8]| {
            let mut reader = bytes;
            let r = Mpint::decode(&mut reader).unwrap();
            let s = Mpint::decode(&mut reader).unwrap();
            assert!(reader.is_empty());
            (
                r.as_positive_bytes().unwrap().to_vec(),
                s.as_positive_bytes().unwrap().to_vec(),
            )
        };
        let padded = |bytes: &[u8], size: usize| {
            let mut out = vec![0u8; size - bytes.len()];
            out.extend_from_slice(bytes);
            out
        };

        // Ed25519 (deterministic: the same request, the same signature).
        let pair = generate_ed25519("agent@test").unwrap();
        let signature = signed(&pair.private_key, 0);
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);
        assert_eq!(signed(&pair.private_key, 0), signature);
        let ssh_key::public::KeyData::Ed25519(public) = public_of(&pair.private_key) else {
            panic!("not Ed25519");
        };
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public.0).unwrap();
        let bytes: [u8; 64] = signature.as_bytes().try_into().unwrap();
        verifying
            .verify_strict(data, &ed25519_dalek::Signature::from_bytes(&bytes))
            .unwrap();
        assert!(
            verifying
                .verify_strict(
                    b"something else",
                    &ed25519_dalek::Signature::from_bytes(&bytes)
                )
                .is_err()
        );

        // ECDSA P-256 (SHA-256).
        let secret = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let sec1 = secret.to_sec1_pem(p256::pkcs8::LineEnding::LF).unwrap();
        let pair = import(&sec1, None, "").unwrap();
        let signature = signed(&pair.private_key, 0);
        assert_eq!(signature.algorithm().as_str(), "ecdsa-sha2-nistp256");
        let (r, s) = mpints(signature.as_bytes());
        let ecdsa = p256::ecdsa::Signature::from_scalars(
            <[u8; 32]>::try_from(padded(&r, 32)).unwrap(),
            <[u8; 32]>::try_from(padded(&s, 32)).unwrap(),
        )
        .unwrap();
        use p256::ecdsa::signature::Verifier;
        p256::ecdsa::VerifyingKey::from(secret.public_key())
            .verify(data, &ecdsa)
            .unwrap();

        // ECDSA P-384 (SHA-384), ssh-keygen's test key.
        let p384_openssh = include_str!("../testdata/ssh/p384-openssh.txt");
        let signature = signed(p384_openssh, 0);
        assert_eq!(signature.algorithm().as_str(), "ecdsa-sha2-nistp384");
        let (r, s) = mpints(signature.as_bytes());
        let ecdsa = p384::ecdsa::Signature::from_scalars(
            <[u8; 48]>::try_from(padded(&r, 48)).unwrap(),
            <[u8; 48]>::try_from(padded(&s, 48)).unwrap(),
        )
        .unwrap();
        let ssh_key::public::KeyData::Ecdsa(public) = public_of(p384_openssh) else {
            panic!("not ECDSA");
        };
        p384::ecdsa::VerifyingKey::from_sec1_bytes(public.as_sec1_bytes())
            .unwrap()
            .verify(data, &ecdsa)
            .unwrap();

        // RSA: SHA-512 or SHA-256 as asked, never SHA-1.
        let rsa_openssh = include_str!("../testdata/ssh/rsa-2048-openssh.txt");
        let ssh_key::public::KeyData::Rsa(public) = public_of(rsa_openssh) else {
            panic!("not RSA");
        };
        let n = public.n.as_positive_bytes().unwrap();
        let e = public.e.as_positive_bytes().unwrap();
        let verifying = rsa::PublicKey::new(
            rsa::BoxedUint::from_be_slice(n, u32::try_from(n.len() * 8).unwrap()).unwrap(),
            rsa::BoxedUint::from_be_slice(e, u32::try_from(e.len() * 8).unwrap()).unwrap(),
        )
        .unwrap();
        let signature = signed(rsa_openssh, AGENT_RSA_SHA2_512);
        assert_eq!(signature.algorithm().as_str(), "rsa-sha2-512");
        assert_eq!(signature.as_bytes().len(), 256);
        rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(verifying.clone())
            .verify(
                data,
                &rsa::pkcs1v15::Signature::try_from(signature.as_bytes()).unwrap(),
            )
            .unwrap();
        let signature = signed(rsa_openssh, AGENT_RSA_SHA2_256);
        assert_eq!(signature.algorithm().as_str(), "rsa-sha2-256");
        rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(verifying)
            .verify(
                data,
                &rsa::pkcs1v15::Signature::try_from(signature.as_bytes()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            agent_sign(rsa_openssh, data, 0).unwrap_err(),
            SignProblem::Unsupported
        );

        // What isn't a key signs nothing.
        assert_eq!(
            agent_sign("not a key", data, 0).unwrap_err(),
            SignProblem::NotAKey
        );
    }

    #[test]
    fn the_agent_lists_a_key_by_its_public_half_in_wire_form() {
        let pair = generate_ed25519("agent@test").unwrap();
        let blob = public_key_blob(&pair.public_key).unwrap();
        // string "ssh-ed25519", string the 32 bytes.
        assert_eq!(blob.len(), 4 + 11 + 4 + 32);
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        let read = ssh_key::public::KeyData::decode(&mut blob.as_slice()).unwrap();
        assert_eq!(
            &read,
            PublicKey::from_openssh(&pair.public_key)
                .unwrap()
                .key_data()
        );
        // The comment isn't part of it.
        let without = pair.public_key.rsplit_once(' ').unwrap().0;
        assert_eq!(public_key_blob(without).unwrap(), blob);
        assert_eq!(public_key_blob("ssh-ed25519 not-base64"), None);
    }

    fn key_data_of(text: &str) -> KeypairData {
        PrivateKey::from_openssh(text.trim())
            .unwrap()
            .key_data()
            .clone()
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
