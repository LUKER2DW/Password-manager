//! Pairing: only an extension the person connected to the app may ask for logins, and nothing
//! between the two can read or change what they say.
//!
//! **Connecting.** The extension and the app agree on a key without sending it (ECDH P-256),
//! and the person checks that the two ends are really they: both show a short code computed from
//! the exchange, and the person connects in the app only when the two are the same:
//! 1. The extension makes a fresh key pair (its private half stays a browser key object no
//!    script can read) and sends a commitment to its public half `E`:
//!    `{"type":"pair","commit":hex(SHA-256("vault-browser/pairing-commit" ‖ E))}`.
//! 2. The app makes a fresh key pair of its own and answers its public half `A`:
//!    `{"type":"pair_offer","key":hex(A)}`.
//! 3. The extension reveals `E` (`{"type":"pair_key","key":hex(E)}`); the app checks it against
//!    the commitment and answers `{"type":"pair_wait"}`.
//! 4. Both compute the connection key
//!    `K = HKDF-SHA-256(IKM = ECDH x-coordinate, salt = E ‖ A, info = "vault-browser/pairing")`
//!    and the code: eight characters from an alphabet of 56 letters and digits that can't be
//!    mistaken for one another, drawn from `SHA-256("vault-browser/pairing-code" ‖ E ‖ A ‖ i)`
//!    (`i` = 0, 1, … one byte) by keeping each byte below 224 as `byte mod 56`. The extension
//!    and the app both show it; the person compares them and connects in the app with the
//!    master password.
//!
//! A program put between them (a changed native-host registration) has to make one key pair
//! with each side, and the two codes then differ. It can't choose its keys to make them agree:
//! it must answer the extension's commitment before it learns `E`, and commit towards the app
//! before it learns `A`, so the codes match by chance only, one in 56^8 (about 10^14) per
//! attempt, each attempt in front of the person. A program that merely asks the app to connect
//! (no extension behind it) makes the app show a code the extension doesn't: the dialog says
//! to connect only when the extension shows the same one, and a second request while one waits
//! is said there too.
//!
//! The extension names its version in step 1 (`"version":"0.4.8"`, its manifest's), and the
//! app connects only one of [`crate::protocol::MIN_EXTENSION_VERSION`] or later. An extension
//! older than the key agreement asked with a bare `{"type":"pair"}` and was handed a random
//! key, which passed through whatever was in between: it is refused now
//! ([`Envelope::Outdated`]), as is every one that names no version or an older one.
//!
//! **Asking.** Every request is sealed (AES-256-GCM) with a key derived from `K`, and so is
//! every answer to it:
//! - `K_req = HKDF-Expand(K, "vault-browser/requests")` and
//!   `K_ans = HKDF-Expand(K, "vault-browser/answers")`, 32 bytes each. `K` is already 32 uniform
//!   bytes, so there is no extract step (RFC 5869 §3.3), and one block of HKDF-Expand is
//!   `HMAC-SHA-256(K, info ‖ 0x01)`, which the extension computes with the key object it holds.
//! - A request: `{"type":"sealed","counter":c,"data":base64(n ‖ AES-256-GCM(K_req, n, request,
//!   aad = "vault-browser/request" ‖ c as 8 bytes LE))}` with a random 96-bit `n`. The counter is
//!   the sender's clock (see [`Replay`]): each one is accepted once, and only near our clock.
//! - Its answer: `{"type":"sealed","data":base64(m ‖ AES-256-GCM(K_ans, m, answer,
//!   aad = "vault-browser/answer" ‖ c ‖ n))}` with a random `m`: bound to the very request it
//!   answers, so an old answer can't be passed off for a new request.
//! - Only the answers given before any trust (not connected, not running, not understood, too
//!   old) are plain: they tell nothing.
//! - Inside, the text is `{"version":…,"request":{…}}` (`protocol::asked`): an extension below
//!   the version floor is refused, sealed, with nothing else said.
//!
//! So a program in between reads nothing (not the logins, not a password being filled or
//! saved, not the PIN typed for a locked login) and can't forge an answer (a generated password
//! it knows, a passkey of its own). Nonces are random, never the counter: the set of counters
//! seen starts empty each time the app starts.
//!
//! An extension older than sealed requests signed them instead
//! (`{"type":"signed","counter","body","mac"}`) and got plain answers: it is refused now, plain
//! (`outdated_extension`), and reads nothing.
//!
//! The extension keeps `K` as a browser key object that scripts can't read back. The app keeps
//! it sealed with the vault, so it is readable only while the vault is open (plus a copy
//! protected for the Windows user, for filling while locked). Neither side stores the master
//! password.
//!
//! Limit: a program with the person's own rights can still copy the browser's stored data,
//! the key object among it. Pairing raises the cost of asking and of listening in; the PIN or
//! Windows Hello on each locked login is what stands in front of the secrets.

use aes_gcm::{Aes256Gcm, aead::AeadInOut};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
use serde::{Deserialize, de::IgnoredAny};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// How far a request's counter (the sender's clock) may be from ours, in milliseconds.
const MAX_CLOCK_DRIFT_MS: u64 = 2 * 60 * 1000;
/// Counters are the sender's clock in milliseconds × this, plus a random part below it.
pub const COUNTER_SCALE: u64 = 1000;
/// Most counters remembered at once; more within the drift window are refused.
const MAX_SEEN: usize = 4096;
/// HKDF info of the key requests are sealed with.
const REQUEST_KEY_INFO: &[u8] = b"vault-browser/requests";
/// HKDF info of the key answers are sealed with.
const ANSWER_KEY_INFO: &[u8] = b"vault-browser/answers";
/// What a sealed request's associated data starts with.
const REQUEST_LABEL: &[u8] = b"vault-browser/request";
/// What a sealed answer's associated data starts with.
const ANSWER_LABEL: &[u8] = b"vault-browser/answer";
/// AES-GCM's nonce and tag sizes.
pub const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// HKDF info of the connection key agreed with ECDH.
const PAIRING_INFO: &[u8] = b"vault-browser/pairing";
/// What the extension's commitment to its public key starts with.
const COMMIT_LABEL: &[u8] = b"vault-browser/pairing-commit";
/// What the code both sides show starts with.
const CODE_LABEL: &[u8] = b"vault-browser/pairing-code";
/// The code's characters: letters and digits, without the ones read for one another
/// (I l 1, O o 0).
const CODE_ALPHABET: &[u8; 56] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
/// How many characters the code has.
const CODE_LENGTH: usize = 8;
/// An uncompressed P-256 point: `04 ‖ x ‖ y`.
const POINT_LEN: usize = 65;

/// The key shared by the app and one connected extension.
#[derive(Clone)]
pub struct PairingKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for PairingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingKey(<redacted>)")
    }
}

/// A request opened by [`PairingKey::open_request`]: its text, and the nonce its answer is
/// bound to.
pub struct OpenedRequest {
    pub body: Zeroizing<Vec<u8>>,
    pub nonce: [u8; NONCE_LEN],
}

impl std::fmt::Debug for OpenedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpenedRequest(<redacted>)")
    }
}

impl PairingKey {
    /// A new random key (`None` only if the system's random source fails).
    pub fn generate() -> Option<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).ok()?;
        Some(Self(bytes))
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(Zeroizing::new(bytes.try_into().ok()?)))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key as hex, wiped on drop.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// One block of HKDF-SHA-256-Expand with this key as the PRK (see the module's notes).
    fn expand(&self, info: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
        let mut hmac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.0.as_ref()).ok()?;
        hmac.update(info);
        hmac.update(&[1]);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&hmac.finalize().into_bytes());
        Some(key)
    }

    fn cipher(&self, info: &[u8]) -> Option<Aes256Gcm> {
        <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(self.expand(info)?.as_ref()).ok()
    }

    /// `text` sealed with the key derived for `info`, under `nonce`, as
    /// `base64(nonce ‖ ciphertext ‖ tag)`.
    fn seal(
        &self,
        info: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        text: &[u8],
    ) -> Option<String> {
        let cipher = self.cipher(info)?;
        // Room for the tag, so the plaintext is never copied by a reallocation.
        let mut buffer = Zeroizing::new(Vec::with_capacity(text.len() + TAG_LEN));
        buffer.extend_from_slice(text);
        cipher
            .encrypt_in_place(nonce.into(), aad, &mut *buffer)
            .ok()?;
        let mut sealed = Vec::with_capacity(NONCE_LEN + buffer.len());
        sealed.extend_from_slice(nonce);
        sealed.extend_from_slice(&buffer);
        Some(STANDARD.encode(sealed))
    }

    /// The text [`PairingKey::seal`] put in `data`, and its nonce, when it was sealed with the
    /// key for `info` and the same associated data, and is unchanged.
    fn open(
        &self,
        info: &[u8],
        aad: &[u8],
        data: &str,
    ) -> Option<(Zeroizing<Vec<u8>>, [u8; NONCE_LEN])> {
        let sealed = STANDARD.decode(data).ok()?;
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = sealed[..NONCE_LEN].try_into().ok()?;
        let mut buffer = Zeroizing::new(sealed[NONCE_LEN..].to_vec());
        self.cipher(info)?
            .decrypt_in_place((&nonce).into(), aad, &mut *buffer)
            .ok()?;
        Some((buffer, nonce))
    }

    /// A request sealed as the extension sends it (`link.js` `seal`), with a fresh nonce: the
    /// whole message, and the nonce its answer will be bound to. For tests and tools.
    pub fn seal_request(&self, counter: u64, request: &[u8]) -> Option<(String, [u8; NONCE_LEN])> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).ok()?;
        Some((self.seal_request_with(counter, request, &nonce)?, nonce))
    }

    fn seal_request_with(
        &self,
        counter: u64,
        request: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Option<String> {
        let data = self.seal(REQUEST_KEY_INFO, nonce, &request_aad(counter), request)?;
        Some(format!(
            r#"{{"type":"sealed","counter":{counter},"data":"{data}"}}"#
        ))
    }

    /// The request in a sealed envelope (`counter`, `data`), when it was sealed with this
    /// connection's key for this counter and is unchanged.
    pub fn open_request(&self, counter: u64, data: &str) -> Option<OpenedRequest> {
        let (body, nonce) = self.open(REQUEST_KEY_INFO, &request_aad(counter), data)?;
        Some(OpenedRequest { body, nonce })
    }

    /// `answer` (JSON) sealed for the extension, bound to the request it answers (`counter`
    /// and that request's nonce), under a fresh nonce of its own: the whole message.
    pub fn seal_answer(
        &self,
        counter: u64,
        request_nonce: &[u8; NONCE_LEN],
        answer: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).ok()?;
        self.seal_answer_with(counter, request_nonce, answer, &nonce)
    }

    fn seal_answer_with(
        &self,
        counter: u64,
        request_nonce: &[u8; NONCE_LEN],
        answer: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Option<Zeroizing<Vec<u8>>> {
        let aad = answer_aad(counter, request_nonce);
        let data = self.seal(ANSWER_KEY_INFO, nonce, &aad, answer)?;
        Some(Zeroizing::new(
            format!(r#"{{"type":"sealed","data":"{data}"}}"#).into_bytes(),
        ))
    }

    /// The text of an answer sealed by [`PairingKey::seal_answer`] for this request, when it
    /// opens (what the extension does, in `link.js` `opened`). For tests and tools.
    pub fn open_answer(
        &self,
        counter: u64,
        request_nonce: &[u8; NONCE_LEN],
        answer: &[u8],
    ) -> Option<Zeroizing<String>> {
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
        enum Sealed {
            Sealed { data: String },
        }
        let Sealed::Sealed { data } = serde_json::from_slice(answer).ok()?;
        let (text, _) = self.open(ANSWER_KEY_INFO, &answer_aad(counter, request_nonce), &data)?;
        let text = std::str::from_utf8(&text).ok()?;
        Some(Zeroizing::new(text.to_owned()))
    }
}

fn request_aad(counter: u64) -> Vec<u8> {
    [REQUEST_LABEL, &counter.to_le_bytes()].concat()
}

fn answer_aad(counter: u64, request_nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    [ANSWER_LABEL, &counter.to_le_bytes(), request_nonce].concat()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Exactly `N` bytes written as `2N` hex digits.
fn from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N || !text.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(bytes)
}

// ---- connecting ----

/// A connection waiting for the person's approval in the app: its key, and the code both
/// sides show for it, which the person compares.
#[derive(Clone, Debug)]
pub struct Pending {
    pub key: PairingKey,
    pub code: String,
}

/// The code both sides of a key agreement show ("74At LSYM"; see the module's notes).
fn agreed_code(extension: &[u8; POINT_LEN], app: &[u8; POINT_LEN]) -> String {
    let mut code = Vec::with_capacity(CODE_LENGTH);
    for block in 0..=u8::MAX {
        let hash = Sha256::new()
            .chain_update(CODE_LABEL)
            .chain_update(extension)
            .chain_update(app)
            .chain_update([block])
            .finalize();
        for &byte in hash.iter() {
            if code.len() == CODE_LENGTH {
                break;
            }
            // 224 = 4 × 56: below it every character is equally likely.
            if byte < 224 {
                code.push(CODE_ALPHABET[usize::from(byte) % CODE_ALPHABET.len()]);
            }
        }
        if code.len() == CODE_LENGTH {
            break;
        }
    }
    let code = String::from_utf8(code).unwrap_or_default();
    format!("{} {}", &code[..CODE_LENGTH / 2], &code[CODE_LENGTH / 2..])
}

/// A fresh secret key (`None` only if the system's random source fails).
fn fresh_secret() -> Option<SecretKey> {
    // A random 32-byte string is a valid P-256 scalar except with a chance of about 2^-32.
    for _ in 0..4 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).ok()?;
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Some(secret);
        }
    }
    None
}

fn public_of(secret: &SecretKey) -> Option<[u8; POINT_LEN]> {
    secret
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .ok()
}

fn commitment(extension: &[u8; POINT_LEN]) -> [u8; 32] {
    Sha256::new()
        .chain_update(COMMIT_LABEL)
        .chain_update(extension)
        .finalize()
        .into()
}

/// The connection key and code, from one side's secret and the other side's public key.
fn agree(
    secret: &SecretKey,
    peer: &[u8; POINT_LEN],
    extension: &[u8; POINT_LEN],
    app: &[u8; POINT_LEN],
) -> Option<Pending> {
    let peer = PublicKey::from_sec1_bytes(peer).ok()?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let salt = [extension.as_slice(), app.as_slice()].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt.as_slice()), shared.raw_secret_bytes().as_slice())
        .expand(PAIRING_INFO, key.as_mut())
        .ok()?;
    Some(Pending {
        key: PairingKey(key),
        code: agreed_code(extension, app),
    })
}

/// The app's half of a connection being agreed: the extension's commitment, and the app's
/// fresh key pair.
pub struct Offer {
    commit: [u8; 32],
    secret: SecretKey,
    public: [u8; POINT_LEN],
}

impl std::fmt::Debug for Offer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Offer(<redacted>)")
    }
}

impl Offer {
    /// Answers an extension's commitment (hex) with a fresh key pair; `None` when the
    /// commitment isn't 32 bytes of hex or the random source fails.
    pub fn new(commit: &str) -> Option<Self> {
        Self::with_secret(commit, fresh_secret()?)
    }

    fn with_secret(commit: &str, secret: SecretKey) -> Option<Self> {
        Some(Self {
            commit: from_hex::<32>(commit)?,
            public: public_of(&secret)?,
            secret,
        })
    }

    /// The app's public key, for `{"type":"pair_offer","key":…}`.
    pub fn public_hex(&self) -> String {
        to_hex(&self.public)
    }

    /// The extension's public key (hex) revealed: the connection waiting for approval, when it
    /// is the key committed to and a point on the curve.
    pub fn finish(&self, extension: &str) -> Option<Pending> {
        let extension = from_hex::<POINT_LEN>(extension)?;
        if commitment(&extension) != self.commit {
            return None;
        }
        agree(&self.secret, &extension, &extension, &self.public)
    }
}

/// The extension's half of the key agreement, as `link.js` does it: for tests, and so this
/// side pins the construction too.
pub struct Joiner {
    secret: SecretKey,
    public: [u8; POINT_LEN],
}

impl std::fmt::Debug for Joiner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Joiner(<redacted>)")
    }
}

impl Joiner {
    pub fn new() -> Option<Self> {
        Self::with_secret(fresh_secret()?)
    }

    fn with_secret(secret: SecretKey) -> Option<Self> {
        Some(Self {
            public: public_of(&secret)?,
            secret,
        })
    }

    /// For `{"type":"pair","commit":…}`.
    pub fn commit_hex(&self) -> String {
        to_hex(&commitment(&self.public))
    }

    /// For `{"type":"pair_key","key":…}`.
    pub fn public_hex(&self) -> String {
        to_hex(&self.public)
    }

    /// The connection agreed with the app's public key (hex), and the code to show.
    pub fn finish(&self, app: &str) -> Option<Pending> {
        let app = from_hex::<POINT_LEN>(app)?;
        agree(&self.secret, &app, &self.public, &app)
    }
}

/// Refuses a request seen before.
///
/// A counter is the sender's clock in milliseconds × [`COUNTER_SCALE`] plus a random part,
/// so requests sent at the same moment differ: the extension's window and its background
/// worker ask in parallel, and their requests may arrive in any order. A counter is accepted
/// once, and only near our clock; older ones are refused by the clock alone, so only the
/// counters of the last few minutes are remembered.
#[derive(Debug, Default)]
pub struct Replay {
    seen: std::collections::VecDeque<u64>,
}

impl Replay {
    pub fn accept(&mut self, counter: u64, now_ms: u64) -> bool {
        let near = |counter: u64| (counter / COUNTER_SCALE).abs_diff(now_ms) <= MAX_CLOCK_DRIFT_MS;
        if !near(counter) {
            return false;
        }
        self.seen.retain(|&seen| near(seen));
        if self.seen.contains(&counter) || self.seen.len() >= MAX_SEEN {
            return false;
        }
        self.seen.push_back(counter);
        true
    }
}

/// What arrives from the extension, before anything is trusted.
#[derive(Debug, PartialEq, Eq)]
pub enum Envelope {
    /// "Is the app there?" Answered to anyone: it tells nothing but locked or not.
    Status,
    /// "Connect me": the extension's commitment to its public key (step 1), from an extension
    /// the app answers.
    PairCommit {
        commit: String,
    },
    /// The extension's public key, revealed (step 3).
    PairKey {
        key: String,
    },
    /// A sealed request (a [`crate::protocol::Request`] as JSON inside `data`).
    Sealed {
        counter: u64,
        data: String,
    },
    /// From an extension older than the version floor (`protocol::MIN_EXTENSION_VERSION`):
    /// a bare `pair` or a `signed` request (extensions older than the sealed link), or a `pair`
    /// that names an older version or none. Refused plain, `outdated_extension`.
    Outdated,
    Invalid,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Outer {
    Status {},
    Pair {
        commit: Option<String>,
        version: Option<String>,
    },
    PairKey {
        key: String,
    },
    Sealed {
        counter: u64,
        data: String,
    },
    /// Read only to be recognised: nothing in it is kept.
    Signed {
        #[serde(rename = "counter")]
        _counter: IgnoredAny,
        #[serde(rename = "body")]
        _body: IgnoredAny,
        #[serde(rename = "mac")]
        _mac: IgnoredAny,
    },
}

impl Envelope {
    pub fn parse(message: &[u8]) -> Self {
        match serde_json::from_slice::<Outer>(message) {
            Ok(Outer::Status {}) => Self::Status,
            Ok(Outer::Pair {
                commit: Some(commit),
                version: Some(version),
            }) if crate::protocol::accepted_version(&version) => Self::PairCommit { commit },
            Ok(Outer::Pair { .. } | Outer::Signed { .. }) => Self::Outdated,
            Ok(Outer::PairKey { key }) => Self::PairKey { key },
            Ok(Outer::Sealed { counter, data }) => Self::Sealed { counter, data },
            Err(_) => Self::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTER: u64 = 1_800_000_000_123;
    const REQUEST: &[u8] = br#"{"type":"logins","url":"https://github.com/"}"#;
    const ANSWER: &[u8] = br#"{"type":"logins","items":[]}"#;
    /// Bytes 1 to 12, and 0x21 to 0x2c.
    const REQUEST_NONCE: [u8; NONCE_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const ANSWER_NONCE: [u8; NONCE_LEN] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
    ];

    /// The same vectors as `apps/extension/test/link.test.mjs`, computed apart with Node's
    /// `crypto` (OpenSSL's HMAC and AES-GCM) for key 07×32: both sides derive the keys and seal
    /// alike.
    #[test]
    fn requests_and_answers_are_sealed_as_specified() {
        let key = PairingKey::from_bytes(&[7u8; 32]).unwrap();
        assert_eq!(
            to_hex(key.expand(REQUEST_KEY_INFO).unwrap().as_ref()),
            "1f4056bcfcc79517d425960af34ebf14356fd5b1f901be2ddcf72b5a46562924"
        );
        assert_eq!(
            to_hex(key.expand(ANSWER_KEY_INFO).unwrap().as_ref()),
            "1549a25fa7507034ac1f2898022e3144b2e91137c4a6e9fa8fd5f11051d6442a"
        );
        let request = key
            .seal_request_with(COUNTER, REQUEST, &REQUEST_NONCE)
            .unwrap();
        let data = "AQIDBAUGBwgJCgsMHtP2/rQqZUHHS+svo50x6RGFhF5yN20hcEMv/K9x2HiZiTpKgUmu+dECSD6oT/oj2BS+bMkb0SZ2T252VA==";
        assert_eq!(
            request,
            format!(r#"{{"type":"sealed","counter":{COUNTER},"data":"{data}"}}"#)
        );
        assert_eq!(
            Envelope::parse(request.as_bytes()),
            Envelope::Sealed {
                counter: COUNTER,
                data: data.into()
            }
        );
        let opened = key.open_request(COUNTER, data).unwrap();
        assert_eq!(opened.body.as_slice(), REQUEST);
        assert_eq!(opened.nonce, REQUEST_NONCE);

        let answer = key
            .seal_answer_with(COUNTER, &REQUEST_NONCE, ANSWER, &ANSWER_NONCE)
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&answer).unwrap(),
            r#"{"type":"sealed","data":"ISIjJCUmJygpKissm6LbrMi/r6elsr/MgqvvVY5ATBtOVbI6FYJcbhUi3IqbMwXbdel3kYt6GF0="}"#
        );
        assert_eq!(
            key.open_answer(COUNTER, &REQUEST_NONCE, &answer)
                .unwrap()
                .as_bytes(),
            ANSWER
        );
    }

    #[test]
    fn a_changed_or_misplaced_message_does_not_open() {
        let key = PairingKey::from_bytes(&[7u8; 32]).unwrap();
        let other = PairingKey::from_bytes(&[8u8; 32]).unwrap();
        let (request, nonce) = key.seal_request(COUNTER, REQUEST).unwrap();
        let Envelope::Sealed { counter, data } = Envelope::parse(request.as_bytes()) else {
            panic!("{request}");
        };
        assert_eq!(counter, COUNTER);
        assert!(key.open_request(COUNTER, &data).is_some());
        // Another connection, another counter, an answer's key, a changed byte, cut short.
        assert!(other.open_request(COUNTER, &data).is_none());
        assert!(key.open_request(COUNTER + 1, &data).is_none());
        assert!(
            key.open(ANSWER_KEY_INFO, &request_aad(COUNTER), &data)
                .is_none()
        );
        let mut bytes = STANDARD.decode(&data).unwrap();
        bytes[NONCE_LEN + 3] ^= 1;
        assert!(
            key.open_request(COUNTER, &STANDARD.encode(&bytes))
                .is_none()
        );
        assert!(
            key.open_request(COUNTER, &STANDARD.encode(&bytes[..20]))
                .is_none()
        );
        assert!(key.open_request(COUNTER, "not base64!").is_none());

        let answer = key.seal_answer(COUNTER, &nonce, ANSWER).unwrap();
        assert_eq!(
            key.open_answer(COUNTER, &nonce, &answer)
                .unwrap()
                .as_bytes(),
            ANSWER
        );
        // Bound to its request: not the answer to another counter or another request.
        assert!(key.open_answer(COUNTER + 1, &nonce, &answer).is_none());
        assert!(key.open_answer(COUNTER, &[0; NONCE_LEN], &answer).is_none());
        assert!(other.open_answer(COUNTER, &nonce, &answer).is_none());
        // A request can't be passed off as an answer, nor an answer as a request.
        let Some(sealed_request) = request.split(r#""data":""#).nth(1) else {
            panic!("{request}");
        };
        let reflected = format!(r#"{{"type":"sealed","data":"{sealed_request}"#);
        assert!(
            key.open_answer(COUNTER, &nonce, reflected.as_bytes())
                .is_none()
        );
        let answer_data: serde_json::Value = serde_json::from_slice(&answer).unwrap();
        assert!(
            key.open_request(COUNTER, answer_data["data"].as_str().unwrap())
                .is_none()
        );
        // Two seals of the same text differ (fresh nonces).
        assert_ne!(
            key.seal_request(COUNTER, REQUEST).unwrap().0,
            key.seal_request(COUNTER, REQUEST).unwrap().0
        );
        // Text that needs escaping in JSON survives the round trip.
        let tricky = "{\"type\":\"x\",\"v\":\"a\\\"b\\u0001\u{e9}\"}";
        let answer = key.seal_answer(1, &nonce, tricky.as_bytes()).unwrap();
        assert_eq!(
            key.open_answer(1, &nonce, &answer).unwrap().as_str(),
            tricky
        );
    }

    /// Fixed secrets 11×32 (the extension) and 22×32 (the app); the same vector as
    /// `apps/extension/test/link.test.mjs`, computed apart with Node's `crypto`.
    #[test]
    fn both_sides_agree_on_the_key_and_the_code() {
        let joiner = Joiner::with_secret(SecretKey::from_slice(&[0x11; 32]).unwrap()).unwrap();
        let extension = "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794";
        assert_eq!(joiner.public_hex(), extension);
        let commit = "56135d400b11486d786cc15da678e0498718808a61cd417e7bc3b40405d108e8";
        assert_eq!(joiner.commit_hex(), commit);
        let current = crate::protocol::MIN_EXTENSION_VERSION;
        assert_eq!(
            Envelope::parse(
                format!(r#"{{"type":"pair","commit":"{commit}","version":"{current}"}}"#)
                    .as_bytes()
            ),
            Envelope::PairCommit {
                commit: commit.into()
            }
        );
        let offer =
            Offer::with_secret(commit, SecretKey::from_slice(&[0x22; 32]).unwrap()).unwrap();
        let app = "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285";
        assert_eq!(offer.public_hex(), app);
        let at_app = offer.finish(extension).unwrap();
        let at_extension = joiner.finish(app).unwrap();
        assert_eq!(
            to_hex(at_app.key.as_bytes()),
            "ea6aae30def35019834e7828de518d6037a7c2d4cd2e1ef596215828f5e0e3ed"
        );
        assert_eq!(at_extension.key.as_bytes(), at_app.key.as_bytes());
        assert_eq!(
            (at_app.code.as_str(), at_extension.code.as_str()),
            ("74At LSYM", "74At LSYM")
        );
    }

    #[test]
    fn a_program_in_between_is_caught_by_the_code() {
        let extension = Joiner::new().unwrap();
        let offer = Offer::new(&extension.commit_hex()).unwrap();
        // A key other than the one committed to is refused, and so is a point off the curve.
        let stranger = Joiner::new().unwrap();
        assert!(offer.finish(&stranger.public_hex()).is_none());
        assert!(offer.finish(&"04".repeat(65)).is_none());
        assert!(offer.finish("04").is_none());
        // In between: one key pair with each side. Both connections open, but their codes
        // differ (unless by a chance of one in 56^8, which the person's comparison must miss).
        let towards_app = Joiner::new().unwrap();
        let app_offer = Offer::new(&towards_app.commit_hex()).unwrap();
        let app_side = app_offer.finish(&towards_app.public_hex()).unwrap();
        let towards_extension = Offer::new(&extension.commit_hex()).unwrap();
        let extension_side = extension.finish(&towards_extension.public_hex()).unwrap();
        assert_ne!(app_side.key.as_bytes(), extension_side.key.as_bytes());
        assert_ne!(app_side.code, extension_side.code);
        // An honest run agrees, and fresh runs make fresh keys.
        let honest = (
            offer.finish(&extension.public_hex()).unwrap(),
            extension.finish(&offer.public_hex()).unwrap(),
        );
        assert_eq!(honest.0.key.as_bytes(), honest.1.key.as_bytes());
        assert_eq!(honest.0.code, honest.1.code);
        // Eight characters of the alphabet, in two groups of four.
        let (left, right) = honest.0.code.split_once(' ').unwrap();
        assert_eq!((left.len(), right.len()), (4, 4));
        assert!(
            format!("{left}{right}")
                .bytes()
                .all(|byte| CODE_ALPHABET.contains(&byte))
        );
        assert_ne!(honest.0.key.as_bytes(), app_side.key.as_bytes());
        assert!(
            !format!("{offer:?}{extension:?}{:?}", honest.0)
                .contains(&to_hex(honest.0.key.as_bytes()))
        );
        assert!(Offer::new("zz").is_none());
    }

    #[test]
    fn extensions_below_the_version_floor_are_refused() {
        let commit = "56".repeat(32);
        let pair = |version: &str| {
            Envelope::parse(
                format!(r#"{{"type":"pair","commit":"{commit}","version":"{version}"}}"#)
                    .as_bytes(),
            )
        };
        assert!(matches!(
            pair(crate::protocol::MIN_EXTENSION_VERSION),
            Envelope::PairCommit { .. }
        ));
        assert!(matches!(pair("9.0.0"), Envelope::PairCommit { .. }));
        for old in ["0.4.6", "0.0.1", "", "0.4", "newest"] {
            assert_eq!(pair(old), Envelope::Outdated, "{old}");
        }
        // An extension older than the key agreement asked to be handed a key; one older than
        // versions commits without naming one; one older than sealed requests signs them.
        // None of them is answered but with "too old".
        let current = crate::protocol::MIN_EXTENSION_VERSION;
        for old in [
            r#"{"type":"pair"}"#.to_owned(),
            format!(r#"{{"type":"pair","commit":"{commit}"}}"#),
            format!(r#"{{"type":"pair","version":"{current}"}}"#),
            format!(
                r#"{{"type":"signed","counter":5,"body":"{{\"type\":\"status\"}}","mac":"{}"}}"#,
                "ab".repeat(32)
            ),
        ] {
            assert_eq!(Envelope::parse(old.as_bytes()), Envelope::Outdated, "{old}");
        }
        assert!(PairingKey::from_bytes(&[7u8; 31]).is_none());
        let key = PairingKey::from_bytes(&[7u8; 32]).unwrap();
        assert_eq!(key.to_hex().len(), 64);
        assert!(!format!("{key:?}").contains('7'));
    }

    #[test]
    fn requests_can_not_be_replayed_or_come_from_another_time() {
        let mut replay = Replay::default();
        let now = 1_800_000_000_000;
        let at = |ms: u64, random: u64| ms * COUNTER_SCALE + random;
        assert!(replay.accept(at(now, 17), now));
        assert!(!replay.accept(at(now, 17), now), "the same request again");
        // Sent at the same moment, or arriving out of order: each one counts once.
        assert!(replay.accept(at(now, 912), now));
        assert!(replay.accept(at(now - 3, 4), now));
        assert!(!replay.accept(at(now - 3, 4), now + 50));
        assert!(
            !replay.accept(at(now + 10 * 60 * 1000, 0), now),
            "from the future"
        );
        assert!(
            !Replay::default().accept(at(now - 10 * 60 * 1000, 0), now),
            "stale"
        );
        // A plain millisecond clock (an older extension) is far from ours: refused.
        assert!(!Replay::default().accept(now, now));
        // What was seen is forgotten once the clock alone refuses it.
        replay.accept(at(now + 5 * 60 * 1000, 1), now + 5 * 60 * 1000);
        assert_eq!(replay.seen.len(), 1);
    }

    #[test]
    fn envelopes_are_strict() {
        assert_eq!(Envelope::parse(br#"{"type":"status"}"#), Envelope::Status);
        assert_eq!(Envelope::parse(br#"{"type":"pair"}"#), Envelope::Outdated);
        assert_eq!(
            Envelope::parse(br#"{"type":"pair_key","key":"04ab"}"#),
            Envelope::PairKey { key: "04ab".into() }
        );
        assert_eq!(
            Envelope::parse(br#"{"type":"signed","counter":5,"body":"{}","mac":"ab"}"#),
            Envelope::Outdated
        );
        for bad in [
            &br#"{"type":"logins","url":"https://github.com/"}"#[..],
            br#"{"type":"signed","counter":5,"body":"{}"}"#,
            br#"{"type":"signed","counter":5,"body":"{}","mac":"ab","more":1}"#,
            br#"{"type":"sealed","counter":5}"#,
            br#"{"type":"sealed","counter":5,"data":"","mac":"ab"}"#,
            br#"{"type":"pair","extra":true}"#,
            br#"{"type":"pair_key"}"#,
            b"",
        ] {
            assert_eq!(Envelope::parse(bad), Envelope::Invalid);
        }
    }
}
