//! What a device and the sync server (`vault-server`) say to each other (spec: SYNC.md §5.3).
//!
//! The server never sees a password, a key of the vault or anything it could use to open a
//! copy. It only has to know that a request comes from a device enrolled for that vault, so
//! every request is signed with the device's own Ed25519 key:
//!
//! ```text
//! vault-sync-v1/request\n METHOD\n PATH?QUERY\n DEVICE\n TIME\n NONCE\n SHA-256(BODY) (hex)
//! ```
//!
//! sent as the `x-vault-*` headers. The server refuses a request more than
//! [`MAX_CLOCK_SKEW`] seconds off its clock and any nonce it already saw, so a recorded request
//! can't be played again. A device is enrolled once with a one-time invite, proving it holds
//! its key by signing the enrollment.
//!
//! Shared by the client (`vault-platform`) and the server, so both build the same bytes.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The version of this protocol, in every signed message.
pub const PROTOCOL: &str = "vault-sync-v1";

/// Request headers.
pub mod header {
    pub const DEVICE: &str = "x-vault-device";
    pub const TIME: &str = "x-vault-time";
    pub const NONCE: &str = "x-vault-nonce";
    pub const SIGNATURE: &str = "x-vault-signature";
}

/// How far a request's time may be from the server's clock (seconds).
pub const MAX_CLOCK_SKEW: i64 = 300;
/// The biggest copy a server stores or a device reads: a vault is kilobytes to a few MB.
pub const MAX_COPY_BYTES: usize = 64 * 1024 * 1024;
/// A device's name, as shown in the lists (same limit as in the vault).
pub const MAX_NAME_CHARS: usize = 60;
/// The most a long-poll waits before answering "nothing new" (seconds).
pub const MAX_WAIT_SECONDS: u64 = 60;

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses exactly `N` bytes of hex (either case).
pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// A vault or device id as used in paths: 32 lowercase hex characters.
pub fn is_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `name` may name a device: 1 to [`MAX_NAME_CHARS`] characters, no control characters.
pub fn is_device_name(name: &str) -> bool {
    let chars = name.chars().count();
    (1..=MAX_NAME_CHARS).contains(&chars)
        && !name.chars().any(char::is_control)
        && name.trim() == name
}

/// The tag of a stored copy (its ETag): the first 16 bytes of its SHA-256, in hex.
pub fn tag(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes)[..16])
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    // An OS without randomness can't run a password manager at all.
    getrandom::fill(&mut bytes).expect("the operating system's random number generator failed");
    bytes
}

/// A fresh nonce for one request (128 bits, hex).
pub fn new_nonce() -> String {
    hex(&random::<16>())
}

/// A fresh one-time invite (128 bits, hex). The server keeps only [`invite_digest`].
pub fn new_invite() -> Zeroizing<String> {
    Zeroizing::new(hex(&random::<16>()))
}

/// What the server stores for an invite: knowing it doesn't let anyone enroll.
pub fn invite_digest(invite: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"vault-sync-v1/invite\n")
        .chain_update(invite.trim().to_ascii_lowercase().as_bytes())
        .finalize()
        .into()
}

/// Compares two invite digests in constant time.
pub fn same_digest(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// The bytes a request's signature covers.
pub fn request_message(
    method: &str,
    path_and_query: &str,
    device: &str,
    time: i64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "{PROTOCOL}/request\n{}\n{path_and_query}\n{device}\n{time}\n{nonce}\n{}",
        method.to_ascii_uppercase(),
        hex(&Sha256::digest(body))
    )
    .into_bytes()
}

/// The bytes an enrollment's signature covers: the new device proves it holds its key.
pub fn enroll_message(enroll: &Enroll) -> Vec<u8> {
    format!(
        "{PROTOCOL}/enroll\n{}\n{}\n{}\n{}\n{}\n{}",
        enroll.vault,
        enroll.device,
        enroll.key,
        enroll.name,
        enroll.time,
        hex(&invite_digest(&enroll.invite))
    )
    .into_bytes()
}

/// Checks a signature made by [`DeviceKey`] (strict: no malleable or weak-key signatures).
pub fn verify(public_key: &[u8; 32], message: &[u8], signature_hex: &str) -> bool {
    let Some(signature) = unhex::<64>(signature_hex) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    if key.is_weak() {
        return false;
    }
    let signature = Signature::from_bytes(&signature);
    key.verify_strict(message, &signature).is_ok()
}

/// A device's own signing key. Kept in the OS credential store on the device; the server
/// only ever gets [`DeviceKey::public_key`].
pub struct DeviceKey(SigningKey);

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceKey({})", hex(&self.public_key()))
    }
}

/// The headers of one signed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub device: String,
    pub time: i64,
    pub nonce: String,
    pub signature: String,
}

impl Signed {
    pub fn headers(&self) -> [(&'static str, String); 4] {
        [
            (header::DEVICE, self.device.clone()),
            (header::TIME, self.time.to_string()),
            (header::NONCE, self.nonce.clone()),
            (header::SIGNATURE, self.signature.clone()),
        ]
    }
}

impl DeviceKey {
    pub fn generate() -> Self {
        let seed = Zeroizing::new(random::<32>());
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The secret seed, to keep in the credential store.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> String {
        hex(&self.0.sign(message).to_bytes())
    }

    /// Signs one request from `device` at `time` (Unix seconds).
    pub fn sign_request(
        &self,
        device: &str,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        time: i64,
    ) -> Signed {
        let nonce = new_nonce();
        let message = request_message(method, path_and_query, device, time, &nonce, body);
        Signed {
            device: device.to_owned(),
            time,
            nonce,
            signature: self.sign(&message),
        }
    }

    /// Builds and signs an enrollment of this key as `device` of `vault`.
    pub fn enroll(&self, invite: &str, vault: &str, device: &str, name: &str, time: i64) -> Enroll {
        let mut enroll = Enroll {
            invite: invite.trim().to_ascii_lowercase(),
            vault: vault.to_owned(),
            device: device.to_owned(),
            key: hex(&self.public_key()),
            name: name.to_owned(),
            time,
            signature: String::new(),
        };
        enroll.signature = self.sign(&enroll_message(&enroll));
        enroll
    }
}

/// `POST /v1/enroll`: a device joins a vault on the server with a one-time invite.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enroll {
    pub invite: String,
    pub vault: String,
    pub device: String,
    /// Ed25519 public key (hex).
    pub key: String,
    pub name: String,
    pub time: i64,
    /// By `key`, over [`enroll_message`].
    pub signature: String,
}

impl std::fmt::Debug for Enroll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enroll")
            .field("vault", &self.vault)
            .field("device", &self.device)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// One stored copy, in `GET /v1/vaults/{vault}/devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Copy {
    pub device: String,
    pub tag: String,
    pub size: u64,
}

/// `GET /v1/vaults/{vault}/devices`: the copies, and where the change counter stands.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Copies {
    pub copies: Vec<Copy>,
    pub seq: u64,
}

/// One enrolled device, in `GET /v1/vaults/{vault}/enrolled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledDevice {
    pub device: String,
    pub name: String,
    pub added_at: i64,
    /// Unix seconds of its last signed request; 0 = none yet.
    pub seen_at: i64,
}

/// `GET /v1/vaults/{vault}/changes?after=SEQ&wait=SECONDS`: answered as soon as the counter
/// passes `after`, or with the same counter when the wait runs out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changes {
    pub seq: u64,
}

/// `POST /v1/vaults/{vault}/invites`: a one-time invite for one more device.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub invite: String,
    pub expires_at: i64,
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// An error body: a short machine-readable reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub error: String,
}

/// What a device needs to join a vault on a server, as one line of text (shown as a QR code
/// and as text to type): `vaultsync:1?server=<url>&vault=<id>&invite=<invite>`. Nothing in it
/// opens the vault: the master password and the Secret Key still have to come from the person.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteLink {
    pub server: String,
    pub vault: String,
    pub invite: String,
    /// A backup server and an invite for it (`&backup=<url>&backup_invite=<invite>`), when
    /// the vault syncs through two. Older apps skip these and join the main one only.
    pub backup: Option<(String, String)>,
}

impl std::fmt::Debug for InviteLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteLink")
            .field("server", &self.server)
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

impl InviteLink {
    const PREFIX: &'static str = "vaultsync:1?";

    pub fn to_text(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(format!(
            "{}server={}&vault={}&invite={}",
            Self::PREFIX,
            escape(&self.server),
            self.vault,
            self.invite
        ));
        if let Some((server, invite)) = &self.backup {
            text.push_str(&format!(
                "&backup={}&backup_invite={invite}",
                escape(server)
            ));
        }
        text
    }

    pub fn parse(text: &str) -> Option<Self> {
        let query = text.trim().strip_prefix(Self::PREFIX)?;
        let (mut server, mut vault, mut invite) = (None, None, None);
        let (mut backup, mut backup_invite) = (None, None);
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=')?;
            let slot = match name {
                "server" => &mut server,
                "vault" => &mut vault,
                "invite" => &mut invite,
                "backup" => &mut backup,
                "backup_invite" => &mut backup_invite,
                _ => continue,
            };
            if slot.is_some() {
                return None;
            }
            *slot = Some(unescape(value)?);
        }
        let backup = match (backup, backup_invite) {
            (Some(server), Some(invite)) => {
                let invite = invite.to_ascii_lowercase();
                if !is_id(&invite) {
                    return None;
                }
                Some((server, invite))
            }
            (None, None) => None,
            _ => return None,
        };
        let link = Self {
            server: server?,
            vault: vault?.to_ascii_lowercase(),
            invite: invite?.to_ascii_lowercase(),
            backup,
        };
        (is_id(&link.vault) && is_id(&link.invite)).then_some(link)
    }
}

fn escape(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~:/[]@".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn unescape(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(pair, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_request_verifies_and_nothing_else_does() {
        let key = DeviceKey::generate();
        let device = "ab".repeat(16);
        let signed = key.sign_request(&device, "put", "/v1/vaults/x/devices/y", b"copy", 1_000);
        let message = request_message(
            "PUT",
            "/v1/vaults/x/devices/y",
            &device,
            1_000,
            &signed.nonce,
            b"copy",
        );
        assert!(verify(&key.public_key(), &message, &signed.signature));
        // Any other body, path, time, device or key fails.
        for other in [
            request_message(
                "PUT",
                "/v1/vaults/x/devices/y",
                &device,
                1_000,
                &signed.nonce,
                b"cop",
            ),
            request_message(
                "PUT",
                "/v1/vaults/x/devices/z",
                &device,
                1_000,
                &signed.nonce,
                b"copy",
            ),
            request_message(
                "PUT",
                "/v1/vaults/x/devices/y",
                &device,
                1_001,
                &signed.nonce,
                b"copy",
            ),
            request_message(
                "GET",
                "/v1/vaults/x/devices/y",
                &device,
                1_000,
                &signed.nonce,
                b"copy",
            ),
            request_message(
                "PUT",
                "/v1/vaults/x/devices/y",
                &"cd".repeat(16),
                1_000,
                &signed.nonce,
                b"copy",
            ),
        ] {
            assert!(!verify(&key.public_key(), &other, &signed.signature));
        }
        let stranger = DeviceKey::generate();
        assert!(!verify(&stranger.public_key(), &message, &signed.signature));
        assert!(!verify(&key.public_key(), &message, "zz"));
        assert!(!verify(&[0; 32], &message, &signed.signature));
    }

    #[test]
    fn an_enrollment_proves_the_key_and_binds_the_invite() {
        let key = DeviceKey::generate();
        let invite = new_invite();
        let enroll = key.enroll(&invite, &"a".repeat(32), &"b".repeat(32), "Phone", 5);
        let public = unhex::<32>(&enroll.key).unwrap();
        assert!(verify(&public, &enroll_message(&enroll), &enroll.signature));
        let mut other = enroll.clone();
        other.name = "Laptop".into();
        assert!(!verify(&public, &enroll_message(&other), &enroll.signature));
        other = enroll.clone();
        other.invite = new_invite().to_string();
        assert!(!verify(&public, &enroll_message(&other), &enroll.signature));
        assert!(!format!("{enroll:?}").contains(&*invite));
    }

    #[test]
    fn a_key_survives_its_seed() {
        let key = DeviceKey::generate();
        let again = DeviceKey::from_seed(&key.seed());
        assert_eq!(key.public_key(), again.public_key());
    }

    #[test]
    fn an_invite_link_reads_back() {
        let link = InviteLink {
            server: "https://vault.example-tailnet.ts.net:8443/sync".into(),
            vault: "0123456789abcdef0123456789abcdef".into(),
            invite: "fedcba9876543210fedcba9876543210".into(),
            backup: None,
        };
        let text = link.to_text();
        assert_eq!(InviteLink::parse(&text), Some(link.clone()));
        let odd = InviteLink {
            server: "https://host/a b&c=d".into(),
            ..link.clone()
        };
        assert_eq!(InviteLink::parse(&odd.to_text()), Some(odd));
        assert_eq!(InviteLink::parse("vaultsync:1?server=x&vault=1"), None);
        assert_eq!(InviteLink::parse(&text.replace("vault=0", "vault=g")), None);
        assert_eq!(
            InviteLink::parse(&format!("{}&vault={}", *text, link.vault)),
            None
        );
        assert!(!format!("{link:?}").contains(&link.invite));

        // With a backup server: both come back; an app that doesn't know them joins the
        // main one; half of a backup is refused.
        let both = InviteLink {
            backup: Some((
                "https://192.168.0.9:8750#pin=00ff".into(),
                "00112233445566778899aabbccddeeff".into(),
            )),
            ..link.clone()
        };
        let text = both.to_text();
        assert!(text.contains("&backup=https://192.168.0.9:8750%23pin%3D00ff&backup_invite="));
        assert_eq!(InviteLink::parse(&text), Some(both));
        assert_eq!(
            InviteLink::parse(&text.replace("&backup_invite=00112233445566778899aabbccddeeff", "")),
            None
        );
        assert_eq!(
            InviteLink::parse(&text.replace("backup_invite=0011", "backup_invite=zz11")),
            None
        );
    }

    #[test]
    fn ids_names_and_hex() {
        assert!(is_id(&"0a".repeat(16)));
        assert!(!is_id(&"0A".repeat(16)));
        assert!(!is_id("../../etc"));
        assert!(is_device_name("Phone"));
        assert!(!is_device_name(""));
        assert!(!is_device_name(" Phone"));
        assert!(!is_device_name("a\nb"));
        assert!(!is_device_name(&"x".repeat(61)));
        assert_eq!(unhex::<2>("0aFF"), Some([0x0a, 0xff]));
        assert_eq!(unhex::<2>("0aF"), None);
        assert_eq!(tag(b"x").len(), 32);
        assert!(same_digest(&invite_digest("AB "), &invite_digest("ab")));
    }
}
