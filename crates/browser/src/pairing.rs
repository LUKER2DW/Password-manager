//! Pairing: only an extension the person connected to the app may ask for logins.
//!
//! The first time, the extension asks to be connected. The app makes a random key, shows a
//! short code and waits for the person to allow it in the app's own window; the extension
//! shows the same code. From then on every request carries a counter and an
//! HMAC-SHA-256 over it, made with that key. A request without a valid one gets nothing, so
//! a program that merely starts the native host is refused.
//!
//! The extension keeps the key as a browser key object that scripts can't read back. The app
//! keeps it sealed with the vault, so it is readable only while the vault is open. Neither
//! side ever stores the master password.
//!
//! Limit: a program with the person's own rights can still copy the browser's stored data.
//! Pairing raises the cost of asking; the PIN or Windows Hello on each locked login is what
//! stands in front of the secrets.

use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// How far a request's counter (the sender's clock, in milliseconds) may be from ours.
const MAX_CLOCK_DRIFT_MS: u64 = 2 * 60 * 1000;

/// The key shared by the app and one connected extension.
#[derive(Clone)]
pub struct PairingKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for PairingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingKey(<redacted>)")
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

    /// The key as hex, to hand to the extension once.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Six digits both sides show while the person decides ("482 913"). Not a secret: it
    /// only lets the person see that the app and the extension mean the same connection.
    pub fn code(&self) -> String {
        let hash = Sha256::new()
            .chain_update(b"vault-browser/pairing-code")
            .chain_update(self.0.as_ref())
            .finalize();
        let number = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 1_000_000;
        format!("{:03} {:03}", number / 1000, number % 1000)
    }

    /// Whether `mac` (hex) is HMAC-SHA-256(key, counter as 8 bytes little-endian ‖ body).
    pub fn verify(&self, counter: u64, body: &[u8], mac: &str) -> bool {
        let Some(mac) = from_hex(mac) else {
            return false;
        };
        let Ok(mut hmac) = <Hmac<Sha256> as KeyInit>::new_from_slice(self.0.as_ref()) else {
            return false;
        };
        hmac.update(&counter.to_le_bytes());
        hmac.update(body);
        hmac.verify_slice(&mac).is_ok()
    }
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    (0..32)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Refuses a request seen before: counters must grow, and stay near the clock.
#[derive(Debug, Default)]
pub struct Replay {
    last: u64,
}

impl Replay {
    pub fn accept(&mut self, counter: u64, now_ms: u64) -> bool {
        if counter <= self.last || counter.abs_diff(now_ms) > MAX_CLOCK_DRIFT_MS {
            return false;
        }
        self.last = counter;
        true
    }
}

/// What arrives from the extension, before anything is trusted.
#[derive(Debug, PartialEq, Eq)]
pub enum Envelope {
    /// "Is the app there?" Answered to anyone: it tells nothing but locked or not.
    Status,
    /// "Connect me": the app asks the person.
    Pair,
    /// A request ([`crate::protocol::Request`] as JSON in `body`) with its proof.
    Signed {
        counter: u64,
        body: String,
        mac: String,
    },
    Invalid,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Outer {
    Status {},
    Pair {},
    Signed {
        counter: u64,
        body: String,
        mac: String,
    },
}

impl Envelope {
    pub fn parse(message: &[u8]) -> Self {
        match serde_json::from_slice::<Outer>(message) {
            Ok(Outer::Status {}) => Self::Status,
            Ok(Outer::Pair {}) => Self::Pair,
            Ok(Outer::Signed { counter, body, mac }) => Self::Signed { counter, body, mac },
            Err(_) => Self::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(key: &PairingKey, counter: u64, body: &[u8]) -> String {
        let mut hmac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes()).unwrap();
        hmac.update(&counter.to_le_bytes());
        hmac.update(body);
        hmac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn only_the_paired_key_signs_requests() {
        let key = PairingKey::from_bytes(&[7u8; 32]).unwrap();
        let other = PairingKey::from_bytes(&[8u8; 32]).unwrap();
        assert!(PairingKey::from_bytes(&[7u8; 31]).is_none());
        let body = br#"{"type":"logins","url":"https://github.com/"}"#;
        let mac = sign(&key, 1_000, body);
        assert!(key.verify(1_000, body, &mac));
        assert!(!key.verify(1_001, body, &mac), "the counter is signed");
        assert!(!key.verify(1_000, b"{}", &mac), "the body is signed");
        assert!(!other.verify(1_000, body, &mac));
        for bad in ["", "zz", &mac[..62], &format!("{mac}00"), &"é".repeat(32)] {
            assert!(!key.verify(1_000, body, bad));
        }
        // RFC 4231 test case 2, to pin the construction (counter 0 would prefix eight zero
        // bytes, so the vector is checked on the raw primitive).
        let mut rfc = <Hmac<Sha256> as KeyInit>::new_from_slice(b"Jefe").unwrap();
        rfc.update(b"what do ya want for nothing?");
        assert_eq!(rfc.finalize().into_bytes()[..4], [0x5b, 0xdc, 0xc1, 0x46]);
        assert!(!format!("{key:?}").contains('7'));
        assert_eq!(key.to_hex().len(), 64);
    }

    #[test]
    fn the_code_is_six_digits_and_follows_the_key() {
        let a = PairingKey::from_bytes(&[1u8; 32]).unwrap().code();
        let b = PairingKey::from_bytes(&[2u8; 32]).unwrap().code();
        assert_ne!(a, b);
        assert_eq!(a.len(), 7);
        assert!(a.chars().all(|c| c.is_ascii_digit() || c == ' '));
        assert_eq!(a, PairingKey::from_bytes(&[1u8; 32]).unwrap().code());
    }

    #[test]
    fn requests_can_not_be_replayed_or_come_from_another_time() {
        let mut replay = Replay::default();
        let now = 1_800_000_000_000;
        assert!(replay.accept(now, now));
        assert!(!replay.accept(now, now), "the same request again");
        assert!(!replay.accept(now - 1, now), "an older one");
        assert!(replay.accept(now + 5, now + 9));
        assert!(!replay.accept(now + 10 * 60 * 1000, now), "from the future");
        assert!(
            !Replay::default().accept(now - 10 * 60 * 1000, now),
            "stale"
        );
    }

    #[test]
    fn envelopes_are_strict() {
        assert_eq!(Envelope::parse(br#"{"type":"status"}"#), Envelope::Status);
        assert_eq!(Envelope::parse(br#"{"type":"pair"}"#), Envelope::Pair);
        assert_eq!(
            Envelope::parse(br#"{"type":"signed","counter":5,"body":"{}","mac":"ab"}"#),
            Envelope::Signed {
                counter: 5,
                body: "{}".into(),
                mac: "ab".into()
            }
        );
        for bad in [
            &br#"{"type":"logins","url":"https://github.com/"}"#[..],
            br#"{"type":"signed","counter":5,"body":"{}"}"#,
            br#"{"type":"pair","extra":true}"#,
            b"",
        ] {
            assert_eq!(Envelope::parse(bad), Envelope::Invalid);
        }
    }
}
