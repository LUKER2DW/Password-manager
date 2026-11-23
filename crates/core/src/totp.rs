//! One-time passwords for items that store a setup key: time-based (TOTP, RFC 6238) and
//! counter-based (HOTP, RFC 4226). A counter-based key keeps its counter in its own
//! `otpauth://hotp/…&counter=N` link, in the item's `totp` field: the next code is asked for by
//! moving the counter on ([`next_counter`]), which changes the link, so it syncs with the item.

use std::fmt;

// The std clock on a computer or phone; the browser's in a web build (std's panics there).
use web_time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed one-time code configuration. The shared secret is wiped on drop.
#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
    /// Counter-based (HOTP): the counter of the current code. `None` for time-based codes.
    counter: Option<u64>,
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("counter", &self.counter)
            .finish()
    }
}

impl Totp {
    /// Parses an `otpauth://totp/...` or `otpauth://hotp/...` URI, or a bare Base32 secret
    /// (RFC 4648; spaces ignored; time-based).
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let counter_based = has_prefix(input, HOTP);
        if !has_prefix(input, TOTP) && !counter_based {
            return Self::new(base32_decode(input)?, TotpAlgorithm::Sha1, 6, 30, None);
        }

        let query = input.split_once('?').map(|(_, q)| q).unwrap_or_default();
        let mut secret = None;
        let (mut algorithm, mut digits, mut period) = (TotpAlgorithm::Sha1, 6, 30);
        let mut counter = counter_based.then_some(0u64);
        for pair in query.split('&') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            match name.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(base32_decode(value)?),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        _ => return Err(Error::InvalidTotp),
                    }
                }
                "digits" => digits = value.parse().map_err(|_| Error::InvalidTotp)?,
                "period" => period = value.parse().map_err(|_| Error::InvalidTotp)?,
                "counter" if counter_based => {
                    counter = Some(value.parse().map_err(|_| Error::InvalidTotp)?);
                }
                _ => {}
            }
        }
        Self::new(
            secret.ok_or(Error::InvalidTotp)?,
            algorithm,
            digits,
            period,
            counter,
        )
    }

    fn new(
        secret: Zeroizing<Vec<u8>>,
        algorithm: TotpAlgorithm,
        digits: u32,
        period: u64,
        counter: Option<u64>,
    ) -> Result<Self> {
        if secret.is_empty() || !(6..=8).contains(&digits) || period == 0 {
            return Err(Error::InvalidTotp);
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
            counter,
        })
    }

    /// Counter-based (HOTP): a new code only when asked for, not with the time.
    pub fn is_counter_based(&self) -> bool {
        self.counter.is_some()
    }

    /// The counter of the current code (counter-based keys only).
    pub fn counter(&self) -> Option<u64> {
        self.counter
    }

    pub fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// Validity window in seconds.
    pub fn period(&self) -> u64 {
        self.period
    }

    /// The time-based code for a given Unix time.
    pub fn code_at(&self, unix_seconds: u64) -> Zeroizing<String> {
        self.code_for(unix_seconds / self.period)
    }

    /// The code for a counter value (RFC 4226; a time-based code's counter is the time step).
    pub fn code_for(&self, counter: u64) -> Zeroizing<String> {
        let counter = counter.to_be_bytes();
        macro_rules! hmac_digest {
            ($hash:ty) => {{
                let mut mac = <Hmac<$hash> as KeyInit>::new_from_slice(&self.secret)
                    .expect("HMAC accepts any key length");
                mac.update(&counter);
                Zeroizing::new(mac.finalize().into_bytes().to_vec())
            }};
        }
        let digest = match self.algorithm {
            TotpAlgorithm::Sha1 => hmac_digest!(sha1::Sha1),
            TotpAlgorithm::Sha256 => hmac_digest!(sha2::Sha256),
            TotpAlgorithm::Sha512 => hmac_digest!(sha2::Sha512),
        };
        // Dynamic truncation (RFC 4226 §5.3).
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let binary = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        let code = binary % 10u32.pow(self.digits);
        Zeroizing::new(format!("{code:0width$}", width = self.digits as usize))
    }

    /// The current code and how many seconds it stays valid (0 for a counter-based code: it
    /// stays until the next one is asked for).
    pub fn now(&self) -> (Zeroizing<String>, u64) {
        if let Some(counter) = self.counter {
            return (self.code_for(counter), 0);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (self.code_at(now), self.period - now % self.period)
    }
}

/// Who an `otpauth://` link is for: the service (`issuer`) and the account at it, as the
/// site wrote them (Key Uri Format: the label is `Issuer:account`, and an `issuer=` parameter
/// wins over the label's). A bare key names nobody. Nothing secret is read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TotpNames {
    pub issuer: String,
    pub account: String,
}

const TOTP: &str = "otpauth://totp/";
const HOTP: &str = "otpauth://hotp/";

fn has_prefix(input: &str, prefix: &str) -> bool {
    input
        .get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// The link of a counter-based key with its counter moved on by one (the next code), or
/// `None` for anything else. The rest of the link is kept as it was.
pub fn next_counter(input: &str) -> Option<String> {
    let input = input.trim();
    let current = Totp::parse(input).ok()?.counter?;
    let next = current.checked_add(1)?;
    let (base, query) = input.split_once('?')?;
    let mut found = false;
    let mut pairs: Vec<String> = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) if name.eq_ignore_ascii_case("counter") => {
                found = true;
                format!("{name}={next}")
            }
            _ => pair.to_owned(),
        })
        .collect();
    if !found {
        pairs.push(format!("counter={next}"));
    }
    Some(format!("{base}?{}", pairs.join("&")))
}

/// A bare setup key made into a link of the kind asked for: time-based keys stay as they
/// were typed (a bare key is time-based), a counter-based one becomes an
/// `otpauth://hotp/…?secret=…&counter=0` link. A link is kept as it is.
pub fn with_kind(input: &str, counter_based: bool) -> String {
    let input = input.trim();
    if has_prefix(input, TOTP) || has_prefix(input, HOTP) || !counter_based {
        return input.to_owned();
    }
    let secret: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    format!("{HOTP}code?secret={secret}&counter=0")
}

/// Reads [`TotpNames`] from what was pasted or scanned.
pub fn names(input: &str) -> TotpNames {
    let input = input.trim();
    let prefix = if has_prefix(input, TOTP) {
        TOTP
    } else if has_prefix(input, HOTP) {
        HOTP
    } else {
        return TotpNames::default();
    };
    let rest = &input[prefix.len()..];
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = percent_decode(label);
    let (mut issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (issuer.trim().to_owned(), account.trim().to_owned()),
        None => (String::new(), label.trim().to_owned()),
    };
    for pair in query.split('&') {
        if let Some((name, value)) = pair.split_once('=')
            && name.eq_ignore_ascii_case("issuer")
        {
            let value = percent_decode(value);
            if !value.trim().is_empty() {
                issuer = value.trim().to_owned();
            }
        }
    }
    TotpNames { issuer, account }
}

/// `%XX` escapes and `+` (a space, in a query) decoded; anything malformed is kept as it is.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(high), Some(low)) => {
                        out.push((high * 16 + low) as u8);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// RFC 4648 Base32 (the alphabet authenticator apps use), case-insensitive; spaces, dashes and
/// `=` padding are ignored.
fn base32_decode(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8 + 1));
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        let value = match c.to_ascii_uppercase() {
            upper @ b'A'..=b'Z' => upper - b'A',
            digit @ b'2'..=b'7' => digit - b'2' + 26,
            b' ' | b'-' | b'=' => continue,
            _ => return Err(Error::InvalidTotp),
        };
        acc = (acc << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc_totp(secret: &[u8], algorithm: TotpAlgorithm) -> Totp {
        Totp::new(Zeroizing::new(secret.to_vec()), algorithm, 8, 30, None).unwrap()
    }

    /// Test vectors from RFC 4226, Appendix D (secret "12345678901234567890", 6 digits).
    #[test]
    fn rfc4226_vectors() {
        // "12345678901234567890" in Base32.
        let base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            let link = format!("otpauth://hotp/Example:me?secret={base32}&counter={counter}");
            let hotp = Totp::parse(&link).unwrap();
            assert!(hotp.is_counter_based());
            assert_eq!(hotp.now().0.as_str(), *code, "counter {counter}");
            assert_eq!(hotp.now().1, 0);
        }
    }

    #[test]
    fn moves_the_counter_on() {
        let link = "otpauth://hotp/Example:me?secret=GEZDGNBVGY3TQOJQ&counter=7&issuer=Example";
        assert_eq!(
            next_counter(link).as_deref(),
            Some("otpauth://hotp/Example:me?secret=GEZDGNBVGY3TQOJQ&counter=8&issuer=Example")
        );
        // No counter yet: it starts at 0, so the next is 1.
        assert_eq!(
            next_counter("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ").as_deref(),
            Some("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1")
        );
        // Time-based keys have no counter.
        assert_eq!(
            next_counter("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ"),
            None
        );
        assert_eq!(next_counter("GEZDGNBVGY3TQOJQ"), None);
        // A bare key asked as counter-based becomes a link at counter 0.
        let made = with_kind("gezd gnbv gy3t qojq", true);
        assert_eq!(
            made,
            "otpauth://hotp/code?secret=gezdgnbvgy3tqojq&counter=0"
        );
        assert!(Totp::parse(&made).unwrap().is_counter_based());
        assert_eq!(with_kind("GEZDGNBVGY3TQOJQ", false), "GEZDGNBVGY3TQOJQ");
        assert_eq!(
            names("otpauth://hotp/Bank:me?secret=X&counter=1").issuer,
            "Bank"
        );
    }

    /// Test vectors from RFC 6238, Appendix B.
    #[test]
    fn rfc6238_vectors() {
        let sha1 = rfc_totp(b"12345678901234567890", TotpAlgorithm::Sha1);
        let sha256 = rfc_totp(b"12345678901234567890123456789012", TotpAlgorithm::Sha256);
        let sha512 = rfc_totp(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            TotpAlgorithm::Sha512,
        );
        let vectors: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (time, expected_sha1, expected_sha256, expected_sha512) in vectors {
            assert_eq!(sha1.code_at(time).as_str(), expected_sha1, "SHA1 at {time}");
            assert_eq!(
                sha256.code_at(time).as_str(),
                expected_sha256,
                "SHA256 at {time}"
            );
            assert_eq!(
                sha512.code_at(time).as_str(),
                expected_sha512,
                "SHA512 at {time}"
            );
        }
    }

    #[test]
    fn names_from_a_link() {
        let link = "otpauth://totp/Example%20Co:me%40example.com?secret=GEZDGNBV&issuer=Example+Co";
        assert_eq!(
            names(link),
            TotpNames {
                issuer: "Example Co".into(),
                account: "me@example.com".into()
            }
        );
        // The parameter wins over the label; a label without an issuer is only the account.
        assert_eq!(
            names("otpauth://totp/Old:me?secret=GEZDGNBV&issuer=New").issuer,
            "New"
        );
        assert_eq!(
            names("otpauth://totp/me?secret=GEZDGNBV"),
            TotpNames {
                issuer: String::new(),
                account: "me".into()
            }
        );
        assert_eq!(names("GEZDGNBVGY3TQOJQ"), TotpNames::default());
        assert_eq!(names("otpauth://totp/100%?secret=X").account, "100%");
    }

    #[test]
    fn parses_uri_and_bare_secret() {
        // "12345678901234567890" in Base32.
        let base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let bare = Totp::parse(&base32.to_lowercase()).unwrap();
        assert_eq!(bare.code_at(59).as_str(), "287082"); // 6-digit default
        let uri = Totp::parse(&format!(
            "otpauth://totp/Example:me?secret={base32}&issuer=Example&digits=8&period=30&algorithm=SHA1"
        ))
        .unwrap();
        assert_eq!(uri.code_at(59).as_str(), "94287082");
        assert_eq!(uri.digits(), 8);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Totp::parse("").is_err());
        assert!(Totp::parse("not base32 !").is_err());
        assert!(Totp::parse("otpauth://totp/x?issuer=nosecret").is_err());
        assert!(Totp::parse("otpauth://totp/x?secret=JBSWY3DP&digits=4").is_err());
        assert!(Totp::parse("otpauth://totp/x?secret=JBSWY3DP&algorithm=MD5").is_err());
        assert!(Totp::parse("otpauth://totp/x?secret=JBSWY3DP&period=0").is_err());
    }

    #[test]
    fn remaining_seconds_are_in_range() {
        let totp = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        let (code, remaining) = totp.now();
        assert_eq!(code.len(), 6);
        assert!((1..=30).contains(&remaining));
    }
}
