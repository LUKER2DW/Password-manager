//! One-time passwords for items that store a setup key: time-based (TOTP, RFC 6238) and
//! counter-based (HOTP, RFC 4226). A counter-based key keeps its counter in its own
//! `otpauth://hotp/…&counter=N` link, in the item's `totp` field: the next code is asked for by
//! moving the counter on ([`next_counter`]), which changes the link, so it syncs with the item.
//!
//! Some game platforms show a time-based code of five characters instead of digits: the same
//! HMAC-SHA-1 code over 30 seconds, written in a 26-character alphabet of digits and capital
//! letters ([`CHARACTERS`]). Such a key is an `otpauth://totp/…&encoder=steam` link (the
//! parameter authenticator apps and KeePassXC write) or an `otpauth://steam/…` link.

use std::fmt;

// The std clock on a computer or phone; the browser's in a web build (std's panics there).
use web_time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use zeroize::{Zeroize, Zeroizing};

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
    /// Five characters of [`CHARACTERS`] instead of digits.
    characters: bool,
}

/// The alphabet of five-character codes: digits and capital letters, without those easily
/// taken for one another (0, 1, A, E, I, L, O, S, U, Z).
pub const CHARACTERS: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// How many characters such a code has.
const CHARACTER_CODE_LENGTH: u32 = 5;

/// The `encoder=` value that marks a five-character key in an `otpauth://` link, as other
/// apps write it.
pub const CHARACTER_ENCODER: &str = "steam";

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("counter", &self.counter)
            .field("characters", &self.characters)
            .finish()
    }
}

impl Totp {
    /// Parses an `otpauth://totp/...` or `otpauth://hotp/...` URI, or a bare Base32 secret
    /// (RFC 4648; spaces ignored; time-based).
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let counter_based = has_prefix(input, HOTP);
        let mut characters = has_prefix(input, CHARACTER_LINK);
        if !has_prefix(input, TOTP) && !counter_based && !characters {
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
                "encoder" if !counter_based => {
                    characters |= value.eq_ignore_ascii_case(CHARACTER_ENCODER);
                }
                _ => {}
            }
        }
        let secret = secret.ok_or(Error::InvalidTotp)?;
        if characters {
            // The code is always five characters of SHA-1 over 30 seconds, whatever else the
            // link says (some apps write `digits=5`, others nothing).
            let mut totp = Self::new(secret, TotpAlgorithm::Sha1, 6, 30, None)?;
            totp.characters = true;
            totp.digits = CHARACTER_CODE_LENGTH;
            return Ok(totp);
        }
        Self::new(secret, algorithm, digits, period, counter)
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
            characters: false,
        })
    }

    /// Five characters of [`CHARACTERS`] instead of digits.
    pub fn is_characters(&self) -> bool {
        self.characters
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
        if self.characters {
            let mut rest = binary;
            let mut code = Zeroizing::new(String::with_capacity(CHARACTER_CODE_LENGTH as usize));
            for _ in 0..CHARACTER_CODE_LENGTH {
                code.push(char::from(CHARACTERS[(rest % 26) as usize]));
                rest /= 26;
            }
            return code;
        }
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
/// A five-character key written with a type of its own instead of `encoder=`.
const CHARACTER_LINK: &str = "otpauth://steam/";

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
    if has_prefix(input, TOTP)
        || has_prefix(input, HOTP)
        || has_prefix(input, CHARACTER_LINK)
        || !counter_based
    {
        return input.to_owned();
    }
    let secret: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    format!("{HOTP}code?secret={secret}&counter=0")
}

/// A key read from another app's export or a QR code, made into the `otpauth://` link the
/// item keeps. Only what differs from the defaults is written (SHA-1, 6 digits, 30 seconds).
#[derive(Clone, Default)]
pub struct LinkParts<'a> {
    pub issuer: &'a str,
    pub account: &'a str,
    /// Base32, as the link writes it (spaces and `=` padding are taken off).
    pub secret: &'a str,
    pub algorithm: TotpAlgorithm,
    /// 0 for the default.
    pub digits: u32,
    /// 0 for the default.
    pub period: u64,
    /// Counter-based, at this counter.
    pub counter: Option<u64>,
    /// A five-character code.
    pub characters: bool,
}

impl fmt::Debug for LinkParts<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkParts")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl LinkParts<'_> {
    /// The link, or `None` when it wouldn't give codes ([`Totp::parse`] refuses it).
    pub fn link(&self) -> Option<Zeroizing<String>> {
        let secret: Zeroizing<String> = Zeroizing::new(
            self.secret
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let kind = if self.counter.is_some() { HOTP } else { TOTP };
        let issuer = self.issuer.trim();
        let account = self.account.trim();
        let label = match (issuer.is_empty(), account.is_empty()) {
            (false, false) => format!("{}:{}", percent_encode(issuer), percent_encode(account)),
            (false, true) => percent_encode(issuer),
            (true, false) => percent_encode(account),
            (true, true) => "code".to_owned(),
        };
        let mut link = Zeroizing::new(String::with_capacity(
            kind.len() + label.len() + secret.len() + issuer.len() * 3 + 96,
        ));
        link.push_str(kind);
        link.push_str(&label);
        link.push_str("?secret=");
        link.push_str(&secret);
        if !issuer.is_empty() {
            link.push_str("&issuer=");
            link.push_str(&percent_encode(issuer));
        }
        if self.characters {
            link.push_str("&digits=5&encoder=");
            link.push_str(CHARACTER_ENCODER);
        } else {
            match self.algorithm {
                TotpAlgorithm::Sha1 => {}
                TotpAlgorithm::Sha256 => link.push_str("&algorithm=SHA256"),
                TotpAlgorithm::Sha512 => link.push_str("&algorithm=SHA512"),
            }
            if self.digits != 0 && self.digits != 6 {
                link.push_str(&format!("&digits={}", self.digits));
            }
            if self.period != 0 && self.period != 30 && self.counter.is_none() {
                link.push_str(&format!("&period={}", self.period));
            }
            if let Some(counter) = self.counter {
                link.push_str(&format!("&counter={counter}"));
            }
        }
        Totp::parse(&link).ok()?;
        Some(link)
    }
}

/// A label part or parameter of a link: what isn't a letter, a digit or `-._~` as `%XX`.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Reads [`TotpNames`] from what was pasted or scanned.
pub fn names(input: &str) -> TotpNames {
    let input = input.trim();
    let prefix = if has_prefix(input, TOTP) {
        TOTP
    } else if has_prefix(input, HOTP) {
        HOTP
    } else if has_prefix(input, CHARACTER_LINK) {
        CHARACTER_LINK
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

/// Bytes as Base32 (RFC 4648, capitals, no padding): a key read as raw bytes made into the
/// text a link holds.
pub fn base32_encode(bytes: &[u8]) -> Zeroizing<String> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(5) * 8));
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for &byte in bytes {
        acc = (acc << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    acc.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_both_ways() {
        assert_eq!(
            base32_encode(b"12345678901234567890").as_str(),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert_eq!(base32_encode(b"f").as_str(), "MY");
        assert_eq!(base32_encode(b"foobar").as_str(), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap().as_slice(), b"foobar");
    }

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

    /// Five-character codes: the RFC 6238 SHA-1 key, its codes worked out apart (Python's
    /// `hmac`, the same truncation, the 31-bit number written in the alphabet from its least
    /// significant end).
    #[test]
    fn five_character_codes() {
        let link = "otpauth://totp/Game:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&encoder=steam";
        let other_type = "otpauth://steam/Game:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        for input in [link, other_type] {
            let totp = Totp::parse(input).unwrap();
            assert!(totp.is_characters());
            assert_eq!(totp.digits(), 5);
            assert_eq!(totp.code_at(59).as_str(), "PV9M4");
            assert_eq!(totp.code_at(1_111_111_109).as_str(), "PY4YB");
            assert_eq!(totp.code_at(20_000_000_000).as_str(), "R5DMB");
        }
        assert_eq!(names(other_type).issuer, "Game");
        // What else the link says changes nothing: always SHA-1, 5 characters, 30 seconds.
        let odd = Totp::parse(&format!("{link}&digits=8&algorithm=SHA512&period=60")).unwrap();
        assert_eq!(odd.code_at(59).as_str(), "PV9M4");
        assert!(
            !Totp::parse("otpauth://totp/x?secret=GEZDGNBV")
                .unwrap()
                .is_characters()
        );
        assert_eq!(with_kind(other_type, true), other_type);
    }

    #[test]
    fn links_made_from_parts() {
        let parts = LinkParts {
            issuer: "Example Co",
            account: "me@example.com",
            secret: "gezd gnbv gy3t qojq====",
            ..LinkParts::default()
        };
        let link = parts.link().unwrap();
        assert_eq!(
            link.as_str(),
            "otpauth://totp/Example%20Co:me%40example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Example%20Co"
        );
        assert_eq!(names(&link).account, "me@example.com");
        let counter = LinkParts {
            secret: "GEZDGNBV",
            algorithm: TotpAlgorithm::Sha256,
            digits: 8,
            counter: Some(7),
            ..LinkParts::default()
        };
        let totp = Totp::parse(&counter.link().unwrap()).unwrap();
        assert_eq!(
            (totp.counter(), totp.digits(), totp.algorithm()),
            (Some(7), 8, TotpAlgorithm::Sha256)
        );
        let characters = LinkParts {
            secret: "GEZDGNBV",
            characters: true,
            ..LinkParts::default()
        };
        assert!(
            Totp::parse(&characters.link().unwrap())
                .unwrap()
                .is_characters()
        );
        // Not a key at all, or digits no code has: nothing.
        let bad = LinkParts {
            secret: "not base32!",
            ..LinkParts::default()
        };
        assert!(bad.link().is_none());
        assert!(!format!("{parts:?}").contains("GEZD"));
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
