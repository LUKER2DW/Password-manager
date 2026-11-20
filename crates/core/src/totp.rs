//! Time-based one-time passwords (RFC 6238) for items that store a TOTP secret.

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

/// A parsed TOTP configuration. The shared secret is wiped on drop.
#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

impl Totp {
    /// Parses an `otpauth://totp/...` URI or a bare Base32 secret (RFC 4648; spaces ignored).
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let prefix = "otpauth://totp/";
        let has_prefix = input
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix));
        if !has_prefix {
            return Self::new(base32_decode(input)?, TotpAlgorithm::Sha1, 6, 30);
        }

        let query = input.split_once('?').map(|(_, q)| q).unwrap_or_default();
        let mut secret = None;
        let (mut algorithm, mut digits, mut period) = (TotpAlgorithm::Sha1, 6, 30);
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
                _ => {}
            }
        }
        Self::new(secret.ok_or(Error::InvalidTotp)?, algorithm, digits, period)
    }

    fn new(
        secret: Zeroizing<Vec<u8>>,
        algorithm: TotpAlgorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self> {
        if secret.is_empty() || !(6..=8).contains(&digits) || period == 0 {
            return Err(Error::InvalidTotp);
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
        })
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

    /// The code for a given Unix time.
    pub fn code_at(&self, unix_seconds: u64) -> Zeroizing<String> {
        let counter = (unix_seconds / self.period).to_be_bytes();
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

    /// The current code and how many seconds it stays valid.
    pub fn now(&self) -> (Zeroizing<String>, u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (self.code_at(now), self.period - now % self.period)
    }
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
        Totp::new(Zeroizing::new(secret.to_vec()), algorithm, 8, 30).unwrap()
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
