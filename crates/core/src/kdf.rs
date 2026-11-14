//! Password hashing with Argon2id (spec: CRYPTO.md §2.1 and §4).

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{Error, Result, random};

const MIN_MEMORY_KIB: u32 = 64 * 1024;
const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
const MIN_ITERATIONS: u32 = 2;
const MAX_ITERATIONS: u32 = 64;
const MIN_PARALLELISM: u32 = 1;
const MAX_PARALLELISM: u32 = 16;

const RECOMMENDED_MEMORY_KIB: u32 = 256 * 1024;
const RECOMMENDED_ITERATIONS: u32 = 3;
const RECOMMENDED_PARALLELISM: u32 = 4;

/// Worst-case NFKC expansion factor for a single code point (e.g. U+FDFA expands to 18).
const NFKC_MAX_EXPANSION: usize = 18;

/// Argon2id cost parameters plus the per-vault salt. Stored in the (authenticated) header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub(crate) memory_kib: u32,
    pub(crate) iterations: u32,
    pub(crate) parallelism: u32,
    pub(crate) salt: [u8; 32],
}

impl KdfParams {
    /// Creates parameters with a fresh random salt, rejecting values outside the allowed range.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self> {
        let params = Self {
            memory_kib,
            iterations,
            parallelism,
            salt: random::array()?,
        };
        params.validate()?;
        Ok(params)
    }

    /// Default for desktop: 256 MiB, 3 iterations, 4 lanes (~0.5–1 s on a modern PC).
    pub fn recommended() -> Result<Self> {
        Self::new(
            RECOMMENDED_MEMORY_KIB,
            RECOMMENDED_ITERATIONS,
            RECOMMENDED_PARALLELISM,
        )
    }

    /// The weakest parameters the format accepts (64 MiB, 2 iterations, 1 lane).
    /// Meant for low-memory devices and tests.
    pub fn minimum() -> Result<Self> {
        Self::new(MIN_MEMORY_KIB, MIN_ITERATIONS, MIN_PARALLELISM)
    }

    pub fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }

    /// Picks the iteration count so that one unlock takes roughly `target` on this device at
    /// the given memory cost. The result never goes below the floor (or above the ceiling).
    pub fn calibrate(memory_kib: u32, parallelism: u32, target: Duration) -> Result<Self> {
        let probe = Self::new(memory_kib, MIN_ITERATIONS, parallelism)?;
        let started = Instant::now();
        derive_password_key("calibration probe", &probe)?;
        let per_iteration = (started.elapsed() / MIN_ITERATIONS).as_nanos().max(1);
        let iterations = u32::try_from(target.as_nanos() / per_iteration)
            .unwrap_or(MAX_ITERATIONS)
            .clamp(MIN_ITERATIONS, MAX_ITERATIONS);
        Self::new(memory_kib, iterations, parallelism)
    }

    /// Lanes to use on this machine: available cores, capped at 4.
    pub fn default_parallelism() -> u32 {
        std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(1))
            .unwrap_or(1)
            .clamp(MIN_PARALLELISM, 4)
    }

    /// Same cost, new random salt (used whenever the password slot is rewritten).
    pub(crate) fn with_fresh_salt(&self) -> Result<Self> {
        Self::new(self.memory_kib, self.iterations, self.parallelism)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let in_range = (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations)
            && (MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism)
            // Argon2 requires at least 8 KiB per lane.
            && self.memory_kib >= 8 * self.parallelism;
        if in_range {
            Ok(())
        } else {
            Err(Error::KdfParamsOutOfRange)
        }
    }
}

/// How much work unlocking costs, as offered to the user. The costs below are the Argon2id
/// ones (the default method: the recommendation of RFC 9106 and OWASP, whose memory cost is
/// what makes guessing on graphics cards and custom chips expensive); [`PasswordKdf::preset`]
/// maps the same four levels onto the other methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfStrength {
    /// 64 MiB, 3 passes: for older computers or little memory.
    Light,
    /// 256 MiB, 3 passes (the default).
    Standard,
    /// 512 MiB, 4 passes.
    Strong,
    /// 1 GiB, 5 passes: a few seconds per unlock.
    Maximum,
}

impl KdfStrength {
    pub const ALL: [KdfStrength; 4] = [Self::Light, Self::Standard, Self::Strong, Self::Maximum];

    /// (memory in KiB, passes, lanes).
    pub fn costs(self) -> (u32, u32, u32) {
        match self {
            Self::Light => (64 * 1024, 3, RECOMMENDED_PARALLELISM),
            Self::Standard => (
                RECOMMENDED_MEMORY_KIB,
                RECOMMENDED_ITERATIONS,
                RECOMMENDED_PARALLELISM,
            ),
            Self::Strong => (512 * 1024, 4, RECOMMENDED_PARALLELISM),
            Self::Maximum => (1024 * 1024, 5, RECOMMENDED_PARALLELISM),
        }
    }

    /// Fresh parameters (new salt) at this level.
    pub fn params(self) -> Result<KdfParams> {
        let (memory, iterations, lanes) = self.costs();
        KdfParams::new(memory, iterations, lanes)
    }

    /// The level these parameters match, or `None` for other (custom or older) values.
    pub fn of(params: &KdfParams) -> Option<Self> {
        Self::ALL.into_iter().find(|level| {
            level.costs() == (params.memory_kib, params.iterations, params.parallelism)
        })
    }
}

/// The method that stretches the master password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfMethod {
    /// Memory-hard, the default and the recommendation (RFC 9106, OWASP).
    Argon2id,
    /// Memory-hard, older than Argon2 (RFC 7914).
    Scrypt,
    /// HMAC-SHA-256 repeated many times (RFC 8018). Needs almost no memory, so graphics cards
    /// guess far faster against it: offered for compatibility of habit, not strength.
    Pbkdf2Sha256,
}

impl KdfMethod {
    pub const ALL: [KdfMethod; 3] = [Self::Argon2id, Self::Scrypt, Self::Pbkdf2Sha256];
}

const PBKDF2_MIN_ITERATIONS: u32 = 600_000;
const PBKDF2_MAX_ITERATIONS: u32 = 100_000_000;
const SCRYPT_MIN_LOG_N: u8 = 17;
const SCRYPT_MAX_LOG_N: u8 = 22;
const SCRYPT_R: u32 = 8;
const SCRYPT_MAX_P: u32 = 16;

/// How the master password is stretched, with its cost and salt. Stored in the
/// (authenticated) header. (Format v6; older files are always Argon2id.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PasswordKdf {
    Argon2id(KdfParams),
    /// N = 2^`log_n`, block size r = 8.
    Scrypt {
        log_n: u8,
        p: u32,
        salt: [u8; 32],
    },
    Pbkdf2Sha256 {
        iterations: u32,
        salt: [u8; 32],
    },
}

impl From<KdfParams> for PasswordKdf {
    fn from(params: KdfParams) -> Self {
        Self::Argon2id(params)
    }
}

impl From<&KdfParams> for PasswordKdf {
    fn from(params: &KdfParams) -> Self {
        Self::Argon2id(params.clone())
    }
}

impl From<&PasswordKdf> for PasswordKdf {
    fn from(kdf: &PasswordKdf) -> Self {
        kdf.clone()
    }
}

impl PasswordKdf {
    /// Fresh parameters (new salt) for a method at one of the four levels.
    ///
    /// | level | Argon2id | scrypt (r = 8) | PBKDF2-SHA-256 |
    /// |---|---|---|---|
    /// | Light | 64 MiB × 3 | N = 2^17 (128 MiB) | 600 000 |
    /// | Standard | 256 MiB × 3 | N = 2^18 (256 MiB) | 1 200 000 |
    /// | Strong | 512 MiB × 4 | N = 2^19 (512 MiB) | 2 400 000 |
    /// | Maximum | 1 GiB × 5 | N = 2^20 (1 GiB) | 5 000 000 |
    pub fn preset(method: KdfMethod, strength: KdfStrength) -> Result<Self> {
        let level = KdfStrength::ALL
            .iter()
            .position(|l| *l == strength)
            .unwrap_or(1);
        let kdf = match method {
            KdfMethod::Argon2id => Self::Argon2id(strength.params()?),
            KdfMethod::Scrypt => Self::Scrypt {
                log_n: [17, 18, 19, 20][level],
                p: 1,
                salt: random::array()?,
            },
            KdfMethod::Pbkdf2Sha256 => Self::Pbkdf2Sha256 {
                iterations: [600_000, 1_200_000, 2_400_000, 5_000_000][level],
                salt: random::array()?,
            },
        };
        kdf.validate()?;
        Ok(kdf)
    }

    pub fn method(&self) -> KdfMethod {
        match self {
            Self::Argon2id(_) => KdfMethod::Argon2id,
            Self::Scrypt { .. } => KdfMethod::Scrypt,
            Self::Pbkdf2Sha256 { .. } => KdfMethod::Pbkdf2Sha256,
        }
    }

    /// The level these parameters match, or `None` for other values.
    pub fn strength(&self) -> Option<KdfStrength> {
        let index = match self {
            Self::Argon2id(params) => return KdfStrength::of(params),
            Self::Scrypt { log_n, p: 1, .. } => [17, 18, 19, 20].iter().position(|n| n == log_n),
            Self::Scrypt { .. } => None,
            Self::Pbkdf2Sha256 { iterations, .. } => [600_000, 1_200_000, 2_400_000, 5_000_000]
                .iter()
                .position(|i| i == iterations),
        };
        index.map(|i| KdfStrength::ALL[i])
    }

    /// Memory each guess needs, in MiB (0 for PBKDF2, which needs next to none).
    pub fn memory_mib(&self) -> u32 {
        match self {
            Self::Argon2id(params) => params.memory_kib / 1024,
            // 128 · r · N bytes.
            Self::Scrypt { log_n, .. } => 1u32 << (log_n.saturating_sub(10)),
            Self::Pbkdf2Sha256 { .. } => 0,
        }
    }

    /// Passes over memory (Argon2id), or iterations (PBKDF2); 1 for scrypt.
    pub fn rounds(&self) -> u32 {
        match self {
            Self::Argon2id(params) => params.iterations,
            Self::Scrypt { .. } => 1,
            Self::Pbkdf2Sha256 { iterations, .. } => *iterations,
        }
    }

    /// Same method and cost, new random salt (used whenever the password slot is rewritten).
    pub(crate) fn with_fresh_salt(&self) -> Result<Self> {
        let fresh = match self {
            Self::Argon2id(params) => Self::Argon2id(params.with_fresh_salt()?),
            Self::Scrypt { log_n, p, .. } => Self::Scrypt {
                log_n: *log_n,
                p: *p,
                salt: random::array()?,
            },
            Self::Pbkdf2Sha256 { iterations, .. } => Self::Pbkdf2Sha256 {
                iterations: *iterations,
                salt: random::array()?,
            },
        };
        fresh.validate()?;
        Ok(fresh)
    }

    /// Floors stop a tampered header from making guesses cheap; ceilings stop a crafted file
    /// from exhausting memory or time.
    pub(crate) fn validate(&self) -> Result<()> {
        let ok = match self {
            Self::Argon2id(params) => return params.validate(),
            Self::Scrypt { log_n, p, .. } => {
                (SCRYPT_MIN_LOG_N..=SCRYPT_MAX_LOG_N).contains(log_n)
                    && (1..=SCRYPT_MAX_P).contains(p)
            }
            Self::Pbkdf2Sha256 { iterations, .. } => {
                (PBKDF2_MIN_ITERATIONS..=PBKDF2_MAX_ITERATIONS).contains(iterations)
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Error::KdfParamsOutOfRange)
        }
    }

    /// Stretches the (NFKC-normalized) password into 32 bytes.
    pub(crate) fn derive(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        let params = match self {
            Self::Argon2id(params) => return derive_password_key(password, params),
            other => other,
        };
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        params.validate()?;
        let normalized = normalize_password(password);
        let mut out = Zeroizing::new([0u8; 32]);
        match params {
            Self::Scrypt { log_n, p, salt } => {
                let scrypt_params = scrypt::Params::new(*log_n, SCRYPT_R, *p)
                    .map_err(|_| Error::KdfParamsOutOfRange)?;
                scrypt::scrypt(normalized.as_bytes(), salt, &scrypt_params, out.as_mut())
                    .map_err(|_| Error::Kdf)?;
            }
            Self::Pbkdf2Sha256 { iterations, salt } => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
                    normalized.as_bytes(),
                    salt,
                    *iterations,
                    out.as_mut(),
                );
            }
            Self::Argon2id(_) => unreachable!("handled above"),
        }
        Ok(out)
    }
}

/// NFKC-normalizes a password into a buffer that is wiped on drop.
pub(crate) fn normalize_password(password: &str) -> Zeroizing<String> {
    // Reserve the worst case up front so pushing never reallocates (which would leave copies).
    let mut out = Zeroizing::new(String::with_capacity(
        password.len().saturating_mul(NFKC_MAX_EXPANSION),
    ));
    for c in password.nfkc() {
        out.push(c);
    }
    out
}

/// Runs Argon2id over the normalized password. Output: 32 bytes, wiped on drop.
pub(crate) fn derive_password_key(
    password: &str,
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    params.validate()?;
    let normalized = normalize_password(password);
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| Error::KdfParamsOutOfRange)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(normalized.as_bytes(), &params.salt, out.as_mut())
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(memory_kib: u32, iterations: u32, parallelism: u32) -> KdfParams {
        KdfParams {
            memory_kib,
            iterations,
            parallelism,
            salt: [42u8; 32],
        }
    }

    #[test]
    fn range_is_enforced() {
        assert!(fixed(MIN_MEMORY_KIB, MIN_ITERATIONS, 1).validate().is_ok());
        assert!(
            fixed(MIN_MEMORY_KIB - 1, MIN_ITERATIONS, 1)
                .validate()
                .is_err()
        );
        assert!(
            fixed(MIN_MEMORY_KIB, MIN_ITERATIONS - 1, 1)
                .validate()
                .is_err()
        );
        assert!(fixed(MIN_MEMORY_KIB, MIN_ITERATIONS, 0).validate().is_err());
        assert!(
            fixed(MAX_MEMORY_KIB + 1, MIN_ITERATIONS, 1)
                .validate()
                .is_err()
        );
        assert!(
            fixed(MIN_MEMORY_KIB, MAX_ITERATIONS + 1, 1)
                .validate()
                .is_err()
        );
        assert!(
            fixed(MIN_MEMORY_KIB, MIN_ITERATIONS, MAX_PARALLELISM + 1)
                .validate()
                .is_err()
        );
        assert!(KdfParams::recommended().is_ok());
    }

    #[test]
    fn strength_levels_are_valid_and_recognised() {
        for level in KdfStrength::ALL {
            let params = level.params().unwrap();
            assert_eq!(KdfStrength::of(&params), Some(level));
        }
        assert_eq!(
            KdfStrength::of(&KdfParams::recommended().unwrap()),
            Some(KdfStrength::Standard)
        );
        assert_eq!(KdfStrength::of(&KdfParams::minimum().unwrap()), None);
    }

    #[test]
    fn other_methods_have_presets_limits_and_known_answers() {
        for method in KdfMethod::ALL {
            for level in KdfStrength::ALL {
                let kdf = PasswordKdf::preset(method, level).unwrap();
                assert_eq!((kdf.method(), kdf.strength()), (method, Some(level)));
                let fresh = kdf.with_fresh_salt().unwrap();
                assert_ne!(kdf, fresh, "a new salt");
                assert_eq!(fresh.strength(), Some(level));
            }
        }
        // Below the floors and above the ceilings.
        for bad in [
            PasswordKdf::Pbkdf2Sha256 {
                iterations: 599_999,
                salt: [0; 32],
            },
            PasswordKdf::Pbkdf2Sha256 {
                iterations: 100_000_001,
                salt: [0; 32],
            },
            PasswordKdf::Scrypt {
                log_n: 16,
                p: 1,
                salt: [0; 32],
            },
            PasswordKdf::Scrypt {
                log_n: 23,
                p: 1,
                salt: [0; 32],
            },
            PasswordKdf::Scrypt {
                log_n: 17,
                p: 0,
                salt: [0; 32],
            },
        ] {
            assert!(matches!(bad.validate(), Err(Error::KdfParamsOutOfRange)));
            assert!(bad.derive("pw").is_err());
        }
        // Deterministic, salt-dependent, and different per method.
        let pbkdf2 = PasswordKdf::Pbkdf2Sha256 {
            iterations: 600_000,
            salt: [7; 32],
        };
        let scrypt = PasswordKdf::Scrypt {
            log_n: 17,
            p: 1,
            salt: [7; 32],
        };
        let a = pbkdf2.derive("correct horse").unwrap();
        assert_eq!(*a, *pbkdf2.derive("correct horse").unwrap());
        assert_ne!(*a, *pbkdf2.derive("correct horsf").unwrap());
        assert_ne!(*a, *scrypt.derive("correct horse").unwrap());
        assert!(pbkdf2.derive("").is_err());
        assert_eq!((scrypt.memory_mib(), pbkdf2.memory_mib()), (128, 0));
    }

    /// RFC 7914 §11 (PBKDF2-HMAC-SHA-256) and §12 (scrypt) vectors, through the same crates
    /// and calls `derive` uses: proof the primitives are wired the standard way.
    #[test]
    fn primitives_match_rfc_7914_vectors() {
        let mut out = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"passwd", b"salt", 1, &mut out);
        assert_eq!(out[..8], [0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f],);
        let params = scrypt::Params::new(10, 8, 16).unwrap();
        scrypt::scrypt(b"password", b"NaCl", &params, &mut out).unwrap();
        assert_eq!(out[..8], [0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00],);
    }

    #[test]
    fn calibration_stays_in_range() {
        let tiny = KdfParams::calibrate(MIN_MEMORY_KIB, 1, Duration::from_millis(1)).unwrap();
        assert_eq!(tiny.iterations(), MIN_ITERATIONS);
        let long = KdfParams::calibrate(MIN_MEMORY_KIB, 1, Duration::from_secs(3600)).unwrap();
        assert_eq!(long.iterations(), MAX_ITERATIONS);
        assert!((1..=4).contains(&KdfParams::default_parallelism()));
    }

    #[test]
    fn empty_password_is_rejected() {
        let params = fixed(MIN_MEMORY_KIB, MIN_ITERATIONS, 1);
        assert!(matches!(
            derive_password_key("", &params),
            Err(Error::EmptyPassword)
        ));
    }

    #[test]
    fn normalization_makes_equivalent_inputs_equal() {
        // "é" as one code point vs "e" + combining acute accent.
        assert_eq!(
            *normalize_password("caf\u{e9}"),
            *normalize_password("cafe\u{301}")
        );
        // Full-width letters fold to ASCII under NFKC.
        assert_eq!(*normalize_password("\u{ff21}\u{ff22}"), "AB");
    }

    #[test]
    fn derivation_is_deterministic_and_salt_dependent() {
        let params = fixed(MIN_MEMORY_KIB, MIN_ITERATIONS, 1);
        let a = derive_password_key("pässword", &params).unwrap();
        let b = derive_password_key("pa\u{308}ssword", &params).unwrap();
        assert_eq!(*a, *b, "NFKC-equivalent passwords derive the same key");

        let mut other_salt = params.clone();
        other_salt.salt = [43u8; 32];
        let c = derive_password_key("pässword", &other_salt).unwrap();
        assert_ne!(*a, *c);
    }
}
