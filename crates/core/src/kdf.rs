//! Password hashing with Argon2id (spec: CRYPTO.md §2.1 and §4).

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
