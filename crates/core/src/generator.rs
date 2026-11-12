//! Random password generation with uniform character selection.

use zeroize::Zeroizing;

use crate::{Error, Result, random};

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/~";
/// Characters that are easy to confuse when read or typed by hand.
const AMBIGUOUS: &[u8] = b"Il1O0o";

const MIN_LENGTH: usize = 4;
const MAX_LENGTH: usize = 256;

/// Which characters a generated password may contain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Leave out `I l 1 O 0 o`.
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

impl PasswordOptions {
    fn sets(&self) -> Vec<Vec<u8>> {
        [
            (self.lowercase, LOWERCASE),
            (self.uppercase, UPPERCASE),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(enabled, _)| *enabled)
        .map(|(_, set)| {
            set.iter()
                .copied()
                .filter(|c| !(self.avoid_ambiguous && AMBIGUOUS.contains(c)))
                .collect()
        })
        .collect()
    }

    /// Approximate strength: `length × log2(alphabet size)`.
    pub fn entropy_bits(&self) -> f64 {
        let alphabet: usize = self.sets().iter().map(Vec::len).sum();
        if alphabet == 0 {
            return 0.0;
        }
        self.length as f64 * (alphabet as f64).log2()
    }
}

/// Generates a password containing at least one character from every enabled set.
pub fn generate_password(options: &PasswordOptions) -> Result<Zeroizing<String>> {
    let sets = options.sets();
    if sets.is_empty()
        || !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length)
        || options.length < sets.len()
    {
        return Err(Error::InvalidGeneratorOptions);
    }
    let pool: Vec<u8> = sets.concat();

    let mut chars = Zeroizing::new(Vec::with_capacity(options.length));
    for set in &sets {
        chars.push(set[uniform_index(set.len())?]);
    }
    while chars.len() < options.length {
        chars.push(pool[uniform_index(pool.len())?]);
    }
    // Fisher–Yates shuffle so the guaranteed characters are not always first.
    for i in (1..chars.len()).rev() {
        let j = uniform_index(i + 1)?;
        chars.swap(i, j);
    }

    let mut out = Zeroizing::new(String::with_capacity(chars.len()));
    out.extend(chars.iter().map(|&c| char::from(c)));
    Ok(out)
}

/// Uniform random index in `0..n` (rejection sampling, no modulo bias).
fn uniform_index(n: usize) -> Result<usize> {
    debug_assert!(n > 0 && n <= u32::MAX as usize);
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let value = u32::from_le_bytes(random::array()?);
        if value < zone {
            return Ok((value % n) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_sets() {
        let options = PasswordOptions {
            length: 32,
            ..Default::default()
        };
        for _ in 0..50 {
            let password = generate_password(&options).unwrap();
            assert_eq!(password.len(), 32);
            let bytes = password.as_bytes();
            assert!(bytes.iter().any(|c| LOWERCASE.contains(c)));
            assert!(bytes.iter().any(|c| UPPERCASE.contains(c)));
            assert!(bytes.iter().any(|c| DIGITS.contains(c)));
            assert!(bytes.iter().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn single_set_and_ambiguous_filter() {
        let options = PasswordOptions {
            length: 64,
            lowercase: false,
            uppercase: false,
            symbols: false,
            avoid_ambiguous: true,
            ..Default::default()
        };
        let password = generate_password(&options).unwrap();
        assert!(
            password
                .bytes()
                .all(|c| c.is_ascii_digit() && c != b'0' && c != b'1')
        );
    }

    #[test]
    fn rejects_impossible_options() {
        let none = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(generate_password(&none).is_err());
        assert!(
            generate_password(&PasswordOptions {
                length: 3,
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            generate_password(&PasswordOptions {
                length: 1000,
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn entropy_estimate() {
        let options = PasswordOptions::default();
        // 20 chars over 26+26+10+25 = 87 symbols ≈ 128.8 bits.
        assert!((options.entropy_bits() - 128.8).abs() < 0.5);
    }

    #[test]
    fn distribution_is_roughly_uniform() {
        let mut counts = [0usize; 10];
        for _ in 0..20_000 {
            counts[uniform_index(10).unwrap()] += 1;
        }
        assert!(
            counts.iter().all(|&c| (1_700..=2_300).contains(&c)),
            "{counts:?}"
        );
    }
}
