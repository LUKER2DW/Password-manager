//! Random password and passphrase generation with uniform selection.

use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::{Error, Result, random};

/// EFF large word list (CC BY 3.0 US, © Electronic Frontier Foundation). See `data/README.md`.
const EFF_LARGE_WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");
const EFF_WORD_COUNT: usize = 7776;
const MIN_WORDS: usize = 3;
const MAX_WORDS: usize = 20;
const MAX_SEPARATOR_CHARS: usize = 3;

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

/// Options for word-based passphrases (easier to type and remember, e.g. for the master password).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// Number of words (3–20). Six words ≈ 77.5 bits.
    pub words: usize,
    /// Placed between words (at most 3 characters; may be empty).
    pub separator: String,
    /// Capitalize the first letter of every word.
    pub capitalize: bool,
    /// Append one random digit to one random word.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    }
}

impl PassphraseOptions {
    /// Strength: `words × log2(7776)`, plus the digit and its position when enabled.
    pub fn entropy_bits(&self) -> f64 {
        let words = self.words as f64 * (EFF_WORD_COUNT as f64).log2();
        if self.include_number && self.words > 0 {
            words + 10f64.log2() + (self.words as f64).log2()
        } else {
            words
        }
    }
}

fn eff_words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        EFF_LARGE_WORDLIST
            .lines()
            .filter_map(|line| line.split_once('\t').map(|(_, word)| word))
            .collect()
    })
}

/// Generates a passphrase from the EFF large word list.
pub fn generate_passphrase(options: &PassphraseOptions) -> Result<Zeroizing<String>> {
    let words = eff_words();
    if words.len() != EFF_WORD_COUNT
        || !(MIN_WORDS..=MAX_WORDS).contains(&options.words)
        || options.separator.chars().count() > MAX_SEPARATOR_CHARS
    {
        return Err(Error::InvalidGeneratorOptions);
    }
    let number_at = if options.include_number {
        Some((uniform_index(options.words)?, uniform_index(10)?))
    } else {
        None
    };

    // Longest word is 9 characters; reserve the worst case so the buffer never reallocates.
    let capacity = options.words * (9 + 1 + options.separator.len());
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    for i in 0..options.words {
        if i > 0 {
            out.push_str(&options.separator);
        }
        let word = words[uniform_index(words.len())?];
        let mut chars = word.chars();
        if options.capitalize
            && let Some(first) = chars.next()
        {
            out.extend(first.to_uppercase());
        }
        out.push_str(chars.as_str());
        if let Some((position, digit)) = number_at
            && position == i
        {
            out.push(char::from(b'0' + digit as u8));
        }
    }
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
    fn bundled_wordlist_is_the_published_one() {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(EFF_LARGE_WORDLIST.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        let words = eff_words();
        assert_eq!(words.len(), EFF_WORD_COUNT);
        assert_eq!((words[0], words[EFF_WORD_COUNT - 1]), ("abacus", "zoom"));
    }

    #[test]
    fn passphrase_shape() {
        let options = PassphraseOptions::default();
        let phrase = generate_passphrase(&options).unwrap();
        let parts: Vec<&str> = phrase.split('-').collect();
        // "drop-down", "felt-tip", "t-shirt" and "yo-yo" contain the separator themselves.
        assert!(parts.len() >= 6, "{}", phrase.as_str());
        assert!((options.entropy_bits() - 77.55).abs() < 0.01);
    }

    #[test]
    fn passphrase_options() {
        let options = PassphraseOptions {
            words: 5,
            separator: " ".into(),
            capitalize: true,
            include_number: true,
        };
        let phrase = generate_passphrase(&options).unwrap();
        let words: Vec<&str> = phrase.split(' ').collect();
        assert_eq!(words.len(), 5);
        assert!(
            words
                .iter()
                .all(|w| w.chars().next().unwrap().is_uppercase())
        );
        assert_eq!(phrase.chars().filter(char::is_ascii_digit).count(), 1);

        let no_separator = PassphraseOptions {
            separator: String::new(),
            ..PassphraseOptions::default()
        };
        assert!(!generate_passphrase(&no_separator).unwrap().contains(' '));
    }

    #[test]
    fn passphrase_rejects_bad_options() {
        for words in [0, 2, 21] {
            let options = PassphraseOptions {
                words,
                ..Default::default()
            };
            assert!(generate_passphrase(&options).is_err());
        }
        let long_separator = PassphraseOptions {
            separator: "----".into(),
            ..Default::default()
        };
        assert!(generate_passphrase(&long_separator).is_err());
    }

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
