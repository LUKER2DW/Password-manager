//! Random password and passphrase generation with uniform selection.

use std::sync::{Arc, OnceLock};

use zeroize::Zeroizing;

use crate::{Error, Result, random};

/// EFF large word list (CC BY 3.0 US, © Electronic Frontier Foundation). See `data/README.md`.
const EFF_LARGE_WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");
pub(crate) const EFF_WORD_COUNT: usize = 7776;
const MIN_WORDS: usize = 3;
const MAX_WORDS: usize = 20;
const MAX_SEPARATOR_CHARS: usize = 3;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/~";
/// Characters that are easy to confuse when read or typed by hand.
const AMBIGUOUS: &str = "Il1O0o|";
/// Most characters a user can add or leave out.
const MAX_CUSTOM_CHARS: usize = 128;

const MIN_LENGTH: usize = 4;
const MAX_LENGTH: usize = 256;

/// Printable Latin-1 characters (U+00A1–U+00FF without the soft hyphen), often called
/// "extended ASCII". Many sites reject them, so they are off by default.
fn extended_ascii() -> impl Iterator<Item = char> {
    ('\u{a1}'..='\u{ff}').filter(|&c| c != '\u{ad}')
}

/// Which characters a generated password may contain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Accented letters and signs such as `é ß ¿ µ` (U+00A1–U+00FF).
    pub extended_ascii: bool,
    /// Leave out `I l 1 O 0 o |`.
    pub avoid_ambiguous: bool,
    /// More characters to draw from (at least one of them appears when not empty).
    pub also_use: String,
    /// Characters that never appear, whatever the sets above say.
    pub never_use: String,
    /// At least this many of each kind (for sites with such rules). Every kind turned on
    /// appears at least once anyway; a minimum for a kind turned off is ignored.
    pub min_lowercase: usize,
    pub min_uppercase: usize,
    pub min_digits: usize,
    pub min_symbols: usize,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            extended_ascii: false,
            avoid_ambiguous: false,
            also_use: String::new(),
            never_use: String::new(),
            min_lowercase: 0,
            min_uppercase: 0,
            min_digits: 0,
            min_symbols: 0,
        }
    }
}

impl PasswordOptions {
    /// The enabled character sets, without excluded characters and without characters already
    /// in an earlier set, each with how many of it the password must have (at least one).
    /// Empty sets are dropped.
    fn sets(&self) -> Vec<(Vec<char>, usize)> {
        let excluded =
            |c: char| (self.avoid_ambiguous && AMBIGUOUS.contains(c)) || self.never_use.contains(c);
        let groups: [(bool, Vec<char>, usize); 6] = [
            (
                self.lowercase,
                LOWERCASE.chars().collect(),
                self.min_lowercase,
            ),
            (
                self.uppercase,
                UPPERCASE.chars().collect(),
                self.min_uppercase,
            ),
            (self.digits, DIGITS.chars().collect(), self.min_digits),
            (self.symbols, SYMBOLS.chars().collect(), self.min_symbols),
            (self.extended_ascii, extended_ascii().collect(), 1),
            (
                true,
                self.also_use
                    .chars()
                    .filter(|c| !c.is_control() && !c.is_whitespace())
                    .collect(),
                1,
            ),
        ];
        let mut seen: Vec<char> = Vec::new();
        let mut sets = Vec::new();
        for (enabled, chars, minimum) in groups {
            if !enabled {
                continue;
            }
            let mut set = Vec::new();
            for c in chars {
                if !excluded(c) && !seen.contains(&c) && !set.contains(&c) {
                    set.push(c);
                }
            }
            if !set.is_empty() {
                seen.extend(&set);
                sets.push((set, minimum.max(1)));
            }
        }
        sets
    }

    /// Number of different characters a password can be made of.
    pub fn alphabet_size(&self) -> usize {
        self.sets().iter().map(|(set, _)| set.len()).sum()
    }

    /// How many characters the minimums take (every set's at least one included).
    pub fn required(&self) -> usize {
        self.sets().iter().map(|(_, minimum)| minimum).sum()
    }

    /// Approximate strength: `length × log2(alphabet size)`. Characters a minimum above one
    /// forces into a set count only that set's choices, so strict minimums lower it.
    pub fn entropy_bits(&self) -> f64 {
        let sets = self.sets();
        let alphabet: usize = sets.iter().map(|(set, _)| set.len()).sum();
        if alphabet == 0 {
            return 0.0;
        }
        let mut free = self.length;
        let mut bits = 0.0;
        for (set, minimum) in &sets {
            if *minimum > 1 {
                let forced = (*minimum).min(free);
                free -= forced;
                bits += forced as f64 * (set.len() as f64).log2();
            }
        }
        bits + free as f64 * (alphabet as f64).log2()
    }
}

/// Generates a password containing at least one character from every enabled set, and at
/// least each set's minimum. Fails when the minimums don't fit in the length.
pub fn generate_password(options: &PasswordOptions) -> Result<Zeroizing<String>> {
    if options.also_use.chars().count() > MAX_CUSTOM_CHARS
        || options.never_use.chars().count() > MAX_CUSTOM_CHARS
    {
        return Err(Error::InvalidGeneratorOptions);
    }
    let sets = options.sets();
    let required: usize = sets.iter().map(|(_, minimum)| minimum).sum();
    if sets.is_empty()
        || !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length)
        || options.length < required
    {
        return Err(Error::InvalidGeneratorOptions);
    }
    let pool: Vec<char> = sets
        .iter()
        .flat_map(|(set, _)| set.iter().copied())
        .collect();

    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(options.length));
    for (set, minimum) in &sets {
        for _ in 0..*minimum {
            chars.push(set[uniform_index(set.len())?]);
        }
    }
    while chars.len() < options.length {
        chars.push(pool[uniform_index(pool.len())?]);
    }
    // Fisher–Yates shuffle so the guaranteed characters are not always first.
    for i in (1..chars.len()).rev() {
        let j = uniform_index(i + 1)?;
        chars.swap(i, j);
    }

    // Latin-1 characters take two bytes in UTF-8; reserve the worst case (no reallocation).
    let mut out = Zeroizing::new(String::with_capacity(chars.len() * 4));
    out.extend(chars.iter());
    Ok(out)
}

/// How the words of a passphrase are written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WordCase {
    /// `correct-horse-battery`
    #[default]
    Lower,
    /// `CORRECT-HORSE-BATTERY`
    Upper,
    /// `Correct-Horse-Battery`
    Title,
    /// Each word written one of the three ways above at random (`correct-HORSE-Battery`):
    /// log2(3) ≈ 1.58 more bits per word.
    Mixed,
}

/// A list of words to build passphrases from.
#[derive(Clone, PartialEq, Eq)]
pub struct Wordlist {
    words: Vec<String>,
}

impl std::fmt::Debug for Wordlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wordlist")
            .field("words", &self.words.len())
            .finish()
    }
}

impl Wordlist {
    /// Fewest distinct words accepted: below this a passphrase needs too many words.
    pub const MIN_WORDS: usize = 500;
    const MAX_WORDS: usize = 200_000;
    const MAX_WORD_CHARS: usize = 32;

    /// Reads a word list: one word per line, or Diceware lines such as `11111<TAB>abacus`
    /// (the last item on the line is the word). Blank lines and `#` comments are skipped and a
    /// repeated word is kept once (ignoring case). Fails when fewer than
    /// [`Wordlist::MIN_WORDS`] distinct words remain.
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut seen = std::collections::HashSet::new();
        let mut words = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some(word) = line.split_whitespace().last() else {
                continue;
            };
            if word.chars().count() > Self::MAX_WORD_CHARS || word.chars().any(char::is_control) {
                continue;
            }
            if seen.insert(word.to_lowercase()) {
                words.push(word.to_owned());
            }
            if words.len() > Self::MAX_WORDS {
                return Err(Error::InvalidGeneratorOptions);
            }
        }
        if words.len() < Self::MIN_WORDS {
            return Err(Error::InvalidGeneratorOptions);
        }
        Ok(Self { words })
    }

    /// The bundled EFF large word list (7,776 words).
    pub fn eff_large() -> Self {
        Self {
            words: eff_words().iter().map(|w| (*w).to_owned()).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }
}

/// Options for word-based passphrases (easier to type and remember, e.g. for the master password).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// Number of words (3–20). Six words from the EFF list ≈ 77.5 bits.
    pub words: usize,
    /// Placed between words (at most 3 characters; may be empty).
    pub separator: String,
    pub case: WordCase,
    /// Append one random digit to one random word.
    pub include_number: bool,
    /// Words to pick from; `None` = the bundled EFF large list.
    pub wordlist: Option<Arc<Wordlist>>,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".into(),
            case: WordCase::Lower,
            include_number: false,
            wordlist: None,
        }
    }
}

impl PassphraseOptions {
    fn list_len(&self) -> usize {
        self.wordlist
            .as_ref()
            .map_or(EFF_WORD_COUNT, |list| list.len())
    }

    /// Strength: `words × log2(list size)`, plus the random case and the digit and its
    /// position when enabled.
    pub fn entropy_bits(&self) -> f64 {
        let words = self.words as f64;
        let mut bits = words * (self.list_len() as f64).log2();
        if self.case == WordCase::Mixed {
            bits += words * 3f64.log2();
        }
        if self.include_number && self.words > 0 {
            bits += 10f64.log2() + words.log2();
        }
        bits
    }
}

pub(crate) fn eff_words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        EFF_LARGE_WORDLIST
            .lines()
            .filter_map(|line| line.split_once('\t').map(|(_, word)| word))
            .collect()
    })
}

fn push_word(out: &mut String, word: &str, case: WordCase) -> Result<()> {
    let case = match case {
        WordCase::Mixed => [WordCase::Lower, WordCase::Upper, WordCase::Title][uniform_index(3)?],
        other => other,
    };
    match case {
        WordCase::Upper => out.extend(word.chars().flat_map(char::to_uppercase)),
        WordCase::Title => {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
            }
            out.extend(chars.flat_map(char::to_lowercase));
        }
        WordCase::Lower | WordCase::Mixed => {
            out.extend(word.chars().flat_map(char::to_lowercase));
        }
    }
    Ok(())
}

/// Generates a passphrase from the chosen word list (the EFF large list by default).
pub fn generate_passphrase(options: &PassphraseOptions) -> Result<Zeroizing<String>> {
    let custom: Option<&[String]> = options.wordlist.as_deref().map(|l| l.words.as_slice());
    let count = custom.map_or(eff_words().len(), <[String]>::len);
    if (custom.is_none() && count != EFF_WORD_COUNT)
        || count == 0
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

    // Reserve the worst case so the buffer never reallocates (that would leave a copy behind).
    let capacity = options.words * (4 * (Wordlist::MAX_WORD_CHARS + 1) + options.separator.len());
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    for i in 0..options.words {
        if i > 0 {
            out.push_str(&options.separator);
        }
        let index = uniform_index(count)?;
        let word = match custom {
            Some(words) => words[index].as_str(),
            None => eff_words()[index],
        };
        push_word(&mut out, word, options.case)?;
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
    fn minimums_per_kind() {
        let options = PasswordOptions {
            length: 12,
            min_digits: 4,
            min_symbols: 3,
            min_uppercase: 2,
            ..PasswordOptions::default()
        };
        assert_eq!(options.required(), 4 + 3 + 2 + 1);
        for _ in 0..50 {
            let made = generate_password(&options).unwrap();
            let count = |set: &str| made.chars().filter(|c| set.contains(*c)).count();
            assert_eq!(made.chars().count(), 12);
            assert!(count(DIGITS) >= 4 && count(SYMBOLS) >= 3 && count(UPPERCASE) >= 2);
            assert!(count(LOWERCASE) >= 1);
        }
        // Forced characters count only their own set's choices.
        assert!(
            options.entropy_bits()
                < PasswordOptions {
                    length: 12,
                    ..PasswordOptions::default()
                }
                .entropy_bits()
        );
        // No minimums: the strength is as before.
        let plain = PasswordOptions::default();
        assert!((plain.entropy_bits() - 20.0 * (plain.alphabet_size() as f64).log2()).abs() < 1e-9);
        // Minimums that don't fit, and one for a kind that is off (ignored).
        assert!(
            generate_password(&PasswordOptions {
                length: 8,
                min_digits: 9,
                ..PasswordOptions::default()
            })
            .is_err()
        );
        let digits_off = PasswordOptions {
            digits: false,
            min_digits: 30,
            ..PasswordOptions::default()
        };
        assert!(
            !generate_password(&digits_off)
                .unwrap()
                .chars()
                .any(|c| c.is_ascii_digit())
        );
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
            case: WordCase::Title,
            include_number: true,
            wordlist: None,
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
    fn word_cases() {
        let lower = |w: &str| w == w.to_lowercase();
        let upper = |w: &str| w == w.to_uppercase();
        let title = |w: &str| {
            w.chars().next().unwrap().is_uppercase() && w.chars().skip(1).all(|c| !c.is_uppercase())
        };
        type Check<'a> = &'a dyn Fn(&str) -> bool;
        let checks: [(WordCase, Check); 3] = [
            (WordCase::Lower, &lower),
            (WordCase::Upper, &upper),
            (WordCase::Title, &title),
        ];
        for (case, check) in checks {
            let options = PassphraseOptions {
                separator: " ".into(),
                case,
                ..Default::default()
            };
            let phrase = generate_passphrase(&options).unwrap();
            assert!(
                phrase.split(' ').all(check),
                "{case:?}: {}",
                phrase.as_str()
            );
        }
        let mixed = PassphraseOptions {
            separator: " ".into(),
            case: WordCase::Mixed,
            ..Default::default()
        };
        let phrase = generate_passphrase(&mixed).unwrap();
        assert!(phrase.split(' ').all(|w| lower(w) || upper(w) || title(w)));
        assert!((mixed.entropy_bits() - (77.55 + 6.0 * 3f64.log2())).abs() < 0.01);
    }

    #[test]
    fn custom_wordlists() {
        assert!(Wordlist::parse("one\ntwo\nthree").is_err(), "too short");
        let mut text = String::from("# my list\n\n");
        for i in 0..600 {
            text.push_str(&format!("{:05}\tpalavra{i}\n", 11111 + i));
        }
        text.push_str("PALAVRA1\n"); // repeated, ignoring case
        let list = Arc::new(Wordlist::parse(&text).unwrap());
        assert_eq!(list.len(), 600);
        let options = PassphraseOptions {
            words: 4,
            separator: ".".into(),
            wordlist: Some(list),
            ..Default::default()
        };
        let phrase = generate_passphrase(&options).unwrap();
        assert!(phrase.split('.').all(|w| w.starts_with("palavra")));
        assert!((options.entropy_bits() - 4.0 * 600f64.log2()).abs() < 0.01);
        assert_eq!(Wordlist::eff_large().len(), EFF_WORD_COUNT);
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
            assert!(password.chars().any(|c| LOWERCASE.contains(c)));
            assert!(password.chars().any(|c| UPPERCASE.contains(c)));
            assert!(password.chars().any(|c| DIGITS.contains(c)));
            assert!(password.chars().any(|c| SYMBOLS.contains(c)));
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
    fn extended_ascii_and_custom_characters() {
        let options = PasswordOptions {
            length: 40,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            extended_ascii: true,
            also_use: "xyz".into(),
            never_use: "é".into(),
            ..Default::default()
        };
        // 94 Latin-1 characters without é, plus x y z.
        assert_eq!(options.alphabet_size(), 93 + 3);
        for _ in 0..20 {
            let password = generate_password(&options).unwrap();
            assert_eq!(password.chars().count(), 40);
            assert!(password.chars().any(|c| "xyz".contains(c)));
            assert!(!password.contains('é') && !password.contains('\u{ad}'));
            assert!(
                password
                    .chars()
                    .all(|c| "xyz".contains(c) || ('\u{a1}'..='\u{ff}').contains(&c))
            );
        }
        // Leaving out every character of the only set leaves nothing to draw from.
        let nothing = PasswordOptions {
            lowercase: false,
            uppercase: false,
            symbols: false,
            never_use: DIGITS.into(),
            ..Default::default()
        };
        assert!(generate_password(&nothing).is_err());
        // Characters already in a set are counted once.
        let overlap = PasswordOptions {
            uppercase: false,
            digits: false,
            symbols: false,
            also_use: "abc!".into(),
            ..Default::default()
        };
        assert_eq!(overlap.alphabet_size(), 27);
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
