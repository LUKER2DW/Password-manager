//! Password health: how hard a password is to guess, which items share a password, which are
//! old, and the helpers for a k-anonymous breach lookup ("Have I Been Pwned" range API).
//!
//! Nothing here touches the network: the app sends [`BreachQuery::prefix`] (5 hex characters
//! of the password's SHA-1) and passes the answer to [`BreachQuery::count_in`].

use std::collections::HashMap;

use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{ItemData, ItemId, ItemKind, Result, Vault, card};

/// Longer passwords are scored on their first characters only (the estimator slows down
/// quickly with length); such a password is strong anyway.
const MAX_SCORED_CHARS: usize = 64;
/// A password not changed for this long is reported as old.
pub const OLD_AFTER_SECONDS: i64 = 365 * 24 * 60 * 60;

/// What makes a password easy to guess (from the zxcvbn estimator).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Pattern {
    #[default]
    None,
    /// `qwerty`, `asdfgh`, short keyboard walks.
    KeyboardPattern,
    /// `aaa`, `abcabc`.
    Repeats,
    /// In the lists of most used passwords.
    Common,
    /// A common password with small changes (`P@ssw0rd`).
    SimilarToCommon,
    /// `abc`, `1234`.
    Sequence,
    /// Years and dates.
    Dates,
    /// One dictionary word on its own.
    SingleWord,
    /// A first name or surname.
    Names,
}

/// How hard a password is to guess.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Strength {
    /// log2 of the estimated number of guesses an attacker needs.
    pub bits: f64,
    /// 0 (guessed almost at once) to 4 (very hard to guess).
    pub score: u8,
    pub pattern: Pattern,
}

impl Strength {
    /// Score 0–2: worth changing.
    pub fn is_weak(&self) -> bool {
        self.score < 3
    }
}

/// Estimates how hard `password` is to guess. `context` holds words an attacker would try
/// first for this account (title, username, site).
pub fn strength(password: &str, context: &[&str]) -> Strength {
    if password.is_empty() {
        return Strength {
            bits: 0.0,
            score: 0,
            pattern: Pattern::None,
        };
    }
    let scored: Zeroizing<String> =
        Zeroizing::new(password.chars().take(MAX_SCORED_CHARS).collect());
    let estimate = zxcvbn::zxcvbn(&scored, context);
    let pattern = estimate
        .feedback()
        .and_then(zxcvbn::feedback::Feedback::warning)
        .map_or(Pattern::None, |warning| {
            use zxcvbn::feedback::Warning as W;
            match warning {
                W::StraightRowsOfKeysAreEasyToGuess | W::ShortKeyboardPatternsAreEasyToGuess => {
                    Pattern::KeyboardPattern
                }
                W::RepeatsLikeAaaAreEasyToGuess
                | W::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess => Pattern::Repeats,
                W::ThisIsATop10Password | W::ThisIsATop100Password | W::ThisIsACommonPassword => {
                    Pattern::Common
                }
                W::ThisIsSimilarToACommonlyUsedPassword => Pattern::SimilarToCommon,
                W::SequencesLikeAbcAreEasyToGuess => Pattern::Sequence,
                W::RecentYearsAreEasyToGuess | W::DatesAreOftenEasyToGuess => Pattern::Dates,
                W::AWordByItselfIsEasyToGuess => Pattern::SingleWord,
                W::NamesAndSurnamesByThemselvesAreEasyToGuess
                | W::CommonNamesAndSurnamesAreEasyToGuess => Pattern::Names,
            }
        });
    Strength {
        bits: estimate.guesses_log10() * std::f64::consts::LOG2_10,
        score: u8::from(estimate.score()),
        pattern,
    }
}

/// Health of one item's password.
#[derive(Clone, Debug, PartialEq)]
pub struct ItemHealth {
    pub id: ItemId,
    pub strength: Strength,
    /// How many other items use the same password.
    pub reused_by: usize,
    /// Not changed for more than a year.
    pub old: bool,
    /// When the password was set (Unix seconds).
    pub set_at: i64,
}

/// Health of every login with a password, plus expired cards.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HealthReport {
    pub logins: Vec<ItemHealth>,
    pub expired_cards: Vec<ItemId>,
}

impl HealthReport {
    pub fn weak(&self) -> impl Iterator<Item = &ItemHealth> {
        self.logins.iter().filter(|h| h.strength.is_weak())
    }

    pub fn reused(&self) -> impl Iterator<Item = &ItemHealth> {
        self.logins.iter().filter(|h| h.reused_by > 0)
    }

    pub fn old(&self) -> impl Iterator<Item = &ItemHealth> {
        self.logins.iter().filter(|h| h.old)
    }
}

fn context_words(item: &ItemData) -> Vec<&str> {
    let mut words = vec![item.title.as_str(), item.username.as_str()];
    words.extend(item.urls.iter().map(String::as_str));
    if let Some((local, _)) = item.username.split_once('@') {
        words.push(local);
    }
    words.retain(|w| !w.is_empty());
    words
}

/// Checks every item. `now` and `(month, year)` are passed in so results are reproducible.
pub fn audit(vault: &Vault, now: i64, month_year: (u32, u32)) -> Result<HealthReport> {
    let mut report = HealthReport::default();
    let mut fingerprints: Vec<[u8; 32]> = Vec::new();
    for id in vault.item_ids() {
        let item = vault.get_item(&id)?;
        match item.kind {
            ItemKind::Login if !item.password.is_empty() => {
                fingerprints.push(Sha256::digest(item.password.as_bytes()).into());
                let set_at = item.password_set_at();
                report.logins.push(ItemHealth {
                    id,
                    strength: strength(&item.password, &context_words(&item)),
                    reused_by: 0,
                    old: set_at > 0 && now - set_at > OLD_AFTER_SECONDS,
                    set_at,
                });
            }
            ItemKind::Card => {
                let details = card::CardDetails::from_item(&item);
                if let Some(expiry) = card::parse_expiry(&details.expiry)
                    && card::is_expired(expiry, month_year)
                {
                    report.expired_cards.push(id);
                }
            }
            _ => {}
        }
    }
    let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
    for fingerprint in &fingerprints {
        *counts.entry(*fingerprint).or_default() += 1;
    }
    for (health, fingerprint) in report.logins.iter_mut().zip(&fingerprints) {
        health.reused_by = counts[fingerprint] - 1;
    }
    Ok(report)
}

/// A k-anonymous breach lookup for one password: only the first 5 hex characters of its
/// SHA-1 leave the device; the service answers with every known suffix in that range.
#[derive(Clone)]
pub struct BreachQuery {
    prefix: String,
    suffix: Zeroizing<String>,
}

impl std::fmt::Debug for BreachQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreachQuery")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl BreachQuery {
    pub fn new(password: &str) -> Self {
        let digest = Sha1::digest(password.as_bytes());
        let hex: Zeroizing<String> =
            Zeroizing::new(digest.iter().map(|b| format!("{b:02X}")).collect());
        Self {
            prefix: hex[..5].to_owned(),
            suffix: Zeroizing::new(hex[5..].to_owned()),
        }
    }

    /// The 5 hex characters sent to the service.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// How many times the password appears in the breaches, from the service's answer
    /// (`SUFFIX:COUNT` lines; padding lines with a count of 0 are ignored).
    pub fn count_in(&self, response: &str) -> u64 {
        response
            .lines()
            .filter_map(|line| line.trim().split_once(':'))
            .find(|(suffix, _)| suffix.eq_ignore_ascii_case(&self.suffix))
            .and_then(|(_, count)| count.trim().parse().ok())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KdfParams, SecretKey};

    #[test]
    fn strength_of_common_and_random_passwords() {
        let weak = strength("password1", &[]);
        assert!(weak.is_weak());
        assert_eq!(weak.pattern, Pattern::Common);
        assert!(strength("qwertyuiop", &[]).is_weak());
        let strong = strength("t7#Kq!9vR2@pLm4$", &[]);
        assert_eq!(strong.score, 4);
        assert!(strong.bits > 50.0);
        // The account's own name makes a password easier to guess.
        assert!(
            strength("githubmegithub", &["github", "me"]).bits
                < strength("githubmegithub", &[]).bits
        );
        assert_eq!(strength("", &[]).score, 0);
        // Very long passwords are scored on a prefix and stay fast.
        assert_eq!(strength(&"x7#Kq!9vR2@pLm4$".repeat(100), &[]).score, 4);
    }

    #[test]
    fn audit_finds_weak_reused_old_and_expired() {
        let key = SecretKey::generate().unwrap();
        let mut vault = Vault::create("pw", &key, None, KdfParams::minimum().unwrap()).unwrap();
        let now = 2_000_000_000;
        let mut a = ItemData::login("A", "me", "same-Strong-pass-91!", "");
        a.created_at = now - 10;
        let mut b = ItemData::login("B", "me", "same-Strong-pass-91!", "");
        b.created_at = now - 2 * OLD_AFTER_SECONDS;
        let c = ItemData::login("C", "me", "123456", "");
        let mut card_item = ItemData::new(ItemKind::Card, "Card");
        card::CardDetails {
            number: String::new(),
            expiry: "01/20".into(),
            security_code: String::new(),
        }
        .apply(&mut card_item);
        let ids: Vec<ItemId> = [a, b, c, card_item]
            .iter()
            .map(|item| vault.add_item(item).unwrap())
            .collect();

        let report = audit(&vault, now, (6, 2033)).unwrap();
        assert_eq!(report.logins.len(), 3);
        let by_id = |id: ItemId| report.logins.iter().find(|h| h.id == id).unwrap();
        assert_eq!(by_id(ids[0]).reused_by, 1);
        assert_eq!(by_id(ids[1]).reused_by, 1);
        assert!(!by_id(ids[0]).old && by_id(ids[1]).old);
        assert!(by_id(ids[2]).strength.is_weak());
        assert_eq!(report.weak().count(), 1);
        assert_eq!(report.reused().count(), 2);
        assert_eq!(report.expired_cards, [ids[3]]);
    }

    #[test]
    fn breach_query_is_k_anonymous() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let query = BreachQuery::new("password");
        assert_eq!(query.prefix(), "5BAA6");
        let response = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                        1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n\
                        FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n";
        assert_eq!(query.count_in(response), 9_545_824);
        assert_eq!(BreachQuery::new("not in it").count_in(response), 0);
        assert!(!format!("{query:?}").contains("1E4C9B"));
    }
}
