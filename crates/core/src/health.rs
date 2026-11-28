//! Password health: how hard a password is to guess, which items share a password, which are
//! old, what a login's site offers that it doesn't use yet ([`Advice`], from the lists bundled
//! in [`crate::site_lists`]), and the helpers for a k-anonymous breach lookup ("Have I Been
//! Pwned" range API).
//!
//! Nothing here touches the network: the app sends [`BreachQuery::prefix`] (5 hex characters
//! of the password's SHA-1) and passes the answer to [`BreachQuery::count_in`].

use std::collections::HashMap;

use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    ItemData, ItemId, ItemKind, Result, Vault, card,
    site_lists::{self, Offer},
};

/// Longer passwords are scored on their first characters only (the estimator slows down
/// quickly with length); such a password is strong anyway.
const MAX_SCORED_CHARS: usize = 64;
/// A password not changed for this long is reported as old.
pub const OLD_AFTER_SECONDS: i64 = 365 * 24 * 60 * 60;

/// The fewest guesses (log10 of zxcvbn's estimate) a password needs when it is the only thing
/// between a thief and what it protects (CRYPTO.md §3.3.1): 10^14, about 3 000 years of one
/// graphics card at the protected export's Argon2id cost. A protected export is refused below
/// it (and a KDBX export, once there is one), and a new master password or item lock password
/// is warned about: each is all that is left once the rest is stolen.
pub const ONE_FACTOR_MIN_GUESSES_LOG10: f64 = 14.0;

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

    /// log10 of the estimated number of guesses.
    pub fn guesses_log10(&self) -> f64 {
        self.bits / std::f64::consts::LOG2_10
    }

    /// Whether it reaches [`ONE_FACTOR_MIN_GUESSES_LOG10`] (with room for rounding: `bits`
    /// went through log2 and back).
    pub fn holds_alone(&self) -> bool {
        self.guesses_log10() + 1e-9 >= ONE_FACTOR_MIN_GUESSES_LOG10
    }
}

/// Whether `password` is strong enough to guard something on its own (a protected export, or
/// what is left of a vault once its Secret Key is stolen): at least
/// [`ONE_FACTOR_MIN_GUESSES_LOG10`] by zxcvbn's estimate. `context` holds words an attacker
/// would try first.
pub fn holds_alone(password: &str, context: &[&str]) -> bool {
    strength(password, context).holds_alone()
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

/// Something a login could do better, found without the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Advice {
    /// This website of the login's is saved with `http://`: what is typed there travels in
    /// clear.
    NoHttps(String),
    /// The site offers two-step sign-in with one-time codes and the login keeps none; the page
    /// that says how to turn it on ("" when the list has none).
    OneTimeCodes(&'static str),
    /// The site takes passkeys and the login has none.
    Passkeys(&'static str),
}

/// Health of every login with a password, plus expired cards, the items whose expiry date
/// (format v11) is past or within [`EXPIRES_SOON_SECONDS`], and the logins' [`Advice`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HealthReport {
    pub logins: Vec<ItemHealth>,
    pub expired_cards: Vec<ItemId>,
    /// With the date each one expires, soonest first.
    pub expiring: Vec<(ItemId, i64)>,
    pub advice: Vec<(ItemId, Advice)>,
}

/// An item whose expiry date is this close is listed on Password health (30 days).
pub const EXPIRES_SOON_SECONDS: i64 = 30 * 86_400;

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

/// What `item` (a login) could do better: a website without HTTPS, and what its site offers
/// that it doesn't use. The offers aren't judged while its secrets are locked (its codes and
/// passkeys can't be seen then).
fn advise(id: ItemId, item: &ItemData, advice: &mut Vec<(ItemId, Advice)>) {
    if let Some(url) = item.urls.iter().find(|url| site_lists::without_https(url)) {
        advice.push((id, Advice::NoHttps(url.clone())));
    }
    if item.is_locked() {
        return;
    }
    let offered = |offer| {
        item.urls
            .iter()
            .find_map(|url| site_lists::offered(offer, url))
    };
    if item.totp.trim().is_empty()
        && !item.password.is_empty()
        && let Some(page) = offered(Offer::OneTimeCodes)
    {
        advice.push((id, Advice::OneTimeCodes(page)));
    }
    if item.passkeys.is_empty()
        && let Some(page) = offered(Offer::Passkeys)
    {
        advice.push((id, Advice::Passkeys(page)));
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
    Ok(collect(vault, now, month_year)?.analyze())
}

/// What an audit needs from the vault, read in one quick pass. The slow part (estimating
/// every password's strength) is [`AuditInput::analyze`], which needs no vault and can run on
/// another thread. Passwords are wiped when this is dropped.
pub struct AuditInput {
    logins: Vec<AuditLogin>,
    expired_cards: Vec<ItemId>,
    expiring: Vec<(ItemId, i64)>,
    advice: Vec<(ItemId, Advice)>,
    now: i64,
}

struct AuditLogin {
    id: ItemId,
    password: Zeroizing<String>,
    context: Vec<String>,
    set_at: i64,
}

impl std::fmt::Debug for AuditInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditInput")
            .field("logins", &self.logins.len())
            .field("expired_cards", &self.expired_cards.len())
            .finish_non_exhaustive()
    }
}

/// Reads what [`audit`] looks at: every login's password and the words around it, and which
/// cards have expired. Items whose secrets are locked are left out, and so are items not in use
/// (in the trash, archived, templates).
pub fn collect(vault: &Vault, now: i64, month_year: (u32, u32)) -> Result<AuditInput> {
    let mut input = AuditInput {
        logins: Vec::new(),
        expired_cards: Vec::new(),
        expiring: Vec::new(),
        advice: Vec::new(),
        now,
    };
    for id in vault.item_ids() {
        let item = vault.get_item(&id)?;
        if !item.is_active() {
            continue;
        }
        if item.expires_at != 0 && item.expires_at <= now.saturating_add(EXPIRES_SOON_SECONDS) {
            input.expiring.push((id, item.expires_at));
        }
        if item.kind == ItemKind::Login {
            advise(id, &item, &mut input.advice);
        }
        match item.kind {
            ItemKind::Login if !item.password.is_empty() => {
                input.logins.push(AuditLogin {
                    id,
                    password: Zeroizing::new(item.password.clone()),
                    context: context_words(&item)
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                    set_at: item.password_set_at(),
                });
            }
            ItemKind::Card => {
                let details = card::CardDetails::from_item(&item);
                if let Some(expiry) = card::parse_expiry(&details.expiry)
                    && card::is_expired(expiry, month_year)
                {
                    input.expired_cards.push(id);
                }
            }
            _ => {}
        }
    }
    Ok(input)
}

impl AuditInput {
    /// Estimates every password's strength and counts reuse.
    pub fn analyze(self) -> HealthReport {
        let mut expiring = self.expiring.clone();
        expiring.sort_by_key(|(id, at)| (*at, *id.as_bytes()));
        let mut report = HealthReport {
            logins: Vec::with_capacity(self.logins.len()),
            expired_cards: self.expired_cards.clone(),
            expiring,
            advice: self.advice.clone(),
        };
        let mut fingerprints: Vec<[u8; 32]> = Vec::with_capacity(self.logins.len());
        for login in &self.logins {
            fingerprints.push(Sha256::digest(login.password.as_bytes()).into());
            let context: Vec<&str> = login.context.iter().map(String::as_str).collect();
            report.logins.push(ItemHealth {
                id: login.id,
                strength: strength(&login.password, &context),
                reused_by: 0,
                old: login.set_at > 0 && self.now - login.set_at > OLD_AFTER_SECONDS,
                set_at: login.set_at,
            });
        }
        let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
        for fingerprint in &fingerprints {
            *counts.entry(*fingerprint).or_default() += 1;
        }
        for (health, fingerprint) in report.logins.iter_mut().zip(&fingerprints) {
            health.reused_by = counts[fingerprint] - 1;
        }
        report
    }
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
    fn the_one_factor_floor() {
        // Twelve characters were all a protected export asked for before: not enough alone.
        for weak in [
            "aaaaaaaaaaaa",
            "password1234",
            "export password",
            "a file password",
            "Tr0ub4dor&3xyz",
            "x8Kq2mZp4Lr7W",
        ] {
            assert!(!holds_alone(weak, &[]), "{weak}");
        }
        for strong in [
            "correct horse battery staple",
            "x8Kq2mZp4Lr7Wd",
            "t7#Kq!9vR2@pLm4$",
        ] {
            assert!(holds_alone(strong, &[]), "{strong}");
        }
        // The passphrase the apps offer instead always reaches it.
        for _ in 0..50 {
            let phrase =
                crate::generator::generate_passphrase(&crate::generator::PassphraseOptions {
                    words: 6,
                    ..Default::default()
                })
                .unwrap();
            assert!(holds_alone(&phrase, &[]), "{}", phrase.as_str());
        }
        // Words an attacker tries first count against it.
        assert!(holds_alone("octocat github mainframe", &[]));
        assert!(!holds_alone(
            "octocat github mainframe",
            &["octocat", "github", "mainframe"]
        ));
        assert!(!holds_alone("", &[]));
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
    fn advice_found_offline() {
        let key = SecretKey::generate().unwrap();
        let mut vault = Vault::create("pw", &key, None, KdfParams::minimum().unwrap()).unwrap();
        // A site of each list, whichever comes first in it.
        let first = |text: &'static str| text.lines().next().unwrap().split_once('\t').unwrap();
        let (codes_site, codes_page) = first(include_str!("../data/sites-totp.txt"));
        let (keys_site, keys_page) = first(include_str!("../data/sites-passkeys.txt"));
        let plain = ItemData::login("Router", "admin", "pw-1", "http://router.example/login");
        let local = ItemData::login("Dev", "me", "pw-2", "http://localhost:8080");
        let codes = ItemData::login("Codes", "me", "pw-3", &format!("https://www.{codes_site}"));
        let mut has_codes = codes.clone();
        has_codes.title = "Has codes".into();
        has_codes.totp = "JBSWY3DPEHPK3PXP".into();
        let keys = ItemData::login("Keys", "me", "pw-4", &format!("https://{keys_site}/"));
        let ids: Vec<ItemId> = [&plain, &local, &codes, &has_codes, &keys]
            .iter()
            .map(|item| vault.add_item(item).unwrap())
            .collect();

        let report = audit(&vault, 1_900_000_000, (1, 2030)).unwrap();
        let of = |id: ItemId| -> Vec<&Advice> {
            report
                .advice
                .iter()
                .filter(|(at, _)| *at == id)
                .map(|(_, advice)| advice)
                .collect()
        };
        assert!(of(ids[0]).contains(&&Advice::NoHttps("http://router.example/login".into())));
        assert!(
            !of(ids[1]).iter().any(|a| matches!(a, Advice::NoHttps(_))),
            "this computer's own address is fine"
        );
        assert!(of(ids[2]).contains(&&Advice::OneTimeCodes(codes_page)));
        assert!(
            !of(ids[3])
                .iter()
                .any(|a| matches!(a, Advice::OneTimeCodes(_))),
            "it keeps its codes already"
        );
        assert!(of(ids[4]).contains(&&Advice::Passkeys(keys_page)));
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
