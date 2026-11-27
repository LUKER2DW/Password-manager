//! Pages that look like a site of the vault without being it.
//!
//! The extension fills a login only on the exact site it is saved for ([`crate::origin`]), so
//! a phishing page gets nothing filled. What a phishing page counts on is the next step: the
//! person, seeing nothing offered, copies the password from the app and pastes it. This module
//! lets the app say, before that, that the page only looks like a site the person has a login
//! for: `paypa1.com`, `pаypal.com` (a Cyrillic `а`), `rnicrosoft.com`, `paypal.co`,
//! `paypal-login.com`, `paypal.com.evil.example`.
//!
//! Everything here is local and uses the vault's own sites: no list is downloaded, nothing is
//! asked of anyone. Names are compared by their registrable domain (the part someone
//! registered, by the Public Suffix List compiled into the app), so `mail.example.com` is
//! never a lookalike of `example.com`: they have one owner.
//!
//! How alike two names look is judged on their *skeletons*: the name with accents dropped,
//! letters of other scripts that look like Latin ones replaced by those (`а` → `a`), `0` → `o`,
//! `1` → `l`, `rn` → `m` and `vv` → `w`. A page looks like a saved site when, with a different
//! registrable domain:
//!
//! 1. the skeletons are equal (`paypa1.com`, `pаypal.com`, `rnicrosoft.com`);
//! 2. the names are the same and the suffix is a typo of the saved one (`paypal.co`,
//!    `paypal.cm`), or a hosting company's where anyone can have a site (`paypal.github.io`);
//! 3. the suffix is the same and the names are one edit apart (two for names of ten letters
//!    or more), for names of five letters or more (`gooogle.com`, `googel.com`); shorter names
//!    differ by one letter too often to mean anything (`ing.com`, `ign.com`);
//! 4. the saved name, five letters or more, is a word of the page's name (`paypal-login.com`,
//!    `secure-paypal.com`), or the saved site stands in the page's subdomains
//!    (`paypal.com.evil.example`, `paypal-com.evil.example`; the name alone, six letters or
//!    more: `paypal.sign-in.example`).
//!
//! [`display_host`] is how a host is shown to the person: in its own letters when they are of
//! one script (`bücher.example`), in its ASCII form (`xn--…`) when they mix scripts or are all
//! letters that look Latin (`аррӏе.com`), as browsers show such names in the address bar.

use psl::Type;
use serde::Serialize;
use unicode_normalization::{UnicodeNormalization as _, char::is_combining_mark};
use unicode_script::{Script, UnicodeScript as _};

use crate::origin::{Origin, wildcard_base};

/// A saved site a page looks like.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Lookalike {
    /// The saved site (its registrable domain), as [`display_host`] shows it.
    pub site: String,
    /// The page's host, as [`display_host`] shows it.
    pub page: String,
}

/// The saved site the page at `page_host` (its host as the browser gives it, international
/// names in their ASCII form) looks like without being it, among the websites `saved` in the
/// vault (as written in items). `None` when it looks like none of them, or when one of them
/// has the page's own registrable domain: the person has a login with that site's owner.
pub fn lookalike<'a>(
    page_host: &str,
    saved: impl IntoIterator<Item = &'a str>,
) -> Option<Lookalike> {
    let page = Parts::of(page_host)?;
    let mut best: Option<(Signal, String)> = None;
    for text in saved {
        let Some(host) = saved_host(text) else {
            continue;
        };
        let Some(site) = Parts::of(&host) else {
            continue;
        };
        if site.registrable == page.registrable {
            return None;
        }
        let Some(signal) = page.resembles(&site) else {
            continue;
        };
        let shown = display_host(&site.registrable);
        if best
            .as_ref()
            .is_none_or(|(was, name)| (signal, &shown) < (*was, name))
        {
            best = Some((signal, shown));
        }
    }
    best.map(|(_, site)| Lookalike {
        site,
        page: display_host(page_host),
    })
}

/// Whether `page_host` and `saved_host` (both as the browser gives them) are the same site
/// owner: the same registrable domain (`mail.example.com` and `example.com`). Hosts without
/// one (an IP address, `localhost`) are the same only when equal.
pub fn same_owner(page_host: &str, saved_host: &str) -> bool {
    match (registrable(page_host), registrable(saved_host)) {
        (Some(page), Some(saved)) => page == saved,
        _ => page_host.eq_ignore_ascii_case(saved_host),
    }
}

/// The site a host belongs to, as the person reads it: its registrable domain (`paypal.com`
/// for `www.paypal.com`), shown by [`display_host`]; the host itself when it has none (an IP
/// address).
pub fn shown_site(host: &str) -> String {
    display_host(&registrable(host).unwrap_or_else(|| host.to_owned()))
}

/// The host a saved website stands for (`*.example.com` stands for `example.com`), as the
/// browser writes it; `None` when it names no website.
pub fn saved_host(text: &str) -> Option<String> {
    wildcard_base(text).or_else(|| Origin::of_saved(text).map(|origin| origin.host().to_owned()))
}

/// A host as the person should read it: its international letters when they are safe to show,
/// its ASCII form (`xn--…`) when a name mixes scripts (`pаypal.com`: Latin and Cyrillic) or
/// is made only of letters that look Latin under an ASCII ending (`аррӏе.com`). The rule
/// browsers follow for the address bar, simplified: Latin with Chinese, Japanese or Korean
/// letters is one script here, as for them.
pub fn display_host(host: &str) -> String {
    if !host.split('.').any(|label| label.starts_with("xn--")) {
        return host.to_owned();
    }
    let unicode = url::quirks::domain_to_unicode(host);
    if unicode.is_empty() || unicode.contains('\u{FFFD}') {
        return host.to_owned();
    }
    let ascii_ending = unicode.rsplit('.').next().is_some_and(|tld| tld.is_ascii());
    if unicode
        .split('.')
        .any(|label| !label.is_ascii() && !safe_label(label, ascii_ending))
    {
        return host.to_owned();
    }
    unicode
}

/// The registrable domain of `host` (ASCII), `None` for an IP address or a name that is a
/// public suffix itself.
fn registrable(host: &str) -> Option<String> {
    if host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = psl::domain(host.as_bytes())?;
    std::str::from_utf8(domain.as_bytes())
        .ok()
        .map(str::to_owned)
}

/// How strongly a page looks like a saved site: the first kind of [`Parts::resembles`] that
/// holds (lower is stronger, so the strongest is named when several sites match).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Signal {
    /// The same skeleton.
    Homograph,
    /// The same name under a suffix that is a typo of the saved one, or a hosting company's.
    Suffix,
    /// One or two edits from the saved name.
    NearMiss,
    /// The saved name inside the page's name or subdomains.
    Inside,
}

/// A host taken apart for comparing: its registrable domain, and the skeletons of its name,
/// suffix and the words of its subdomains.
#[derive(Debug)]
struct Parts {
    /// The registrable domain, ASCII (`paypal.com`, `xn--pypal-4ve.com`).
    registrable: String,
    /// The name's skeleton (`paypal` for `pаypal.com`).
    name: String,
    /// The name's length in letters, before the skeleton.
    name_len: usize,
    /// The words of the name, split at `-` (skeletons).
    name_words: Vec<String>,
    /// The suffix's skeleton (`com`, `co.uk`).
    suffix: String,
    /// The suffix's words, split at `.` (skeletons).
    suffix_words: Vec<String>,
    /// Anyone can register a site right under the suffix of a hosting company (`github.io`).
    hosted: bool,
    /// The words of the subdomains in front of the registrable domain, split at `.` and `-`
    /// (skeletons): `[www, paypal, com]` for `www.paypal.com.evil.example`.
    sub_words: Vec<String>,
}

impl Parts {
    fn of(host: &str) -> Option<Self> {
        if host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok() {
            return None;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let domain = psl::domain(host.as_bytes())?;
        let registrable = std::str::from_utf8(domain.as_bytes()).ok()?.to_owned();
        let suffix_ascii = std::str::from_utf8(domain.suffix().as_bytes()).ok()?;
        let name_ascii = registrable
            .strip_suffix(suffix_ascii)?
            .strip_suffix('.')
            .filter(|name| !name.is_empty())?;
        let subdomains = host
            .strip_suffix(registrable.as_str())
            .map_or("", |rest| rest.trim_end_matches('.'));
        let name_unicode = unicode_of(name_ascii);
        let suffix = skeleton(&unicode_of(suffix_ascii));
        let name = skeleton(&name_unicode);
        Some(Self {
            name_words: name
                .split('-')
                .filter(|w| !w.is_empty())
                .map(str::to_owned)
                .collect(),
            suffix_words: suffix.split('.').map(str::to_owned).collect(),
            name_len: name_unicode.chars().count(),
            name,
            suffix,
            hosted: domain.suffix().typ() == Some(Type::Private),
            sub_words: skeleton(&unicode_of(subdomains))
                .split(['.', '-'])
                .filter(|w| !w.is_empty())
                .map(str::to_owned)
                .collect(),
            registrable,
        })
    }

    /// How this page looks like the saved site `site` (another registrable domain), if it does.
    fn resembles(&self, site: &Self) -> Option<Signal> {
        let same_name = self.name == site.name;
        if same_name && self.suffix == site.suffix {
            return Some(Signal::Homograph);
        }
        if same_name && (edits(&self.suffix, &site.suffix) == 1 || self.hosted) {
            return Some(Signal::Suffix);
        }
        let allowed = match site.name_len {
            0..5 => 0,
            5..10 => 1,
            _ => 2,
        };
        if self.suffix == site.suffix && edits(&self.name, &site.name) <= allowed {
            return Some(Signal::NearMiss);
        }
        let long = site.name_len >= 5 && !site.name.contains('-');
        if long && self.name_words.len() > 1 && self.name_words.contains(&site.name) {
            return Some(Signal::Inside);
        }
        // The whole saved site in front of the page's suffix (`paypal.com.evil.example`,
        // `www.paypal.com-secure.example`), or its name alone among the subdomains when it is
        // long enough to be no common word.
        let mut whole = site.name_words.clone();
        whole.extend(site.suffix_words.iter().cloned());
        let words: Vec<&String> = self.sub_words.iter().chain(&self.name_words).collect();
        let in_front = !whole.is_empty()
            && words
                .windows(whole.len())
                .any(|run| run.iter().copied().eq(whole.iter()));
        let in_subdomains = site.name_len >= 6 && long && self.sub_words.contains(&site.name);
        (in_front || in_subdomains).then_some(Signal::Inside)
    }
}

/// A name in its own letters (`xn--pypal-4ve` → `pаypal`); as given when it can't be read.
fn unicode_of(ascii: &str) -> String {
    if ascii.is_empty() || !ascii.split('.').any(|label| label.starts_with("xn--")) {
        return ascii.to_owned();
    }
    let unicode = url::quirks::domain_to_unicode(ascii);
    if unicode.is_empty() || unicode.contains('\u{FFFD}') {
        ascii.to_owned()
    } else {
        unicode
    }
}

/// What `text` looks like to a reader: lower case, accents dropped, letters of other scripts
/// that look like Latin ones and the digits `0` and `1` replaced by those letters, `rn` read
/// as `m` and `vv` as `w`.
fn skeleton(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.nfd().filter(|c| !is_combining_mark(*c)) {
        for lower in c.to_lowercase() {
            out.push(looks_like(lower).unwrap_or(lower));
        }
    }
    out.replace("rn", "m").replace("vv", "w")
}

/// The Latin letter a lower-case character is easily read as, if it isn't one: digits,
/// Latin letters without a decomposition, and the Cyrillic, Greek and Armenian letters that
/// look like Latin ones in common fonts.
fn looks_like(c: char) -> Option<char> {
    Some(match c {
        '0' => 'o',
        '1' => 'l',
        // Latin letters NFD doesn't take apart.
        'ı' | 'ɩ' => 'i',
        'ł' | 'ŀ' | 'ǀ' => 'l',
        'ø' => 'o',
        'đ' => 'd',
        'ħ' => 'h',
        'ɡ' => 'g',
        'ɑ' => 'a',
        'ſ' => 'f',
        // Cyrillic.
        'а' => 'a',
        'ь' => 'b',
        'с' => 'c',
        'ԁ' => 'd',
        'е' => 'e',
        'һ' => 'h',
        'і' => 'i',
        'ј' => 'j',
        'к' => 'k',
        'ӏ' => 'l',
        'о' => 'o',
        'р' => 'p',
        'ԛ' => 'q',
        'г' => 'r',
        'ѕ' => 's',
        'у' | 'ү' => 'y',
        'х' => 'x',
        'ԝ' | 'ѡ' => 'w',
        // Greek.
        'α' => 'a',
        'β' => 'b',
        'ϲ' => 'c',
        'ε' => 'e',
        'η' => 'n',
        'ι' => 'i',
        'ϳ' => 'j',
        'κ' => 'k',
        'ν' => 'v',
        'ο' => 'o',
        'ρ' => 'p',
        'τ' => 't',
        'υ' => 'u',
        'χ' => 'x',
        'ω' => 'w',
        'γ' => 'y',
        // Armenian.
        'օ' => 'o',
        'ս' => 'u',
        'ց' => 'g',
        'հ' => 'h',
        'ո' => 'n',
        'զ' => 'q',
        'ա' => 'w',
        _ => return None,
    })
}

/// Whether an international label may be shown in its own letters: one script (Latin with
/// Chinese, Japanese or Korean counts as one), and, under an ASCII ending, not made only of
/// letters that look Latin.
fn safe_label(label: &str, ascii_ending: bool) -> bool {
    let mut scripts: Vec<Script> = Vec::new();
    for c in label.chars() {
        let script = c.script();
        if matches!(script, Script::Common | Script::Inherited | Script::Unknown) {
            continue;
        }
        if !scripts.contains(&script) {
            scripts.push(script);
        }
    }
    let within = |allowed: &[Script]| scripts.iter().all(|s| allowed.contains(s));
    let one_script = scripts.len() <= 1
        || within(&[
            Script::Latin,
            Script::Han,
            Script::Hiragana,
            Script::Katakana,
        ])
        || within(&[Script::Latin, Script::Han, Script::Bopomofo])
        || within(&[Script::Latin, Script::Han, Script::Hangul]);
    if !one_script {
        return false;
    }
    // A whole name in another script that reads as Latin (`аррӏе`): under `.com` it is shown
    // as what it is.
    let other = matches!(
        scripts.as_slice(),
        [Script::Cyrillic | Script::Greek | Script::Armenian]
    );
    let all_latin_looking = label
        .chars()
        .filter(|c| !matches!(c.script(), Script::Common | Script::Inherited))
        .all(|c| c.to_lowercase().all(|lower| looks_like(lower).is_some()));
    !(ascii_ending && other && all_latin_looking)
}

/// The number of single-letter insertions, deletions, substitutions and swaps of two
/// neighbours between `a` and `b` (the optimal string alignment distance).
fn edits(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    // Three rows: two back (for swaps), the one before, this one.
    let mut before_last: Vec<usize> = vec![0; b.len() + 1];
    let mut last: Vec<usize> = (0..=b.len()).collect();
    let mut row: Vec<usize> = vec![0; b.len() + 1];
    for i in 1..=a.len() {
        row[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (last[j] + 1).min(row[j - 1] + 1).min(last[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(before_last[j - 2] + 1);
            }
            row[j] = best;
        }
        std::mem::swap(&mut before_last, &mut last);
        std::mem::swap(&mut last, &mut row);
    }
    last[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host of a page as the browser gives it (lower case, international names in ASCII).
    fn host(page: &str) -> String {
        Origin::of_page(&format!("https://{page}/"))
            .unwrap()
            .host()
            .to_owned()
    }

    fn looks(page: &str, saved: &[&str]) -> Option<String> {
        lookalike(&host(page), saved.iter().copied()).map(|found| found.site)
    }

    /// Pages that only look like a saved site: each warns, naming that site.
    #[test]
    fn lookalikes_of_a_saved_site_are_told() {
        let cases: &[(&str, &str)] = &[
            // Digits for letters.
            ("paypa1.com", "paypal.com"),
            ("micros0ft.com", "microsoft.com"),
            ("faceb00k.com", "facebook.com"),
            // Letters of other scripts (Cyrillic а, о, р; Greek ο).
            ("p\u{430}ypal.com", "paypal.com"),
            ("\u{430}\u{440}\u{440}\u{4cf}\u{435}.com", "apple.com"),
            ("g\u{3bf}\u{3bf}gle.com", "google.com"),
            // Accents.
            ("p\u{e4}ypal.com", "paypal.com"),
            // Pairs of letters that read as one.
            ("rnicrosoft.com", "microsoft.com"),
            ("arnazon.com", "amazon.com"),
            ("vvellsfargo.com", "wellsfargo.com"),
            // One letter off (two for long names).
            ("gooogle.com", "google.com"),
            ("googel.com", "google.com"),
            ("gogle.com", "google.com"),
            ("wellsfarqo.com", "wellsfargo.com"),
            ("bankofamercia.com", "bankofamerica.com"),
            ("bnkofamerica.com", "bankofamerica.com"),
            ("bnkofamerca.com", "bankofamerica.com"),
            ("aple.com", "apple.com"),
            // The same name under a mistyped suffix, or on a hosting company's.
            ("paypal.co", "paypal.com"),
            ("paypal.cm", "paypal.com"),
            ("paypal.github.io", "paypal.com"),
            // The saved site inside the page's name or subdomains.
            ("paypal-login.com", "paypal.com"),
            ("secure-paypal.com", "paypal.com"),
            ("paypal.com.evil.example", "paypal.com"),
            ("www.paypal.com-secure.example", "paypal.com"),
            ("paypal-com.evil.example", "paypal.com"),
            ("paypal.sign-in.example", "paypal.com"),
            ("login.bbc.co.uk.evil.example", "bbc.co.uk"),
        ];
        for (page, site) in cases {
            assert_eq!(
                looks(
                    page,
                    &[
                        &format!("https://{site}/login"),
                        "https://unrelated.example"
                    ]
                ),
                Some((*site).to_owned()),
                "{page} looks like {site}"
            );
        }
        // Saved as a site and everything under it, or without a scheme: the same.
        assert_eq!(
            looks("paypa1.com", &["*.paypal.com"]).as_deref(),
            Some("paypal.com")
        );
        assert_eq!(
            looks("www.paypa1.com", &["www.paypal.com"]).as_deref(),
            Some("paypal.com")
        );
    }

    /// Ordinary sites that are simply other sites: none warns.
    #[test]
    fn ordinary_other_sites_are_not_lookalikes() {
        let cases: &[(&str, &str)] = &[
            // Another name altogether, or two letters off a short one.
            ("gitlab.com", "github.com"),
            ("youtube.com", "google.com"),
            ("chess.com", "chase.com"),
            ("maple.com", "apple.com"),
            ("stackoverflow.com", "stackexchange.com"),
            // Short names: one letter apart is just another site.
            ("ign.com", "ing.com"),
            ("bbc.com", "abc.com"),
            ("x.com", "y.com"),
            ("ebey.com", "ebay.com"),
            // The same company's sites in other countries, or its other domains.
            ("amazon.de", "amazon.com"),
            ("amazon.co.uk", "amazon.com"),
            ("paypal.me", "paypal.com"),
            ("google.com.br", "google.com"),
            // Common words of a subdomain, and names that only start the same.
            ("mail.yahoo.com", "mail.com"),
            ("login.live.com", "login.gov"),
            ("login.microsoftonline.com", "microsoft.com"),
            ("paypalobjects.com", "paypal.com"),
            ("mybank.example", "bank.example"),
            // A different TLD of the same length.
            ("example.org", "example.com"),
        ];
        for (page, site) in cases {
            assert_eq!(looks(page, &[*site]), None, "{page} is not {site}");
        }
    }

    /// A page of a site's own owner is never a lookalike, whatever else it looks like.
    #[test]
    fn the_same_owner_is_never_a_lookalike() {
        assert_eq!(
            looks("mail.google.com", &["https://accounts.google.com"]),
            None
        );
        assert_eq!(looks("gist.github.com", &["github.com"]), None);
        assert_eq!(looks("google.com", &["google.com:8443"]), None);
        // One saved site of the page's owner is enough, even with a lookalike saved too.
        assert_eq!(
            looks("paypa1.com", &["paypal.com", "https://login.paypa1.com"]),
            None
        );
        // Pages without a registrable domain: an IP address, a name that is a suffix.
        assert_eq!(lookalike("192.168.1.10", ["192.168.1.11"]), None);
        assert_eq!(lookalike("[::1]", ["paypal.com"]), None);
        assert_eq!(lookalike("github.io", ["github.com"]), None);
        // Nothing saved, or nothing that names a site.
        assert_eq!(looks("paypa1.com", &[]), None);
        assert_eq!(
            looks("paypa1.com", &["", "not a site", "ftp://paypal.com"]),
            None
        );
        assert!(same_owner("login.example.com", "example.com"));
        assert!(!same_owner("example.com", "example.org"));
        assert!(same_owner("192.168.1.10", "192.168.1.10"));
        assert!(!same_owner("192.168.1.10", "192.168.1.11"));
    }

    #[test]
    fn the_strongest_resemblance_is_named() {
        // `paypa1.com` is one letter from `paypai.com` too, but reads as `paypal.com`.
        assert_eq!(
            looks("paypa1.com", &["paypai.com", "paypal.com"]).as_deref(),
            Some("paypal.com")
        );
        // The page is shown as the warning shows it: a mixed-script name in ASCII.
        let found = lookalike(&host("p\u{430}ypal.com"), ["paypal.com"]).unwrap();
        assert_eq!(found.page, host("p\u{430}ypal.com"));
        assert!(found.page.starts_with("xn--"));
    }

    #[test]
    fn hosts_are_shown_in_their_own_letters_only_when_that_is_safe() {
        // One script: its letters.
        assert_eq!(display_host(&host("bücher.example")), "bücher.example");
        assert_eq!(display_host(&host("пример.рф")), "пример.рф");
        assert_eq!(display_host(&host("例え.jp")), "例え.jp");
        assert_eq!(display_host(&host("한국.kr")), "한국.kr");
        assert_eq!(display_host("github.com"), "github.com");
        assert_eq!(display_host("192.168.1.10"), "192.168.1.10");
        // Latin and Cyrillic mixed, Latin and Greek mixed: ASCII.
        for mixed in [
            "p\u{430}ypal.com",
            "g\u{3bf}ogle.com",
            "www.p\u{430}ypal.com",
        ] {
            let ascii = host(mixed);
            assert_eq!(display_host(&ascii), ascii, "{mixed}");
            assert!(ascii.contains("xn--"));
        }
        // All Cyrillic, but every letter looks Latin, under `.com`: ASCII.
        let apple = host("\u{430}\u{440}\u{440}\u{4cf}\u{435}.com");
        assert_eq!(display_host(&apple), apple);
        // All Cyrillic letters that don't read as Latin: shown.
        assert_eq!(display_host(&host("москва.com")), "москва.com");
    }

    #[test]
    fn skeletons_and_edits() {
        assert_eq!(skeleton("P\u{430}yPa1"), "paypal");
        assert_eq!(skeleton("rnicrosoft"), "microsoft");
        assert_eq!(skeleton("bücher"), "bucher");
        assert_eq!(edits("google", "google"), 0);
        assert_eq!(edits("google", "gogle"), 1);
        assert_eq!(edits("google", "googel"), 1);
        assert_eq!(edits("google", "goggle"), 1);
        assert_eq!(edits("github", "gitlab"), 2);
        assert_eq!(edits("", "abc"), 3);
        assert_eq!(edits("com", "co"), 1);
    }
}
