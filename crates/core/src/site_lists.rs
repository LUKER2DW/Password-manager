//! Which sites offer two-step sign-in with one-time codes, and which take passkeys: two lists
//! bundled with the app (`data/sites-totp.txt`, `data/sites-passkeys.txt`, from 2FA Directory
//! and Passkeys Directory by 2factorauth; `data/README.md`), compared with a login's websites
//! by Password health. Nothing is fetched: the lists are refreshed by hand with
//! `tools/site-lists/update.ps1`.

use std::{collections::HashMap, sync::OnceLock};

const TOTP: &str = include_str!("../data/sites-totp.txt");
const PASSKEYS: &str = include_str!("../data/sites-passkeys.txt");

/// What a site's entry says it offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offer {
    /// Two-step sign-in with one-time codes from an authenticator.
    OneTimeCodes,
    /// Passkeys, to sign in or as the second step.
    Passkeys,
}

fn list(offer: Offer) -> &'static HashMap<&'static str, &'static str> {
    static CODES: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    static KEYS: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    let (cell, text) = match offer {
        Offer::OneTimeCodes => (&CODES, TOTP),
        Offer::Passkeys => (&KEYS, PASSKEYS),
    };
    cell.get_or_init(|| {
        text.lines()
            .filter_map(|line| {
                let (domain, page) = line.split_once('\t').unwrap_or((line, ""));
                let page = if page.starts_with("https://") {
                    page
                } else {
                    ""
                };
                (!domain.is_empty()).then_some((domain, page))
            })
            .collect()
    })
}

/// The host of a website as saved (`https://www.example.com:8443/path` gives
/// `www.example.com`), in lowercase; `None` when there is none.
pub fn host_of(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = host
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.');
    (host.contains('.') && !host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Whether the site at `url` offers `offer`: its host, or a domain the host is under, is in the
/// list. Gives the page that says how to turn it on ("" when the list has none).
pub fn offered(offer: Offer, url: &str) -> Option<&'static str> {
    let host = host_of(url)?;
    let list = list(offer);
    let mut name = host.as_str();
    loop {
        if let Some(page) = list.get(name) {
            return Some(page);
        }
        name = name.split_once('.')?.1;
        if !name.contains('.') {
            return None;
        }
    }
}

/// Whether `url` is a website saved without HTTPS (`http://`), other than this computer's own
/// (`localhost`, `127.0.0.1`, `[::1]`): what is typed there travels in clear.
pub fn without_https(url: &str) -> bool {
    let url = url.trim();
    let Some(rest) = url
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .map(|_| &url[7..])
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if host.starts_with('[') {
        host.split(']').next().map_or(host, |h| &host[..=h.len()])
    } else {
        host.split(':').next().unwrap_or_default()
    };
    let host = host.to_ascii_lowercase();
    !(host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lists_are_read_whole() {
        for offer in [Offer::OneTimeCodes, Offer::Passkeys] {
            let list = list(offer);
            assert!(list.len() > 100, "{offer:?}: {}", list.len());
            for (domain, page) in list {
                assert!(
                    domain.contains('.')
                        && domain.bytes().all(|b| b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || b == b'.'
                            || b == b'-'),
                    "{domain}"
                );
                assert!(page.is_empty() || page.starts_with("https://"), "{page}");
            }
        }
    }

    #[test]
    fn a_site_is_found_by_its_host_or_a_domain_above_it() {
        // The list's first entries, whatever they are, are found through a website.
        let (domain, page) = TOTP.lines().next().unwrap().split_once('\t').unwrap();
        let url = format!("https://login.{domain}:8443/path?q=1");
        assert_eq!(offered(Offer::OneTimeCodes, &url), Some(page));
        assert_eq!(
            offered(Offer::OneTimeCodes, &format!("{domain}/x")),
            Some(page)
        );
        assert_eq!(
            offered(Offer::OneTimeCodes, "https://not-a-listed-site.invalid"),
            None
        );
        assert_eq!(offered(Offer::Passkeys, ""), None);
        assert_eq!(offered(Offer::Passkeys, "https://com"), None);
    }

    #[test]
    fn hosts_and_plain_http() {
        assert_eq!(
            host_of("https://user@Www.Example.COM:443/a").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(host_of("example.org").as_deref(), Some("example.org"));
        assert_eq!(host_of("not a site"), None);
        assert!(without_https("http://example.com/login"));
        assert!(without_https("HTTP://router.example:8080"));
        assert!(!without_https("https://example.com"));
        assert!(!without_https("http://localhost:3000"));
        assert!(!without_https("http://127.0.0.1/admin"));
        assert!(!without_https("http://[::1]:8080/"));
        assert!(!without_https("example.com"));
    }
}
