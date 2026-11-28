//! Help changing a password (F19): where a site changes its password, and what it accepts in
//! one.
//!
//! - Every site may answer `/.well-known/change-password` (W3C's "A Well-Known URL for
//!   Changing Passwords"), sending the person to its own page for it: the default.
//! - Sites that don't, and sites whose password rules are stricter than their fields say, are
//!   listed by the `password-manager-resources` project (MIT, notice in
//!   `data/password-manager-resources/LICENSE.md`): a copy pinned in the repository at the
//!   commit named in its README, compiled in. Nothing is fetched at run time; the copy is
//!   brought up to date by hand, in a commit of its own.

use std::{collections::BTreeMap, sync::OnceLock};

const CHANGE_URLS: &str =
    include_str!("../data/password-manager-resources/change-password-URLs.json");
const PASSWORD_RULES: &str = include_str!("../data/password-manager-resources/password-rules.json");

fn change_urls() -> &'static BTreeMap<String, String> {
    static LIST: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    LIST.get_or_init(|| serde_json::from_str(CHANGE_URLS).unwrap_or_default())
}

fn password_rules() -> &'static BTreeMap<String, String> {
    static LIST: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    LIST.get_or_init(|| {
        #[derive(serde::Deserialize)]
        struct Quirk {
            #[serde(rename = "password-rules")]
            rules: String,
        }
        serde_json::from_str::<BTreeMap<String, Quirk>>(PASSWORD_RULES)
            .map(|list| {
                list.into_iter()
                    .map(|(domain, quirk)| (domain, quirk.rules))
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// The host of a saved website or page (`https://www.example.com/x` → `www.example.com`),
/// lowercase, https or http only. `None` for anything else.
fn host_of(site: &str) -> Option<(String, Option<u16>)> {
    let site = site.trim();
    let with_scheme = if site.contains("://") {
        site.to_owned()
    } else {
        format!("https://{site}")
    };
    let url = url::Url::parse(&with_scheme).ok()?;
    if !matches!(url.scheme(), "https" | "http") {
        return None;
    }
    let host = url.host_str()?.trim_start_matches("*.").to_lowercase();
    (!host.is_empty()).then(|| (host, url.port()))
}

/// The entry of `list` for `host`: its own, or that of the nearest domain above it
/// (`accounts.example.com` takes `example.com`'s), never a public suffix's.
fn listed<'a>(list: &'a BTreeMap<String, String>, host: &str) -> Option<&'a str> {
    let mut name = host;
    loop {
        if let Some(found) = list.get(name) {
            return Some(found);
        }
        let (_, rest) = name.split_once('.')?;
        if !rest.contains('.') {
            // Only a top-level domain is left: never matched.
            return None;
        }
        name = rest;
    }
}

/// Where the person changes their password for the site `site` (a saved website): the page
/// the list names for it, else the site's `/.well-known/change-password`. `None` for anything
/// that isn't a web address. Always https: a site's change of password is never sent over
/// plain http.
pub fn change_password_url(site: &str) -> Option<String> {
    let (host, port) = host_of(site)?;
    if let Some(page) = listed(change_urls(), &host).filter(|page| page.starts_with("https://")) {
        return Some(page.to_owned());
    }
    Some(match port {
        Some(port) if port != 443 && port != 80 => {
            format!("https://{host}:{port}/.well-known/change-password")
        }
        _ => format!("https://{host}/.well-known/change-password"),
    })
}

/// Whether the built-in list names the page where `site` changes its password. Otherwise
/// [`change_password_url`] is the site's `/.well-known/change-password`, which only sites that
/// support the standard send on to their page: an attempt, said as one.
pub fn change_page_listed(site: &str) -> bool {
    host_of(site).is_some_and(|(host, _)| {
        listed(change_urls(), &host).is_some_and(|page| page.starts_with("https://"))
    })
}

/// What the site `site` accepts in a password, in the `passwordrules` language
/// (`minlength: 8; required: digit;`), when the list knows more than its fields say.
pub fn password_rules_for(site: &str) -> Option<&'static str> {
    let (host, _) = host_of(site)?;
    listed(password_rules(), &host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_lists_read_whole() {
        assert!(change_urls().len() > 500, "{}", change_urls().len());
        assert!(password_rules().len() > 300, "{}", password_rules().len());
        assert!(
            change_urls()
                .values()
                .all(|page| page.starts_with("https://")),
            "every listed page is https"
        );
    }

    #[test]
    fn a_listed_site_gets_its_page_and_any_other_the_well_known_address() {
        let (domain, page) = change_urls().iter().next().unwrap();
        assert_eq!(change_password_url(domain).as_deref(), Some(page.as_str()));
        assert_eq!(
            change_password_url(&format!("https://accounts.{domain}/login")).as_deref(),
            Some(page.as_str()),
            "a host under a listed domain takes its page"
        );
        assert_eq!(
            change_password_url("https://unlisted.example.test/sign-in").as_deref(),
            Some("https://unlisted.example.test/.well-known/change-password")
        );
        assert_eq!(
            change_password_url("http://plain.example.test").as_deref(),
            Some("https://plain.example.test/.well-known/change-password"),
            "always https"
        );
        assert_eq!(
            change_password_url("https://intranet.example.test:8443/").as_deref(),
            Some("https://intranet.example.test:8443/.well-known/change-password")
        );
        assert!(change_page_listed(domain));
        assert!(!change_page_listed("https://unlisted.example.test/"));
        assert_eq!(change_password_url("not a site at all ://"), None);
        assert_eq!(change_password_url("javascript:alert(1)"), None);
    }

    #[test]
    fn password_rules_come_for_listed_sites_only() {
        let (domain, rules) = password_rules().iter().next().unwrap();
        assert_eq!(password_rules_for(domain), Some(rules.as_str()));
        assert_eq!(
            password_rules_for(&format!("https://www.{domain}/")),
            Some(rules.as_str())
        );
        assert_eq!(password_rules_for("https://unlisted.example.test/"), None);
        // A public suffix alone matches nothing, even one written as a site.
        assert_eq!(password_rules_for("https://com/"), None);
    }
}
