//! Which saved website belongs to which page.
//!
//! The rule is the browser's own same-origin rule: scheme, host and port must all be equal.
//! `accounts.example.com` is not `example.com`, and a look-alike host is simply another host.
//! Pages without HTTPS are never filled: on them anyone on the network can read what is typed.
//!
//! A login can be used on more sites only by the person's choice: every website saved in the
//! item counts, and one written as `*.example.com` stands for `example.com` and every site
//! under it (default port only).
//!
//! Addresses are parsed with the WHATWG URL rules browsers use, so tricks such as
//! `https://good.example@evil.example/` or mixed-script hosts resolve here exactly as they do
//! in the address bar (international names compare in their punycode form).

use url::Url;

/// Why a page gets no logins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageProblem {
    /// Not an address a login can belong to (a browser page, a file, nonsense).
    NotAWebsite,
    /// A website without HTTPS.
    Insecure,
}

/// The origin of a page: `https://host` or `https://host:port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    text: String,
    host: String,
    default_port: bool,
}

impl Origin {
    /// The origin of the page at `url` (the tab's full address, as the browser reports it).
    pub fn of_page(url: &str) -> Result<Self, PageProblem> {
        let url = Url::parse(url).map_err(|_| PageProblem::NotAWebsite)?;
        match url.scheme() {
            "https" => {}
            "http" => return Err(PageProblem::Insecure),
            _ => return Err(PageProblem::NotAWebsite),
        }
        Self::of_https(&url).ok_or(PageProblem::NotAWebsite)
    }

    /// The host alone, as the browser writes it.
    pub fn host(&self) -> &str {
        &self.host
    }

    fn of_https(url: &Url) -> Option<Self> {
        let host = url.host_str().filter(|host| !host.is_empty())?;
        Some(Self {
            text: url.origin().ascii_serialization(),
            host: host.to_owned(),
            default_port: url.port().is_none(),
        })
    }

    /// The origin a saved website stands for. People save `example.com`, `http://example.com`
    /// or a full sign-in address: a missing scheme means HTTPS, and plain `http` (on its
    /// default port) is read as the HTTPS site of the same host, since only that is filled.
    pub fn of_saved(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let with_scheme = if text.contains("://") {
            text.to_owned()
        } else {
            format!("https://{text}")
        };
        let mut url = Url::parse(&with_scheme).ok()?;
        if url.scheme() == "http" && url.port().is_none() {
            url.set_scheme("https").ok()?;
        }
        if url.scheme() != "https" {
            return None;
        }
        Self::of_https(&url)
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// The site a `*.example.com` entry is about (`example.com`, as the browser writes it), or
/// `None` when the text is not such an entry. The part after `*.` must be a name with at
/// least one dot (not `*.com`, not an IP address) that is not a public suffix (not
/// `*.co.uk`), on HTTPS and its default port.
pub fn wildcard_base(saved: &str) -> Option<String> {
    let text = saved.trim();
    let rest = text.strip_prefix("https://").unwrap_or(text);
    let name = rest.strip_prefix("*.")?;
    // Only the name: no path, port, user or further wildcard may hide in it.
    let name = name.strip_suffix('/').unwrap_or(name);
    if name.is_empty() || name.contains(['/', ':', '@', '*', '?', '#', ' ']) {
        return None;
    }
    let url = Url::parse(&format!("https://{name}")).ok()?;
    match url.host()? {
        url::Host::Domain(domain)
            if domain.contains('.') && !domain.ends_with('.') && !is_public_suffix(domain) =>
        {
            Some(domain.to_owned())
        }
        _ => None,
    }
}

/// Whether anyone can register a name right under `domain` (`co.uk`, `github.io`): a `*.`
/// entry over it would hand a login to sites of other people.
fn is_public_suffix(domain: &str) -> bool {
    psl::suffix(domain.as_bytes()).is_some_and(|suffix| suffix.as_bytes() == domain.as_bytes())
}

/// Whether one saved website covers the page: its exact origin, or by `*.` its site and
/// everything under it.
pub fn saved_matches(saved: &str, page: &Origin) -> bool {
    if let Some(base) = wildcard_base(saved) {
        return page.default_port
            && (page.host == base
                || page
                    .host
                    .strip_suffix(&base)
                    .is_some_and(|sub| sub.ends_with('.')));
    }
    Origin::of_saved(saved).as_ref() == Some(page)
}

/// Whether any of an item's saved websites covers the page.
pub fn item_matches<S: AsRef<str>>(saved: &[S], page: &Origin) -> bool {
    saved.iter().any(|url| saved_matches(url.as_ref(), page))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(url: &str) -> Origin {
        Origin::of_page(url).unwrap()
    }

    #[test]
    fn pages_have_an_origin_only_over_https() {
        assert_eq!(
            page("https://github.com/login?next=/").as_str(),
            "https://github.com"
        );
        assert_eq!(
            page("https://GitHub.com:443/").as_str(),
            "https://github.com"
        );
        assert_eq!(
            page("https://app.example:8443/x").as_str(),
            "https://app.example:8443"
        );
        assert_eq!(
            Origin::of_page("http://github.com/login"),
            Err(PageProblem::Insecure)
        );
        for other in [
            "chrome://extensions",
            "file:///C:/page.html",
            "about:blank",
            "data:text/html,<input type=password>",
            "javascript:alert(1)",
            "",
            "github.com",
        ] {
            assert_eq!(
                Origin::of_page(other),
                Err(PageProblem::NotAWebsite),
                "{other}"
            );
        }
    }

    #[test]
    fn saved_websites_match_their_exact_origin_only() {
        let github = page("https://github.com/login");
        for saved in [
            "https://github.com",
            "https://github.com/session",
            "github.com",
            "  GitHub.com/login ",
            "http://github.com",
            "https://github.com:443",
        ] {
            assert!(item_matches(&[saved], &github), "{saved}");
        }
        for other in [
            "https://gist.github.com",
            "https://www.github.com",
            "https://github.com.evil.example",
            "https://evil.example/github.com",
            "https://github.com@evil.example",
            "https://github.com:8443",
            "http://github.com:8080",
            "https://githab.com",
            "ftp://github.com",
            "",
            "not a url at all",
        ] {
            assert!(!item_matches(&[other], &github), "{other}");
        }
        // Any one of an item's websites is enough.
        assert!(item_matches(
            &["https://other.example", "https://github.com"],
            &github
        ));
        assert!(!item_matches::<&str>(&[], &github));
    }

    #[test]
    fn a_star_entry_covers_the_site_and_what_is_under_it_and_nothing_else() {
        let saved = ["*.example.com"];
        for url in [
            "https://example.com/",
            "https://accounts.example.com/login",
            "https://a.b.example.com/",
            "https://ACCOUNTS.Example.com/",
        ] {
            assert!(item_matches(&saved, &page(url)), "{url}");
        }
        for url in [
            "https://badexample.com/",
            "https://example.com.evil.example/",
            "https://example.org/",
            "https://accounts.example.com:8443/",
            "https://example.com@evil.example/",
        ] {
            assert!(!item_matches(&saved, &page(url)), "{url}");
        }
        assert!(item_matches(
            &["https://*.example.com/"],
            &page("https://x.example.com/")
        ));
        // Too wide, or not a plain name: such entries match nothing at all.
        let anywhere = page("https://accounts.example.com/");
        for bad in [
            "*.com",
            "*.co.uk",
            "*.com.br",
            "*.github.io",
            "*.",
            "*",
            "*.*.example.com",
            "*.example.com:8443",
            "*.example.com/path",
            "*.example.com@evil.example",
            "*.192.168.0.1",
            "http://*.example.com",
            "a.*.example.com",
            "*.example.com.",
        ] {
            assert_eq!(wildcard_base(bad), None, "{bad}");
            assert!(!item_matches(&[bad], &anywhere), "{bad}");
        }
        assert_eq!(
            wildcard_base(" *.Example.COM ").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn address_tricks_resolve_like_in_the_address_bar() {
        // What looks like the host before an @ is only a user name.
        assert_eq!(
            page("https://github.com@evil.example/login").as_str(),
            "https://evil.example"
        );
        assert_eq!(
            page("https://github.com%2f@evil.example/").as_str(),
            "https://evil.example"
        );
        // A Cyrillic look-alike is another host (compared as punycode).
        let fake = page("https://g\u{0456}thub.com/");
        assert!(fake.as_str().starts_with("https://xn--"));
        assert!(!item_matches(&["https://github.com"], &fake));
        assert!(item_matches(&["https://g\u{0456}thub.com"], &fake));
        // Ports matter, and a non-default one never matches the plain site.
        assert!(!item_matches(
            &["https://github.com"],
            &page("https://github.com:444/")
        ));
        // A trailing dot is another name to the browser, so it is to us.
        assert!(!item_matches(
            &["https://github.com"],
            &page("https://github.com./")
        ));
    }
}
