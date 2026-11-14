//! Which saved website belongs to which page.
//!
//! The rule is the browser's own same-origin rule: scheme, host and port must all be equal.
//! `accounts.example.com` is not `example.com`, and a look-alike host is simply another host.
//! Pages without HTTPS are never filled: on them anyone on the network can read what is typed.
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

/// The origin of a page, as text: `https://host` or `https://host:port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin(String);

impl Origin {
    /// The origin of the page at `url` (the tab's full address, as the browser reports it).
    pub fn of_page(url: &str) -> Result<Self, PageProblem> {
        let url = Url::parse(url).map_err(|_| PageProblem::NotAWebsite)?;
        match url.scheme() {
            "https" => {}
            "http" => return Err(PageProblem::Insecure),
            _ => return Err(PageProblem::NotAWebsite),
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(PageProblem::NotAWebsite);
        }
        Ok(Self(url.origin().ascii_serialization()))
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
        if url.scheme() != "https" || url.host_str().is_none_or(str::is_empty) {
            return None;
        }
        Some(Self(url.origin().ascii_serialization()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether any of an item's saved websites is the page's origin.
pub fn item_matches<S: AsRef<str>>(saved: &[S], page: &Origin) -> bool {
    saved
        .iter()
        .any(|url| Origin::of_saved(url.as_ref()).as_ref() == Some(page))
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
