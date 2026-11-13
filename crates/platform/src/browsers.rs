//! Which web browsers are installed, and opening a browser's own passwords page so the user can
//! export a CSV from there.
//!
//! This only looks for the browser's program file. It never opens a browser profile or reads
//! the passwords a browser stores: an export the user makes by hand is the only way in (reading
//! browser stores directly is what infostealers do, and Chrome now blocks it anyway).

use std::path::{Path, PathBuf};

/// A browser the import page knows about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Edge,
    Firefox,
    Brave,
    Opera,
    OperaGx,
    Vivaldi,
}

impl Browser {
    pub const ALL: [Browser; 7] = [
        Browser::Chrome,
        Browser::Edge,
        Browser::Firefox,
        Browser::Brave,
        Browser::Opera,
        Browser::OperaGx,
        Browser::Vivaldi,
    ];

    /// The page where the browser lists saved passwords (and offers "Export").
    pub fn passwords_page(self) -> &'static str {
        match self {
            Browser::Chrome | Browser::Brave | Browser::Vivaldi => {
                "chrome://password-manager/settings"
            }
            Browser::Edge => "edge://settings/passwords",
            Browser::Firefox => "about:logins",
            Browser::Opera | Browser::OperaGx => "opera://settings/passwords",
        }
    }

    /// Program file locations, relative to an environment folder.
    fn candidates(self) -> &'static [(&'static str, &'static str)] {
        const PF: &str = "ProgramFiles";
        const PF86: &str = "ProgramFiles(x86)";
        const LOCAL: &str = "LOCALAPPDATA";
        match self {
            Browser::Chrome => &[
                (PF, r"Google\Chrome\Application\chrome.exe"),
                (PF86, r"Google\Chrome\Application\chrome.exe"),
                (LOCAL, r"Google\Chrome\Application\chrome.exe"),
            ],
            Browser::Edge => &[
                (PF86, r"Microsoft\Edge\Application\msedge.exe"),
                (PF, r"Microsoft\Edge\Application\msedge.exe"),
            ],
            Browser::Firefox => &[
                (PF, r"Mozilla Firefox\firefox.exe"),
                (PF86, r"Mozilla Firefox\firefox.exe"),
                (LOCAL, r"Mozilla Firefox\firefox.exe"),
            ],
            Browser::Brave => &[
                (PF, r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                (PF86, r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                (LOCAL, r"BraveSoftware\Brave-Browser\Application\brave.exe"),
            ],
            Browser::Opera => &[
                (LOCAL, r"Programs\Opera\opera.exe"),
                (PF, r"Opera\opera.exe"),
            ],
            Browser::OperaGx => &[(LOCAL, r"Programs\Opera GX\opera.exe")],
            Browser::Vivaldi => &[
                (LOCAL, r"Vivaldi\Application\vivaldi.exe"),
                (PF, r"Vivaldi\Application\vivaldi.exe"),
            ],
        }
    }

    /// The browser's program, when it is installed in a usual place.
    pub fn program(self) -> Option<PathBuf> {
        if !cfg!(windows) {
            return None;
        }
        self.candidates().iter().find_map(|(var, relative)| {
            let base = std::env::var_os(var)?;
            let path = Path::new(&base).join(relative);
            path.is_file().then_some(path)
        })
    }

    /// Starts the browser on its passwords page.
    pub fn open_passwords_page(self) -> anyhow::Result<()> {
        let program = self
            .program()
            .ok_or_else(|| anyhow::anyhow!("browser not found"))?;
        std::process::Command::new(program)
            .arg(self.passwords_page())
            .spawn()?;
        Ok(())
    }
}

/// A saved website tidied into a link that is safe to hand to the shell: `https://` added when
/// no scheme is given, only `http` and `https` accepted, and no spaces, control characters or
/// quotes (which could otherwise turn into extra command-line arguments). `None` otherwise.
pub fn web_link(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty()
        || text.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '"' | '<' | '>' | '\\' | '^' | '`')
        })
    {
        return None;
    }
    let link = match text.split_once("://") {
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http") =>
        {
            if rest.is_empty() {
                return None;
            }
            text.to_owned()
        }
        Some(_) => return None,
        None => {
            // "mailto:x", "ms-settings:y", "javascript:z": a scheme without slashes is not a
            // website. "host:port" is (the part before ':' then looks like a host).
            if let Some((before, _)) = text.split_once(':') {
                let looks_like_host = before.contains('.') || before == "localhost";
                if !looks_like_host || before.contains('/') {
                    return None;
                }
            }
            format!("https://{text}")
        }
    };
    let host = link
        .split_once("://")?
        .1
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?;
    (!host.is_empty() && !host.starts_with(':')).then_some(link)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_links_are_tidied_and_limited_to_http() {
        assert_eq!(
            web_link("github.com").as_deref(),
            Some("https://github.com")
        );
        assert_eq!(
            web_link(" https://bank.example/login?x=1 ").as_deref(),
            Some("https://bank.example/login?x=1")
        );
        assert_eq!(
            web_link("http://intranet.example:8080").as_deref(),
            Some("http://intranet.example:8080")
        );
        assert_eq!(
            web_link("localhost:3000").as_deref(),
            Some("https://localhost:3000")
        );
        for bad in [
            "",
            "file:///C:/Windows/system32/calc.exe",
            "javascript:alert(1)",
            "mailto:me@example.com",
            "ms-settings:privacy",
            "android://hash@com.example.app/",
            "https://",
            "https://exa mple.com",
            "https://example.com\" --flag\"",
            r"C:\Windows\notepad.exe",
        ] {
            assert_eq!(web_link(bad), None, "{bad}");
        }
    }

    #[test]
    fn every_browser_has_a_page_and_locations() {
        for browser in Browser::ALL {
            assert!(!browser.passwords_page().is_empty());
            assert!(!browser.candidates().is_empty());
            // Looking never fails, installed or not.
            let _ = browser.program();
        }
    }
}
