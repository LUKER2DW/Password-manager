//! Which web browsers are installed, which one opens web links (the default browser), and
//! starting a browser on one of its own pages: its passwords page, so the user can export a CSV
//! from there, or its extensions page, to add the extension (Settings → Browser extension).
//!
//! This only looks for the browser's program file and the user's choice of browser. It never
//! opens a browser profile or reads the passwords a browser stores: an export the user makes by
//! hand is the only way in (reading browser stores directly is what infostealers do, and Chrome
//! now blocks it anyway).

use std::path::{Path, PathBuf};

/// A browser the import page and the extension's settings know about.
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

    /// The browser's name, as it calls itself.
    pub fn name(self) -> &'static str {
        match self {
            Browser::Chrome => "Chrome",
            Browser::Edge => "Edge",
            Browser::Firefox => "Firefox",
            Browser::Brave => "Brave",
            Browser::Opera => "Opera",
            Browser::OperaGx => "Opera GX",
            Browser::Vivaldi => "Vivaldi",
        }
    }

    /// Whether it is Firefox (the others are built on Chromium and load an extension the same
    /// way).
    pub fn is_firefox(self) -> bool {
        self == Browser::Firefox
    }

    /// The page where an extension is loaded from a folder: Chromium's extensions page (with
    /// Developer mode and "Load unpacked"), or Firefox's "This Firefox" page of about:debugging
    /// ("Load Temporary Add-on…").
    pub fn extensions_page(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome://extensions",
            Browser::Edge => "edge://extensions",
            Browser::Firefox => "about:debugging#/runtime/this-firefox",
            Browser::Brave => "brave://extensions",
            Browser::Opera | Browser::OperaGx => "opera://extensions",
            Browser::Vivaldi => "vivaldi://extensions",
        }
    }

    /// The browser that the person's choice of program for web links (a `ProgId`, see
    /// [`default_browser`]) names, when it is one of these.
    pub fn from_prog_id(prog_id: &str) -> Option<Browser> {
        let id = prog_id.trim();
        let starts = |prefix: &str| {
            id.get(..prefix.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
        };
        // As each browser registers itself: Firefox and Vivaldi add a suffix per install.
        if id.eq_ignore_ascii_case("ChromeHTML") {
            Some(Browser::Chrome)
        } else if id.eq_ignore_ascii_case("MSEdgeHTM") {
            Some(Browser::Edge)
        } else if starts("FirefoxURL") {
            Some(Browser::Firefox)
        } else if id.eq_ignore_ascii_case("BraveHTML") {
            Some(Browser::Brave)
        } else if id.eq_ignore_ascii_case("Opera GXStable") {
            Some(Browser::OperaGx)
        } else if id.eq_ignore_ascii_case("OperaStable") {
            Some(Browser::Opera)
        } else if starts("VivaldiHTM") {
            Some(Browser::Vivaldi)
        } else {
            None
        }
    }

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
        self.open(self.passwords_page())
    }

    /// Starts the browser on its extensions page ([`Browser::extensions_page`]).
    pub fn open_extensions_page(self) -> anyhow::Result<()> {
        self.open(self.extensions_page())
    }

    /// Starts the browser's own program with one of its pages (one of the fixed ones above,
    /// never an address from elsewhere).
    fn open(self, page: &'static str) -> anyhow::Result<()> {
        let program = self
            .program()
            .ok_or_else(|| anyhow::anyhow!("browser not found"))?;
        std::process::Command::new(program).arg(page).spawn()?;
        Ok(())
    }
}

/// The installed browsers with the default one first, and which one that is (best effort:
/// when Windows' choice for web links can't be read, or is another program, they come in
/// [`Browser::ALL`]'s order and there is none).
pub fn installed() -> (Vec<Browser>, Option<Browser>) {
    let mut found: Vec<Browser> = Browser::ALL
        .into_iter()
        .filter(|browser| browser.program().is_some())
        .collect();
    let default = default_browser().filter(|browser| found.contains(browser));
    if let Some(default) = default {
        found.retain(|&browser| browser != default);
        found.insert(0, default);
    }
    (found, default)
}

/// The browser that opens `https` links for this user: the `ProgId` of Windows' choice (newer
/// Windows keeps it under `UserChoiceLatest`, older under `UserChoice`). `None` when it can't be
/// read or names another program.
pub fn default_browser() -> Option<Browser> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Registry::HKEY_CURRENT_USER;
        const CHOICE: &str = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https";
        ["UserChoiceLatest", "UserChoice"]
            .into_iter()
            .find_map(|key| {
                crate::registry::read_text(
                    HKEY_CURRENT_USER,
                    &format!(r"{CHOICE}\{key}"),
                    Some("ProgId"),
                )
            })
            .and_then(|prog_id| Browser::from_prog_id(&prog_id))
    }
    #[cfg(not(windows))]
    {
        None
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
    fn the_default_browser_is_named_by_its_prog_id() {
        assert_eq!(Browser::from_prog_id("ChromeHTML"), Some(Browser::Chrome));
        assert_eq!(Browser::from_prog_id("MSEdgeHTM"), Some(Browser::Edge));
        assert_eq!(
            Browser::from_prog_id("FirefoxURL-308046B0AF4A39CB"),
            Some(Browser::Firefox)
        );
        assert_eq!(Browser::from_prog_id("BraveHTML"), Some(Browser::Brave));
        assert_eq!(Browser::from_prog_id("OperaStable"), Some(Browser::Opera));
        assert_eq!(
            Browser::from_prog_id("Opera GXStable"),
            Some(Browser::OperaGx)
        );
        assert_eq!(
            Browser::from_prog_id("VivaldiHTM.ABCDEF"),
            Some(Browser::Vivaldi)
        );
        for other in [
            "",
            "IE.HTTPS",
            "AppXq0fevzme2pys62n3e0fbqa7peapykr8v",
            "Chrome",
        ] {
            assert_eq!(Browser::from_prog_id(other), None, "{other}");
        }
        // Looking never fails, set or not; the default one comes first.
        let (found, default) = installed();
        if let Some(default) = default {
            assert_eq!(found.first(), Some(&default));
        }
    }

    #[test]
    fn every_browser_has_a_page_and_locations() {
        for browser in Browser::ALL {
            assert!(!browser.name().is_empty());
            let page = browser.extensions_page();
            assert!(page.ends_with("://extensions") || page.starts_with("about:debugging#"));
            assert!(!browser.passwords_page().is_empty());
            assert!(!browser.candidates().is_empty());
            // Looking never fails, installed or not.
            let _ = browser.program();
        }
    }
}
