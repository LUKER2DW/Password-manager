//! The JSON messages between the extension and the desktop app.
//!
//! Every message is one JSON object with a `type`. The extension sends a [`Request`] and gets
//! exactly one [`Response`].

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// What the extension may ask.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Is the app there, and is the vault open?
    Status {},
    /// Which logins are saved for the page at `url`? Answered without passwords.
    Logins { url: String },
    /// The username and password of login `id`, to fill the page at `url`. Refused unless
    /// the login is saved for that page's origin. `check` is the item lock's PIN or password,
    /// typed in the extension's window, when the login is locked.
    Fill {
        url: String,
        id: String,
        #[serde(default)]
        check: Option<Secret>,
        /// Ask the app to open a locked login with the device's user verification (Windows
        /// Hello): the system's own prompt appears, nothing is typed in the browser.
        #[serde(default)]
        hello: bool,
    },
}

/// Something typed that must not linger: wiped when dropped, never printed.
#[derive(Clone, PartialEq, Eq, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// What opens the logins behind the item lock, as far as the extension is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    /// A PIN, which may be typed in the extension's window.
    Pin,
    /// The item lock's own password, which may be typed there too.
    Password,
    /// The master password: only ever typed in the app.
    App,
}

/// What the app answers.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Status {
        locked: bool,
        /// The vault's name, when it has one and is open.
        name: String,
    },
    Logins {
        /// The origin the logins belong to; the extension shows it.
        origin: String,
        /// What opens the entries marked `locked`.
        check: Check,
        /// Windows Hello can open them too (asked by the app, with the system's prompt).
        hello: bool,
        items: Vec<LoginEntry>,
    },
    Fill(Credentials),
    /// The app is asking the person whether to connect this extension. `key` is the shared
    /// key (hex), useless until the person allows it in the app; `code` is shown by both.
    Pairing {
        key: String,
        code: String,
    },
    Error {
        code: ErrorCode,
        /// With `item_locked`: what opens it.
        #[serde(skip_serializing_if = "Option::is_none")]
        check: Option<Check>,
        /// With `wrong_check`: tries left before the whole vault locks.
        #[serde(skip_serializing_if = "Option::is_none")]
        left: Option<u32>,
    },
}

/// One login offered for a page: who it is, never its password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LoginEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    /// Behind the item lock: its PIN or password is asked before it is filled.
    pub locked: bool,
}

/// What is typed into the page. Wiped from memory when dropped.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct Credentials {
    /// The origin the page must still have when the fields are filled.
    #[zeroize(skip)]
    pub origin: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The app is not running, or its browser link is off (made by the native host).
    NotRunning,
    /// The vault is locked.
    Locked,
    /// The page has no HTTPS.
    InsecurePage,
    /// The page is not a website (a browser page, a file).
    NotAWebsite,
    /// The login is not saved for this page's origin, or no longer exists.
    NoMatch,
    /// The login is behind the item lock.
    ItemLocked,
    /// The PIN or password typed for the item lock was wrong.
    WrongCheck,
    /// The request did not come from the extension connected to this app.
    NotPaired,
    /// The message was not understood.
    BadRequest,
}
