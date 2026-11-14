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
    /// Every login in the vault, for the extension's own window: who and where, never a
    /// password.
    Vault {},
    /// The password of login `id`, to show in the extension's window (never in a page).
    Reveal {
        id: String,
        #[serde(default)]
        check: Option<Secret>,
        #[serde(default)]
        hello: bool,
    },
    /// Asks the app to copy something of login `id` to the clipboard. The app copies it
    /// itself (kept out of clipboard history, cleared after a while): a password or code
    /// copied this way never reaches the browser.
    Copy {
        id: String,
        what: CopyWhat,
        #[serde(default)]
        check: Option<Secret>,
        #[serde(default)]
        hello: bool,
    },
    /// A new password made by the app's generator. `url` is the page it is for, kept with
    /// it in the app's history once used. Nothing is kept until [`Request::Keep`].
    Generate {
        #[serde(default)]
        length: Option<u32>,
        #[serde(default = "yes")]
        lower: bool,
        #[serde(default = "yes")]
        upper: bool,
        #[serde(default = "yes")]
        digits: bool,
        #[serde(default)]
        symbols: Symbols,
        /// Leave out characters people misread (I l 1 O 0 o |).
        #[serde(default)]
        avoid_ambiguous: bool,
        /// A passphrase of this many words instead of characters.
        #[serde(default)]
        words: Option<u32>,
        /// Between the words of a passphrase (at most 3 characters).
        #[serde(default)]
        separator: Option<String>,
        /// Passphrase words with a capital first letter.
        #[serde(default)]
        capitalize: bool,
        /// A digit added to one word of a passphrase.
        #[serde(default)]
        number: bool,
        #[serde(default)]
        url: Option<String>,
    },
    /// The person used generated password `id`: the app adds it to its history of generated
    /// passwords and, with `copy`, copies it (the app does, as with any secret).
    Keep {
        id: String,
        #[serde(default)]
        copy: bool,
    },
    /// Saves a login typed into the page at `url` (or made in the extension's window for the
    /// site `url`) as a new item. With an item lock that
    /// covers new items, it is asked for first (`check` or `hello`), as for a fill.
    Save {
        url: String,
        /// The item's name; the site's host when left out.
        #[serde(default)]
        title: Option<String>,
        username: String,
        password: Secret,
        #[serde(default)]
        check: Option<Secret>,
        #[serde(default)]
        hello: bool,
    },
}

/// Which symbols a generated password may use.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Symbols {
    /// The usual set, or none.
    Any(bool),
    /// Only these (the ones a site says it accepts).
    Only(String),
}

impl Default for Symbols {
    fn default() -> Self {
        Self::Any(true)
    }
}

fn yes() -> bool {
    true
}

/// What [`Request::Copy`] copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyWhat {
    Username,
    Password,
    /// The current one-time code.
    Code,
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
    Vault {
        check: Check,
        hello: bool,
        items: Vec<VaultEntry>,
    },
    Reveal(Revealed),
    /// The app copied it; the clipboard is cleared after `seconds` (0: not cleared, it was
    /// not a secret).
    Copied {
        seconds: u32,
    },
    Generated(GeneratedPassword),
    /// Generated password kept in the history.
    Kept {},
    /// The login was saved; `existing` when one with that username was already there.
    /// `queued`: the vault is locked, so the login waits (sealed) and joins the vault at the
    /// next unlock.
    Saved {
        existing: bool,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        queued: bool,
    },
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

/// One login in the extension's view of the vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    /// The first website saved in it, as written.
    pub site: String,
    pub locked: bool,
    pub has_password: bool,
    pub has_code: bool,
}

/// A generated password, with the id that keeps it (see [`Request::Keep`]). Wiped from
/// memory when dropped.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct GeneratedPassword {
    #[zeroize(skip)]
    pub id: String,
    pub password: String,
    /// Strength estimate: length × log2(alphabet).
    #[zeroize(skip)]
    pub bits: u32,
}

impl std::fmt::Debug for GeneratedPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GeneratedPassword(<redacted>)")
    }
}

/// A password on its way to the extension's window. Wiped from memory when dropped.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct Revealed {
    pub password: String,
}

impl std::fmt::Debug for Revealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Revealed(<redacted>)")
    }
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
