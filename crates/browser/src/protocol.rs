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
    /// the login is saved for that page's origin.
    Fill { url: String, id: String },
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
        items: Vec<LoginEntry>,
    },
    Fill(Credentials),
    Error {
        code: ErrorCode,
    },
}

/// One login offered for a page: who it is, never its password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LoginEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    /// Behind the item lock: it must be opened in the app before it can be filled.
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
    /// The message was not understood.
    BadRequest,
}
