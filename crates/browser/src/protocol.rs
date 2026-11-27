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
    /// The current one-time code of login `id`, to type into the page at `url`. Refused
    /// unless the login is saved for that page's origin, as for [`Request::Fill`].
    Code {
        url: String,
        id: String,
        #[serde(default)]
        check: Option<Secret>,
        #[serde(default)]
        hello: bool,
    },
    /// Every login in the vault, for the extension's own window: who and where, never a
    /// password.
    Vault {},
    /// The password of login `id` (or, with `what: "code"`, its current one-time code), to
    /// show in the extension's window (never in a page).
    Reveal {
        id: String,
        #[serde(default)]
        check: Option<Secret>,
        #[serde(default)]
        hello: bool,
        #[serde(default)]
        what: Shown,
    },
    /// Lock the vault in the app now (the extension's Lock button).
    Lock {},
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
    /// Whether `password`, just sent with `username` from the page at `url`, differs from the
    /// password saved for that site and username: asked before offering to update it. A
    /// locked login is not opened for this; the answer is then "unknown".
    Changed {
        url: String,
        username: String,
        password: Secret,
    },
    /// Which passkeys the vault has for the site `rp_id` (empty: the page's host), which the
    /// page at `url` must be allowed to speak for ([`crate::origin::passkey_site`]). `allow`
    /// is the site's list of credential ids (base64url), when it gave one. Answered without
    /// any key, locked logins too.
    Passkeys {
        url: String,
        #[serde(default)]
        rp_id: String,
        #[serde(default)]
        allow: Vec<String>,
    },
    /// Signs in with passkey `credential` (base64url) of login `id` on the page at `url`: the
    /// app writes the client data itself, from the page's origin and the site's `challenge`
    /// (base64url), and signs it. A locked login is opened first, as for a fill.
    PasskeyGet {
        url: String,
        #[serde(default)]
        rp_id: String,
        id: String,
        credential: String,
        challenge: String,
        #[serde(default)]
        check: Option<Secret>,
        #[serde(default)]
        hello: bool,
        /// What the site asked about verifying the person (WebAuthn's `userVerification`).
        #[serde(default)]
        user_verification: UserVerification,
    },
    /// Makes a passkey for the site `rp_id` and the account `user_id` (base64url) named
    /// `user_name`, for the page at `url`, and keeps it in the login saved for that page with
    /// that username (a new login when there is none). Refused when a passkey in `exclude`
    /// (credential ids, base64url) is already in the vault, or when `algorithms` (COSE numbers,
    /// in the site's order; empty: any) leave out ES256.
    PasskeyCreate {
        url: String,
        #[serde(default)]
        rp_id: String,
        user_id: String,
        user_name: String,
        #[serde(default)]
        display_name: String,
        challenge: String,
        #[serde(default)]
        exclude: Vec<String>,
        #[serde(default)]
        algorithms: Vec<i64>,
        #[serde(default)]
        check: Option<Secret>,
        #[serde(default)]
        hello: bool,
        /// What the site asked about verifying the person (its `authenticatorSelection`'s
        /// `userVerification`).
        #[serde(default)]
        user_verification: UserVerification,
    },
    /// Replaces the password of login `id`, saved for `url`'s origin, with `password`. The old
    /// one goes into the item's password history. A locked login is opened first, as for a
    /// fill.
    ///
    /// `username` and `stamp` bind it to the login the person was offered to update: the
    /// username typed and the stamp the app gave in its [`Response::Changed`]. When given, a
    /// login edited since (in the app, by a sync) or with another username now is not
    /// overwritten (`changed_since`). Older extensions leave them out.
    Update {
        url: String,
        id: String,
        password: Secret,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        stamp: Option<String>,
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
/// What a [`Request::Reveal`] shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Shown {
    #[default]
    Password,
    /// The current one-time code, with the seconds it stays valid.
    Code,
}

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

/// What a site asks about verifying the person for a passkey (WebAuthn's `userVerification`).
/// The answer says "verified" only after Windows Hello or the item lock's PIN or password in
/// that very request. Missing or unknown: `Preferred`, as WebAuthn reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerification {
    /// Verify, or don't answer at all (the browser's own handler takes the request).
    Required,
    /// Don't ask: answer as not verified.
    Discouraged,
    /// Verify when there is a way to; otherwise answer as not verified. (Last: serde's
    /// `other` catches every unknown value here.)
    #[default]
    #[serde(other)]
    Preferred,
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
        /// Every password, code or passkey asks for the person first, each time (Settings →
        /// Browser extension): every entry is `locked`.
        always_asks: bool,
        items: Vec<LoginEntry>,
    },
    Fill(Credentials),
    Code(OneTimeCode),
    Vault {
        check: Check,
        hello: bool,
        always_asks: bool,
        items: Vec<VaultEntry>,
    },
    Reveal(Revealed),
    /// A login's current one-time code ([`Request::Reveal`] with `what: "code"`).
    CodeShown(ShownCode),
    /// The vault was locked ([`Request::Lock`]).
    LockedNow {},
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
    /// The answer to [`Request::Changed`]: the login it is about, and whether its password is
    /// another one (`None`: the login is locked, so the app can't tell without opening it).
    /// `stamp` names this version of the login (not secret), for [`Request::Update`].
    Changed {
        id: String,
        changed: Option<bool>,
        stamp: String,
    },
    /// The password of the login was replaced (`changed`), or was already that one.
    Updated {
        changed: bool,
    },
    /// The passkeys for a site ([`Request::Passkeys`]).
    Passkeys {
        origin: String,
        /// The site they belong to, as the app checked it.
        rp_id: String,
        check: Check,
        hello: bool,
        items: Vec<PasskeyEntry>,
    },
    /// A signature for the site ([`Request::PasskeyGet`]). (Boxed: the largest answers, kept
    /// out of the size of every other one.)
    Assertion(Box<Assertion>),
    /// A passkey made and kept ([`Request::PasskeyCreate`]).
    Attestation(Box<Attestation>),
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
    /// It has a one-time code (unknown, and so `false`, while the vault is locked).
    pub has_code: bool,
}

/// One passkey offered for a site: whose it is, never its key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PasskeyEntry {
    /// The login it is kept in.
    pub id: String,
    /// Its credential id (base64url).
    pub credential: String,
    pub title: String,
    pub user_name: String,
    pub display_name: String,
    /// Behind the item lock: its PIN or password is asked before it signs.
    pub locked: bool,
}

/// What a page hands the site when signing in with a passkey (all base64url): the
/// `AuthenticatorAssertionResponse` of WebAuthn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Assertion {
    /// The origin the page must still have when it gets this.
    pub origin: String,
    pub credential: String,
    pub client_data: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
}

/// What a page hands the site when a passkey is made (all base64url): the
/// `AuthenticatorAttestationResponse` of WebAuthn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Attestation {
    /// The origin the page must still have when it gets this.
    pub origin: String,
    pub credential: String,
    pub client_data: String,
    pub attestation_object: String,
    pub authenticator_data: String,
    /// The public key as a DER SubjectPublicKeyInfo (`getPublicKey()`).
    pub public_key: String,
    /// Its COSE algorithm (ES256, -7).
    pub algorithm: i64,
    /// A passkey kept before for the same site and account was replaced by this one: once the
    /// site has this one, the earlier one no longer signs in (as with a security key).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub replaced: bool,
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

/// A one-time code on its way to the extension's window: the code, the length of its period
/// and the seconds it stays valid (0 for a counter-based code). Wiped from memory when dropped.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct ShownCode {
    pub code: String,
    #[zeroize(skip)]
    pub period: u64,
    #[zeroize(skip)]
    pub left: u64,
}

impl std::fmt::Debug for ShownCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShownCode(<redacted>)")
    }
}

/// A one-time code on its way into the page. Wiped from memory when dropped.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct OneTimeCode {
    /// The origin the page must still have when the code is typed.
    #[zeroize(skip)]
    pub origin: String,
    pub code: String,
    /// Seconds before it changes.
    #[zeroize(skip)]
    pub seconds: u64,
}

impl std::fmt::Debug for OneTimeCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTimeCode")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
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
    /// The page may not make or use passkeys for that site (another site, a public suffix,
    /// an IP address).
    WrongSite,
    /// One of the passkeys the site listed as already made is in the vault.
    Exists,
    /// The site accepts none of the kinds of passkey the app makes (ES256).
    Unsupported,
    /// The person turned this off in the app (saving logins, or passkeys).
    TurnedOff,
    /// The change could not be written to the vault file (it was changed elsewhere, or the
    /// disk refused): nothing was kept, and it may be asked again.
    NotSaved,
    /// The login an update was offered for has been changed since (edited in the app, merged
    /// by a sync, another username): nothing was replaced.
    ChangedSince,
}
