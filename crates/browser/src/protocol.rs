//! The JSON messages between the extension and the desktop app.
//!
//! Every message is one JSON object with a `type`. The extension sends a [`Request`] and gets
//! exactly one [`Response`].
//!
//! A sealed request (`pairing.rs`) holds `{"version":"0.4.8","request":{…}}`: the request,
//! and the version of the extension that sends it (its `manifest.json`'s). The app answers
//! only an extension of [`MIN_EXTENSION_VERSION`] or later ([`asked`]); an older one hears
//! `outdated_extension` ([`outdated`]) and nothing else, so an old copy with a known fault put
//! back in the extension's place gets nothing from the vault.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use crate::lookalike::Lookalike;

/// The oldest extension the app answers. Raised when a release fixes a fault in the extension
/// that must not stay reachable.
///
/// 0.4.7 is the version the sealed link carries until the next release raises every app's
/// version: the extension of every release up to 0.4.7 signs its requests instead of sealing
/// them and names no version, and is refused whatever this says ([`asked`]). Every extension
/// that names a version seals its requests and agrees its key by ECDH.
pub const MIN_EXTENSION_VERSION: &str = "0.4.7";

/// Whether `version` (an extension's, `x.y.z`) is one the app answers.
pub fn accepted_version(version: &str) -> bool {
    match (
        vault_sync_wire::parse_version(version),
        vault_sync_wire::parse_version(MIN_EXTENSION_VERSION),
    ) {
        (Some(version), Some(minimum)) => version >= minimum,
        _ => false,
    }
}

/// The request inside the text of a sealed request (`{"version":…,"request":{…}}`), as it
/// came (not copied), when the extension that sent it is one the app answers. Otherwise
/// [`ErrorCode::OutdatedExtension`] (no version it can read, as from an extension older than
/// versions sending a bare request, or one below [`MIN_EXTENSION_VERSION`]), or
/// [`ErrorCode::BadRequest`] for anything that isn't a JSON object of those two.
pub fn asked(text: &[u8]) -> Result<&[u8], ErrorCode> {
    // Each field as it is in `text`: nothing of the request is copied or decoded here.
    let fields = serde_json::from_slice::<std::collections::BTreeMap<&str, &RawValue>>(text)
        .map_err(|_| ErrorCode::BadRequest)?;
    let version = fields
        .get("version")
        .and_then(|raw| serde_json::from_str::<&str>(raw.get()).ok());
    if !version.is_some_and(accepted_version) {
        return Err(ErrorCode::OutdatedExtension);
    }
    match (fields.get("request"), fields.len()) {
        (Some(request), 2) => Ok(request.get().as_bytes()),
        _ => Err(ErrorCode::BadRequest),
    }
}

/// The answer to an extension below [`MIN_EXTENSION_VERSION`]: the oldest version the app
/// answers, and the version of the extension the app carries (`carried`), so a copy loaded
/// from the app's folder reloads itself into it (`apps/extension/update.js`).
pub fn outdated(carried: Option<&str>) -> Vec<u8> {
    #[derive(Serialize)]
    struct Outdated<'a> {
        #[serde(rename = "type")]
        kind: &'static str,
        code: ErrorCode,
        minimum: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        extension_version: Option<&'a str>,
    }
    serde_json::to_vec(&Outdated {
        kind: "error",
        code: ErrorCode::OutdatedExtension,
        minimum: MIN_EXTENSION_VERSION,
        extension_version: carried,
    })
    .unwrap_or_else(|_| br#"{"type":"error","code":"outdated_extension"}"#.to_vec())
}

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
    /// The logins the extension's own window lists: who and where, never a password. Only the
    /// logins of the open page `url` (S18), unless the person let the window list the whole
    /// vault ([`crate::service::Gate::whole_vault`]). Never what is kept out of the browser.
    Vault {
        #[serde(default)]
        url: Option<String>,
    },
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
    /// Whether `password`, just pasted into a password field of the page at `url` or sent
    /// from it, is the password of a login saved for another site, and so should not be given
    /// to this page; or one of the emergency kit's keys, which no page may have. Answered with
    /// that site's name at most, never which login, and only for logins outside the item lock;
    /// the password is compared and dropped, never kept.
    Elsewhere { url: String, password: Secret },
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
    /// The page at `url` used the WebAuthn Signal API (F23): a passkey the site doesn't know
    /// (`unknown`, with `credential`), the passkeys it still accepts for an account (`accepted`,
    /// with `user_id` and `accepted`), or the account's names now (`details`, with `user_id`,
    /// `name` and `display_name`). The site `rp_id` must be one the page speaks for. The app
    /// changes nothing by itself: it notes what the site said on the passkeys concerned, and
    /// the person removes or renames them on the item's page.
    PasskeySignal {
        url: String,
        #[serde(default)]
        rp_id: String,
        signal: SignalKind,
        #[serde(default)]
        credential: String,
        #[serde(default)]
        user_id: String,
        #[serde(default)]
        accepted: Vec<String>,
        #[serde(default)]
        name: String,
        #[serde(default)]
        display_name: String,
    },
    /// Whether `password`, about to be offered for saving on the page at `url`, is the password
    /// of other logins of the vault (outside the item lock, saved for other sites), and whether
    /// it turned up in known breaches (only while the leak watch is on: the leak check's
    /// k-anonymous question). Answered by the app with counts, never which logins; the password
    /// is compared and dropped.
    Weigh { url: String, password: Secret },
    /// The icons the app has for these sites (saved websites, at most 40), for the extension's
    /// window: answered by the app from its own sealed cache, only while Settings → Website
    /// icons is on, as `data:` addresses. The extension fetches nothing for them.
    Icons { sites: Vec<String> },
    /// What the site of the page at `url` accepts in a password, as the built-in list says
    /// ([`crate::resources`]), for a new-password field that doesn't say it itself. Needs no
    /// vault.
    PasswordRules { url: String },
    /// The vault's payment cards, offered for the payment fields of the page at `url`: who and
    /// which (the name on the card, the brand and last four digits, the expiry), never a number
    /// or a security code. Locked cards too.
    Cards { url: String },
    /// The details of card `id`, to type into the payment fields of the page at `url` (and of
    /// the frames in it the extension may fill: [`crate::rules::card_frame_allowed`]). A card
    /// behind the item lock, or every card when every use asks, is opened first, as for a fill.
    CardFill {
        url: String,
        id: String,
        #[serde(default)]
        check: Option<Secret>,
        #[serde(default)]
        hello: bool,
    },
    /// Changes the person's rule for the site of the page at `url` (the extension's window, for
    /// the site in front): answered by the app itself, with the rule as it is now
    /// ([`crate::rules`]). Kept on this device.
    SiteRule {
        url: String,
        rule: crate::rules::RuleChange,
    },
}

/// Which of the Signal API's calls a [`Request::PasskeySignal`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// `signalUnknownCredential`.
    Unknown,
    /// `signalAllAcceptedCredentials`.
    Accepted,
    /// `signalCurrentUserDetails`.
    Details,
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
        /// The version of the extension the app carries (`apps/extension`, built into the desktop
        /// app): an extension older than it reloads itself to take the new files the app wrote
        /// into its folder (`apps/extension/update.js`). Left out by an app that doesn't say;
        /// older extensions ignore it.
        #[serde(skip_serializing_if = "Option::is_none")]
        extension_version: Option<String>,
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
        /// With no login for this page: the saved site it looks like without being it
        /// ([`crate::lookalike`]), which the extension warns about instead of offering nothing.
        /// Left out otherwise; older extensions ignore it.
        #[serde(skip_serializing_if = "Option::is_none")]
        lookalike: Option<Lookalike>,
    },
    Fill(Credentials),
    Code(OneTimeCode),
    /// The answer to [`Request::PasskeySignal`]: how many of the vault's passkeys it concerns
    /// (noted for the person, nothing changed).
    Signaled {
        noted: u32,
    },
    /// The answer to [`Request::PasswordRules`]: `passwordrules` text, or none.
    PasswordRules {
        rules: Option<String>,
    },
    /// The vault's cards ([`Request::Cards`]).
    Cards {
        origin: String,
        check: Check,
        hello: bool,
        always_asks: bool,
        items: Vec<CardEntry>,
    },
    /// What a card fill types ([`Request::CardFill`]).
    CardFill(Box<CardFill>),
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
    /// The answer to [`Request::Elsewhere`]: what to warn the person about, if anything.
    Elsewhere {
        /// The page's host, as a warning shows it (punycode when it mixes scripts).
        page: String,
        /// The site the password is saved for (its registrable domain, as shown), when it is
        /// the password of a login of another site and of no login of this page's owner.
        #[serde(skip_serializing_if = "Option::is_none")]
        site: Option<String>,
        /// The page looks like that site without being it ([`crate::lookalike`]).
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        lookalike: bool,
        /// It is one of the emergency kit's keys ([`crate::kit`]): never given to any page.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        kit: bool,
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

/// One card offered for a page's payment fields: never its number or security code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CardEntry {
    pub id: String,
    pub title: String,
    /// The name on the card.
    pub holder: String,
    /// "Visa •••• 4242" (empty when no number is saved).
    pub hint: String,
    pub brand: String,
    /// "MM/YY", or empty.
    pub expiry: String,
    pub expired: bool,
    pub locked: bool,
}

/// What is typed into a page's payment fields. Wiped from memory when dropped.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct CardFill {
    /// The origin the top page must still have when the fields are filled.
    #[zeroize(skip)]
    pub origin: String,
    pub holder: String,
    pub number: String,
    /// The expiry month (1–12) and four-digit year; 0 when none is saved.
    #[zeroize(skip)]
    pub month: u32,
    #[zeroize(skip)]
    pub year: u32,
    pub security_code: String,
    #[zeroize(skip)]
    pub brand: String,
}

impl std::fmt::Debug for CardFill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardFill")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
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
    /// What a page sent as a password is one of the emergency kit's keys
    /// ([`crate::kit`]): it is never saved, compared or kept.
    KitKey,
    /// The person's rule for the page's site forbids it (never save, never fill, no passkeys:
    /// [`crate::rules`]).
    SiteRule,
    /// The extension is older than [`MIN_EXTENSION_VERSION`] (or names no version): nothing
    /// it asks is answered, and connecting it is refused.
    OutdatedExtension,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_names_the_extension_version_only_when_the_app_says_it() {
        let status = |extension_version: Option<&str>| {
            serde_json::to_string(&Response::Status {
                locked: false,
                name: String::new(),
                extension_version: extension_version.map(str::to_owned),
            })
            .unwrap()
        };
        assert_eq!(
            status(Some("0.4.7")),
            r#"{"type":"status","locked":false,"name":"","extension_version":"0.4.7"}"#
        );
        // As before: an extension reads no version, and offers no update.
        assert_eq!(
            status(None),
            r#"{"type":"status","locked":false,"name":""}"#
        );
    }

    #[test]
    fn only_an_extension_at_the_floor_or_later_is_answered() {
        let request = br#"{"type":"logins","url":"https://github.com/A"}"#;
        let wrapped = |version: &str| {
            format!(
                r#"{{"version":"{version}","request":{}}}"#,
                std::str::from_utf8(request).unwrap()
            )
        };
        // The request comes out as it went in, byte for byte (escapes too).
        for version in [MIN_EXTENSION_VERSION, "0.4.10", "0.5.0", "1.0.0"] {
            assert_eq!(
                asked(wrapped(version).as_bytes()),
                Ok(&request[..]),
                "{version}"
            );
        }
        // Older, no version (an extension from before versions: a bare request), or one that
        // isn't `x.y.z`.
        for version in [
            "0.4.6",
            "0.3.99",
            "0.4",
            "0.4.7.1",
            "",
            "v0.4.8",
            "0.4.8-beta",
        ] {
            assert_eq!(
                asked(wrapped(version).as_bytes()),
                Err(ErrorCode::OutdatedExtension),
                "{version}"
            );
        }
        assert_eq!(asked(request), Err(ErrorCode::OutdatedExtension));
        assert_eq!(
            asked(br#"{"version":0.5,"request":{}}"#),
            Err(ErrorCode::OutdatedExtension)
        );
        // Anything else around the request, or none, is not understood.
        let current = MIN_EXTENSION_VERSION;
        for bad in [
            format!(r#"{{"version":"{current}"}}"#),
            format!(r#"{{"version":"{current}","request":{{}},"more":1}}"#),
            "not json".to_owned(),
            "[]".to_owned(),
        ] {
            assert_eq!(asked(bad.as_bytes()), Err(ErrorCode::BadRequest), "{bad}");
        }
        assert!(accepted_version(MIN_EXTENSION_VERSION));
        assert!(!accepted_version("0.0.1"));
    }

    #[test]
    fn the_refusal_names_the_floor_and_the_extension_the_app_carries() {
        let refusal: serde_json::Value = serde_json::from_slice(&outdated(Some("0.4.9"))).unwrap();
        assert_eq!(
            refusal,
            serde_json::json!({
                "type": "error",
                "code": "outdated_extension",
                "minimum": MIN_EXTENSION_VERSION,
                "extension_version": "0.4.9",
            })
        );
        let plain: serde_json::Value = serde_json::from_slice(&outdated(None)).unwrap();
        assert_eq!(plain.get("extension_version"), None);
    }
}
