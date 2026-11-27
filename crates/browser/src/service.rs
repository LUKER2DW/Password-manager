//! How the app answers the extension from its (maybe locked) vault.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use vault_core::{
    ItemData, ItemId, ItemKind, Passkey, Vault,
    generator::{self, PassphraseOptions, PasswordOptions, WordCase},
    passkey::{ES256, attestation_object},
    totp::Totp,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    origin::{Origin, PageProblem, item_matches, passkey_site},
    protocol::{
        Assertion, Attestation, Check, CopyWhat, Credentials, ErrorCode, GeneratedPassword,
        LoginEntry, OneTimeCode, PasskeyEntry, Request, Response, Revealed, Secret, Symbols,
        UserVerification, VaultEntry,
    },
};

/// The answer to one message, as JSON bytes (wiped when dropped: it may hold a password),
/// and what the app must do or say about it.
#[derive(Debug)]
pub struct Answer {
    pub bytes: Zeroizing<Vec<u8>>,
    /// The title of the login whose password was handed out (filled or shown), if one was.
    pub filled: Option<String>,
    /// Something the app must copy to the clipboard itself.
    pub copy: Option<Copy>,
    /// The title of a login that was just added to the vault: the app saves the file.
    pub saved: Option<String>,
    /// The title of a login whose password was just replaced: the app saves the file.
    pub updated: Option<String>,
    /// A generated password the person used: the app adds it to its history.
    pub kept: Option<Kept>,
    /// The title of the login a new passkey was kept in: the app saves the file.
    pub passkey_saved: Option<String>,
    /// The title of the login whose passkey just signed in to a site.
    pub passkey_used: Option<String>,
}

/// A generated password that was used, and the site it was made for ("" when none).
pub struct Kept {
    pub password: Zeroizing<String>,
    pub site: String,
}

impl std::fmt::Debug for Kept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kept")
            .field("site", &self.site)
            .finish_non_exhaustive()
    }
}

/// What the app copies for a [`Request::Copy`].
pub struct Copy {
    pub what: CopyWhat,
    pub value: Zeroizing<String>,
}

impl std::fmt::Debug for Copy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Copy")
            .field("what", &self.what)
            .finish_non_exhaustive()
    }
}

/// The app's item lock, as the extension's requests meet it.
pub trait Gate {
    /// What opens locked logins.
    fn check(&self, vault: &Vault) -> Check;
    /// Whether this login's secrets are behind the lock right now.
    fn locked(&self, vault: &Vault, item: &ItemData) -> bool;
    /// Whether the device's user verification (Windows Hello) can open locked logins.
    fn hello(&self, vault: &Vault) -> bool;
    /// Opens with the device's user verification, which the app has already asked for.
    fn open_hello(&mut self, vault: &mut Vault) -> bool;
    /// Tries the PIN or password typed in the extension's window. Wrong tries are counted by
    /// the app, across the app and the extension alike.
    fn open(&mut self, vault: &mut Vault, secret: &str) -> Opened;
    /// Called after a login opened by [`Gate::open`] was read: lock again what that opened.
    fn close(&mut self, vault: &mut Vault);
    /// How long the app keeps a copied secret on the clipboard.
    fn clipboard_seconds(&self) -> u32 {
        30
    }
    /// Holds a generated password until the person uses it or it is replaced; returns its id.
    fn remember(&mut self, password: Zeroizing<String>, site: String) -> String;
    /// The generated password `id`, taken out of what is held.
    fn take(&mut self, id: &str) -> Option<Kept>;
}

/// The outcome of [`Gate::open`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
    Yes,
    /// Wrong; `left` tries remain.
    No {
        left: u32,
    },
    /// Wrong once too often: the app locks the whole vault.
    LockedOut,
}

/// Whether a message asks for something to be opened with Windows Hello. The app looks
/// before answering, because the system's prompt must not block its window.
pub fn wants_hello(message: &[u8]) -> bool {
    matches!(
        serde_json::from_slice::<Request>(message),
        Ok(Request::Fill { hello: true, .. }
            | Request::Code { hello: true, .. }
            | Request::Reveal { hello: true, .. }
            | Request::Copy { hello: true, .. }
            | Request::Update { hello: true, .. }
            | Request::PasskeyGet { hello: true, .. }
            | Request::PasskeyCreate { hello: true, .. })
    )
}

/// Where generated passwords wait until the person uses one (see [`Request::Keep`]).
pub trait Held {
    /// Holds a generated password until the person uses it or it is replaced; returns its id.
    fn remember(&mut self, password: Zeroizing<String>, site: String) -> String;
    /// The generated password `id`, taken out of what is held.
    fn take(&mut self, id: &str) -> Option<Kept>;
    /// How long the app keeps a copied secret on the clipboard.
    fn clipboard_seconds(&self) -> u32 {
        30
    }
}

/// The open vault's [`Gate`] holds the generated passwords too.
struct GateHeld<'a>(&'a mut dyn Gate);

impl Held for GateHeld<'_> {
    fn remember(&mut self, password: Zeroizing<String>, site: String) -> String {
        self.0.remember(password, site)
    }
    fn take(&mut self, id: &str) -> Option<Kept> {
        self.0.take(id)
    }
    fn clipboard_seconds(&self) -> u32 {
        self.0.clipboard_seconds()
    }
}

/// Answers the requests that need no vault: a new password from the generator, and keeping
/// (or copying) one that was used. The generator works the same with the vault locked; the
/// app adds a kept password to its history once the vault is open again. `None` for any
/// other request.
pub fn answer_generator(message: &[u8], held: &mut dyn Held) -> Option<Answer> {
    let request = serde_json::from_slice::<Request>(message).ok()?;
    if !matches!(request, Request::Generate { .. } | Request::Keep { .. }) {
        return None;
    }
    Some(finish(generator_outcome(request, held)))
}

fn finish(outcome: Outcome) -> Answer {
    // Serializing cannot fail for these types; an empty answer would only confuse the caller.
    let bytes = serde_json::to_vec(&outcome.response)
        .unwrap_or_else(|_| br#"{"type":"error","code":"bad_request"}"#.to_vec());
    Answer {
        bytes: Zeroizing::new(bytes),
        filled: outcome.filled,
        copy: outcome.copy,
        saved: outcome.saved,
        updated: outcome.updated,
        kept: outcome.kept,
        passkey_saved: outcome.passkey_saved,
        passkey_used: outcome.passkey_used,
    }
}

/// A [`Request::Generate`] or [`Request::Keep`]; anything else is a bad request.
fn generator_outcome(request: Request, held: &mut dyn Held) -> Outcome {
    match request {
        Request::Generate {
            length,
            lower,
            upper,
            digits,
            symbols,
            avoid_ambiguous,
            words,
            separator,
            capitalize,
            number,
            url,
        } => {
            let made = match words {
                Some(words) => {
                    let options = PassphraseOptions {
                        words: usize::try_from(words).unwrap_or(6).clamp(3, 20),
                        separator: separator.unwrap_or_else(|| "-".into()),
                        case: if capitalize {
                            WordCase::Title
                        } else {
                            WordCase::Lower
                        },
                        include_number: number,
                        wordlist: None,
                    };
                    generator::generate_passphrase(&options)
                        .ok()
                        .map(|password| (password, options.entropy_bits()))
                }
                None => generator_options(length, lower, upper, digits, symbols).and_then(
                    |mut options| {
                        options.avoid_ambiguous = avoid_ambiguous;
                        generator::generate_password(&options)
                            .ok()
                            .map(|password| (password, options.entropy_bits()))
                    },
                ),
            };
            let Some((password, entropy)) = made else {
                return error(ErrorCode::BadRequest).into();
            };
            let site = url
                .and_then(|url| Origin::of_page(&url).ok())
                .map(|origin| origin.host().to_owned())
                .unwrap_or_default();
            let text = password.as_str().to_owned();
            let id = held.remember(password, site);
            // `entropy_bits` is small and positive: the cast only drops the fraction.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let bits = entropy.round() as u32;
            Response::Generated(GeneratedPassword {
                id,
                password: text,
                bits,
            })
            .into()
        }
        Request::Keep { id, copy } => match held.take(&id) {
            Some(kept) => Outcome {
                copy: copy.then(|| Copy {
                    what: CopyWhat::Password,
                    value: kept.password.clone(),
                }),
                kept: Some(kept),
                ..if copy {
                    Response::Copied {
                        seconds: held.clipboard_seconds(),
                    }
                } else {
                    Response::Kept {}
                }
                .into()
            },
            None => error(ErrorCode::NoMatch).into(),
        },
        _ => error(ErrorCode::BadRequest).into(),
    }
}

/// Answers one raw message. `vault` is `None` while locked.
pub fn answer(message: &[u8], vault: Option<&mut Vault>, gate: &mut dyn Gate) -> Answer {
    let outcome = match serde_json::from_slice::<Request>(message) {
        Ok(request) => respond(request, vault, gate),
        Err(_) => error(ErrorCode::BadRequest).into(),
    };
    finish(outcome)
}

struct Outcome {
    response: Response,
    filled: Option<String>,
    copy: Option<Copy>,
    saved: Option<String>,
    updated: Option<String>,
    kept: Option<Kept>,
    passkey_saved: Option<String>,
    passkey_used: Option<String>,
}

impl From<Response> for Outcome {
    fn from(response: Response) -> Self {
        Self {
            response,
            filled: None,
            copy: None,
            saved: None,
            updated: None,
            kept: None,
            passkey_saved: None,
            passkey_used: None,
        }
    }
}

/// The generator's options for a [`Request::Generate`]. `None` when they make no password.
fn generator_options(
    length: Option<u32>,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: Symbols,
) -> Option<PasswordOptions> {
    let (symbols, also_use) = match symbols {
        Symbols::Any(on) => (on, String::new()),
        // Only printable ASCII punctuation, each once: a site's list is not trusted further.
        Symbols::Only(allowed) => {
            let mut chosen = String::new();
            for c in allowed.chars().filter(char::is_ascii_punctuation) {
                if !chosen.contains(c) {
                    chosen.push(c);
                }
            }
            (false, chosen)
        }
    };
    let length = usize::try_from(length.unwrap_or(20)).ok()?.clamp(4, 128);
    Some(PasswordOptions {
        length,
        lowercase: lower,
        uppercase: upper,
        digits,
        symbols,
        also_use,
        ..PasswordOptions::default()
    })
}

fn error(code: ErrorCode) -> Response {
    Response::Error {
        code,
        check: None,
        left: None,
    }
}

pub(crate) fn page_origin(url: &str) -> Result<Origin, Response> {
    Origin::of_page(url).map_err(|problem| {
        error(match problem {
            PageProblem::Insecure => ErrorCode::InsecurePage,
            PageProblem::NotAWebsite => ErrorCode::NotAWebsite,
        })
    })
}

fn item_locked(kind: Check) -> Response {
    Response::Error {
        code: ErrorCode::ItemLocked,
        check: Some(kind),
        left: None,
    }
}

/// Opens the item lock for one request: Windows Hello when asked and verified, else the PIN
/// or password typed in the extension. On `Ok` the caller reads (or writes) and then calls
/// [`Gate::close`].
fn open_gate(
    vault: &mut Vault,
    gate: &mut dyn Gate,
    check: Option<Secret>,
    hello: bool,
) -> Result<(), Response> {
    let kind = gate.check(vault);
    if hello && gate.open_hello(vault) {
        return Ok(());
    }
    let Some(secret) = check.filter(|_| kind != Check::App) else {
        return Err(item_locked(kind));
    };
    match gate.open(vault, secret.as_str()) {
        Opened::Yes => Ok(()),
        Opened::No { left } => Err(Response::Error {
            code: ErrorCode::WrongCheck,
            check: Some(kind),
            left: Some(left),
        }),
        Opened::LockedOut => Err(error(ErrorCode::Locked)),
    }
}

/// Verifies the person for this one request, as a site's passkey request asks
/// (`userVerification`): Windows Hello when asked for, else the item lock's PIN or password
/// typed in the extension's window, the lock opened and closed again at once. Answers whether
/// they were verified. `Discouraged`, or `Preferred` with no way to verify here, answers
/// `false` without asking; `Required` with no way is refused (`Unsupported`: the browser's
/// own handler takes the request). Nothing given yet: the item lock's answer, so the
/// extension's window asks.
fn verify_for(
    vault: &mut Vault,
    gate: &mut dyn Gate,
    wants: UserVerification,
    check: Option<Secret>,
    hello: bool,
) -> Result<bool, Response> {
    if wants == UserVerification::Discouraged {
        return Ok(false);
    }
    if !(gate.hello(vault) || gate.check(vault) != Check::App) {
        return match wants {
            UserVerification::Required => Err(error(ErrorCode::Unsupported)),
            _ => Ok(false),
        };
    }
    open_gate(vault, gate, check, hello)?;
    gate.close(vault);
    Ok(true)
}

/// Reads login `id` with its secrets, opening the item lock for this one read when it is
/// locked. `belongs` says whether the caller may have this login at all; an id that fails it
/// looks exactly like one that does not exist, and no PIN is ever tried for it.
fn read_login(
    vault: &mut Vault,
    gate: &mut dyn Gate,
    id: &str,
    check: Option<Secret>,
    hello: bool,
    belongs: impl Fn(&ItemData) -> bool,
) -> Result<ItemData, Response> {
    with_login(
        vault,
        gate,
        id,
        check,
        hello,
        None,
        belongs,
        |_, _, item, _| item,
    )
}

/// Runs `act` on login `id` with its secrets readable, opening the item lock first when it
/// covers the login (and closing it again right after `act`). `act` also hears whether the
/// person was verified for this request: the lock opened for it, or, for a login outside the
/// lock, the check `verify` asks for ([`verify_for`]).
#[allow(clippy::too_many_arguments)]
fn with_login<R>(
    vault: &mut Vault,
    gate: &mut dyn Gate,
    id: &str,
    check: Option<Secret>,
    hello: bool,
    verify: Option<UserVerification>,
    belongs: impl Fn(&ItemData) -> bool,
    act: impl FnOnce(&mut Vault, &ItemId, ItemData, bool) -> R,
) -> Result<R, Response> {
    let id = ItemId::from_hex(id).ok_or_else(|| error(ErrorCode::NoMatch))?;
    let read = |vault: &Vault| {
        vault
            .get_item(&id)
            .ok()
            .filter(|item| item.kind == ItemKind::Login && belongs(item))
    };
    let item = read(vault).ok_or_else(|| error(ErrorCode::NoMatch))?;
    if !(item.is_locked() || gate.locked(vault, &item)) {
        let verified = match verify {
            Some(wants) => verify_for(vault, gate, wants, check, hello)?,
            None => false,
        };
        return Ok(act(vault, &id, item, verified));
    }
    let kind = gate.check(vault);
    open_gate(vault, gate, check, hello)?;
    // Read once while open, then closed again: only this login was decrypted. Opened for this
    // request: the person was verified.
    let done = read(vault)
        .filter(|item| !item.is_locked())
        .map(|item| act(vault, &id, item, true));
    gate.close(vault);
    done.ok_or_else(|| item_locked(kind))
}

/// Which version of item `id` is stored now ([`Vault::item_stamp`], base64url): what an
/// update offered for one version is checked against. Not secret.
fn stamp_of(vault: &Vault, id: &ItemId) -> Option<String> {
    vault
        .item_stamp(id)
        .map(|stamp| URL_SAFE_NO_PAD.encode(stamp))
}

/// Whether a login to save is of a size a sign-in form could hold: what the extension sends
/// is typed by a person or read from a page, never trusted for its length.
pub(crate) fn save_fits(title: Option<&str>, username: &str, password: &Secret) -> bool {
    title.is_none_or(|title| title.len() <= 256)
        && username.len() <= 1024
        && password.as_str().len() <= 1024
}

fn respond(request: Request, vault: Option<&mut Vault>, gate: &mut dyn Gate) -> Outcome {
    if matches!(request, Request::Status {}) {
        return Response::Status {
            locked: vault.is_none(),
            name: vault.map_or_else(String::new, |v| v.settings().name.clone()),
        }
        .into();
    }
    // A page's address is judged before anything else, locked or not.
    let origin = match &request {
        Request::Logins { url }
        | Request::Fill { url, .. }
        | Request::Code { url, .. }
        | Request::Save { url, .. }
        | Request::Changed { url, .. }
        | Request::Update { url, .. }
        | Request::Passkeys { url, .. }
        | Request::PasskeyGet { url, .. }
        | Request::PasskeyCreate { url, .. } => match page_origin(url) {
            Ok(origin) => Some(origin),
            Err(response) => return response.into(),
        },
        _ => None,
    };
    let Some(vault) = vault else {
        return error(ErrorCode::Locked).into();
    };
    match (request, origin) {
        (Request::Logins { .. }, Some(origin)) => {
            let mut items: Vec<LoginEntry> = vault
                .item_ids()
                .filter_map(|id| {
                    let item = vault.get_item(&id).ok()?;
                    (item.kind == ItemKind::Login && item_matches(&item.urls, &origin)).then(|| {
                        LoginEntry {
                            id: id.to_hex(),
                            title: item.title.clone(),
                            username: item.username.clone(),
                            locked: item.is_locked() || gate.locked(vault, &item),
                            has_code: item
                                .sealed
                                .as_ref()
                                .map_or(!item.totp.is_empty(), |sealed| sealed.has_totp),
                        }
                    })
                })
                .collect();
            items.sort_by_key(|entry| (entry.title.to_lowercase(), entry.username.to_lowercase()));
            Response::Logins {
                origin: origin.as_str().to_owned(),
                check: gate.check(vault),
                hello: gate.hello(vault),
                items,
            }
            .into()
        }
        (
            Request::Fill {
                id, check, hello, ..
            },
            Some(origin),
        ) => {
            // The same answer for "no such login" and "saved for another site": the caller
            // learns nothing about logins of other origins, and can't try PINs on them.
            match read_login(vault, gate, &id, check, hello, |item| {
                item_matches(&item.urls, &origin)
            }) {
                Ok(item) => Outcome {
                    filled: Some(item.title.clone()),
                    ..Response::Fill(Credentials {
                        origin: origin.as_str().to_owned(),
                        username: item.username.clone(),
                        password: item.password.clone(),
                    })
                    .into()
                },
                Err(response) => response.into(),
            }
        }
        (
            Request::Code {
                id, check, hello, ..
            },
            Some(origin),
        ) => {
            match read_login(vault, gate, &id, check, hello, |item| {
                item_matches(&item.urls, &origin)
            }) {
                Ok(item) => match Totp::parse(&item.totp) {
                    Ok(totp) => {
                        let (code, seconds) = totp.now();
                        Outcome {
                            filled: Some(item.title.clone()),
                            ..Response::Code(OneTimeCode {
                                origin: origin.as_str().to_owned(),
                                code: code.as_str().to_owned(),
                                seconds,
                            })
                            .into()
                        }
                    }
                    Err(_) => error(ErrorCode::NoMatch).into(),
                },
                Err(response) => response.into(),
            }
        }
        (
            Request::Changed {
                username, password, ..
            },
            Some(origin),
        ) => {
            if !save_fits(None, &username, &password) {
                return error(ErrorCode::BadRequest).into();
            }
            // The first login of this site with that username, in the order they are listed.
            let mut matches: Vec<(ItemId, ItemData)> = vault
                .item_ids()
                .filter_map(|id| Some((id, vault.get_item(&id).ok()?)))
                .filter(|(_, item)| {
                    item.kind == ItemKind::Login
                        && item.username == username
                        && item_matches(&item.urls, &origin)
                })
                .collect();
            matches.sort_by_key(|(_, item)| item.title.to_lowercase());
            match matches.into_iter().next() {
                Some((id, item)) => {
                    // Never opened for this: a locked login answers "unknown".
                    let changed = (!(item.is_locked() || gate.locked(vault, &item)))
                        .then(|| item.password != password.as_str());
                    Response::Changed {
                        id: id.to_hex(),
                        changed,
                        stamp: stamp_of(vault, &id).unwrap_or_default(),
                    }
                    .into()
                }
                None => error(ErrorCode::NoMatch).into(),
            }
        }
        (
            Request::Update {
                id,
                password,
                username,
                stamp,
                check,
                hello,
                ..
            },
            Some(origin),
        ) => {
            if password.as_str().is_empty() || !save_fits(None, "", &password) {
                return error(ErrorCode::BadRequest).into();
            }
            // The login the person was offered to update, as it was then: edited since (in
            // the app, by a sync) or with another username now, it is not overwritten. Checked
            // before the item lock is opened, so no PIN is asked for a refusal.
            if username.is_some() || stamp.is_some() {
                let Some(item_id) = ItemId::from_hex(&id) else {
                    return error(ErrorCode::NoMatch).into();
                };
                let Some(item) = vault.get_item(&item_id).ok().filter(|item| {
                    item.kind == ItemKind::Login && item_matches(&item.urls, &origin)
                }) else {
                    return error(ErrorCode::NoMatch).into();
                };
                let same_user = username.as_ref().is_none_or(|name| *name == item.username);
                let same_version = stamp
                    .as_ref()
                    .is_none_or(|stamp| stamp_of(vault, &item_id).as_ref() == Some(stamp));
                if !(same_user && same_version) {
                    return error(ErrorCode::ChangedSince).into();
                }
            }
            let done = with_login(
                vault,
                gate,
                &id,
                check,
                hello,
                None,
                |item| item_matches(&item.urls, &origin),
                |vault, id, mut item, _| {
                    if item.password == password.as_str() {
                        return Ok((item.title.clone(), false));
                    }
                    item.password.zeroize();
                    item.password.push_str(password.as_str());
                    // The old password goes into the history (`Vault::update_item`).
                    vault
                        .update_item(id, &item)
                        .map(|()| (item.title.clone(), true))
                },
            );
            match done {
                Ok(Ok((title, changed))) => Outcome {
                    updated: changed.then_some(title),
                    ..Response::Updated { changed }.into()
                },
                Ok(Err(_)) => error(ErrorCode::BadRequest).into(),
                Err(response) => response.into(),
            }
        }
        (Request::Vault {}, _) => {
            let mut items: Vec<VaultEntry> = vault
                .item_ids()
                .filter_map(|id| {
                    let item = vault.get_item(&id).ok()?;
                    if item.kind != ItemKind::Login {
                        return None;
                    }
                    let sealed = item.sealed.as_ref();
                    Some(VaultEntry {
                        id: id.to_hex(),
                        title: item.title.clone(),
                        username: item.username.clone(),
                        site: item.urls.first().cloned().unwrap_or_default(),
                        locked: item.is_locked() || gate.locked(vault, &item),
                        has_password: sealed
                            .map_or(!item.password.is_empty(), |sealed| sealed.has_password),
                        has_code: sealed.map_or(!item.totp.is_empty(), |sealed| sealed.has_totp),
                    })
                })
                .collect();
            items.sort_by_key(|entry| (entry.title.to_lowercase(), entry.username.to_lowercase()));
            Response::Vault {
                check: gate.check(vault),
                hello: gate.hello(vault),
                items,
            }
            .into()
        }
        (Request::Reveal { id, check, hello }, _) => {
            match read_login(vault, gate, &id, check, hello, |_| true) {
                Ok(item) => Outcome {
                    filled: Some(item.title.clone()),
                    ..Response::Reveal(Revealed {
                        password: item.password.clone(),
                    })
                    .into()
                },
                Err(response) => response.into(),
            }
        }
        (
            Request::Copy {
                id,
                what: CopyWhat::Username,
                ..
            },
            _,
        ) => {
            // A username is shown even while locked: nothing to open.
            let item = ItemId::from_hex(&id)
                .and_then(|id| vault.get_item(&id).ok())
                .filter(|item| item.kind == ItemKind::Login);
            match item {
                Some(item) => Outcome {
                    copy: Some(Copy {
                        what: CopyWhat::Username,
                        value: Zeroizing::new(item.username.clone()),
                    }),
                    ..Response::Copied { seconds: 0 }.into()
                },
                None => error(ErrorCode::NoMatch).into(),
            }
        }
        (
            Request::Copy {
                id,
                what,
                check,
                hello,
            },
            _,
        ) => {
            let item = match read_login(vault, gate, &id, check, hello, |_| true) {
                Ok(item) => item,
                Err(response) => return response.into(),
            };
            let value = match what {
                CopyWhat::Code => Totp::parse(&item.totp).ok().map(|totp| totp.now().0),
                _ => Some(Zeroizing::new(item.password.clone())),
            };
            match value.filter(|value| !value.is_empty()) {
                Some(value) => Outcome {
                    copy: Some(Copy { what, value }),
                    ..Response::Copied {
                        seconds: gate.clipboard_seconds(),
                    }
                    .into()
                },
                None => error(ErrorCode::NoMatch).into(),
            }
        }
        (
            Request::Save {
                title,
                username,
                password,
                check,
                hello,
                ..
            },
            Some(origin),
        ) => {
            if password.as_str().is_empty() || !save_fits(title.as_deref(), &username, &password) {
                return error(ErrorCode::BadRequest).into();
            }
            let existing = vault.item_ids().any(|id| {
                vault.get_item(&id).is_ok_and(|item| {
                    item.kind == ItemKind::Login
                        && item.username == username
                        && item_matches(&item.urls, &origin)
                })
            });
            if existing {
                return Response::Saved {
                    existing: true,
                    queued: false,
                }
                .into();
            }
            let host = origin.host();
            let named = title.as_deref().map(str::trim).filter(|t| !t.is_empty());
            let title = named.unwrap_or_else(|| host.strip_prefix("www.").unwrap_or(host));
            let item = ItemData::login(title, &username, password.as_str(), origin.as_str());
            // A new login needs no PIN or Windows Hello: the item lock seals it the next time
            // it opens (`Vault::add_item`). `check` and `hello` are accepted and ignored.
            let _ = (check, hello);
            match vault.add_item(&item) {
                Ok(_) => Outcome {
                    saved: Some(item.title.clone()),
                    ..Response::Saved {
                        existing: false,
                        queued: false,
                    }
                    .into()
                },
                Err(_) => error(ErrorCode::BadRequest).into(),
            }
        }
        (request @ (Request::Generate { .. } | Request::Keep { .. }), _) => {
            generator_outcome(request, &mut GateHeld(gate))
        }
        (
            Request::Passkeys {
                rp_id, allow: list, ..
            },
            Some(origin),
        ) => {
            let Some(rp_id) = passkey_site(&rp_id, &origin) else {
                return error(ErrorCode::WrongSite).into();
            };
            let allow: Vec<Vec<u8>> = list
                .iter()
                .take(MAX_LISTED)
                .filter_map(|id| unbase64(id))
                .collect();
            let mut items: Vec<PasskeyEntry> = Vec::new();
            for id in vault.item_ids() {
                let Ok(item) = vault.get_item(&id) else {
                    continue;
                };
                if item.kind != ItemKind::Login {
                    continue;
                }
                let locked = item.is_locked() || gate.locked(vault, &item);
                for passkey in item.passkeys.iter().filter(|p| {
                    p.rp_id == rp_id && (list.is_empty() || allow.contains(&p.credential_id))
                }) {
                    items.push(PasskeyEntry {
                        id: id.to_hex(),
                        credential: URL_SAFE_NO_PAD.encode(&passkey.credential_id),
                        title: item.title.clone(),
                        user_name: passkey.user_name.clone(),
                        display_name: passkey.display_name.clone(),
                        locked,
                    });
                }
            }
            items.sort_by_key(|entry| (entry.user_name.to_lowercase(), entry.title.to_lowercase()));
            Response::Passkeys {
                origin: origin.as_str().to_owned(),
                rp_id,
                check: gate.check(vault),
                hello: gate.hello(vault),
                items,
            }
            .into()
        }
        (
            Request::PasskeyGet {
                rp_id,
                id,
                credential,
                challenge,
                check,
                hello,
                user_verification,
                ..
            },
            Some(origin),
        ) => {
            let Some(rp_id) = passkey_site(&rp_id, &origin) else {
                return error(ErrorCode::WrongSite).into();
            };
            let (Some(credential), Some(client_data)) = (
                unbase64(&credential),
                client_data("webauthn.get", &challenge, &origin),
            ) else {
                return error(ErrorCode::BadRequest).into();
            };
            let ours = |p: &Passkey| p.rp_id == rp_id && p.credential_id == credential;
            let signed = with_login(
                vault,
                gate,
                &id,
                check,
                hello,
                Some(user_verification),
                |item| item.passkeys.iter().any(ours),
                |_, _, item, verified| {
                    let passkey = item.passkeys.iter().find(|p| ours(p))?;
                    let data = passkey.authenticator_data(false, verified).ok()?;
                    let hash: [u8; 32] = Sha256::digest(&client_data).into();
                    let signature = passkey.sign(&data, &hash).ok()?;
                    Some((
                        item.title.clone(),
                        Assertion {
                            origin: origin.as_str().to_owned(),
                            credential: URL_SAFE_NO_PAD.encode(&passkey.credential_id),
                            client_data: URL_SAFE_NO_PAD.encode(&client_data),
                            authenticator_data: URL_SAFE_NO_PAD.encode(&data),
                            signature: URL_SAFE_NO_PAD.encode(&signature),
                            user_handle: URL_SAFE_NO_PAD.encode(&passkey.user_handle),
                        },
                    ))
                },
            );
            match signed {
                Ok(Some((title, assertion))) => Outcome {
                    passkey_used: Some(title),
                    ..Response::Assertion(Box::new(assertion)).into()
                },
                Ok(None) => error(ErrorCode::BadRequest).into(),
                Err(response) => response.into(),
            }
        }
        (
            Request::PasskeyCreate {
                rp_id,
                user_id,
                user_name,
                display_name,
                challenge,
                exclude,
                algorithms,
                check,
                hello,
                user_verification,
                ..
            },
            Some(origin),
        ) => create_passkey(
            vault,
            gate,
            &origin,
            NewPasskey {
                rp_id,
                user_id,
                user_name,
                display_name,
                challenge,
                exclude,
                algorithms,
                user_verification,
            },
            check,
            hello,
        ),
        // A page request always has its origin by now.
        _ => error(ErrorCode::BadRequest).into(),
    }
}

/// At most this many credential ids are read from a site's list.
const MAX_LISTED: usize = 64;
/// The longest challenge a site may send (WebAuthn asks for at least 16 bytes; sites send 32).
const MAX_CHALLENGE: usize = 1024;

/// Bytes from base64url, with or without padding.
fn unbase64(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

/// The client data the passkey signs (WebAuthn §5.8.1), written by the app from the page's
/// origin, as the browser would. `None` when the challenge isn't base64url or is too long.
fn client_data(kind: &str, challenge: &str, origin: &Origin) -> Option<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct ClientData<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
        challenge: String,
        origin: &'a str,
        #[serde(rename = "crossOrigin")]
        cross_origin: bool,
    }
    let challenge = unbase64(challenge).filter(|c| !c.is_empty() && c.len() <= MAX_CHALLENGE)?;
    serde_json::to_vec(&ClientData {
        kind,
        challenge: URL_SAFE_NO_PAD.encode(challenge),
        origin: origin.as_str(),
        // Only a page's top frame is answered.
        cross_origin: false,
    })
    .ok()
}

/// What the page hands the site for a passkey just made; `verified`: the person was verified
/// for this request.
fn attestation_for(
    passkey: &Passkey,
    client_data: &[u8],
    origin: &Origin,
    verified: bool,
) -> Option<Attestation> {
    let data = passkey.authenticator_data(true, verified).ok()?;
    Some(Attestation {
        origin: origin.as_str().to_owned(),
        credential: URL_SAFE_NO_PAD.encode(&passkey.credential_id),
        client_data: URL_SAFE_NO_PAD.encode(client_data),
        attestation_object: URL_SAFE_NO_PAD.encode(attestation_object(&data)),
        authenticator_data: URL_SAFE_NO_PAD.encode(&data),
        public_key: URL_SAFE_NO_PAD.encode(passkey.spki().ok()?),
        algorithm: ES256,
        replaced: false,
    })
}

/// What a [`Request::PasskeyCreate`] asks for.
struct NewPasskey {
    rp_id: String,
    user_id: String,
    user_name: String,
    display_name: String,
    challenge: String,
    exclude: Vec<String>,
    algorithms: Vec<i64>,
    user_verification: UserVerification,
}

/// Makes a passkey and keeps it in the login for that page and username (a new login when
/// there is none, opening a locked one first). A passkey of that site and account already
/// there is replaced, as an authenticator does.
fn create_passkey(
    vault: &mut Vault,
    gate: &mut dyn Gate,
    origin: &Origin,
    new: NewPasskey,
    check: Option<Secret>,
    hello: bool,
) -> Outcome {
    let Some(rp_id) = passkey_site(&new.rp_id, origin) else {
        return error(ErrorCode::WrongSite).into();
    };
    if !new.algorithms.is_empty() && !new.algorithms.contains(&ES256) {
        return error(ErrorCode::Unsupported).into();
    }
    let (Some(user_handle), Some(client_data)) = (
        unbase64(&new.user_id).filter(|h| !h.is_empty() && h.len() <= Passkey::MAX_USER_HANDLE),
        client_data("webauthn.create", &new.challenge, origin),
    ) else {
        return error(ErrorCode::BadRequest).into();
    };
    let user_name = new.user_name.trim();
    let display_name = new.display_name.trim();
    if user_name.chars().count() > Passkey::MAX_NAME_CHARS
        || display_name.chars().count() > Passkey::MAX_NAME_CHARS
    {
        return error(ErrorCode::BadRequest).into();
    }
    let exclude: Vec<Vec<u8>> = new
        .exclude
        .iter()
        .take(MAX_LISTED)
        .filter_map(|id| unbase64(id))
        .collect();
    let mut target = None;
    for id in vault.item_ids() {
        let Ok(item) = vault.get_item(&id) else {
            continue;
        };
        if item.kind != ItemKind::Login {
            continue;
        }
        if item
            .passkeys
            .iter()
            .any(|p| p.rp_id == rp_id && exclude.contains(&p.credential_id))
        {
            return error(ErrorCode::Exists).into();
        }
        if target.is_none() && item.username == user_name && item_matches(&item.urls, origin) {
            target = Some(id);
        }
    }
    let Ok(passkey) = Passkey::new(&rp_id, &user_handle, user_name, display_name) else {
        return error(ErrorCode::BadRequest).into();
    };
    // Both answers made before anything is kept; which one goes depends on whether the person
    // is verified on the way.
    let (Some(plain), Some(checked)) = (
        attestation_for(&passkey, &client_data, origin, false),
        attestation_for(&passkey, &client_data, origin, true),
    ) else {
        return error(ErrorCode::BadRequest).into();
    };
    // A passkey of the same site and account is replaced, as a security key does: the answer
    // says so, so that when it never reaches the page the window can tell the person that
    // the earlier one is gone too.
    let kept = match target {
        Some(id) => with_login(
            vault,
            gate,
            &id.to_hex(),
            check,
            hello,
            Some(new.user_verification),
            |_| true,
            |vault, id, mut item, verified| {
                let before = item.passkeys.len();
                item.passkeys.retain(|p| {
                    !(p.rp_id == passkey.rp_id && p.user_handle == passkey.user_handle)
                });
                let replaced = item.passkeys.len() != before;
                if item.passkeys.len() >= Passkey::MAX_PER_ITEM {
                    return None;
                }
                item.passkeys.push(passkey.clone());
                item.touch();
                vault
                    .update_item(id, &item)
                    .ok()
                    .map(|()| (item.title.clone(), replaced, verified))
            },
        ),
        None => verify_for(vault, gate, new.user_verification, check, hello).map(|verified| {
            let host = origin.host();
            let title = host.strip_prefix("www.").unwrap_or(host);
            let mut item = ItemData::login(title, user_name, "", origin.as_str());
            item.passkeys.push(passkey.clone());
            // Like a login saved from a page: the item lock seals it the next time it opens.
            vault
                .add_item(&item)
                .ok()
                .map(|_| (item.title.clone(), false, verified))
        }),
    };
    match kept {
        Ok(Some((title, replaced, verified))) => {
            let mut attestation = if verified { checked } else { plain };
            attestation.replaced = replaced;
            Outcome {
                passkey_saved: Some(title),
                ..Response::Attestation(Box::new(attestation)).into()
            }
        }
        Ok(None) => error(ErrorCode::BadRequest).into(),
        Err(response) => response.into(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use vault_core::{GuardCheck, KdfParams, SecretKey};

    use super::*;

    fn vault() -> (Vault, String, String) {
        let secret_key = SecretKey::generate().unwrap();
        let mut vault =
            Vault::create("pw", &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
        let github = vault
            .add_item(&ItemData::login(
                "GitHub",
                "octocat",
                "gh-secret",
                "https://github.com/login",
            ))
            .unwrap();
        let mut second = ItemData::login("GitHub (work)", "hubot", "work-secret", "github.com");
        second.reprompt = true;
        let work = vault.add_item(&second).unwrap();
        vault
            .add_item(&ItemData::login(
                "Bank",
                "me",
                "bank-secret",
                "https://bank.example",
            ))
            .unwrap();
        let mut note = ItemData::new(ItemKind::SecureNote, "Note about github");
        note.urls.push("https://github.com".into());
        vault.add_item(&note).unwrap();
        (vault, github.to_hex(), work.to_hex())
    }

    /// A stand-in for the app: marked items are locked, a PIN opens them, three tries.
    struct TestGate {
        kind: Check,
        open: bool,
        tries: u32,
        closed: u32,
        hello: bool,
        held: Vec<(String, Zeroizing<String>, String)>,
    }

    impl TestGate {
        fn new(kind: Check) -> Self {
            Self {
                kind,
                open: false,
                tries: 0,
                closed: 0,
                hello: false,
                held: Vec::new(),
            }
        }
    }

    impl Gate for TestGate {
        fn check(&self, _vault: &Vault) -> Check {
            self.kind
        }
        fn locked(&self, _vault: &Vault, item: &ItemData) -> bool {
            item.reprompt && !self.open
        }
        fn hello(&self, _vault: &Vault) -> bool {
            self.hello
        }
        fn open_hello(&mut self, _vault: &mut Vault) -> bool {
            self.open = self.hello;
            self.hello
        }
        fn open(&mut self, _vault: &mut Vault, secret: &str) -> Opened {
            if secret == "4821" {
                self.open = true;
                return Opened::Yes;
            }
            self.tries += 1;
            if self.tries >= 3 {
                Opened::LockedOut
            } else {
                Opened::No {
                    left: 3 - self.tries,
                }
            }
        }
        fn close(&mut self, _vault: &mut Vault) {
            self.open = false;
            self.closed += 1;
        }
        fn remember(&mut self, password: Zeroizing<String>, site: String) -> String {
            let id = format!("g{}", self.held.len());
            self.held.push((id.clone(), password, site));
            id
        }
        fn take(&mut self, id: &str) -> Option<Kept> {
            let at = self.held.iter().position(|(held, ..)| held == id)?;
            let (_, password, site) = self.held.remove(at);
            Some(Kept { password, site })
        }
    }

    fn ask_with(
        vault: Option<&mut Vault>,
        gate: &mut TestGate,
        request: Value,
    ) -> (Value, Option<String>) {
        let answer = answer(request.to_string().as_bytes(), vault, gate);
        (
            serde_json::from_slice(&answer.bytes).unwrap(),
            answer.filled,
        )
    }

    fn ask(vault: Option<&mut Vault>, request: Value) -> (Value, Option<String>) {
        ask_with(vault, &mut TestGate::new(Check::App), request)
    }

    fn unb64(value: &Value) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
    }

    /// What the site's server checks of a passkey's answer: the client data it expects, its
    /// own site's hash, the flags, and the signature by the public key it kept.
    fn site_checks(
        public_key: &[u8],
        answer: &Value,
        kind: &str,
        challenge: &str,
        origin: &str,
        rp_id: &str,
    ) {
        let client_data = unb64(&answer["client_data"]);
        let client: Value = serde_json::from_slice(&client_data).unwrap();
        assert_eq!(
            client,
            json!({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
        );
        let data = unb64(&answer["authenticator_data"]);
        assert_eq!(&data[..32], Sha256::digest(rp_id.as_bytes()).as_slice());
        assert_eq!(data[32] & 0x05, 0x05, "present and verified");
        if kind == "webauthn.get" {
            let mut message = data;
            message.extend_from_slice(&Sha256::digest(&client_data));
            assert!(vault_core::passkey::verify(
                public_key,
                &message,
                &unb64(&answer["signature"])
            ));
        }
    }

    fn passkey_answer(vault: &mut Vault, gate: &mut TestGate, request: Value) -> (Value, Answer) {
        let answer = answer(request.to_string().as_bytes(), Some(vault), gate);
        (serde_json::from_slice(&answer.bytes).unwrap(), answer)
    }

    #[test]
    fn a_passkey_is_made_and_used_by_its_site_only() {
        let (mut vault, _, _) = vault();
        let mut gate = TestGate::new(Check::Pin);
        let challenge = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let create = json!({
            "type": "passkey_create",
            "url": "https://login.example.com/new",
            "rp_id": "example.com",
            "user_id": URL_SAFE_NO_PAD.encode(b"user-42"),
            "user_name": "me@example.com",
            "display_name": "Me",
            "challenge": challenge,
            "algorithms": [-8, -7, -257],
            // Verified for the request (the site asks for it by default).
            "check": "4821",
        });
        let (made, answer) = passkey_answer(&mut vault, &mut gate, create.clone());
        assert_eq!(made["type"], "attestation", "{made}");
        assert_eq!(answer.passkey_saved.as_deref(), Some("login.example.com"));
        assert_eq!(made.get("replaced"), None, "nothing was there before");
        assert_eq!(
            (made["algorithm"].as_i64(), made["origin"].as_str()),
            (Some(-7), Some("https://login.example.com"))
        );
        site_checks(
            &[],
            &made,
            "webauthn.create",
            &challenge,
            "https://login.example.com",
            "example.com",
        );
        // The attestation object carries the same authenticator data, with the new key.
        let data = unb64(&made["authenticator_data"]);
        assert!(unb64(&made["attestation_object"]).ends_with(&data));
        let spki = unb64(&made["public_key"]);
        assert_eq!(&data[55..71], unb64(&made["credential"]).as_slice());
        // Kept in a new login for that page, with the account's name.
        let login = vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .find(|item| item.title == "login.example.com")
            .unwrap();
        assert_eq!(
            (
                login.username.as_str(),
                login.urls.as_slice(),
                login.passkeys.len()
            ),
            (
                "me@example.com",
                &["https://login.example.com".to_owned()][..],
                1
            )
        );
        assert_eq!(login.passkeys[0].public_key().unwrap()[..], spki[26..]);

        // Listed for another page of the site, without any key.
        let list = |url: &str, rp_id: &str| json!({"type": "passkeys", "url": url, "rp_id": rp_id});
        let (listed, _) = passkey_answer(
            &mut vault,
            &mut gate,
            list("https://www.example.com/", "example.com"),
        );
        assert_eq!(listed["rp_id"], "example.com");
        let entry = &listed["items"][0];
        assert_eq!(
            (entry["user_name"].as_str(), entry["locked"].as_bool()),
            (Some("me@example.com"), Some(false))
        );
        assert_eq!(entry["credential"], made["credential"]);
        assert!(
            !listed
                .to_string()
                .contains(made["public_key"].as_str().unwrap())
        );
        // The site's own list of credentials narrows it.
        let (narrowed, _) = passkey_answer(
            &mut vault,
            &mut gate,
            json!({"type": "passkeys", "url": "https://example.com/", "rp_id": "example.com", "allow": ["AAAA"]}),
        );
        assert_eq!(narrowed["items"], json!([]));

        // Signing in: the app writes the client data from the page's origin, and signs it.
        let challenge = URL_SAFE_NO_PAD.encode(b"another challenge of the site");
        let get = |url: &str, rp_id: &str| {
            json!({
                "type": "passkey_get",
                "url": url,
                "rp_id": rp_id,
                "id": entry["id"],
                "credential": made["credential"],
                "challenge": challenge,
                "check": "4821",
            })
        };
        let (signed, answer) = passkey_answer(
            &mut vault,
            &mut gate,
            get("https://www.example.com/", "example.com"),
        );
        assert_eq!(signed["type"], "assertion", "{signed}");
        assert_eq!(answer.passkey_used.as_deref(), Some("login.example.com"));
        assert_eq!(unb64(&signed["user_handle"]), b"user-42");
        site_checks(
            &spki[26..],
            &signed,
            "webauthn.get",
            &challenge,
            "https://www.example.com",
            "example.com",
        );

        // Another site never lists or uses it, whatever it claims.
        for (url, rp_id) in [
            ("https://example.org/", "example.com"),
            ("https://example.com.evil.example/", "example.com"),
            ("https://login.example.com/", "com"),
            ("http://example.com/", "example.com"),
        ] {
            for request in [list(url, rp_id), get(url, rp_id)] {
                let (reply, answer) = passkey_answer(&mut vault, &mut gate, request);
                assert!(
                    ["wrong_site", "insecure_page"].contains(&reply["code"].as_str().unwrap()),
                    "{url} {rp_id}: {reply}"
                );
                assert!(answer.passkey_used.is_none());
            }
        }
        // A page that may speak only for its own host doesn't find the site's passkey there.
        let (reply, _) = passkey_answer(&mut vault, &mut gate, get("https://www.example.com/", ""));
        assert_eq!(reply["code"], "no_match");

        // Already made (the site lists it): refused; no ES256: refused, the browser may try.
        let mut again = create.clone();
        again["exclude"] = json!([made["credential"]]);
        let (reply, _) = passkey_answer(&mut vault, &mut gate, again);
        assert_eq!(reply["code"], "exists");
        let mut rsa_only = create.clone();
        rsa_only["algorithms"] = json!([-257]);
        let (reply, _) = passkey_answer(&mut vault, &mut gate, rsa_only);
        assert_eq!(reply["code"], "unsupported");
        // Made again for the same account: it takes the old one's place in the same login,
        // and the answer says so (the window tells it when the page never gets this one).
        let (remade, _) = passkey_answer(&mut vault, &mut gate, create);
        assert_eq!(remade["type"], "attestation");
        assert_eq!(remade["replaced"], true);
        let logins: Vec<ItemData> = vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .filter(|item| item.title == "login.example.com")
            .collect();
        assert_eq!(logins.len(), 1);
        assert_eq!(logins[0].passkeys.len(), 1);
        assert_eq!(
            logins[0].passkeys[0].credential_id,
            unb64(&remade["credential"])
        );
    }

    /// "User verified" only after a check in that very request (Windows Hello, the item lock's
    /// PIN or password), as the site asks: never because the vault happens to be open.
    #[test]
    fn verified_only_after_a_check_in_that_request() {
        let (mut vault, _, _) = vault();
        let challenge = URL_SAFE_NO_PAD.encode([5u8; 32]);
        let verified = |answer: &Value| unb64(&answer["authenticator_data"])[32] & 0x04 != 0;
        // Made where the site discourages a check: nothing asked, not verified.
        let mut gate = TestGate::new(Check::Pin);
        let (made, _) = passkey_answer(
            &mut vault,
            &mut gate,
            json!({
                "type": "passkey_create",
                "url": "https://shop.example/account",
                "user_id": URL_SAFE_NO_PAD.encode(b"buyer"),
                "user_name": "buyer",
                "challenge": challenge,
                "user_verification": "discouraged",
            }),
        );
        assert_eq!(made["type"], "attestation", "{made}");
        assert!(!verified(&made));
        assert_eq!(gate.closed, 0, "nothing was opened");
        let (listed, _) = passkey_answer(
            &mut vault,
            &mut gate,
            json!({"type": "passkeys", "url": "https://shop.example/"}),
        );
        let id = listed["items"][0]["id"].clone();
        let get = |extra: Value| {
            let mut request = json!({
                "type": "passkey_get",
                "url": "https://shop.example/",
                "id": id,
                "credential": made["credential"],
                "challenge": challenge,
            });
            for (key, value) in extra.as_object().unwrap() {
                request[key.as_str()] = value.clone();
            }
            request
        };
        // Preferred (also when missing or unknown) with a PIN to check: asked first.
        for asked in [
            json!({}),
            json!({"user_verification": "preferred"}),
            json!({"user_verification": "sometimes"}),
        ] {
            let (reply, _) = passkey_answer(&mut vault, &mut gate, get(asked.clone()));
            assert_eq!(reply["code"], "item_locked", "{asked}: {reply}");
        }
        let (signed, _) = passkey_answer(&mut vault, &mut gate, get(json!({"check": "4821"})));
        assert_eq!(signed["type"], "assertion", "{signed}");
        assert!(verified(&signed));
        assert!(!gate.open, "closed again");
        // Required, with a wrong PIN: refused, the try counted.
        let (reply, _) = passkey_answer(
            &mut vault,
            &mut gate,
            get(json!({"user_verification": "required", "check": "0000"})),
        );
        assert_eq!(reply["code"], "wrong_check");
        // Discouraged: signed at once, not verified.
        let (signed, _) = passkey_answer(
            &mut vault,
            &mut gate,
            get(json!({"user_verification": "discouraged"})),
        );
        assert_eq!(signed["type"], "assertion", "{signed}");
        assert!(!verified(&signed));
        // Windows Hello, asked for: verified by it.
        let mut hello = TestGate::new(Check::App);
        hello.hello = true;
        let (signed, _) = passkey_answer(&mut vault, &mut hello, get(json!({"hello": true})));
        assert!(verified(&signed), "{signed}");
        // No way to verify here (only the master password, no Windows Hello): preferred signs
        // as not verified, required leaves the request to the browser.
        let mut none = TestGate::new(Check::App);
        let (signed, _) = passkey_answer(&mut vault, &mut none, get(json!({})));
        assert_eq!(signed["type"], "assertion", "{signed}");
        assert!(!verified(&signed));
        let (reply, _) = passkey_answer(
            &mut vault,
            &mut none,
            get(json!({"user_verification": "required"})),
        );
        assert_eq!(reply["code"], "unsupported");
    }

    #[test]
    fn a_locked_login_asks_for_its_pin_before_its_passkey_is_made_or_signs() {
        let (mut vault, _, work) = vault();
        let mut gate = TestGate::new(Check::Pin);
        let challenge = URL_SAFE_NO_PAD.encode([9u8; 32]);
        let create = |check: Option<&str>| {
            let mut request = json!({
                "type": "passkey_create",
                "url": "https://github.com/settings/security",
                "user_id": URL_SAFE_NO_PAD.encode(b"hubot-id"),
                "user_name": "hubot",
                "challenge": challenge,
            });
            if let Some(pin) = check {
                request["check"] = json!(pin);
            }
            request
        };
        // The login for that page and username is behind the item lock.
        let (reply, answer) = passkey_answer(&mut vault, &mut gate, create(None));
        assert_eq!(
            reply,
            json!({"type": "error", "code": "item_locked", "check": "pin"})
        );
        assert!(answer.passkey_saved.is_none());
        let (made, answer) = passkey_answer(&mut vault, &mut gate, create(Some("4821")));
        assert_eq!(made["type"], "attestation", "{made}");
        assert_eq!(answer.passkey_saved.as_deref(), Some("GitHub (work)"));
        assert!(!gate.open, "closed again");
        let (listed, _) = passkey_answer(
            &mut vault,
            &mut gate,
            json!({"type": "passkeys", "url": "https://github.com/login"}),
        );
        assert_eq!(listed["rp_id"], "github.com");
        assert_eq!(listed["items"][0]["id"], work);
        assert_eq!(listed["items"][0]["locked"], true);
        let get = |check: Option<&str>| {
            let mut request = json!({
                "type": "passkey_get",
                "url": "https://github.com/login",
                "id": work,
                "credential": made["credential"],
                "challenge": challenge,
            });
            if let Some(pin) = check {
                request["check"] = json!(pin);
            }
            request
        };
        assert!(wants_hello(br#"{"type":"passkey_get","url":"u","id":"i","credential":"c","challenge":"x","hello":true}"#));
        let (reply, _) = passkey_answer(&mut vault, &mut gate, get(None));
        assert_eq!(reply["code"], "item_locked");
        let (reply, _) = passkey_answer(&mut vault, &mut gate, get(Some("0000")));
        assert_eq!(reply["code"], "wrong_check");
        let (signed, answer) = passkey_answer(&mut vault, &mut gate, get(Some("4821")));
        assert_eq!(signed["type"], "assertion", "{signed}");
        assert_eq!(answer.passkey_used.as_deref(), Some("GitHub (work)"));
        assert!(!gate.open);
    }

    #[test]
    fn a_locked_vault_gives_nothing() {
        let (status, _) = ask(None, json!({"type": "status"}));
        assert_eq!(
            status,
            json!({"type": "status", "locked": true, "name": ""})
        );
        for request in [
            json!({"type": "logins", "url": "https://github.com/"}),
            json!({"type": "fill", "url": "https://github.com/", "id": "00"}),
            json!({"type": "vault"}),
            json!({"type": "reveal", "id": "00"}),
            json!({"type": "copy", "id": "00", "what": "password"}),
            json!({"type": "save", "url": "https://github.com/", "username": "a", "password": "b"}),
        ] {
            let (reply, filled) = ask(None, request);
            assert_eq!(reply, json!({"type": "error", "code": "locked"}));
            assert!(filled.is_none());
        }
    }

    #[test]
    fn logins_are_listed_for_the_exact_site_without_passwords() {
        let (mut vault, github, work) = vault();
        let (reply, filled) = ask(
            Some(&mut vault),
            json!({"type": "logins", "url": "https://github.com/login?return_to=x"}),
        );
        assert!(filled.is_none());
        assert_eq!(
            reply,
            json!({"type": "logins", "origin": "https://github.com", "check": "app", "hello": false, "items": [
                {"id": github, "title": "GitHub", "username": "octocat", "locked": false, "has_code": false},
                {"id": work, "title": "GitHub (work)", "username": "hubot", "locked": true, "has_code": false},
            ]})
        );
        assert!(!reply.to_string().contains("secret"));
        let (other, _) = ask(
            Some(&mut vault),
            json!({"type": "logins", "url": "https://gist.github.com/"}),
        );
        assert_eq!(other["items"], json!([]));
        let (http, _) = ask(
            Some(&mut vault),
            json!({"type": "logins", "url": "http://github.com/login"}),
        );
        assert_eq!(http, json!({"type": "error", "code": "insecure_page"}));
        let (internal, _) = ask(
            Some(&mut vault),
            json!({"type": "logins", "url": "chrome://settings"}),
        );
        assert_eq!(internal, json!({"type": "error", "code": "not_a_website"}));
    }

    #[test]
    fn a_password_leaves_only_for_its_own_site() {
        let (mut vault, github, work) = vault();
        let (reply, filled) = ask(
            Some(&mut vault),
            json!({"type": "fill", "url": "https://github.com/session", "id": github}),
        );
        assert_eq!(
            reply,
            json!({"type": "fill", "origin": "https://github.com",
                   "username": "octocat", "password": "gh-secret"})
        );
        assert_eq!(filled.as_deref(), Some("GitHub"));

        // Asked from any other page (a phishing look-alike, a subdomain, plain http), the
        // same id gives nothing.
        for url in [
            "https://github.com.evil.example/login",
            "https://github.com@evil.example/",
            "https://gist.github.com/",
            "https://bank.example/",
            "https://github.com:8443/",
        ] {
            let (reply, filled) = ask(
                Some(&mut vault),
                json!({"type": "fill", "url": url, "id": github}),
            );
            assert_eq!(reply, json!({"type": "error", "code": "no_match"}), "{url}");
            assert!(filled.is_none());
        }
        let (http, _) = ask(
            Some(&mut vault),
            json!({"type": "fill", "url": "http://github.com/", "id": github}),
        );
        assert_eq!(http, json!({"type": "error", "code": "insecure_page"}));
        // Unknown and malformed ids look the same as another site's login.
        for id in ["", "zz", &"0".repeat(32)] {
            let (reply, _) = ask(
                Some(&mut vault),
                json!({"type": "fill", "url": "https://github.com/", "id": id}),
            );
            assert_eq!(reply, json!({"type": "error", "code": "no_match"}));
        }
        // Behind the item lock: not until it is opened in the app.
        let (locked, filled) = ask(
            Some(&mut vault),
            json!({"type": "fill", "url": "https://github.com/", "id": work}),
        );
        assert_eq!(
            locked,
            json!({"type": "error", "code": "item_locked", "check": "app"})
        );
        assert!(filled.is_none());
        // With the master password as the check, nothing typed in the extension opens it.
        let (still, _) = ask(
            Some(&mut vault),
            json!({"type": "fill", "url": "https://github.com/", "id": work, "check": "4821"}),
        );
        assert_eq!(
            still,
            json!({"type": "error", "code": "item_locked", "check": "app"})
        );
    }

    #[test]
    fn a_pin_typed_in_the_extension_opens_one_login_and_is_counted() {
        let (mut vault, github, work) = vault();
        let mut gate = TestGate::new(Check::Pin);
        let fill = |id: &str, pin: Option<&str>, url: &str| match pin {
            Some(pin) => json!({"type": "fill", "url": url, "id": id, "check": pin}),
            None => json!({"type": "fill", "url": url, "id": id}),
        };
        let site = "https://github.com/login";
        let (listed, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "logins", "url": site}),
        );
        assert_eq!(listed["check"], "pin");
        // Without the PIN the extension is told what to ask for.
        let (reply, _) = ask_with(Some(&mut vault), &mut gate, fill(&work, None, site));
        assert_eq!(
            reply,
            json!({"type": "error", "code": "item_locked", "check": "pin"})
        );
        // A PIN is never tried for a login of another site: no guessing through a fake page.
        let (reply, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            fill(&work, Some("0000"), "https://github.com.evil.example/"),
        );
        assert_eq!(reply, json!({"type": "error", "code": "no_match"}));
        assert_eq!(gate.tries, 0);
        // Wrong, then right: the login is handed out and the lock is closed again.
        let (reply, filled) =
            ask_with(Some(&mut vault), &mut gate, fill(&work, Some("0000"), site));
        assert_eq!(
            reply,
            json!({"type": "error", "code": "wrong_check", "check": "pin", "left": 2})
        );
        assert!(filled.is_none());
        let (reply, filled) =
            ask_with(Some(&mut vault), &mut gate, fill(&work, Some("4821"), site));
        assert_eq!(reply["password"], "work-secret");
        assert_eq!(filled.as_deref(), Some("GitHub (work)"));
        assert!(!gate.open && gate.closed == 1, "closed again right away");
        // An unlocked login needs no PIN and tries none.
        let (reply, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            fill(&github, Some("0000"), site),
        );
        assert_eq!(reply["password"], "gh-secret");
        assert_eq!(gate.tries, 1);
        // Windows Hello, verified by the app, opens it without anything typed; when the
        // app could not verify, the extension is told to ask for the PIN.
        let with_hello = json!({"type": "fill", "url": site, "id": work, "hello": true});
        assert!(wants_hello(with_hello.to_string().as_bytes()));
        assert!(!wants_hello(fill(&work, None, site).to_string().as_bytes()));
        assert!(!wants_hello(
            b"{\"type\":\"logins\",\"url\":\"x\",\"hello\":true}"
        ));
        // Saving a new login never asks for Windows Hello.
        assert!(!wants_hello(
            br#"{"type":"save","url":"https://x.example/","username":"u","password":"p","hello":true}"#
        ));
        let (reply, _) = ask_with(Some(&mut vault), &mut gate, with_hello.clone());
        assert_eq!(
            reply,
            json!({"type": "error", "code": "item_locked", "check": "pin"})
        );
        gate.hello = true;
        let (listed, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "logins", "url": site}),
        );
        assert_eq!(listed["hello"], true);
        let (reply, filled) = ask_with(Some(&mut vault), &mut gate, with_hello);
        assert_eq!(reply["password"], "work-secret");
        assert!(filled.is_some() && !gate.open && gate.closed == 2);
        gate.hello = false;
        // Too many wrong tries: the vault is reported locked.
        ask_with(Some(&mut vault), &mut gate, fill(&work, Some("1"), site));
        let (reply, _) = ask_with(Some(&mut vault), &mut gate, fill(&work, Some("2"), site));
        assert_eq!(reply, json!({"type": "error", "code": "locked"}));
    }

    #[test]
    fn secrets_sealed_by_the_item_guard_are_never_handed_out() {
        let (mut vault, github, _) = vault();
        vault
            .set_item_guard(true, GuardCheck::Pin, Some("482193"), None)
            .unwrap();
        vault.lock_secrets();
        // Even a gate that says "not locked" can't give what the vault keeps sealed.
        struct Careless;
        impl Gate for Careless {
            fn check(&self, _: &Vault) -> Check {
                Check::App
            }
            fn locked(&self, _: &Vault, _: &ItemData) -> bool {
                false
            }
            fn hello(&self, _: &Vault) -> bool {
                true
            }
            fn open_hello(&mut self, _: &mut Vault) -> bool {
                true
            }
            fn open(&mut self, _: &mut Vault, _: &str) -> Opened {
                Opened::Yes
            }
            fn close(&mut self, _: &mut Vault) {}
            fn remember(&mut self, _: Zeroizing<String>, _: String) -> String {
                String::new()
            }
            fn take(&mut self, _: &str) -> Option<Kept> {
                None
            }
        }
        let request = json!({"type": "fill", "url": "https://github.com/", "id": github});
        let reply = answer(
            request.to_string().as_bytes(),
            Some(&mut vault),
            &mut Careless,
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.bytes).unwrap(),
            json!({"type": "error", "code": "item_locked", "check": "app"})
        );
        assert!(vault.unlock_secrets("482193").unwrap());
        let reply = answer(
            request.to_string().as_bytes(),
            Some(&mut vault),
            &mut Careless,
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.bytes).unwrap()["password"],
            "gh-secret"
        );
    }

    #[test]
    fn the_vault_is_listed_without_secrets_and_opened_one_login_at_a_time() {
        let (mut vault, github, work) = vault();
        let mut gate = TestGate::new(Check::Pin);
        let (listed, _) = ask_with(Some(&mut vault), &mut gate, json!({"type": "vault"}));
        assert_eq!(listed["type"], "vault");
        // Logins only (the note is left out), sorted, and nothing secret in them.
        let titles: Vec<&str> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["title"].as_str().unwrap())
            .collect();
        assert_eq!(titles, ["Bank", "GitHub", "GitHub (work)"]);
        assert_eq!(
            listed["items"][2],
            json!({"id": work, "title": "GitHub (work)", "username": "hubot",
                   "site": "github.com", "locked": true, "has_password": true, "has_code": false})
        );
        assert!(!listed.to_string().contains("secret"));

        // Showing a password: asked for the PIN when locked, closed again after.
        let (reply, shown) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "reveal", "id": work}),
        );
        assert_eq!(
            reply,
            json!({"type": "error", "code": "item_locked", "check": "pin"})
        );
        assert!(shown.is_none());
        let (reply, shown) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "reveal", "id": work, "check": "4821"}),
        );
        assert_eq!(reply, json!({"type": "reveal", "password": "work-secret"}));
        assert_eq!(shown.as_deref(), Some("GitHub (work)"));
        assert!(!gate.open && gate.closed == 1);

        // Copying: the app gets the value, the extension only hears that it was copied.
        let copy = json!({"type": "copy", "id": github, "what": "password"});
        let answer = answer(copy.to_string().as_bytes(), Some(&mut vault), &mut gate);
        assert_eq!(
            serde_json::from_slice::<Value>(&answer.bytes).unwrap(),
            json!({"type": "copied", "seconds": 30})
        );
        let copied = answer.copy.unwrap();
        assert_eq!(copied.what, CopyWhat::Password);
        assert_eq!(copied.value.as_str(), "gh-secret");
        // A username needs no check even on a locked login.
        let copy = json!({"type": "copy", "id": work, "what": "username"});
        let answer = super::answer(copy.to_string().as_bytes(), Some(&mut vault), &mut gate);
        assert_eq!(answer.copy.unwrap().value.as_str(), "hubot");
        // No one-time code saved: nothing to copy.
        let (reply, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "copy", "id": github, "what": "code"}),
        );
        assert_eq!(reply, json!({"type": "error", "code": "no_match"}));
    }

    #[test]
    fn a_login_typed_in_a_page_is_saved_once_for_its_site() {
        let (mut vault, ..) = vault();
        let mut gate = TestGate::new(Check::Pin);
        let before = vault.len();
        let save = |url: &str, user: &str| json!({"type": "save", "url": url, "username": user, "password": "new-secret"});
        let request = save("https://www.shop.example/account/login", "me@example.com");
        let answer = answer(request.to_string().as_bytes(), Some(&mut vault), &mut gate);
        assert_eq!(
            serde_json::from_slice::<Value>(&answer.bytes).unwrap(),
            json!({"type": "saved", "existing": false})
        );
        assert_eq!(answer.saved.as_deref(), Some("shop.example"));
        assert_eq!(vault.len(), before + 1);
        // It is offered on that site from now on, and only there.
        let (listed, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "logins", "url": "https://www.shop.example/"}),
        );
        assert_eq!(listed["items"][0]["username"], "me@example.com");
        // The same username again adds nothing.
        let (again, _) = ask_with(Some(&mut vault), &mut gate, request);
        assert_eq!(again, json!({"type": "saved", "existing": true}));
        assert_eq!(vault.len(), before + 1);
        // Never from a page without https, and never an empty password.
        let (http, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            save("http://shop.example/", "x"),
        );
        assert_eq!(http, json!({"type": "error", "code": "insecure_page"}));
        let (empty, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "save", "url": "https://shop.example/", "username": "x", "password": ""}),
        );
        assert_eq!(empty, json!({"type": "error", "code": "bad_request"}));
        // Made in the extension's window, with a name of its own.
        let request = json!({"type": "save", "url": "https://forum.example", "title": "Forum",
                             "username": "me", "password": "made-here"});
        let answer = super::answer(request.to_string().as_bytes(), Some(&mut vault), &mut gate);
        assert_eq!(answer.saved.as_deref(), Some("Forum"));
        // Nothing longer than a form would hold is stored.
        for (field, length) in [("title", 257), ("username", 1025), ("password", 1025)] {
            let mut request = json!({"type": "save", "url": "https://long.example",
                                     "title": "Long", "username": "me", "password": "pw"});
            request[field] = json!("x".repeat(length));
            let answer = super::answer(request.to_string().as_bytes(), Some(&mut vault), &mut gate);
            assert!(answer.saved.is_none(), "{field}");
        }
    }

    #[test]
    fn saving_under_an_item_lock_that_covers_everything_asks_nothing() {
        let (mut vault, ..) = vault();
        vault
            .set_item_guard(true, GuardCheck::Pin, Some("482193"), None)
            .unwrap();
        vault.lock_secrets();
        /// The real lock, as the app would drive it.
        struct Real;
        impl Gate for Real {
            fn check(&self, _: &Vault) -> Check {
                Check::Pin
            }
            fn locked(&self, vault: &Vault, item: &ItemData) -> bool {
                vault.guards(item)
            }
            fn hello(&self, _: &Vault) -> bool {
                false
            }
            fn open_hello(&mut self, _: &mut Vault) -> bool {
                false
            }
            fn open(&mut self, vault: &mut Vault, secret: &str) -> Opened {
                if vault.unlock_secrets(secret).unwrap_or(false) {
                    Opened::Yes
                } else {
                    Opened::No { left: 2 }
                }
            }
            fn close(&mut self, vault: &mut Vault) {
                vault.lock_secrets();
            }
            fn remember(&mut self, _: Zeroizing<String>, _: String) -> String {
                String::new()
            }
            fn take(&mut self, _: &str) -> Option<Kept> {
                None
            }
        }
        let before = vault.len();
        let save = json!({"type": "save", "url": "https://shop.example/",
                          "username": "me", "password": "new-secret"});
        let reply = answer(save.to_string().as_bytes(), Some(&mut vault), &mut Real);
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.bytes).unwrap(),
            json!({"type": "saved", "existing": false})
        );
        assert_eq!(reply.saved.as_deref(), Some("shop.example"));
        assert!(!vault.secrets_open());
        assert_eq!(vault.len(), before + 1);
        // Sealed under the item lock the next time it opens.
        assert_eq!(vault.pending_seal().unwrap(), 1);
        assert!(vault.unlock_secrets("482193").unwrap());
        assert_eq!(vault.seal_pending().unwrap(), 1);
        vault.lock_secrets();
        let saved = vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .find(|item| item.title == "shop.example")
            .unwrap();
        assert!(saved.is_locked());
    }

    #[test]
    fn passwords_are_generated_by_the_app_and_kept_only_when_used() {
        let (mut vault, ..) = vault();
        let mut gate = TestGate::new(Check::Pin);
        // A site that allows 12 characters, letters, digits and only "-" and "_".
        let request = json!({"type": "generate", "length": 12, "symbols": "-_ab<>",
                             "url": "https://www.shop.example/register"});
        let (made, _) = ask_with(Some(&mut vault), &mut gate, request.clone());
        let password = made["password"].as_str().unwrap().to_owned();
        assert_eq!(password.chars().count(), 12);
        assert!(
            password
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_<>".contains(c)),
            "{password}"
        );
        assert!(made["bits"].as_u64().unwrap() > 60);
        let id = made["id"].as_str().unwrap().to_owned();
        // Without symbols, digits or capitals when asked.
        let (plain, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "generate", "length": 30, "upper": false, "symbols": false}),
        );
        assert!(
            plain["password"]
                .as_str()
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        // Nothing to draw from: refused.
        let (none, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "generate", "lower": false, "upper": false, "digits": false,
                   "symbols": false}),
        );
        assert_eq!(none, json!({"type": "error", "code": "bad_request"}));
        // Used: the app keeps it (with its site) and copies it when asked; only once.
        let keep = json!({"type": "keep", "id": id, "copy": true});
        let reply = answer(keep.to_string().as_bytes(), Some(&mut vault), &mut gate);
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.bytes).unwrap(),
            json!({"type": "copied", "seconds": 30})
        );
        let kept = reply.kept.unwrap();
        assert_eq!(kept.password.as_str(), password);
        assert_eq!(kept.site, "www.shop.example");
        assert_eq!(reply.copy.unwrap().value.as_str(), password);
        let (again, _) = ask_with(Some(&mut vault), &mut gate, keep);
        assert_eq!(again, json!({"type": "error", "code": "no_match"}));
        // A passphrase: words from the bundled list, capitalised, with a digit.
        let (phrase, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "generate", "words": 5, "separator": ".", "capitalize": true,
                   "number": true}),
        );
        let text = phrase["password"].as_str().unwrap();
        assert_eq!(text.split('.').count(), 5, "{text}");
        assert!(text.chars().any(|c| c.is_ascii_digit()));
        assert!(text.chars().any(|c| c.is_ascii_uppercase()));
        assert!(phrase["bits"].as_u64().unwrap() > 60);
        // Through the vault's own answer, a locked vault refuses it…
        let (locked, _) = ask(None, request);
        assert_eq!(locked, json!({"type": "error", "code": "locked"}));
    }

    /// Holds generated passwords without a vault (the locked app).
    #[derive(Default)]
    struct Holder(Vec<(String, Kept)>);

    impl Held for Holder {
        fn remember(&mut self, password: Zeroizing<String>, site: String) -> String {
            let id = format!("h{}", self.0.len());
            self.0.push((id.clone(), Kept { password, site }));
            id
        }
        fn take(&mut self, id: &str) -> Option<Kept> {
            let at = self.0.iter().position(|(held, _)| held == id)?;
            Some(self.0.remove(at).1)
        }
    }

    #[test]
    fn the_generator_needs_no_vault() {
        let mut held = Holder::default();
        let ask = |held: &mut Holder, request: Value| {
            answer_generator(request.to_string().as_bytes(), held)
                .map(|answer| serde_json::from_slice::<Value>(&answer.bytes).unwrap())
        };
        let made = ask(
            &mut held,
            json!({"type": "generate", "length": 16, "url": "https://shop.example/join"}),
        )
        .unwrap();
        assert_eq!(made["type"], "generated");
        assert_eq!(made["password"].as_str().unwrap().len(), 16);
        let id = made["id"].as_str().unwrap().to_owned();
        let kept = answer_generator(
            json!({"type": "keep", "id": id, "copy": true})
                .to_string()
                .as_bytes(),
            &mut held,
        )
        .unwrap();
        assert_eq!(kept.kept.unwrap().site, "shop.example");
        assert!(kept.copy.is_some());
        // Nothing else is answered here.
        assert!(ask(&mut held, json!({"type": "vault"})).is_none());
        assert!(ask(&mut held, json!({"type": "status"})).is_none());
        assert!(answer_generator(b"not json", &mut held).is_none());
    }

    #[test]
    fn a_one_time_code_leaves_only_for_its_own_site() {
        let (mut vault, github, work) = vault();
        let id = ItemId::from_hex(&github).unwrap();
        let mut item = vault.get_item(&id).unwrap();
        item.totp = "JBSWY3DPEHPK3PXP".into();
        vault.update_item(&id, &item).unwrap();

        let (listed, _) = ask(
            Some(&mut vault),
            json!({"type": "logins", "url": "https://github.com/"}),
        );
        assert_eq!(listed["items"][0]["has_code"], json!(true));
        assert_eq!(listed["items"][1]["has_code"], json!(false));

        let (reply, filled) = ask(
            Some(&mut vault),
            json!({"type": "code", "url": "https://github.com/sessions/two-factor", "id": github}),
        );
        assert_eq!(reply["type"], json!("code"));
        assert_eq!(reply["origin"], json!("https://github.com"));
        let code = reply["code"].as_str().unwrap();
        assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()));
        assert!((1..=30).contains(&reply["seconds"].as_u64().unwrap()));
        assert_eq!(filled.as_deref(), Some("GitHub"));

        for url in [
            "https://github.com.evil.example/",
            "https://gist.github.com/",
        ] {
            let (reply, filled) = ask(
                Some(&mut vault),
                json!({"type": "code", "url": url, "id": github}),
            );
            assert_eq!(reply, json!({"type": "error", "code": "no_match"}), "{url}");
            assert!(filled.is_none());
        }
        // A login with no code, once opened, has nothing to give.
        let mut gate = TestGate::new(Check::Pin);
        let (locked, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "code", "url": "https://github.com/", "id": work}),
        );
        assert_eq!(
            locked,
            json!({"type": "error", "code": "item_locked", "check": "pin"})
        );
        let (none, _) = ask_with(
            Some(&mut vault),
            &mut gate,
            json!({"type": "code", "url": "https://github.com/", "id": work, "check": "4821"}),
        );
        assert_eq!(none, json!({"type": "error", "code": "no_match"}));
        assert_eq!(gate.closed, 1);
    }

    #[test]
    fn a_changed_password_is_noticed_and_updated_with_its_history() {
        let (mut vault, github, work) = vault();
        let mut gate = TestGate::new(Check::Pin);
        let send = |vault: &mut Vault, gate: &mut TestGate, request: Value| {
            let answer = answer(request.to_string().as_bytes(), Some(vault), gate);
            let reply: Value = serde_json::from_slice(&answer.bytes).unwrap();
            (reply, answer.updated)
        };
        let changed = |username: &str, password: &str| {
            json!({"type": "changed", "url": "https://github.com/login",
                   "username": username, "password": password})
        };

        let stamp = |vault: &Vault, id: &str| stamp_of(vault, &ItemId::from_hex(id).unwrap());
        let (same, _) = send(&mut vault, &mut gate, changed("octocat", "gh-secret"));
        assert_eq!(
            same,
            json!({"type": "changed", "id": github, "changed": false, "stamp": stamp(&vault, &github)})
        );
        let (other, _) = send(&mut vault, &mut gate, changed("octocat", "gh-new"));
        assert_eq!(
            other,
            json!({"type": "changed", "id": github, "changed": true, "stamp": stamp(&vault, &github)})
        );
        // Behind the item lock the app can't tell, and doesn't open it to find out.
        let (unknown, _) = send(&mut vault, &mut gate, changed("hubot", "guess"));
        assert_eq!(
            unknown,
            json!({"type": "changed", "id": work, "changed": null, "stamp": stamp(&vault, &work)})
        );
        assert_eq!(gate.closed, 0);
        let (nobody, _) = send(&mut vault, &mut gate, changed("someone", "x"));
        assert_eq!(nobody, json!({"type": "error", "code": "no_match"}));

        let update = |id: &str, url: &str, password: &str| json!({"type": "update", "url": url, "id": id, "password": password});
        let (wrong_site, updated) = send(
            &mut vault,
            &mut gate,
            update(&github, "https://bank.example/", "gh-new"),
        );
        assert_eq!(wrong_site, json!({"type": "error", "code": "no_match"}));
        assert!(updated.is_none());
        let (done, updated) = send(
            &mut vault,
            &mut gate,
            update(&github, "https://github.com/", "gh-new"),
        );
        assert_eq!(done, json!({"type": "updated", "changed": true}));
        assert_eq!(updated.as_deref(), Some("GitHub"));
        let item = vault.get_item(&ItemId::from_hex(&github).unwrap()).unwrap();
        assert_eq!(item.password, "gh-new");
        assert_eq!(item.password_history.last().unwrap().password, "gh-secret");
        let (again, updated) = send(
            &mut vault,
            &mut gate,
            update(&github, "https://github.com/", "gh-new"),
        );
        assert_eq!(again, json!({"type": "updated", "changed": false}));
        assert!(updated.is_none());

        // A locked login is opened for the change only, then closed again.
        let (locked, _) = send(
            &mut vault,
            &mut gate,
            update(&work, "https://github.com/", "work-new"),
        );
        assert_eq!(
            locked,
            json!({"type": "error", "code": "item_locked", "check": "pin"})
        );
        let mut with_pin = update(&work, "https://github.com/", "work-new");
        with_pin["check"] = json!("4821");
        let (opened, updated) = send(&mut vault, &mut gate, with_pin);
        assert_eq!(opened, json!({"type": "updated", "changed": true}));
        assert_eq!(updated.as_deref(), Some("GitHub (work)"));
        assert_eq!(gate.closed, 1);
        let item = vault.get_item(&ItemId::from_hex(&work).unwrap()).unwrap();
        assert_eq!(item.password, "work-new");
    }

    #[test]
    fn an_update_offered_for_one_version_of_a_login_does_not_overwrite_a_later_one() {
        let (mut vault, github, work) = vault();
        let mut gate = TestGate::new(Check::Pin);
        let send = |vault: &mut Vault, gate: &mut TestGate, request: Value| {
            let answer = answer(request.to_string().as_bytes(), Some(vault), gate);
            let reply: Value = serde_json::from_slice(&answer.bytes).unwrap();
            (reply, answer.updated)
        };
        let (offered, _) = send(
            &mut vault,
            &mut gate,
            json!({"type": "changed", "url": "https://github.com/login",
                   "username": "octocat", "password": "typed-for-octocat"}),
        );
        assert_eq!(offered["changed"], true);
        let bound = |stamp: &Value, username: &str| {
            json!({"type": "update", "url": "https://github.com/", "id": github,
                   "password": "typed-for-octocat", "username": username, "stamp": stamp})
        };

        // Edited in the app meanwhile (a newer password, a sync merge): not overwritten.
        let id = ItemId::from_hex(&github).unwrap();
        let mut item = vault.get_item(&id).unwrap();
        item.password = "newer-from-sync".into();
        vault.update_item(&id, &item).unwrap();
        let (refused, updated) = send(&mut vault, &mut gate, bound(&offered["stamp"], "octocat"));
        assert_eq!(refused, json!({"type": "error", "code": "changed_since"}));
        assert!(updated.is_none());
        assert_eq!(vault.get_item(&id).unwrap().password, "newer-from-sync");

        // Another username now (renamed to someone else's account): not overwritten either.
        let mut item = vault.get_item(&id).unwrap();
        item.username = "someone-else".into();
        vault.update_item(&id, &item).unwrap();
        let (now, _) = send(
            &mut vault,
            &mut gate,
            json!({"type": "changed", "url": "https://github.com/login",
                   "username": "someone-else", "password": "typed-for-octocat"}),
        );
        let (refused, _) = send(&mut vault, &mut gate, bound(&now["stamp"], "octocat"));
        assert_eq!(refused, json!({"type": "error", "code": "changed_since"}));
        assert_eq!(vault.get_item(&id).unwrap().password, "newer-from-sync");

        // The version offered, for the username offered: replaced.
        let (done, updated) = send(&mut vault, &mut gate, bound(&now["stamp"], "someone-else"));
        assert_eq!(done, json!({"type": "updated", "changed": true}));
        assert_eq!(updated.as_deref(), Some("GitHub"));
        assert_eq!(vault.get_item(&id).unwrap().password, "typed-for-octocat");

        // A locked login is refused before its PIN is asked for, and a bound update of an id
        // of another site looks like one that does not exist.
        let (locked, _) = send(
            &mut vault,
            &mut gate,
            json!({"type": "changed", "url": "https://github.com/login",
                   "username": "hubot", "password": "work-typed"}),
        );
        let work_id = ItemId::from_hex(&work).unwrap();
        let mut item = vault.get_item(&work_id).unwrap();
        item.title = "GitHub (work, renamed)".into();
        vault.update_item(&work_id, &item).unwrap();
        let (refused, _) = send(
            &mut vault,
            &mut gate,
            json!({"type": "update", "url": "https://github.com/", "id": work,
                   "password": "work-typed", "username": "hubot", "stamp": locked["stamp"]}),
        );
        assert_eq!(refused["code"], "changed_since");
        assert_eq!(gate.closed, 0, "the item lock was not opened");
        let (elsewhere, _) = send(
            &mut vault,
            &mut gate,
            json!({"type": "update", "url": "https://bank.example/", "id": github,
                   "password": "x", "username": "someone-else", "stamp": now["stamp"]}),
        );
        assert_eq!(elsewhere["code"], "no_match");
    }

    #[test]
    fn anything_else_is_a_bad_request() {
        let (mut vault, ..) = vault();
        for raw in [
            &b"not json"[..],
            br#"{"type":"export"}"#,
            br#"{"type":"logins"}"#,
            br#"{"type":"status","extra":1}"#,
            br#"{"type":"fill","url":"https://github.com/"}"#,
            br#"{"type":"fill","url":"https://github.com/","id":"00","check":1}"#,
            br#"{"type":"fill","url":"https://github.com/","id":"00","pin":"1"}"#,
            br#"[]"#,
            b"",
        ] {
            let reply = answer(raw, Some(&mut vault), &mut TestGate::new(Check::Pin));
            assert_eq!(
                serde_json::from_slice::<Value>(&reply.bytes).unwrap(),
                json!({"type": "error", "code": "bad_request"}),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
    }
}
