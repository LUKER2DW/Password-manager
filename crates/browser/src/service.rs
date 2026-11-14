//! How the app answers the extension from its (maybe locked) vault.

use vault_core::{
    ItemData, ItemId, ItemKind, Vault,
    generator::{self, PassphraseOptions, PasswordOptions, WordCase},
    totp::Totp,
};
use zeroize::Zeroizing;

use crate::{
    origin::{Origin, PageProblem, item_matches},
    protocol::{
        Check, CopyWhat, Credentials, ErrorCode, GeneratedPassword, LoginEntry, Request, Response,
        Revealed, Secret, Symbols, VaultEntry,
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
    /// A generated password the person used: the app adds it to its history.
    pub kept: Option<Kept>,
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
            | Request::Reveal { hello: true, .. }
            | Request::Copy { hello: true, .. }
            | Request::Save { hello: true, .. })
    )
}

/// Answers one raw message. `vault` is `None` while locked.
pub fn answer(message: &[u8], vault: Option<&mut Vault>, gate: &mut dyn Gate) -> Answer {
    let outcome = match serde_json::from_slice::<Request>(message) {
        Ok(request) => respond(request, vault, gate),
        Err(_) => error(ErrorCode::BadRequest).into(),
    };
    // Serializing cannot fail for these types; an empty answer would only confuse the caller.
    let bytes = serde_json::to_vec(&outcome.response)
        .unwrap_or_else(|_| br#"{"type":"error","code":"bad_request"}"#.to_vec());
    Answer {
        bytes: Zeroizing::new(bytes),
        filled: outcome.filled,
        copy: outcome.copy,
        saved: outcome.saved,
        kept: outcome.kept,
    }
}

struct Outcome {
    response: Response,
    filled: Option<String>,
    copy: Option<Copy>,
    saved: Option<String>,
    kept: Option<Kept>,
}

impl From<Response> for Outcome {
    fn from(response: Response) -> Self {
        Self {
            response,
            filled: None,
            copy: None,
            saved: None,
            kept: None,
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

fn page_origin(url: &str) -> Result<Origin, Response> {
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
    let id = ItemId::from_hex(id).ok_or_else(|| error(ErrorCode::NoMatch))?;
    let read = |vault: &Vault| {
        vault
            .get_item(&id)
            .ok()
            .filter(|item| item.kind == ItemKind::Login && belongs(item))
    };
    let item = read(vault).ok_or_else(|| error(ErrorCode::NoMatch))?;
    if !(item.is_locked() || gate.locked(vault, &item)) {
        return Ok(item);
    }
    let kind = gate.check(vault);
    open_gate(vault, gate, check, hello)?;
    // Read once while open, then closed again: only this login was decrypted.
    let opened = read(vault).filter(|item| !item.is_locked());
    gate.close(vault);
    opened.ok_or_else(|| item_locked(kind))
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
        Request::Logins { url } | Request::Fill { url, .. } | Request::Save { url, .. } => {
            match page_origin(url) {
                Ok(origin) => Some(origin),
                Err(response) => return response.into(),
            }
        }
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
            if password.as_str().is_empty() {
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
                return Response::Saved { existing: true }.into();
            }
            let host = origin.host();
            let named = title.as_deref().map(str::trim).filter(|t| !t.is_empty());
            let title = named.unwrap_or_else(|| host.strip_prefix("www.").unwrap_or(host));
            let item = ItemData::login(title, &username, password.as_str(), origin.as_str());
            let opened = vault.needs_unlock_to_store(&item);
            if opened && let Err(response) = open_gate(vault, gate, check, hello) {
                return response.into();
            }
            let added = vault.add_item(&item);
            if opened {
                gate.close(vault);
            }
            match added {
                Ok(_) => Outcome {
                    saved: Some(item.title.clone()),
                    ..Response::Saved { existing: false }.into()
                },
                Err(_) => error(ErrorCode::BadRequest).into(),
            }
        }
        (
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
            },
            _,
        ) => {
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
            let id = gate.remember(password, site);
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
        (Request::Keep { id, copy }, _) => match gate.take(&id) {
            Some(kept) => Outcome {
                copy: copy.then(|| Copy {
                    what: CopyWhat::Password,
                    value: kept.password.clone(),
                }),
                kept: Some(kept),
                ..if copy {
                    Response::Copied {
                        seconds: gate.clipboard_seconds(),
                    }
                } else {
                    Response::Kept {}
                }
                .into()
            },
            None => error(ErrorCode::NoMatch).into(),
        },
        // A page request always has its origin by now.
        _ => error(ErrorCode::BadRequest).into(),
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
                {"id": github, "title": "GitHub", "username": "octocat", "locked": false},
                {"id": work, "title": "GitHub (work)", "username": "hubot", "locked": true},
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
    }

    #[test]
    fn saving_under_an_item_lock_that_covers_everything_asks_for_it() {
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
        let mut save = json!({"type": "save", "url": "https://shop.example/",
                              "username": "me", "password": "new-secret"});
        let reply = answer(save.to_string().as_bytes(), Some(&mut vault), &mut Real);
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.bytes).unwrap(),
            json!({"type": "error", "code": "item_locked", "check": "pin"})
        );
        assert_eq!(vault.len(), before);
        save["check"] = json!("482193");
        let reply = answer(save.to_string().as_bytes(), Some(&mut vault), &mut Real);
        assert_eq!(reply.saved.as_deref(), Some("shop.example"));
        assert!(!vault.secrets_open(), "locked again after the save");
        assert_eq!(vault.len(), before + 1);
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
        // Locked vault: no generator either.
        let (locked, _) = ask(None, request);
        assert_eq!(locked, json!({"type": "error", "code": "locked"}));
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
