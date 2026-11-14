//! How the app answers the extension from its (maybe locked) vault.

use vault_core::{ItemData, ItemId, ItemKind, Vault};
use zeroize::Zeroizing;

use crate::{
    origin::{Origin, PageProblem, item_matches},
    protocol::{Check, Credentials, ErrorCode, LoginEntry, Request, Response},
};

/// The answer to one message, as JSON bytes (wiped when dropped: it may hold a password),
/// and the title of the login that was handed out, if one was.
#[derive(Debug)]
pub struct Answer {
    pub bytes: Zeroizing<Vec<u8>>,
    pub filled: Option<String>,
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

/// Whether a message asks for a login to be opened with Windows Hello. The app looks before
/// answering, because the system's prompt must not block its window.
pub fn wants_hello(message: &[u8]) -> bool {
    matches!(
        serde_json::from_slice::<Request>(message),
        Ok(Request::Fill { hello: true, .. })
    )
}

/// Answers one raw message. `vault` is `None` while locked.
pub fn answer(message: &[u8], vault: Option<&mut Vault>, gate: &mut dyn Gate) -> Answer {
    let (response, filled) = match serde_json::from_slice::<Request>(message) {
        Ok(request) => respond(request, vault, gate),
        Err(_) => (error(ErrorCode::BadRequest), None),
    };
    // Serializing cannot fail for these types; an empty answer would only confuse the caller.
    let bytes = serde_json::to_vec(&response)
        .unwrap_or_else(|_| br#"{"type":"error","code":"bad_request"}"#.to_vec());
    Answer {
        bytes: Zeroizing::new(bytes),
        filled,
    }
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

fn respond(
    request: Request,
    vault: Option<&mut Vault>,
    gate: &mut dyn Gate,
) -> (Response, Option<String>) {
    match request {
        Request::Status {} => (
            Response::Status {
                locked: vault.is_none(),
                name: vault.map_or_else(String::new, |v| v.settings().name.clone()),
            },
            None,
        ),
        Request::Logins { url } => {
            let origin = match page_origin(&url) {
                Ok(origin) => origin,
                Err(response) => return (response, None),
            };
            let Some(vault) = vault else {
                return (error(ErrorCode::Locked), None);
            };
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
            (
                Response::Logins {
                    origin: origin.as_str().to_owned(),
                    check: gate.check(vault),
                    hello: gate.hello(vault),
                    items,
                },
                None,
            )
        }
        Request::Fill {
            url,
            id,
            check,
            hello,
        } => {
            let origin = match page_origin(&url) {
                Ok(origin) => origin,
                Err(response) => return (response, None),
            };
            let Some(vault) = vault else {
                return (error(ErrorCode::Locked), None);
            };
            // The same answer for "no such login" and "saved for another site": the caller
            // learns nothing about logins of other origins, and can't try PINs on them.
            let Some(id) = ItemId::from_hex(&id) else {
                return (error(ErrorCode::NoMatch), None);
            };
            let read = |vault: &Vault| {
                vault.get_item(&id).ok().filter(|item| {
                    item.kind == ItemKind::Login && item_matches(&item.urls, &origin)
                })
            };
            let Some(item) = read(vault) else {
                return (error(ErrorCode::NoMatch), None);
            };
            let hand_out = |item: &ItemData| {
                (
                    Response::Fill(Credentials {
                        origin: origin.as_str().to_owned(),
                        username: item.username.clone(),
                        password: item.password.clone(),
                    }),
                    Some(item.title.clone()),
                )
            };
            if !(item.is_locked() || gate.locked(vault, &item)) {
                return hand_out(&item);
            }
            let kind = gate.check(vault);
            let locked = || {
                (
                    Response::Error {
                        code: ErrorCode::ItemLocked,
                        check: Some(kind),
                        left: None,
                    },
                    None,
                )
            };
            if hello && gate.open_hello(vault) {
                let opened = read(vault).filter(|item| !item.is_locked());
                gate.close(vault);
                return opened.as_ref().map_or_else(locked, hand_out);
            }
            let Some(secret) = check.filter(|_| kind != Check::App) else {
                return locked();
            };
            match gate.open(vault, secret.as_str()) {
                Opened::Yes => {
                    // Read once while open, then closed again: only this login was decrypted.
                    let opened = read(vault).filter(|item| !item.is_locked());
                    gate.close(vault);
                    opened.as_ref().map_or_else(locked, hand_out)
                }
                Opened::No { left } => (
                    Response::Error {
                        code: ErrorCode::WrongCheck,
                        check: Some(kind),
                        left: Some(left),
                    },
                    None,
                ),
                Opened::LockedOut => (error(ErrorCode::Locked), None),
            }
        }
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
    }

    impl TestGate {
        fn new(kind: Check) -> Self {
            Self {
                kind,
                open: false,
                tries: 0,
                closed: 0,
                hello: false,
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
