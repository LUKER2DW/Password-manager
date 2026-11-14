//! How the app answers the extension from its (maybe locked) vault.

use vault_core::{ItemData, ItemId, ItemKind, Vault};
use zeroize::Zeroizing;

use crate::{
    origin::{Origin, PageProblem, item_matches},
    protocol::{Credentials, ErrorCode, LoginEntry, Request, Response},
};

/// The answer to one message, as JSON bytes (wiped when dropped: it may hold a password),
/// and the title of the login that was handed out, if one was.
#[derive(Debug)]
pub struct Answer {
    pub bytes: Zeroizing<Vec<u8>>,
    pub filled: Option<String>,
}

/// Answers one raw message.
///
/// `vault` is `None` while locked. `item_locked` says whether an item's secrets are behind the
/// item lock right now (the app's rule, on top of what the vault itself keeps sealed).
pub fn answer(
    message: &[u8],
    vault: Option<&Vault>,
    item_locked: &dyn Fn(&ItemData) -> bool,
) -> Answer {
    let (response, filled) = match serde_json::from_slice::<Request>(message) {
        Ok(request) => respond(request, vault, item_locked),
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
    Response::Error { code }
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
    vault: Option<&Vault>,
    item_locked: &dyn Fn(&ItemData) -> bool,
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
                            locked: item.is_locked() || item_locked(&item),
                        }
                    })
                })
                .collect();
            items.sort_by_key(|entry| (entry.title.to_lowercase(), entry.username.to_lowercase()));
            (
                Response::Logins {
                    origin: origin.as_str().to_owned(),
                    items,
                },
                None,
            )
        }
        Request::Fill { url, id } => {
            let origin = match page_origin(&url) {
                Ok(origin) => origin,
                Err(response) => return (response, None),
            };
            let Some(vault) = vault else {
                return (error(ErrorCode::Locked), None);
            };
            // The same answer for "no such login" and "saved for another site": the caller
            // learns nothing about logins of other origins.
            let item = ItemId::from_hex(&id)
                .and_then(|id| vault.get_item(&id).ok())
                .filter(|item| item.kind == ItemKind::Login && item_matches(&item.urls, &origin));
            let Some(item) = item else {
                return (error(ErrorCode::NoMatch), None);
            };
            if item.is_locked() || item_locked(&item) {
                return (error(ErrorCode::ItemLocked), None);
            }
            (
                Response::Fill(Credentials {
                    origin: origin.as_str().to_owned(),
                    username: item.username.clone(),
                    password: item.password.clone(),
                }),
                Some(item.title.clone()),
            )
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

    fn ask(vault: Option<&Vault>, request: Value) -> (Value, Option<String>) {
        let answer = answer(request.to_string().as_bytes(), vault, &|item| item.reprompt);
        (
            serde_json::from_slice(&answer.bytes).unwrap(),
            answer.filled,
        )
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
        let (vault, github, work) = vault();
        let (reply, filled) = ask(
            Some(&vault),
            json!({"type": "logins", "url": "https://github.com/login?return_to=x"}),
        );
        assert!(filled.is_none());
        assert_eq!(
            reply,
            json!({"type": "logins", "origin": "https://github.com", "items": [
                {"id": github, "title": "GitHub", "username": "octocat", "locked": false},
                {"id": work, "title": "GitHub (work)", "username": "hubot", "locked": true},
            ]})
        );
        assert!(!reply.to_string().contains("secret"));
        let (other, _) = ask(
            Some(&vault),
            json!({"type": "logins", "url": "https://gist.github.com/"}),
        );
        assert_eq!(other["items"], json!([]));
        let (http, _) = ask(
            Some(&vault),
            json!({"type": "logins", "url": "http://github.com/login"}),
        );
        assert_eq!(http, json!({"type": "error", "code": "insecure_page"}));
        let (internal, _) = ask(
            Some(&vault),
            json!({"type": "logins", "url": "chrome://settings"}),
        );
        assert_eq!(internal, json!({"type": "error", "code": "not_a_website"}));
    }

    #[test]
    fn a_password_leaves_only_for_its_own_site() {
        let (vault, github, work) = vault();
        let (reply, filled) = ask(
            Some(&vault),
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
                Some(&vault),
                json!({"type": "fill", "url": url, "id": github}),
            );
            assert_eq!(reply, json!({"type": "error", "code": "no_match"}), "{url}");
            assert!(filled.is_none());
        }
        let (http, _) = ask(
            Some(&vault),
            json!({"type": "fill", "url": "http://github.com/", "id": github}),
        );
        assert_eq!(http, json!({"type": "error", "code": "insecure_page"}));
        // Unknown and malformed ids look the same as another site's login.
        for id in ["", "zz", &"0".repeat(32)] {
            let (reply, _) = ask(
                Some(&vault),
                json!({"type": "fill", "url": "https://github.com/", "id": id}),
            );
            assert_eq!(reply, json!({"type": "error", "code": "no_match"}));
        }
        // Behind the item lock: not until it is opened in the app.
        let (locked, filled) = ask(
            Some(&vault),
            json!({"type": "fill", "url": "https://github.com/", "id": work}),
        );
        assert_eq!(locked, json!({"type": "error", "code": "item_locked"}));
        assert!(filled.is_none());
    }

    #[test]
    fn secrets_sealed_by_the_item_guard_are_never_handed_out() {
        let (mut vault, github, _) = vault();
        vault
            .set_item_guard(true, GuardCheck::Pin, Some("482193"), None)
            .unwrap();
        vault.lock_secrets();
        let never = |_: &ItemData| false;
        let request = json!({"type": "fill", "url": "https://github.com/", "id": github});
        let reply = answer(request.to_string().as_bytes(), Some(&vault), &never);
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.bytes).unwrap(),
            json!({"type": "error", "code": "item_locked"})
        );
        assert!(vault.unlock_secrets("482193").unwrap());
        let reply = answer(request.to_string().as_bytes(), Some(&vault), &never);
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.bytes).unwrap()["password"],
            "gh-secret"
        );
    }

    #[test]
    fn anything_else_is_a_bad_request() {
        let (vault, ..) = vault();
        for raw in [
            &b"not json"[..],
            br#"{"type":"export"}"#,
            br#"{"type":"logins"}"#,
            br#"{"type":"status","extra":1}"#,
            br#"{"type":"fill","url":"https://github.com/"}"#,
            br#"[]"#,
            b"",
        ] {
            let reply = answer(raw, Some(&vault), &|_| false);
            assert_eq!(
                serde_json::from_slice::<Value>(&reply.bytes).unwrap(),
                json!({"type": "error", "code": "bad_request"}),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
    }
}
