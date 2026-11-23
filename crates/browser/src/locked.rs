//! How the app answers the extension while its vault is locked.
//!
//! The locked app has no vault key. It knows only what it kept for this purpose
//! (`vault_core::locked_fill`): each login's name, username and websites, and a blob of
//! passwords that only the device's user verification (Windows Hello) opens. So:
//! - logins are listed for the exact site, as with an open vault, all marked locked;
//! - a password leaves only after Windows Hello, which the app asks for before answering,
//!   for one login of the page's own origin (fill) or one picked in the extension's window
//!   (show, copy). Nothing typed in the browser opens anything here: no PIN.
//! - a login saved meanwhile is handed to the app to keep sealed until the next unlock
//!   ([`answer_locked_save`], `vault_core::drop_box`): nothing is asked for that;
//! - anything else that needs the vault itself (one-time codes) is refused as locked. The
//!   generator needs no vault: the app answers it first with
//!   [`crate::service::answer_generator`], locked or not.

use zeroize::Zeroizing;

use crate::{
    origin::item_matches,
    protocol::{
        Check, CopyWhat, Credentials, ErrorCode, LoginEntry, Request, Response, Revealed,
        VaultEntry,
    },
    service::{Answer, Copy, page_origin},
};

/// One login as the locked app knows it: never its password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockedLogin {
    pub id: String,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    /// Its password was kept for filling while locked.
    pub fillable: bool,
}

/// A login saved from the browser while the vault is locked, for the app to keep sealed.
pub struct QueuedLogin {
    /// The page's origin (`https://host[:port]`).
    pub url: String,
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for QueuedLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedLogin")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// Answers a [`Request::Save`] while the vault is locked: the login goes to `queue`, which
/// keeps it sealed for the next unlock (and says whether it could). A login already known for
/// that site and username (from `logins`) is reported as existing. `None` for any other
/// request.
pub fn answer_locked_save(
    message: &[u8],
    logins: &[LockedLogin],
    queue: &mut dyn FnMut(QueuedLogin) -> bool,
) -> Option<Answer> {
    let Ok(Request::Save {
        url,
        title,
        username,
        password,
        ..
    }) = serde_json::from_slice::<Request>(message)
    else {
        return None;
    };
    let origin = match page_origin(&url) {
        Ok(origin) => origin,
        Err(response) => return Some(finish(response, None, None)),
    };
    if password.as_str().is_empty()
        || !crate::service::save_fits(title.as_deref(), &username, &password)
    {
        return Some(finish(error(ErrorCode::BadRequest), None, None));
    }
    let existing = logins
        .iter()
        .any(|login| login.username == username && item_matches(&login.urls, &origin));
    if existing {
        return Some(finish(
            Response::Saved {
                existing: true,
                queued: false,
            },
            None,
            None,
        ));
    }
    let host = origin.host();
    let title = title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| host.strip_prefix("www.").unwrap_or(host))
        .to_owned();
    let kept = queue(QueuedLogin {
        url: origin.as_str().to_owned(),
        title,
        username,
        password: Zeroizing::new(password.as_str().to_owned()),
    });
    Some(finish(
        if kept {
            Response::Saved {
                existing: false,
                queued: true,
            }
        } else {
            error(ErrorCode::Locked)
        },
        None,
        None,
    ))
}

/// What opens a kept password: the app, with what Windows Hello produced for this request.
pub trait LockedGate {
    /// The password of login `id`, when Windows Hello was verified for this request.
    fn password(&mut self, id: &str) -> Option<Zeroizing<String>>;
}

fn error(code: ErrorCode) -> Response {
    Response::Error {
        code,
        check: None,
        left: None,
    }
}

/// Opened with the app only (Windows Hello was not verified, or the login was not kept).
fn needs_hello() -> Response {
    Response::Error {
        code: ErrorCode::ItemLocked,
        check: Some(Check::App),
        left: None,
    }
}

fn finish(response: Response, filled: Option<String>, copy: Option<Copy>) -> Answer {
    let bytes = serde_json::to_vec(&response)
        .unwrap_or_else(|_| br#"{"type":"error","code":"bad_request"}"#.to_vec());
    Answer {
        bytes: Zeroizing::new(bytes),
        filled,
        copy,
        saved: None,
        updated: None,
        kept: None,
        passkey_saved: None,
        passkey_used: None,
    }
}

/// Answers one raw message from what the locked app kept.
pub fn answer_locked(message: &[u8], logins: &[LockedLogin], gate: &mut dyn LockedGate) -> Answer {
    let Ok(request) = serde_json::from_slice::<Request>(message) else {
        return finish(error(ErrorCode::BadRequest), None, None);
    };
    let find = |id: &str| logins.iter().find(|login| login.id == id);
    match request {
        Request::Status {} => finish(
            Response::Status {
                locked: true,
                name: String::new(),
            },
            None,
            None,
        ),
        Request::Logins { url } => {
            let origin = match page_origin(&url) {
                Ok(origin) => origin,
                Err(response) => return finish(response, None, None),
            };
            let mut items: Vec<LoginEntry> = logins
                .iter()
                .filter(|login| item_matches(&login.urls, &origin))
                .map(|login| LoginEntry {
                    id: login.id.clone(),
                    title: login.title.clone(),
                    username: login.username.clone(),
                    locked: true,
                    has_code: false,
                })
                .collect();
            items.sort_by_key(|entry| (entry.title.to_lowercase(), entry.username.to_lowercase()));
            finish(
                Response::Logins {
                    origin: origin.as_str().to_owned(),
                    check: Check::App,
                    hello: true,
                    items,
                },
                None,
                None,
            )
        }
        Request::Fill { url, id, hello, .. } => {
            let origin = match page_origin(&url) {
                Ok(origin) => origin,
                Err(response) => return finish(response, None, None),
            };
            // Another site's login looks exactly like no login, and Hello is never asked for it.
            let Some(login) = find(&id).filter(|login| item_matches(&login.urls, &origin)) else {
                return finish(error(ErrorCode::NoMatch), None, None);
            };
            match hello.then(|| gate.password(&login.id)).flatten() {
                Some(password) => finish(
                    Response::Fill(Credentials {
                        origin: origin.as_str().to_owned(),
                        username: login.username.clone(),
                        password: password.to_string(),
                    }),
                    Some(login.title.clone()),
                    None,
                ),
                None => finish(needs_hello(), None, None),
            }
        }
        Request::Vault {} => {
            let mut items: Vec<VaultEntry> = logins
                .iter()
                .map(|login| VaultEntry {
                    id: login.id.clone(),
                    title: login.title.clone(),
                    username: login.username.clone(),
                    site: login.urls.first().cloned().unwrap_or_default(),
                    locked: true,
                    has_password: login.fillable,
                    has_code: false,
                })
                .collect();
            items.sort_by_key(|entry| (entry.title.to_lowercase(), entry.username.to_lowercase()));
            finish(
                Response::Vault {
                    check: Check::App,
                    hello: true,
                    items,
                },
                None,
                None,
            )
        }
        Request::Reveal { id, hello, .. } => {
            let Some(login) = find(&id) else {
                return finish(error(ErrorCode::NoMatch), None, None);
            };
            match hello.then(|| gate.password(&login.id)).flatten() {
                Some(password) => finish(
                    Response::Reveal(Revealed {
                        password: password.to_string(),
                    }),
                    Some(login.title.clone()),
                    None,
                ),
                None => finish(needs_hello(), None, None),
            }
        }
        Request::Copy {
            id, what, hello, ..
        } => {
            let Some(login) = find(&id) else {
                return finish(error(ErrorCode::NoMatch), None, None);
            };
            let value = match what {
                CopyWhat::Username => Some(Zeroizing::new(login.username.clone())),
                CopyWhat::Password => match hello.then(|| gate.password(&login.id)).flatten() {
                    Some(password) => Some(password),
                    None => return finish(needs_hello(), None, None),
                },
                // One-time codes are not kept for the locked app.
                CopyWhat::Code => return finish(error(ErrorCode::Locked), None, None),
            };
            match value {
                Some(value) => {
                    let secret = what != CopyWhat::Username;
                    finish(
                        Response::Copied {
                            seconds: if secret { 30 } else { 0 },
                        },
                        None,
                        Some(Copy { what, value }),
                    )
                }
                None => finish(error(ErrorCode::NoMatch), None, None),
            }
        }
        Request::Save { .. }
        | Request::Generate { .. }
        | Request::Keep { .. }
        | Request::Code { .. }
        | Request::Changed { .. }
        | Request::Update { .. }
        // Passkeys need the open vault: the extension asks the person to unlock it.
        | Request::Passkeys { .. }
        | Request::PasskeyGet { .. }
        | Request::PasskeyCreate { .. } => finish(error(ErrorCode::Locked), None, None),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    struct Hello {
        verified: bool,
        asked: u32,
    }

    impl LockedGate for Hello {
        fn password(&mut self, id: &str) -> Option<Zeroizing<String>> {
            self.asked += 1;
            (self.verified && id == "a1").then(|| Zeroizing::new("kept-secret".to_owned()))
        }
    }

    fn logins() -> Vec<LockedLogin> {
        vec![
            LockedLogin {
                id: "a1".into(),
                title: "GitHub".into(),
                username: "octocat".into(),
                urls: vec!["https://github.com/login".into()],
                fillable: true,
            },
            LockedLogin {
                id: "b2".into(),
                title: "Bank".into(),
                username: "me".into(),
                urls: vec!["bank.example".into()],
                fillable: false,
            },
        ]
    }

    fn ask(gate: &mut Hello, request: Value) -> Value {
        let answer = answer_locked(request.to_string().as_bytes(), &logins(), gate);
        serde_json::from_slice(&answer.bytes).unwrap()
    }

    #[test]
    fn a_login_saved_while_locked_is_queued_without_asking() {
        let mut queued = Vec::new();
        let save = |request: Value, queued: &mut Vec<QueuedLogin>| {
            let answer =
                answer_locked_save(request.to_string().as_bytes(), &logins(), &mut |login| {
                    queued.push(login);
                    true
                })
                .expect("a save");
            serde_json::from_slice::<Value>(&answer.bytes).unwrap()
        };
        let reply = save(
            json!({"type": "save", "url": "https://shop.example/join", "username": "me",
                   "password": "new-secret"}),
            &mut queued,
        );
        assert_eq!(
            reply,
            json!({"type": "saved", "existing": false, "queued": true})
        );
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].url, "https://shop.example");
        assert_eq!(queued[0].title, "shop.example");
        assert_eq!(queued[0].password.as_str(), "new-secret");
        assert!(!format!("{:?}", queued[0]).contains("new-secret"));
        // Known already: nothing is queued.
        let known = save(
            json!({"type": "save", "url": "https://github.com/login", "username": "octocat",
                   "password": "x"}),
            &mut queued,
        );
        assert_eq!(known, json!({"type": "saved", "existing": true}));
        // Not https: refused before anything is kept.
        let insecure = save(
            json!({"type": "save", "url": "http://shop.example/", "username": "me",
                   "password": "x"}),
            &mut queued,
        );
        assert_eq!(insecure["code"], "insecure_page");
        assert_eq!(queued.len(), 1);
        // Other requests are not answered here.
        assert!(answer_locked_save(br#"{"type":"status"}"#, &logins(), &mut |_| true).is_none());
        // The app couldn't keep it: locked.
        let refused = answer_locked_save(
            json!({"type": "save", "url": "https://shop.example/", "username": "you",
                   "password": "x"})
            .to_string()
            .as_bytes(),
            &logins(),
            &mut |_| false,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&refused.bytes).unwrap(),
            json!({"type": "error", "code": "locked"})
        );
    }

    #[test]
    fn locked_logins_are_listed_and_filled_with_hello_only() {
        let mut gate = Hello {
            verified: true,
            asked: 0,
        };
        let listed = ask(
            &mut gate,
            json!({"type": "logins", "url": "https://github.com/x"}),
        );
        assert_eq!(listed["check"], "app");
        assert_eq!(listed["hello"], true);
        assert_eq!(
            listed["items"],
            json!([{"id": "a1", "title": "GitHub", "username": "octocat", "locked": true, "has_code": false}])
        );
        assert!(!listed.to_string().contains("secret"));

        // Without Windows Hello, a typed PIN opens nothing.
        let pin = ask(
            &mut gate,
            json!({"type": "fill", "url": "https://github.com/", "id": "a1", "check": "4821"}),
        );
        assert_eq!(
            pin,
            json!({"type": "error", "code": "item_locked", "check": "app"})
        );
        assert_eq!(gate.asked, 0);
        // With it, the one login of this site is filled.
        let filled = ask(
            &mut gate,
            json!({"type": "fill", "url": "https://github.com/", "id": "a1", "hello": true}),
        );
        assert_eq!(filled["password"], "kept-secret");
        // Never for another site, and Hello is not even tried.
        let other = ask(
            &mut gate,
            json!({"type": "fill", "url": "https://github.com.evil.example/", "id": "a1", "hello": true}),
        );
        assert_eq!(other, json!({"type": "error", "code": "no_match"}));
        assert_eq!(gate.asked, 1);
        // Hello not verified: the app is where it opens.
        gate.verified = false;
        let refused = ask(
            &mut gate,
            json!({"type": "fill", "url": "https://github.com/", "id": "a1", "hello": true}),
        );
        assert_eq!(refused["code"], "item_locked");
    }

    #[test]
    fn the_vault_view_works_locked_and_the_rest_waits_for_the_app() {
        let mut gate = Hello {
            verified: true,
            asked: 0,
        };
        let vault = ask(&mut gate, json!({"type": "vault"}));
        assert_eq!(vault["items"][0]["title"], "Bank");
        assert_eq!(vault["items"][0]["has_password"], false);
        assert_eq!(vault["items"][1]["has_password"], true);
        let shown = ask(
            &mut gate,
            json!({"type": "reveal", "id": "a1", "hello": true}),
        );
        assert_eq!(shown, json!({"type": "reveal", "password": "kept-secret"}));
        let copy = json!({"type": "copy", "id": "a1", "what": "password", "hello": true});
        let answer = answer_locked(copy.to_string().as_bytes(), &logins(), &mut gate);
        assert_eq!(answer.copy.unwrap().value.as_str(), "kept-secret");
        for request in [
            json!({"type": "copy", "id": "a1", "what": "code", "hello": true}),
            json!({"type": "save", "url": "https://x.example/", "username": "a", "password": "b"}),
            json!({"type": "generate"}),
            json!({"type": "keep", "id": "g"}),
        ] {
            assert_eq!(
                ask(&mut gate, request),
                json!({"type": "error", "code": "locked"})
            );
        }
        assert_eq!(
            ask(&mut gate, json!({"type": "status"})),
            json!({"type": "status", "locked": true, "name": ""})
        );
        assert_eq!(
            ask(&mut gate, json!({"type": "nonsense"})),
            json!({"type": "error", "code": "bad_request"})
        );
    }
}
