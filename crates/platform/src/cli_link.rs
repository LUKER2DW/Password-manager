//! The `vault` command asking the open desktop app for secrets (`vault run`, `vault inject`,
//! `vault git-credential`), each use approved in the app. The command never opens the vault for
//! these, so no master password is typed into a script.
//!
//! It goes through a named pipe of the signed-in user's (`browser_link`'s, with a name of its
//! own): only that user may open it, remote clients are refused, and the app listens only while
//! Settings → Security → "The vault command" is on (off by default). Any program of the user may
//! ask; the app shows which one (its full path), what it asks for and why, and answers only
//! after the person allows it. The command, for its part, talks only to the desktop app's own
//! program (`vault-desktop.exe`), so a program that took the pipe's name first gets no request.
//!
//! Messages are JSON in `browser_link`'s frames. An answer holds secrets as [`Secret`], wiped
//! when dropped.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// What a reference names: an item (by title, or the first characters of its id) and a field of
/// it (`password`, `username`, `totp` for its current one-time code, `url`, `notes`, or a custom
/// field's name).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub item: String,
    pub field: String,
}

impl Reference {
    /// `vault://<item>/<field>`. The item may hold `/` itself: the field is what follows the
    /// last one.
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.trim().strip_prefix("vault://")?;
        let (item, field) = rest.rsplit_once('/')?;
        let (item, field) = (item.trim(), field.trim());
        (!item.is_empty() && !field.is_empty() && item.len() <= 256 && field.len() <= 128).then(
            || Self {
                item: item.to_owned(),
                field: field.to_owned(),
            },
        )
    }
}

/// What the command asks.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// The values of `refs`, for `purpose` (what the command will do with them, shown in the
    /// app: "run cargo publish", "fill .env").
    Get {
        purpose: String,
        refs: Vec<Reference>,
    },
    /// The username and password of the login saved for the website `url` (git's credential
    /// helper), the one with `username` when it says.
    Login {
        purpose: String,
        url: String,
        username: Option<String>,
    },
}

/// A secret in an answer, wiped when dropped.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(…)")
    }
}

/// What the app answers.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Answer {
    /// The values asked for, in the same order.
    Values {
        values: Vec<Secret>,
    },
    Login {
        username: Secret,
        password: Secret,
    },
    /// The person said no, or didn't answer in time.
    Denied,
    /// The vault is locked, or an item asked for waits for the item lock.
    Locked,
    /// No such item, or no such field (which one, by name).
    NotFound {
        what: String,
    },
    Error {
        detail: String,
    },
}

/// How long the app waits for the person to answer before it says no.
pub const ANSWER_TIME: std::time::Duration = std::time::Duration::from_secs(120);

/// The pipe of the signed-in user.
pub fn pipe_name() -> Result<String> {
    crate::browser_link::cli_pipe_name()
}

/// Whether `program` is the desktop app's own program, the only one the command talks to.
pub fn is_desktop_app(program: &Path) -> bool {
    program.file_name().is_some_and(|name| {
        name.to_string_lossy()
            .eq_ignore_ascii_case("vault-desktop.exe")
    })
}

/// Sends `request` to the desktop app and waits for its answer (the person may take up to
/// [`ANSWER_TIME`] to choose). Fails when the app isn't listening.
pub fn ask(request: &Request) -> Result<Answer> {
    let name = pipe_name()?;
    let message = serde_json::to_vec(request)?;
    let mut reply = crate::browser_link::request_if(&name, is_desktop_app, &message)?;
    let answer = serde_json::from_slice(&reply).context("the app's answer");
    reply.zeroize();
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_read() {
        let r = Reference::parse("vault://GitHub/password").unwrap();
        assert_eq!((r.item.as_str(), r.field.as_str()), ("GitHub", "password"));
        let r = Reference::parse(" vault://Work/Mail server/API key ").unwrap();
        assert_eq!(
            (r.item.as_str(), r.field.as_str()),
            ("Work/Mail server", "API key")
        );
        for wrong in [
            "",
            "vault://",
            "vault://GitHub",
            "vault:///password",
            "vault://x/",
            "https://x/y",
        ] {
            assert_eq!(Reference::parse(wrong), None, "{wrong:?}");
        }
    }

    #[test]
    fn messages_round_trip_and_hide_secrets() {
        let asked = Request::Get {
            purpose: "run cargo publish".into(),
            refs: vec![Reference::parse("vault://crates.io/token").unwrap()],
        };
        let text = serde_json::to_string(&asked).unwrap();
        assert!(text.contains(r#""type":"get""#), "{text}");
        let answer: Answer =
            serde_json::from_str(r#"{"type":"values","values":["s3cret"]}"#).unwrap();
        let Answer::Values { values } = &answer else {
            panic!("values");
        };
        assert_eq!(values[0].as_str(), "s3cret");
        assert!(!format!("{answer:?}").contains("s3cret"));
        assert!(is_desktop_app(Path::new(r"C:\Apps\Vault-Desktop.EXE")));
        assert!(!is_desktop_app(Path::new(r"C:\Apps\vault.exe")));
    }
}
