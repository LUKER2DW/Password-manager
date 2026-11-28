//! The `vault` command's requests (`vault run`, `vault inject`, `vault git-credential`), heard
//! on a pipe of this user's while Settings → Security → "The vault command" is on (off by
//! default; `vault_platform::cli_link`). Each request is shown to the person, with the program
//! that asks and what for, and answered only once they allow it; "Allow for 10 minutes" answers
//! the same program asking for the same things again without a question, until then or until
//! the vault locks. Nothing is given while the vault is locked, nor from an item waiting for
//! the item lock.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use slint::{ModelRc, SharedString, VecModel};
use vault_core::{ItemData, ItemId, ItemKind, site_lists};
use vault_platform::{
    browser_link,
    cli_link::{self, Answer, Request, Secret},
};
use zeroize::Zeroizing;

use super::{Controller, Runner, error};

/// How long "Allow for 10 minutes" lasts.
const ALLOWED_FOR: Duration = Duration::from_secs(600);

/// What a request names in the open vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Asked {
    /// Each reference's item and field, in the request's order.
    Fields(Vec<(ItemId, String)>),
    /// The login whose username and password git asks for.
    Login(ItemId),
}

/// A request shown to the person, waiting for their answer.
pub(super) struct Pending {
    program: PathBuf,
    asked: Asked,
    reply: mpsc::Sender<Answer>,
    at: Instant,
}

/// The listening thread; dropping it stops it.
pub(super) struct Listener {
    stop: Arc<AtomicBool>,
    name: String,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        browser_link::wake(&self.name);
    }
}

fn listen() -> anyhow::Result<Listener> {
    let name = cli_link::pipe_name()?;
    let mut server = browser_link::Server::bind_any(&name)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    std::thread::spawn(move || {
        while !stopping.load(Ordering::SeqCst) {
            let served = server.serve_one_from(|program, message| {
                let answer = match serde_json::from_slice::<Request>(message) {
                    Ok(request) => ask_app(program.to_owned(), request),
                    Err(_) => Answer::Error {
                        detail: "a request this app can't read".into(),
                    },
                };
                serde_json::to_vec(&answer).unwrap_or_default()
            });
            if served.is_err() && !stopping.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    });
    Ok(Listener { stop, name })
}

/// Hands the request to the UI thread, then waits for the answer the person gives there.
fn ask_app(program: PathBuf, request: Request) -> Answer {
    let (reply, answer) = mpsc::channel();
    let sent = slint::invoke_from_event_loop(move || {
        match super::CURRENT.with(|c| c.borrow().upgrade()) {
            Some(controller) => controller.cli_request(program, request, reply),
            None => {
                let _ = reply.send(Answer::Locked);
            }
        }
    });
    if sent.is_err() {
        return Answer::Error {
            detail: "the app is closing".into(),
        };
    }
    answer
        .recv_timeout(cli_link::ANSWER_TIME + Duration::from_secs(5))
        .unwrap_or(Answer::Denied)
}

/// The value of `field` in `item`: `password`, `username`, `totp` (its code now), `url`,
/// `notes`, or a custom field by name (case aside). `None` when there is none or it is empty.
fn field_value(item: &ItemData, field: &str) -> Option<Zeroizing<String>> {
    let value = match field.to_ascii_lowercase().as_str() {
        "password" => Zeroizing::new(item.password.clone()),
        "username" | "user" => Zeroizing::new(item.username.clone()),
        "totp" | "code" | "otp" => {
            let totp = vault_core::totp::Totp::parse(&item.totp).ok()?;
            if totp.is_counter_based() {
                return None; // a counter-based code moves on when used: only the app gives it
            }
            totp.now().0
        }
        "url" | "website" => Zeroizing::new(item.urls.first()?.clone()),
        "notes" => Zeroizing::new(item.notes.clone()),
        _ => Zeroizing::new(
            item.custom_fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(field))?
                .value
                .clone(),
        ),
    };
    (!value.is_empty()).then_some(value)
}

impl Controller {
    /// Settings → Security → "The vault command": the pipe listens while it is on. Not in
    /// tests (they hand requests to [`Controller::cli_request`] themselves).
    pub(super) fn apply_cli_link(&self) {
        let on = {
            let state = self.state.borrow();
            state.settings.cli_link && state.runner != Runner::Inline
        };
        self.state.borrow_mut().cli_listener = None;
        if !on {
            return;
        }
        match listen() {
            Ok(listener) => self.state.borrow_mut().cli_listener = Some(listener),
            Err(err) => self.set_error(error::CLI_LINK, &format!("{err:#}")),
        }
    }

    /// The item the command names: the first characters of its id (6 at least), or its title
    /// (case aside), among the items in use. `Err` says why not.
    fn cli_item(&self, name: &str) -> Result<ItemId, Answer> {
        let state = self.state.borrow();
        let lower = name.to_lowercase();
        let by_id: Vec<ItemId> = state
            .summaries
            .iter()
            .filter(|s| name.len() >= 6 && s.id.to_hex().starts_with(&lower))
            .map(|s| s.id)
            .collect();
        let found: Vec<ItemId> = if by_id.is_empty() {
            state
                .summaries
                .iter()
                .filter(|s| s.title.to_lowercase() == lower)
                .map(|s| s.id)
                .collect()
        } else {
            by_id
        };
        match found.as_slice() {
            [id] => Ok(*id),
            [] => Err(Answer::NotFound {
                what: name.to_owned(),
            }),
            _ => Err(Answer::Error {
                detail: format!(
                    "\"{name}\" names more than one item: use the first characters of its id"
                ),
            }),
        }
    }

    /// The item `id` with its secrets, unless it waits for the item lock.
    fn cli_open(&self, id: &ItemId) -> Result<ItemData, Answer> {
        let item = {
            let state = self.state.borrow();
            let session = state.session.as_ref().ok_or(Answer::Locked)?;
            session.vault.get_item(id).map_err(|_| Answer::Locked)?
        };
        if !item.is_active() {
            return Err(Answer::NotFound {
                what: item.title.clone(),
            });
        }
        if self.item_locked(&item) || item.is_locked() {
            return Err(Answer::Locked);
        }
        Ok(item)
    }

    /// What a request names, the lines that say so in the question, and what for.
    fn cli_resolve(&self, request: &Request) -> Result<(Asked, Vec<String>, String), Answer> {
        match request {
            Request::Get { purpose, refs } => {
                if refs.is_empty() || refs.len() > 64 {
                    return Err(Answer::Error {
                        detail: "between 1 and 64 references at a time".into(),
                    });
                }
                let mut fields = Vec::new();
                let mut lines = Vec::new();
                for reference in refs {
                    let id = self.cli_item(&reference.item)?;
                    let item = self.cli_open(&id)?;
                    if field_value(&item, &reference.field).is_none() {
                        return Err(Answer::NotFound {
                            what: format!("{}/{}", reference.item, reference.field),
                        });
                    }
                    let line = format!("{} → {}", item.title, reference.field);
                    if !lines.contains(&line) {
                        lines.push(line);
                    }
                    fields.push((id, reference.field.clone()));
                }
                Ok((Asked::Fields(fields), lines, purpose.clone()))
            }
            Request::Login {
                purpose,
                url,
                username,
            } => {
                let host = site_lists::host_of(url)
                    .ok_or_else(|| Answer::NotFound { what: url.clone() })?;
                let candidates: Vec<ItemId> = self
                    .state
                    .borrow()
                    .summaries
                    .iter()
                    .filter(|s| s.kind == ItemKind::Login)
                    .filter(|s| username.as_ref().is_none_or(|u| &s.username == u))
                    .map(|s| s.id)
                    .collect();
                let mut found: Vec<(ItemId, ItemData)> = candidates
                    .into_iter()
                    .filter_map(|id| {
                        let item = self.cli_open(&id).ok()?;
                        item.urls
                            .iter()
                            .any(|saved| {
                                saved.trim().to_ascii_lowercase().starts_with("https://")
                                    && site_lists::host_of(saved).as_deref() == Some(host.as_str())
                            })
                            .then_some((id, item))
                    })
                    .collect();
                // Several logins for the site and no username: which one isn't guessed.
                if found.len() > 1 {
                    return Err(Answer::Error {
                        detail: format!(
                            "{} logins for {host}: put the username in the remote's address                              (https://user@{host}/…)",
                            found.len()
                        ),
                    });
                }
                let Some((id, item)) = found.pop() else {
                    return Err(Answer::NotFound { what: host });
                };
                if item.password.is_empty() {
                    return Err(Answer::NotFound { what: host });
                }
                Ok((
                    Asked::Login(id),
                    vec![format!("{} → username and password", item.title)],
                    purpose.clone(),
                ))
            }
        }
    }

    /// The secrets `asked` names, read now.
    fn cli_answer(&self, asked: &Asked) -> Answer {
        match asked {
            Asked::Fields(fields) => {
                let mut values = Vec::with_capacity(fields.len());
                for (id, field) in fields {
                    let item = match self.cli_open(id) {
                        Ok(item) => item,
                        Err(answer) => return answer,
                    };
                    match field_value(&item, field) {
                        Some(value) => values.push(Secret::new(&value)),
                        None => {
                            return Answer::NotFound {
                                what: format!("{}/{field}", item.title),
                            };
                        }
                    }
                }
                Answer::Values { values }
            }
            Asked::Login(id) => match self.cli_open(id) {
                Ok(item) => Answer::Login {
                    username: Secret::new(&item.username),
                    password: Secret::new(&item.password),
                },
                Err(answer) => answer,
            },
        }
    }

    /// A request of the vault command's: answered at once when the vault can't (locked,
    /// nothing found) or when the same program was allowed the same things for a while;
    /// otherwise shown to the person, the window brought forward.
    pub(crate) fn cli_request(
        &self,
        program: PathBuf,
        request: Request,
        reply: mpsc::Sender<Answer>,
    ) {
        if self.state.borrow().cli_pending.is_some() {
            let _ = reply.send(Answer::Denied); // one question at a time
            return;
        }
        if !self.state.borrow().vault_open {
            let _ = reply.send(Answer::Locked);
            return;
        }
        let (asked, lines, purpose) = match self.cli_resolve(&request) {
            Ok(resolved) => resolved,
            Err(answer) => {
                let _ = reply.send(answer);
                return;
            }
        };
        let allowed = self
            .state
            .borrow()
            .cli_allowed
            .iter()
            .any(|(who, what, until)| who == &program && what == &asked && *until > Instant::now());
        if allowed {
            let _ = reply.send(self.cli_answer(&asked));
            return;
        }
        let app = self.app();
        app.set_cli_program(SharedString::from(program.display().to_string()));
        app.set_cli_purpose(SharedString::from(purpose));
        app.set_cli_lines(ModelRc::new(VecModel::from(
            lines
                .into_iter()
                .map(SharedString::from)
                .collect::<Vec<_>>(),
        )));
        app.set_cli_asking(true);
        let at = Instant::now();
        self.state.borrow_mut().cli_pending = Some(Pending {
            program,
            asked,
            reply,
            at,
        });
        if self.state.borrow().runner != Runner::Inline {
            self.show_from_tray();
        }
        // No answer in time: no (the command stops waiting then too).
        let weak = self.this.borrow().clone();
        slint::Timer::single_shot(cli_link::ANSWER_TIME, move || {
            if let Some(controller) = weak.upgrade() {
                let late = controller
                    .state
                    .borrow()
                    .cli_pending
                    .as_ref()
                    .is_some_and(|pending| pending.at == at);
                if late {
                    controller.cli_decide(0);
                }
            }
        });
    }

    /// The person's answer to the vault command: 0 no, 1 yes this once, 2 yes for 10 minutes.
    pub(super) fn cli_decide(&self, choice: i32) {
        let Some(pending) = self.state.borrow_mut().cli_pending.take() else {
            return;
        };
        let app = self.app();
        app.set_cli_asking(false);
        app.set_cli_lines(ModelRc::default());
        let answer = if choice == 0 {
            Answer::Denied
        } else {
            self.cli_answer(&pending.asked)
        };
        if choice == 2 && matches!(answer, Answer::Values { .. } | Answer::Login { .. }) {
            self.state.borrow_mut().cli_allowed.push((
                pending.program,
                pending.asked,
                Instant::now() + ALLOWED_FOR,
            ));
        }
        let _ = pending.reply.send(answer);
    }

    /// The vault locked: a question waiting is answered no, and what was allowed for a while
    /// is forgotten.
    pub(super) fn cli_forget(&self) {
        if self.state.borrow().cli_pending.is_some() {
            self.cli_decide(0);
        }
        self.state.borrow_mut().cli_allowed.clear();
    }
}
