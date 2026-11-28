//! The SSH agent (M10 F9): `ssh`, `git` and other programs that use Windows' OpenSSH sign in
//! with the vault's SSH key items, and the person approves every signature here.
//!
//! Off unless turned on in Settings → Security. What a program gets:
//! - the list of the vault's SSH keys (their public halves), only while the vault is open;
//! - a signature, only after the person approves it in the app's dialog (which key, which
//!   program Windows says asked and what it says it is for), or within 5 minutes of an
//!   approval that said "don't ask again" for that key and that program;
//! - nothing from a key behind the item lock until the lock is opened in the app.
//!
//! The private key never leaves the app: the signature is made here (`vault_core::ssh`) and
//! only the signature is written to the pipe (`vault_platform::ssh_agent`). Locking the
//! vault refuses every question still open and forgets every "don't ask again".

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use slint::SharedString;
use vault_core::{ItemData, ItemId, ItemKind, ssh};
use vault_platform::{
    clipboard,
    security_log::{Event, kind},
    ssh_agent::{self, Client, Identity, Purpose, Request},
};

use super::{CURRENT, Controller, Runner, error, notice};

/// How long "don't ask again" lasts, at most.
pub(super) const GRANT_FOR: Duration = Duration::from_secs(5 * 60);
/// How long a program waits for the person's answer before it is refused.
const ASK_FOR: Duration = Duration::from_secs(120);
/// Connections open at once; more are hung up on.
const MAX_CONNECTIONS: usize = 16;

/// Where the agent listens (Settings shows it): 0 off or starting, 1 where Windows' OpenSSH
/// looks, 2 a pipe of its own (`SSH_AUTH_SOCK` needed), 3 it couldn't start.
pub(super) mod listening {
    pub const NOT: i32 = 0;
    pub const OPENSSH: i32 = 1;
    pub const OWN_PIPE: i32 = 2;
    pub const FAILED: i32 = 3;
}

/// A running agent: the flag that stops its threads, and its pipe once made.
#[derive(Debug)]
struct Running {
    stop: Arc<AtomicBool>,
    pipe: Option<String>,
}

/// A signature waiting for the person.
#[derive(Debug)]
struct Ask {
    id: u64,
    item: ItemId,
    key: Vec<u8>,
    data: Vec<u8>,
    flags: u32,
    program: Option<PathBuf>,
    parent: Option<PathBuf>,
    reply: mpsc::Sender<Vec<u8>>,
}

/// "Don't ask again" for one key and one program, until `until`.
#[derive(Debug)]
struct Grant {
    key: Vec<u8>,
    program: PathBuf,
    until: Instant,
}

/// The agent's part of the app's state.
#[derive(Debug, Default)]
pub(super) struct AgentState {
    running: Option<Running>,
    asks: VecDeque<Ask>,
    grants: Vec<Grant>,
    next_id: u64,
}

/// A program's file name ("ssh.exe"), shown to the person.
fn program_name(path: Option<&Path>) -> String {
    path.and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Runs `work` on the UI thread (where the vault lives) and waits for it here.
fn on_ui<T: Send + 'static>(work: impl FnOnce(&Controller) -> T + Send + 'static) -> Option<T> {
    let (reply_to, reply) = mpsc::channel();
    let _ = slint::invoke_from_event_loop(move || {
        let answer = CURRENT
            .with(|c| c.borrow().upgrade())
            .map(|controller| work(&controller));
        let _ = reply_to.send(answer);
    });
    reply.recv_timeout(Duration::from_secs(5)).ok().flatten()
}

/// Answers one connection's requests until the program hangs up.
fn answer_connection(connection: ssh_agent::Connection, client: Client, stop: &AtomicBool) {
    let _ = ssh_agent::serve(connection, |request| {
        if stop.load(Ordering::Relaxed) {
            return ssh_agent::failure();
        }
        match request {
            Request::Identities => {
                on_ui(|c| c.agent_identities()).unwrap_or_else(ssh_agent::failure)
            }
            Request::Sign { key, data, flags } => {
                let (reply_to, reply) = mpsc::channel();
                let client = client.clone();
                let Some(id) = on_ui(move |c| c.agent_sign(key, data, flags, &client, reply_to))
                else {
                    return ssh_agent::failure();
                };
                match reply.recv_timeout(ASK_FOR) {
                    Ok(answer) => answer,
                    Err(_) => {
                        let _ = on_ui(move |c| c.agent_ask_expired(id));
                        ssh_agent::failure()
                    }
                }
            }
            Request::Other(_) => ssh_agent::failure(),
        }
    });
}

impl Controller {
    /// Starts or stops answering as the SSH agent.
    pub(super) fn apply_ssh_agent(&self, on: bool) {
        if let Some(running) = self.state.borrow_mut().agent.running.take() {
            running.stop.store(true, Ordering::Relaxed);
            if let Some(pipe) = running.pipe {
                ssh_agent::wake(&pipe);
            }
        }
        self.agent_refuse_all();
        self.app().set_ssh_agent_listening(listening::NOT);
        self.app().set_ssh_agent_pipe(SharedString::new());
        // Headless tests open no pipes: they ask the controller directly.
        if !on || self.state.borrow().runner == Runner::Inline {
            return;
        }
        let names = match ssh_agent::own_pipe_name() {
            Ok(own) => vec![ssh_agent::OPENSSH_PIPE.to_owned(), own],
            Err(_) => {
                self.app().set_ssh_agent_listening(listening::FAILED);
                return;
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        self.state.borrow_mut().agent.running = Some(Running {
            stop: stop.clone(),
            pipe: None,
        });
        std::thread::spawn(move || {
            let mut listener = match ssh_agent::Listener::bind(&names) {
                Ok(listener) => listener,
                Err(_) => {
                    let _ = on_ui(move |c| c.agent_listening(&stop, None));
                    return;
                }
            };
            let pipe = listener.name().to_owned();
            {
                let stop = stop.clone();
                let pipe = pipe.clone();
                let _ = on_ui(move |c| c.agent_listening(&stop, Some(pipe)));
            }
            let open = Arc::new(AtomicUsize::new(0));
            while !stop.load(Ordering::Relaxed) {
                let Ok((connection, client)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                };
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if open.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
                    open.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }
                let stop = stop.clone();
                let open = open.clone();
                std::thread::spawn(move || {
                    answer_connection(connection, client, &stop);
                    open.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
    }

    /// The listener made its pipe (`Some(name)`) or found no name free.
    fn agent_listening(&self, stop: &Arc<AtomicBool>, pipe: Option<String>) {
        {
            let mut state = self.state.borrow_mut();
            let Some(running) = state
                .agent
                .running
                .as_mut()
                .filter(|running| Arc::ptr_eq(&running.stop, stop))
            else {
                // Turned off meanwhile: that thread stops at its next client.
                if let Some(pipe) = pipe {
                    stop.store(true, Ordering::Relaxed);
                    ssh_agent::wake(&pipe);
                }
                return;
            };
            running.pipe.clone_from(&pipe);
            if pipe.is_none() {
                state.agent.running = None;
            }
        }
        let app = self.app();
        match pipe {
            Some(pipe) if pipe == ssh_agent::OPENSSH_PIPE => {
                app.set_ssh_agent_listening(listening::OPENSSH);
                app.set_ssh_agent_pipe(SharedString::from(pipe));
            }
            Some(pipe) => {
                app.set_ssh_agent_listening(listening::OWN_PIPE);
                app.set_ssh_agent_pipe(SharedString::from(pipe));
            }
            None => app.set_ssh_agent_listening(listening::FAILED),
        }
    }

    /// Settings → Security: the `SSH_AUTH_SOCK` line for the agent's own pipe, copied.
    pub(super) fn copy_agent_pipe(&self) {
        let pipe = self.app().get_ssh_agent_pipe();
        if pipe.is_empty() {
            return;
        }
        if clipboard::copy_plain(&format!("SSH_AUTH_SOCK={pipe}")).is_err() {
            self.set_error(error::CLIPBOARD, "");
            return;
        }
        self.notify(notice::SSH_AGENT_PIPE_COPIED, "");
    }

    /// The vault's SSH key items with their public halves, while the vault is open (the
    /// answer to a program asking which keys there are).
    fn agent_keys(&self) -> Vec<(ItemId, ItemData, Vec<u8>)> {
        let state = self.state.borrow();
        let Some(session) = state.session.as_ref() else {
            return Vec::new();
        };
        let vault = &session.vault;
        vault
            .item_ids()
            .filter_map(|id| {
                let item = vault.get_item(&id).ok()?;
                if item.kind != ItemKind::SshKey || !item.is_active() {
                    return None;
                }
                let public = item
                    .custom_fields
                    .iter()
                    .find(|f| f.name == ssh::PUBLIC_KEY_FIELD)
                    .map(|f| f.value.clone())
                    .filter(|value| !value.trim().is_empty())
                    .or_else(|| ssh::public_key_of(&item.password))?;
                let blob = ssh::public_key_blob(&public)?;
                Some((id, item, blob))
            })
            .collect()
    }

    /// The answer to "which keys": the vault's SSH keys, each named by its item's title.
    /// None while the vault is locked.
    pub(crate) fn agent_identities(&self) -> Vec<u8> {
        let keys: Vec<Identity> = self
            .agent_keys()
            .into_iter()
            .map(|(_, item, blob)| Identity {
                blob,
                comment: item.title.clone(),
            })
            .collect();
        ssh_agent::identities_answer(&keys)
    }

    /// A program asks for a signature with `key`: answered at once (refused, or signed within
    /// a "don't ask again"), or the person is asked and `reply` gets the answer later. Returns
    /// the question's number, for [`Self::agent_ask_expired`].
    pub(crate) fn agent_sign(
        &self,
        key: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
        client: &Client,
        reply: mpsc::Sender<Vec<u8>>,
    ) -> u64 {
        let Some((item_id, item)) = self
            .agent_keys()
            .into_iter()
            .find(|(_, _, blob)| *blob == key)
            .map(|(id, item, _)| (id, item))
        else {
            let _ = reply.send(ssh_agent::failure());
            return 0;
        };
        let granted = client.program.as_ref().is_some_and(|program| {
            let now = Instant::now();
            let mut state = self.state.borrow_mut();
            state.agent.grants.retain(|grant| grant.until > now);
            state
                .agent
                .grants
                .iter()
                .any(|grant| grant.key == key && grant.program == *program)
        });
        if granted && !self.item_locked(&item) {
            let answer = self.agent_signature(&item_id, &data, flags);
            if answer != ssh_agent::failure() {
                self.agent_used(&item.title, client.program.as_deref());
            }
            let _ = reply.send(answer);
            return 0;
        }
        let id = {
            let mut state = self.state.borrow_mut();
            state.agent.next_id += 1;
            let id = state.agent.next_id;
            state.agent.asks.push_back(Ask {
                id,
                item: item_id,
                key,
                data,
                flags,
                program: client.program.clone(),
                parent: client.parent.clone(),
                reply,
            });
            id
        };
        self.show_agent_ask();
        self.bring_to_front();
        id
    }

    /// The signature for `data` with the item's key, or the protocol's failure: never while
    /// the item waits for its lock (`item_locked`), whatever was approved.
    fn agent_signature(&self, item_id: &ItemId, data: &[u8], flags: u32) -> Vec<u8> {
        let item = {
            let state = self.state.borrow();
            let Some(session) = state.session.as_ref() else {
                return ssh_agent::failure();
            };
            let Ok(item) = session.vault.get_item(item_id) else {
                return ssh_agent::failure();
            };
            item
        };
        if item.kind != ItemKind::SshKey || !item.is_active() || self.item_locked(&item) {
            return ssh_agent::failure();
        }
        ssh::agent_sign(&item.password, data, flags).map_or_else(
            |_| ssh_agent::failure(),
            |signed| ssh_agent::sign_response(&signed),
        )
    }

    /// A signature was made: said in the app and written to the security log.
    fn agent_used(&self, title: &str, program: Option<&Path>) {
        self.notify(notice::SSH_KEY_USED, title);
        self.log_event(
            Event::new(kind::SSH_SIGNED, super::view::now_unix())
                .title(title)
                .detail(&program_name(program)),
        );
    }

    /// Shows the first question waiting, or closes the dialog when none is.
    fn show_agent_ask(&self) {
        let app = self.app();
        let shown = {
            let state = self.state.borrow();
            state.agent.asks.front().map(|ask| {
                (
                    ask.item,
                    program_name(ask.program.as_deref()),
                    program_name(ask.parent.as_deref()),
                    ssh_agent::purpose(&ask.data),
                    state.agent.asks.len() - 1,
                    ask.program.is_some(),
                )
            })
        };
        let Some((item_id, program, parent, purpose, waiting, known)) = shown else {
            app.set_agent_asking(false);
            return;
        };
        let item = self
            .state
            .borrow()
            .session
            .as_ref()
            .and_then(|s| s.vault.get_item(&item_id).ok());
        let Some(item) = item else {
            // The item went away meanwhile.
            return self.agent_decided(false, false);
        };
        let fingerprint = item
            .custom_fields
            .iter()
            .find(|f| f.name == ssh::FINGERPRINT_FIELD)
            .map(|f| f.value.clone())
            .unwrap_or_default();
        let (kind, detail) = match purpose {
            Purpose::Login { user } => (1, user),
            Purpose::Signature { namespace } => (2, namespace),
            Purpose::Unknown => (0, String::new()),
        };
        app.set_agent_key_title(SharedString::from(item.title.as_str()));
        app.set_agent_key_fingerprint(SharedString::from(fingerprint));
        app.set_agent_program(SharedString::from(program));
        app.set_agent_parent(SharedString::from(parent));
        app.set_agent_purpose(kind);
        app.set_agent_purpose_detail(SharedString::from(detail));
        app.set_agent_key_locked(self.item_locked(&item));
        app.set_agent_can_remember(known);
        app.set_agent_waiting(i32::try_from(waiting).unwrap_or(i32::MAX));
        app.set_agent_asking(true);
    }

    /// The person's answer to the first question: approve (and maybe "don't ask again for 5
    /// minutes" for that key and that program) or refuse.
    pub(crate) fn agent_decided(&self, approve: bool, for_a_while: bool) {
        let Some(ask) = self.state.borrow_mut().agent.asks.pop_front() else {
            self.app().set_agent_asking(false);
            return;
        };
        let answer = if approve {
            self.agent_signature(&ask.item, &ask.data, ask.flags)
        } else {
            ssh_agent::failure()
        };
        if answer != ssh_agent::failure() {
            if for_a_while && let Some(program) = ask.program.clone() {
                self.state.borrow_mut().agent.grants.push(Grant {
                    key: ask.key.clone(),
                    program,
                    until: Instant::now() + GRANT_FOR,
                });
            }
            let title = self
                .state
                .borrow()
                .session
                .as_ref()
                .and_then(|s| s.vault.get_item(&ask.item).ok())
                .map(|item| item.title.clone())
                .unwrap_or_default();
            self.agent_used(&title, ask.program.as_deref());
        }
        let _ = ask.reply.send(answer);
        self.show_agent_ask();
    }

    /// A program stopped waiting for question `id` (or its time ran out).
    pub(crate) fn agent_ask_expired(&self, id: u64) {
        let was_first = {
            let mut state = self.state.borrow_mut();
            let first = state.agent.asks.front().is_some_and(|ask| ask.id == id);
            state.agent.asks.retain(|ask| ask.id != id);
            first
        };
        if was_first {
            self.show_agent_ask();
        }
    }

    /// The vault locked (or the agent stopped): every question is refused and every "don't
    /// ask again" forgotten.
    pub(super) fn agent_refuse_all(&self) {
        let asks: Vec<Ask> = {
            let mut state = self.state.borrow_mut();
            state.agent.grants.clear();
            state.agent.asks.drain(..).collect()
        };
        for ask in asks {
            let _ = ask.reply.send(ssh_agent::failure());
        }
        self.app().set_agent_asking(false);
    }
}
