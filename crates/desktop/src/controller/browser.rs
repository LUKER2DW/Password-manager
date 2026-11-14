//! The browser extension's link: a local pipe on which the extension (through its native
//! host) asks for the logins of the page in front of the person, and for the one they pick.
//!
//! Off unless turned on in Settings. Three things stand between a caller and a password:
//! - pairing: only the extension the person connected in this window may ask
//!   (`vault_browser::pairing`);
//! - the rules in `vault_browser::service`: exact origin, HTTPS only, nothing while locked;
//! - the item lock: a locked login is opened for one fill by Windows Hello (asked here, with
//!   the system's prompt) or by the PIN typed in the extension's window.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use slint::{ComponentHandle, SharedString};
use vault_browser::{
    host::NOT_RUNNING,
    pairing::{Envelope, PairingKey},
    protocol::{Check, CopyWhat},
    service::{self, Gate, Held, Kept, Opened},
};
use vault_core::{GuardCheck, ItemData, ItemGuard, Vault, storage};
use vault_platform::{
    browser_link, dpapi, paths,
    quick_unlock::{self, DeviceVerifier},
};
use zeroize::Zeroizing;

use super::{CURRENT, Controller, JobResult, Runner, error, field, notice};

const PAIRING_PURPOSE: &str = "browser-pairing";
const LOCKED: &[u8] = br#"{"type":"error","code":"locked"}"#;
const NOT_PAIRED: &[u8] = br#"{"type":"error","code":"not_paired"}"#;
const BAD_REQUEST: &[u8] = br#"{"type":"error","code":"bad_request"}"#;

/// A running link: the flag that stops its thread, and the pipe to wake it on.
#[derive(Debug)]
pub(super) struct BrowserLink {
    stop: Arc<AtomicBool>,
    pipe: String,
}

/// The connected extension's key, sealed with the vault, next to the app's other files.
fn pairing_path(vault_id: &str) -> Option<PathBuf> {
    Some(
        paths::app_dir()
            .ok()?
            .join(format!("browser-pairing-{vault_id}.bin")),
    )
}

/// The connection key again, protected for the Windows user (DPAPI), so requests can be
/// checked while the vault is locked.
fn pairing_path_locked(vault_id: &str) -> Option<PathBuf> {
    Some(
        paths::app_dir()
            .ok()?
            .join(format!("browser-pairing-{vault_id}.dpapi")),
    )
}

/// What the Windows Hello prompt needs, when a request asks for it.
type HelloInputs = (Arc<dyn DeviceVerifier>, String);

impl Controller {
    /// Turns the link on or off: tells Chrome and Edge where the native host is (or removes
    /// that), and starts or stops listening.
    pub(super) fn apply_browser_link(&self, on: bool) {
        if self.state.borrow().runner == Runner::Inline {
            return; // headless tests never touch the registry or open pipes
        }
        if let Some(link) = self.state.borrow_mut().browser_link.take() {
            link.stop.store(true, Ordering::Relaxed);
            browser_link::wake(&link.pipe);
        }
        if !on {
            browser_link::unregister_host();
            return;
        }
        let host: Option<PathBuf> = std::env::current_exe()
            .ok()
            .and_then(|exe| Some(exe.parent()?.join(browser_link::HOST_EXE)));
        let Some(host) = host.filter(|host| host.exists()) else {
            self.set_error(error::BROWSER_HOST, browser_link::HOST_EXE);
            return;
        };
        let pipe = match browser_link::register_host(&host).and_then(|()| browser_link::pipe_name())
        {
            Ok(pipe) => pipe,
            Err(err) => {
                self.set_error(error::OTHER, &err.to_string());
                return;
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        self.state.borrow_mut().browser_link = Some(BrowserLink {
            stop: stop.clone(),
            pipe: pipe.clone(),
        });
        std::thread::spawn(move || {
            // Taken already: another window of the app is answering the extension.
            let Ok(mut server) = browser_link::Server::bind(&pipe, &host) else {
                return;
            };
            /// Runs `work` on the UI thread (where the vault lives) and waits for it here.
            fn on_ui<T: Send + 'static>(
                work: impl FnOnce(&Controller) -> T + Send + 'static,
            ) -> Option<T> {
                let (reply_to, reply) = mpsc::channel();
                let _ = slint::invoke_from_event_loop(move || {
                    let answer = CURRENT
                        .with(|c| c.borrow().upgrade())
                        .map(|controller| work(&controller));
                    let _ = reply_to.send(answer);
                });
                reply.recv_timeout(Duration::from_secs(5)).ok().flatten()
            }
            while !stop.load(Ordering::Relaxed) {
                let served = server.serve_one(|message| {
                    let message = message.to_vec();
                    // Windows Hello is asked here, off the UI thread: its prompt may stay
                    // open for as long as the person takes.
                    let asked = message.clone();
                    let device = on_ui(move |c| c.browser_hello_inputs(&asked))
                        .flatten()
                        .and_then(|(verifier, key_id)| verifier.secret(&key_id).ok());
                    on_ui(move |c| c.browser_answer(&message, device))
                        .map_or_else(|| NOT_RUNNING.to_vec(), |answer| answer.to_vec())
                });
                if served.is_err() {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        });
    }

    /// Answers one message from the extension, asking Windows Hello first when the message
    /// wants a locked login opened with it. (The app's pipe does the two steps on its own
    /// thread; this is the same thing in one call.)
    pub fn browser_request(&self, message: &[u8]) -> Zeroizing<Vec<u8>> {
        let device = self
            .browser_hello_inputs(message)
            .and_then(|(verifier, key_id)| verifier.secret(&key_id).ok());
        self.browser_answer(message, device)
    }

    /// Whether this message asks for Windows Hello, and Hello can open the item lock here (or,
    /// with the vault locked, the passwords kept for the extension).
    fn browser_hello_inputs(&self, message: &[u8]) -> Option<HelloInputs> {
        let Envelope::Signed { body, .. } = Envelope::parse(message) else {
            return None;
        };
        if !service::wants_hello(body.as_bytes()) {
            return None;
        }
        if self.state.borrow().session.is_none() {
            let id = self.locked_vault_id()?;
            super::locked_fill::read_index(&id)?;
            return self
                .state
                .borrow()
                .verifier
                .clone()
                .map(|verifier| (verifier, quick_unlock::item_lock_key_id(&id)));
        }
        let state = self.state.borrow();
        let vault = &state.session.as_ref()?.vault;
        let id = vault.id_hex();
        (vault.item_guard().encrypts() && quick_unlock::item_lock_enrolled(&id))
            .then(|| state.verifier.clone())
            .flatten()
            .map(|verifier| (verifier, quick_unlock::item_lock_key_id(&id)))
    }

    /// Answers one message. `device` is the secret Windows Hello produced for it, if any.
    fn browser_answer(
        &self,
        message: &[u8],
        device: Option<Zeroizing<Vec<u8>>>,
    ) -> Zeroizing<Vec<u8>> {
        let fixed = |bytes: &[u8]| Zeroizing::new(bytes.to_vec());
        match Envelope::parse(message) {
            Envelope::Status => self.browser_inner(br#"{"type":"status"}"#, None),
            Envelope::Pair => self.start_pairing(),
            Envelope::Signed { counter, body, mac } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                let trusted = self
                    .pairing_key()
                    .is_some_and(|key| key.verify(counter, body.as_bytes(), &mac))
                    && self.state.borrow_mut().browser_replay.accept(counter, now);
                if !trusted {
                    return fixed(NOT_PAIRED);
                }
                if self.state.borrow().session.is_none() {
                    return self.browser_locked(body.as_bytes(), device);
                }
                self.browser_inner(body.as_bytes(), device)
            }
            Envelope::Invalid => fixed(BAD_REQUEST),
        }
    }

    /// Answers a request that may be answered (see `vault_browser::service`). A login handed
    /// out is announced in the app, so a fill the person didn't ask for doesn't go unnoticed.
    ///
    /// A PIN typed in the extension's window is tried on the same count of wrong tries as in
    /// the app: too many lock the whole vault. Whatever opened the item lock, it opens the
    /// one login asked for and is closed again before this returns.
    fn browser_inner(
        &self,
        request: &[u8],
        device: Option<Zeroizing<Vec<u8>>>,
    ) -> Zeroizing<Vec<u8>> {
        let (answer, locked_out, save) = {
            let mut state = self.state.borrow_mut();
            let state = &mut *state;
            let id = state.session.as_ref().map(|s| s.vault.id_hex());
            let hello = state.quick_available
                && id.as_deref().is_some_and(quick_unlock::item_lock_enrolled);
            let mut gate = AppGate {
                attempts: &mut state.guard_attempts,
                app_open: state.secrets_open,
                hello,
                device: device.zip(id.as_deref().and_then(quick_unlock::item_lock_load)),
                locked_out: false,
                save: false,
                clipboard_seconds: state.settings.clipboard_clear_seconds.max(5),
                generated: &mut state.browser_generated,
            };
            let vault = state.session.as_mut().map(|session| &mut session.vault);
            let answer = service::answer(request, vault, &mut gate);
            (answer, gate.locked_out, gate.save)
        };
        if locked_out {
            self.lock();
            self.notify_long(notice::GUARD_LOCKED_OUT, "");
        } else if save {
            self.save_vault();
        }
        if let Some(kept) = answer.kept {
            self.record_generated(&kept.password, &kept.site);
        }
        if let Some(title) = &answer.saved {
            if !locked_out {
                self.state.borrow_mut().summaries_stale = true;
                if self.save_vault() {
                    self.refresh_list();
                    self.notify(notice::BROWSER_SAVED, title);
                }
            }
        } else if let Some(copy) = answer.copy {
            // Copied here, by the app: kept out of clipboard history and cleared later, and
            // never handed to the browser.
            let (secret, code) = match copy.what {
                CopyWhat::Username => (false, notice::USERNAME_COPIED),
                CopyWhat::Password => (true, notice::PASSWORD_COPIED),
                CopyWhat::Code => (true, notice::CODE_COPIED),
            };
            self.copy(copy.value, secret, code);
        } else if let Some(title) = &answer.filled {
            self.notify(notice::BROWSER_FILLED, title);
        }
        answer.bytes
    }

    /// The id of the vault this window would unlock, read from its file's header.
    pub(super) fn locked_vault_id(&self) -> Option<String> {
        let path = self.state.borrow().path.clone();
        let bytes = storage::read(&path).ok()?;
        Some(Vault::inspect(&bytes).ok()?.id_hex)
    }

    /// Answers the extension while the vault is locked: from what was kept for it, with
    /// Windows Hello for any password (see `vault_browser::locked`).
    fn browser_locked(
        &self,
        request: &[u8],
        device: Option<Zeroizing<Vec<u8>>>,
    ) -> Zeroizing<Vec<u8>> {
        let locked = || Zeroizing::new(LOCKED.to_vec());
        // The generator needs no vault. A password used meanwhile joins the history of
        // generated passwords once the vault is open again.
        let generated = {
            let mut state = self.state.borrow_mut();
            let state = &mut *state;
            let mut held = LockedHeld {
                generated: &mut state.browser_generated,
                clipboard_seconds: state.settings.clipboard_clear_seconds.max(5),
            };
            vault_browser::service::answer_generator(request, &mut held)
        };
        if let Some(answer) = generated {
            if let Some(copy) = answer.copy {
                self.copy(copy.value, true, notice::PASSWORD_COPIED);
            }
            if let Some(kept) = answer.kept {
                self.record_generated(&kept.password, &kept.site);
            }
            return answer.bytes;
        }
        let Some(id) = self.locked_vault_id() else {
            return locked();
        };
        let wanted = {
            let settings = &self.state.borrow().settings;
            settings.browser_locked_fill && quick_unlock::item_lock_enrolled(&id)
        };
        let index = super::locked_fill::read_index(&id).filter(|_| wanted);
        let logins = index
            .as_ref()
            .map(super::locked_fill::logins)
            .unwrap_or_default();
        // A login saved meanwhile is kept sealed for the next unlock: nothing to ask.
        let saved = vault_browser::locked::answer_locked_save(request, &logins, &mut |login| {
            super::drop_box::keep(&id, login)
        });
        if let Some(answer) = saved {
            return answer.bytes;
        }
        let Some(file) = index else {
            return locked();
        };
        let mut gate = super::locked_fill::HelloGate {
            file: &file,
            vault_id: id,
            device,
        };
        let answer = vault_browser::locked::answer_locked(request, &logins, &mut gate);
        if let Some(copy) = answer.copy {
            let (secret, code) = match copy.what {
                CopyWhat::Username => (false, notice::USERNAME_COPIED),
                CopyWhat::Password => (true, notice::PASSWORD_COPIED),
                CopyWhat::Code => (true, notice::CODE_COPIED),
            };
            self.copy(copy.value, secret, code);
        } else if let Some(title) = &answer.filled {
            self.notify(notice::BROWSER_FILLED, title);
        }
        answer.bytes
    }

    // ---- pairing ----

    /// The connected extension's key: read once per unlock from its file sealed with the
    /// vault, or, while the vault is locked, from its copy protected for the Windows user.
    fn pairing_key(&self) -> Option<PairingKey> {
        if let Some(key) = &self.state.borrow().browser_pairing {
            return Some(key.clone());
        }
        if self.state.borrow().session.is_none() {
            let sealed = std::fs::read(pairing_path_locked(&self.locked_vault_id()?)?).ok()?;
            return PairingKey::from_bytes(&dpapi::unprotect(&sealed)?);
        }
        let key = {
            let state = self.state.borrow();
            let vault = &state.session.as_ref()?.vault;
            let sealed = std::fs::read(pairing_path(&vault.id_hex())?).ok()?;
            let plain = vault.open_local(PAIRING_PURPOSE, &sealed).ok()?;
            PairingKey::from_bytes(&plain)?
        };
        // Connected before the copy for a locked vault existed: make it now.
        if let Some(id) = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
        {
            store_locked_pairing(&id, &key);
        }
        self.state.borrow_mut().browser_pairing = Some(key.clone());
        Some(key)
    }

    /// An extension asks to be connected: make a key, bring this window forward and ask the
    /// person (their master password, and Connect). Until then the key opens nothing. With
    /// the vault locked, the question comes right after it is unlocked.
    fn start_pairing(&self) -> Zeroizing<Vec<u8>> {
        let Some(key) = PairingKey::generate() else {
            return Zeroizing::new(BAD_REQUEST.to_vec());
        };
        let reply = pairing_reply(&key, &key.code());
        let open = {
            let mut state = self.state.borrow_mut();
            state.browser_pending = Some(key);
            state.session.is_some()
        };
        if open {
            self.offer_pending_pairing(true);
        }
        self.bring_to_front();
        reply
    }

    /// Shows the dialog for a connection that is waiting. `needs_password` is off when the
    /// master password was typed a moment ago to unlock the vault for this.
    pub(super) fn offer_pending_pairing(&self, needs_password: bool) {
        let Some(code) = self
            .state
            .borrow()
            .browser_pending
            .as_ref()
            .map(PairingKey::code)
        else {
            return;
        };
        self.clear_secret(field::PAIRING);
        let app = self.app();
        app.set_pairing_needs_password(needs_password);
        app.set_pairing_code(SharedString::from(code));
    }

    /// Puts the app's window in front, so the person sees what the extension asked for.
    pub(super) fn bring_to_front(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        use slint::winit_030::WinitWindowAccessor;
        self.app().window().with_winit_window(|window| {
            window.set_minimized(false);
            window.focus_window();
            window.request_user_attention(Some(
                slint::winit_030::winit::window::UserAttentionType::Informational,
            ));
        });
    }

    /// The person's answer to the pairing dialog. Connecting needs the master password,
    /// checked against the vault file, unless it was just typed to unlock.
    pub(super) fn pairing_decided(&self, allow: bool) {
        let app = self.app();
        if !allow {
            self.state.borrow_mut().browser_pending = None;
            self.clear_secret(field::PAIRING);
            app.set_pairing_code(SharedString::new());
            self.set_error(error::NONE, "");
            return;
        }
        if self.state.borrow().browser_pending.is_none() {
            app.set_pairing_code(SharedString::new());
            return;
        }
        if !app.get_pairing_needs_password() {
            return self.finish_pairing();
        }
        let typed = Zeroizing::new(
            self.state.borrow().secrets[field::PAIRING]
                .as_str()
                .to_owned(),
        );
        if typed.is_empty() {
            self.set_error(error::WRONG_CURRENT, "");
            return;
        }
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let path = self.state.borrow().path.clone();
        self.run_job(
            move || match super::verify_current(&path, &typed, &session) {
                Ok(()) => JobResult::PairingVerified { session },
                Err((code, detail)) => JobResult::Failed {
                    code,
                    detail,
                    session: Some(session),
                },
            },
        );
    }

    /// Stores the connection: from now on requests signed with its key are answered.
    pub(super) fn finish_pairing(&self) {
        self.clear_secret(field::PAIRING);
        self.app().set_pairing_code(SharedString::new());
        let Some(key) = self.state.borrow_mut().browser_pending.take() else {
            return;
        };
        let stored = {
            let state = self.state.borrow();
            state.session.as_ref().and_then(|session| {
                let sealed = session
                    .vault
                    .seal_local(PAIRING_PURPOSE, key.as_bytes())
                    .ok()?;
                let path = pairing_path(&session.vault.id_hex())?;
                std::fs::create_dir_all(path.parent()?).ok()?;
                storage::write_atomic(&path, &sealed).ok()
            })
        };
        if stored.is_some() {
            if let Some(id) = self
                .state
                .borrow()
                .session
                .as_ref()
                .map(|s| s.vault.id_hex())
            {
                store_locked_pairing(&id, &key);
            }
            self.state.borrow_mut().browser_pairing = Some(key);
            self.app().set_browser_paired(true);
            self.set_error(error::NONE, "");
            self.notify(notice::BROWSER_PAIRED, "");
        } else {
            self.set_error(error::OTHER, "the connection could not be saved");
        }
    }

    /// Settings: disconnect the extension. It must ask to be connected again.
    pub(super) fn forget_pairing(&self) {
        let id = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex());
        if let Some(path) = id.as_deref().and_then(pairing_path) {
            let _ = std::fs::remove_file(storage::backup_path(&path));
            let _ = std::fs::remove_file(path);
        }
        if let Some(path) = id.as_deref().and_then(pairing_path_locked) {
            let _ = std::fs::remove_file(storage::backup_path(&path));
            let _ = std::fs::remove_file(path);
        }
        {
            let mut state = self.state.borrow_mut();
            state.browser_pairing = None;
            state.browser_pending = None;
        }
        self.app().set_browser_paired(false);
        self.notify(notice::BROWSER_UNPAIRED, "");
    }

    /// Whether an extension is connected to the open vault (for Settings).
    pub(super) fn browser_is_paired(&self) -> bool {
        self.state
            .borrow()
            .session
            .as_ref()
            .and_then(|s| pairing_path(&s.vault.id_hex()))
            .is_some_and(|path| path.exists())
    }
}

/// Writes the DPAPI copy of the connection key, when it is missing.
fn store_locked_pairing(vault_id: &str, key: &PairingKey) {
    let Some(path) = pairing_path_locked(vault_id) else {
        return;
    };
    if path.exists() {
        return;
    }
    if let Some(sealed) = dpapi::protect(key.as_bytes()) {
        let _ = storage::write_atomic(&path, &sealed);
    }
}

/// `{"type":"pairing","key":…,"code":…}`, in a buffer wiped on drop.
fn pairing_reply(key: &PairingKey, code: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        format!(
            r#"{{"type":"pairing","key":"{}","code":"{code}"}}"#,
            key.to_hex().as_str()
        )
        .into_bytes(),
    )
}

/// The item lock as the extension's requests meet it.
struct AppGate<'a> {
    /// Wrong tries since the last right one (shared with the app's own lock box).
    attempts: &'a mut u32,
    /// The lock was already opened in the app: nothing more is asked, nothing is closed.
    app_open: bool,
    /// Windows Hello can open the item lock on this computer.
    hello: bool,
    /// What Windows Hello produced for this request, and the guard key it unwraps.
    device: Option<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    locked_out: bool,
    /// A format v5 PIN was just turned into encryption: the vault must be saved.
    save: bool,
    clipboard_seconds: u32,
    /// Generated passwords handed to the extension and not used yet.
    generated: &'a mut Vec<(String, Kept)>,
}

/// How many generated passwords wait to be used at most; older ones are dropped.
const HELD_GENERATED: usize = 8;

impl Gate for AppGate<'_> {
    fn check(&self, vault: &Vault) -> Check {
        match vault.item_guard().check {
            GuardCheck::Pin => Check::Pin,
            GuardCheck::Password => Check::Password,
            // The master password is typed in the app only, never in a browser.
            GuardCheck::Master => Check::App,
        }
    }

    fn locked(&self, vault: &Vault, item: &ItemData) -> bool {
        !self.app_open && vault.guards(item)
    }

    fn hello(&self, vault: &Vault) -> bool {
        self.hello && vault.item_guard().encrypts()
    }

    fn open_hello(&mut self, vault: &mut Vault) -> bool {
        let Some((secret, sealed)) = self.device.take() else {
            return false;
        };
        let opened = vault
            .unlock_secrets_with_device(&secret, &sealed)
            .unwrap_or(false);
        if opened {
            *self.attempts = 0;
            // New items added while it was closed are sealed while it is open.
            self.save |= vault.seal_pending().unwrap_or(0) > 0;
        }
        opened
    }

    fn open(&mut self, vault: &mut Vault, secret: &str) -> Opened {
        let legacy = vault.item_guard().is_legacy();
        if vault.unlock_secrets(secret).unwrap_or(false) {
            *self.attempts = 0;
            self.save = legacy || vault.seal_pending().unwrap_or(0) > 0;
            return Opened::Yes;
        }
        *self.attempts += 1;
        if *self.attempts >= ItemGuard::MAX_ATTEMPTS {
            self.locked_out = true;
            Opened::LockedOut
        } else {
            Opened::No {
                left: ItemGuard::MAX_ATTEMPTS - *self.attempts,
            }
        }
    }

    fn close(&mut self, vault: &mut Vault) {
        if !self.app_open {
            vault.lock_secrets();
        }
    }

    fn clipboard_seconds(&self) -> u32 {
        self.clipboard_seconds
    }

    fn remember(&mut self, password: Zeroizing<String>, site: String) -> String {
        hold(self.generated, password, site)
    }

    fn take(&mut self, id: &str) -> Option<Kept> {
        take_held(self.generated, id)
    }
}

/// Holds a generated password for the extension; returns its id.
fn hold(generated: &mut Vec<(String, Kept)>, password: Zeroizing<String>, site: String) -> String {
    let id = PairingKey::generate()
        .map(|key| key.to_hex()[..16].to_owned())
        .unwrap_or_default();
    if generated.len() >= HELD_GENERATED {
        generated.remove(0);
    }
    generated.push((id.clone(), Kept { password, site }));
    id
}

fn take_held(generated: &mut Vec<(String, Kept)>, id: &str) -> Option<Kept> {
    let at = generated
        .iter()
        .position(|(held, _)| !held.is_empty() && held == id)?;
    Some(generated.remove(at).1)
}

/// The generated passwords held while the vault is locked.
struct LockedHeld<'a> {
    generated: &'a mut Vec<(String, Kept)>,
    clipboard_seconds: u32,
}

impl Held for LockedHeld<'_> {
    fn remember(&mut self, password: Zeroizing<String>, site: String) -> String {
        hold(self.generated, password, site)
    }

    fn take(&mut self, id: &str) -> Option<Kept> {
        take_held(self.generated, id)
    }

    fn clipboard_seconds(&self) -> u32 {
        self.clipboard_seconds
    }
}
