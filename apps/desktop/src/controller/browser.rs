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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use slint::{ComponentHandle, SharedString};
use vault_browser::{
    host::NOT_RUNNING,
    pairing::{Envelope, Offer, PairingKey, Pending},
    protocol::{Check, CopyWhat, Secret},
    service::{self, Gate, Held, Kept, Opened},
};
use vault_core::{GuardCheck, GuardOpened, ItemData, ItemGuard, Vault, storage};
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
/// The browsers' registration of the host changed while the link ran: this message gets
/// nothing (the extension reads it as an answer it can't trust).
const LINK_CHANGED: &[u8] = br#"{"type":"error","code":"link_changed"}"#;
/// How long a check of that registration stands before it is read again.
const REGISTRATION_CHECKED_FOR: Duration = Duration::from_secs(5);
/// Saving logins, passkeys or the warnings about other sites turned off in Settings → Browser
/// extension.
const TURNED_OFF: &[u8] = br#"{"type":"error","code":"turned_off"}"#;
/// A login, a new password or a passkey that could not be written to the vault file: the
/// extension is told so (and may ask again), never "saved".
const NOT_SAVED: &[u8] = br#"{"type":"error","code":"not_saved"}"#;

/// The requests that change the vault: their answer may say "saved" only once the file on
/// disk holds the change.
fn changes_vault(kind: &str) -> bool {
    matches!(kind, "save" | "update" | "passkey_create")
}

/// The `type` of a request from the extension ("" when it has none): what Settings →
/// Browser extension may have turned off is known before the request is answered.
fn request_type(request: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct Kind {
        #[serde(rename = "type", default)]
        kind: String,
    }
    serde_json::from_slice::<Kind>(request).map_or_else(|_| String::new(), |k| k.kind)
}

/// The password a `save` or `update` request carries, if any (wiped on drop).
fn request_password(request: &[u8]) -> Option<Secret> {
    #[derive(serde::Deserialize)]
    struct WithPassword {
        password: Option<Secret>,
    }
    serde_json::from_slice::<WithPassword>(request)
        .ok()?
        .password
        .filter(|password| !password.as_str().is_empty())
}

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

/// After a renewal of the vault key: the connection key sealed again under the new key (its
/// copy for the Windows user stays as it is).
pub(super) fn reseal_pairing(vault: &Vault, former: &vault_core::FormerKey) {
    if let Some(path) = pairing_path(&vault.id_hex()) {
        vault_platform::files::reseal(&path, vault, former, PAIRING_PURPOSE);
    }
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
    /// Turns the link on or off: tells Chrome, Edge and Firefox where the native host is (or
    /// removes that), and starts or stops listening.
    pub(super) fn apply_browser_link(&self, on: bool) {
        if self.state.borrow().runner == Runner::Inline {
            // Headless tests never touch the registry or open pipes; the extension's folder is
            // kept as when the link starts.
            if on {
                self.check_extension_folder();
            }
            return;
        }
        if let Some(link) = self.state.borrow_mut().browser_link.take() {
            link.stop.store(true, Ordering::Relaxed);
            browser_link::wake(&link.pipe);
        }
        if !on {
            self.stop_extension_checks();
            browser_link::unregister_host();
            return;
        }
        // The browsers start this same executable as the extension's native host.
        let host: Option<PathBuf> = std::env::current_exe().ok();
        let Some(host) = host.filter(|host| host.exists()) else {
            self.set_error(error::BROWSER_HOST, "");
            return;
        };
        let pipe = match browser_link::pipe_name() {
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
        // The extension's folder is looked at every few minutes while the link runs (and once
        // below, before anything is answered).
        self.start_extension_checks();
        std::thread::spawn(move || {
            // The extension's folder first: an extension that asks at once (and reloads when
            // this app carries a newer version) finds this version's files there.
            let (checked, in_use) = super::extension::keep_folder();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    controller.extension_checked(checked, in_use);
                }
            });
            // Taken already: another window of the app is answering the extension, or another
            // program holds the name. Said in the app, and this link is not kept as running.
            let Ok(mut server) = browser_link::Server::bind(&pipe, &host) else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                        controller.browser_link_failed(&stop);
                    }
                });
                return;
            };
            // Only the copy of the app that holds the pipe points the browsers at its host.
            // Registered before the pipe was ours, a second copy elsewhere (that then failed
            // to bind) would leave the browsers talking to its host, which this pipe refuses.
            if let Err(err) = browser_link::register_host(&host) {
                let detail = err.to_string();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                        controller.browser_link_failed(&stop);
                        controller.set_error(error::OTHER, &detail);
                    }
                });
                return;
            }
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
            // When the registration was last found intact.
            let mut intact_at: Option<Instant> = None;
            while !stop.load(Ordering::Relaxed) {
                let served = server.serve_one(|message| {
                    // While the link runs nothing of ours changes the browsers' registration
                    // (one copy of the app): a change is another program putting a host of
                    // its own between the browser and the app. It is put back, said in the
                    // app, and this message gets nothing.
                    if intact_at.is_none_or(|at| at.elapsed() > REGISTRATION_CHECKED_FOR) {
                        if browser_link::registration_intact(&host) {
                            intact_at = Some(Instant::now());
                        } else {
                            intact_at = None;
                            let _ = browser_link::register_host(&host);
                            let _ = slint::invoke_from_event_loop(|| {
                                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                                    controller.notify_long(notice::BROWSER_LINK_REPAIRED, "");
                                }
                            });
                            return LINK_CHANGED.to_vec();
                        }
                    }
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

    /// The pipe could not be made: forget the link (if it is still this one) and say so.
    fn browser_link_failed(&self, stop: &Arc<AtomicBool>) {
        {
            let mut state = self.state.borrow_mut();
            if state
                .browser_link
                .as_ref()
                .is_some_and(|link| Arc::ptr_eq(&link.stop, stop))
            {
                state.browser_link = None;
            }
        }
        self.set_error(error::BROWSER_PIPE, "");
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
        // Only the connected extension may bring up a Windows Hello prompt. (Whether the
        // request was seen before is checked when it is answered.)
        let request = match Envelope::parse(message) {
            Envelope::Sealed { counter, data } => {
                self.pairing_key()?.open_request(counter, &data)?.body
            }
            Envelope::Signed { counter, body, mac } => {
                if !self
                    .pairing_key()
                    .is_some_and(|key| key.verify(counter, body.as_bytes(), &mac))
                {
                    return None;
                }
                Zeroizing::new(body.into_bytes())
            }
            _ => return None,
        };
        if !service::wants_hello(&request) {
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
        let verifier = state.verifier.clone()?;
        if vault.item_guard().encrypts() && quick_unlock::item_lock_enrolled(&id) {
            return Some((verifier, quick_unlock::item_lock_key_id(&id)));
        }
        // Every use asks, and the item lock has no Windows Hello here: the vault's quick
        // unlock key verifies the person (its prompt is Windows Hello all the same).
        (state.settings.browser_always_asks && quick_unlock::is_enrolled(&id))
            .then_some((verifier, id))
    }

    /// What the extension can ask for when every use asks (Settings → Browser extension):
    /// 1 Windows Hello, 2 the item lock's PIN or password, 3 both, 0 nothing (the browser then
    /// gets no password at all).
    pub(super) fn browser_ask_way(&self) -> i32 {
        let state = self.state.borrow();
        let Some(session) = state.session.as_ref() else {
            return 0;
        };
        let id = session.vault.id_hex();
        let hello = state.quick_available
            && (quick_unlock::item_lock_enrolled(&id) || quick_unlock::is_enrolled(&id));
        let typed = matches!(
            session.vault.item_guard().check,
            GuardCheck::Pin | GuardCheck::Password
        );
        i32::from(hello) + 2 * i32::from(typed)
    }

    /// Answers one message. `device` is the secret Windows Hello produced for it, if any.
    fn browser_answer(
        &self,
        message: &[u8],
        device: Option<Zeroizing<Vec<u8>>>,
    ) -> Zeroizing<Vec<u8>> {
        let fixed = |bytes: &[u8]| Zeroizing::new(bytes.to_vec());
        match Envelope::parse(message) {
            // Asked by anyone who can start the helper program: whether the vault is locked,
            // and nothing more (its name goes to the connected extension only).
            Envelope::Status => fixed(if self.state.borrow().session.is_none() {
                br#"{"type":"status","locked":true,"name":""}"#
            } else {
                br#"{"type":"status","locked":false,"name":""}"#
            }),
            Envelope::Pair => self.start_pairing(),
            Envelope::PairCommit { commit } => self.offer_pairing(&commit),
            Envelope::PairKey { key } => self.pairing_key_revealed(&key),
            // Sealed both ways: a program between the browser and the app reads nothing and
            // can't forge an answer (pairing.rs).
            Envelope::Sealed { counter, data } => {
                let Some(key) = self.pairing_key() else {
                    return fixed(NOT_PAIRED);
                };
                let Some(request) = key.open_request(counter, &data) else {
                    return fixed(NOT_PAIRED);
                };
                if !self.fresh_counter(counter) {
                    return fixed(NOT_PAIRED);
                }
                let answer = self.trusted_answer(&request.body, device);
                key.seal_answer(counter, &request.nonce, &answer)
                    .unwrap_or_else(|| fixed(BAD_REQUEST))
            }
            // An extension older than sealed requests: signed, and answered plain as before.
            Envelope::Signed { counter, body, mac } => {
                let signed = self
                    .pairing_key()
                    .is_some_and(|key| key.verify(counter, body.as_bytes(), &mac));
                if !signed || !self.fresh_counter(counter) {
                    return fixed(NOT_PAIRED);
                }
                self.trusted_answer(body.as_bytes(), device)
            }
            Envelope::Invalid => fixed(BAD_REQUEST),
        }
    }

    /// Whether a request's counter is near this clock and new (pairing.rs `Replay`).
    fn fresh_counter(&self, counter: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        self.state.borrow_mut().browser_replay.accept(counter, now)
    }

    /// The answer to a request from the connected extension.
    fn trusted_answer(
        &self,
        request: &[u8],
        device: Option<Zeroizing<Vec<u8>>>,
    ) -> Zeroizing<Vec<u8>> {
        let kind = request_type(request);
        if let Some(refused) = self.browser_turned_off(&kind) {
            return refused;
        }
        // The same, locked or not: what the extension needs to know of the app.
        let answer = if kind == "status" {
            self.browser_status()
        } else if self.state.borrow().session.is_none() {
            self.browser_locked(request, device)
        } else {
            self.browser_inner(request, device)
        };
        let answer = self.with_browser_settings(&kind, answer);
        self.with_extension_version(&kind, answer)
    }

    /// What Settings → Browser extension turned off is refused before anything is read:
    /// saving logins from pages (also while locked), the vault's passkeys (the browser then
    /// uses its own), and comparing a password a page was given with other sites' (the
    /// password is not even read).
    fn browser_turned_off(&self, kind: &str) -> Option<Zeroizing<Vec<u8>>> {
        let settings = &self.state.borrow().settings;
        let off = match kind {
            "save" | "changed" | "update" => !settings.browser_saves,
            "passkeys" | "passkey_get" | "passkey_create" => !settings.browser_passkeys,
            "elsewhere" => !settings.browser_warnings,
            _ => false,
        };
        off.then(|| Zeroizing::new(TURNED_OFF.to_vec()))
    }

    /// The answer about a page's logins (and the status) says what the person turned off, so
    /// the extension doesn't offer it: `"saves": false`, `"passkeys": false`, `"warns": false`
    /// (and then no lookalike is named either: the extension stops sending what a page was
    /// given, and warns about no page).
    fn with_browser_settings(&self, kind: &str, answer: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
        if !matches!(kind, "status" | "logins") {
            return answer;
        }
        let (saves, passkeys, warns) = {
            let settings = &self.state.borrow().settings;
            (
                settings.browser_saves,
                settings.browser_passkeys,
                settings.browser_warnings,
            )
        };
        if saves && passkeys && warns {
            return answer;
        }
        // Names and usernames only (a status or a list of logins, never a password).
        let Ok(serde_json::Value::Object(mut reply)) = serde_json::from_slice(&answer) else {
            return answer;
        };
        if !saves {
            reply.insert("saves".into(), false.into());
        }
        if !passkeys {
            reply.insert("passkeys".into(), false.into());
        }
        if !warns {
            reply.remove("lookalike");
            reply.insert("warns".into(), false.into());
        }
        serde_json::to_vec(&reply).map_or(answer, Zeroizing::new)
    }

    /// Answers a request that may be answered (see `vault_browser::service`). A login handed
    /// out is announced in the app, so a fill the person didn't ask for doesn't go unnoticed.
    ///
    /// A PIN typed in the extension's window is tried on the same count of wrong tries as in
    /// the app: too many lock the whole vault. Whatever opened the item lock, it opens the
    /// one login asked for and is closed again before this returns.
    ///
    /// A change (a login saved, a password updated, a passkey made) is answered as done only
    /// once it is on disk. A vault file changed elsewhere refuses it before anything is
    /// touched (the other change is kept); a write that fails puts the vault back as it was.
    /// Either way the extension hears `not_saved` and may ask again.
    fn browser_inner(
        &self,
        request: &[u8],
        device: Option<Zeroizing<Vec<u8>>>,
    ) -> Zeroizing<Vec<u8>> {
        let changes = changes_vault(&request_type(request));
        if changes && self.changed_outside() {
            self.set_error(error::CHANGED_OUTSIDE, "");
            self.notify_long(notice::NOT_SAVED, "");
            return Zeroizing::new(NOT_SAVED.to_vec());
        }
        // An earlier change this window couldn't write is still only in memory: the answer
        // would be read from it ("already saved", "unchanged") with nothing written. It is
        // written first, or the extension hears that nothing is saved.
        if changes && self.state.borrow().unsaved && !self.save_vault() {
            return Zeroizing::new(NOT_SAVED.to_vec());
        }
        let rebuild_fill = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
            .is_some_and(|id| self.locked_fill_missing(&id));
        let (mut answer, locked_out, save, before) = {
            let mut state = self.state.borrow_mut();
            let state = &mut *state;
            let id = state.session.as_ref().map(|s| s.vault.id_hex());
            let hello = state.quick_available
                && id.as_deref().is_some_and(quick_unlock::item_lock_enrolled);
            let presence = state.quick_available
                && id.as_deref().is_some_and(|id| {
                    quick_unlock::item_lock_enrolled(id) || quick_unlock::is_enrolled(id)
                });
            // Windows Hello answered for this request (with whichever key it was asked).
            let verified = device.is_some();
            let mut gate = AppGate {
                attempts: &mut state.guard_attempts,
                app_open: state.secrets_open,
                hello,
                always: state.settings.browser_always_asks,
                presence,
                verified,
                device: device.zip(id.as_deref().and_then(quick_unlock::item_lock_load)),
                locked_out: false,
                save: false,
                rebuild_fill,
                clipboard_seconds: state.settings.clipboard_clear_seconds.max(5),
                generated: &mut state.browser_generated,
            };
            let vault = state.session.as_mut().map(|session| &mut session.vault);
            let before = changes
                .then(|| vault.as_deref().map(Vault::snapshot))
                .flatten();
            let answer = service::answer(request, vault, &mut gate);
            (answer, gate.locked_out, gate.save, before)
        };
        // The extension's Lock button.
        if answer.lock {
            self.lock();
            return answer.bytes;
        }
        let changed =
            answer.saved.is_some() || answer.updated.is_some() || answer.passkey_saved.is_some();
        if locked_out {
            self.lock();
            self.notify_long(notice::GUARD_LOCKED_OUT, "");
        } else if save && !changed {
            // A change below writes this too: one write, so a second one that fails can't
            // roll memory back behind what the first already put on disk.
            self.save_vault();
        }
        if let Some(kept) = answer.kept {
            self.record_generated(&kept.password, &kept.site);
        }
        if changed {
            self.state.borrow_mut().summaries_stale = true;
            if locked_out || !self.save_vault() {
                // Not on disk: the copy in memory goes back to what the file holds, so the
                // change is neither shown here nor written later behind the person's back.
                if let Some(before) = before {
                    let mut state = self.state.borrow_mut();
                    if let Some(session) = state.session.as_mut() {
                        session.vault.roll_back(before);
                        // As written last (anything unsaved was written before this request).
                        state.unsaved = false;
                    }
                }
                if !locked_out {
                    self.refresh_list();
                }
                answer.bytes = Zeroizing::new(NOT_SAVED.to_vec());
                return answer.bytes;
            }
            self.refresh_list();
            // The generator's result that just became a login's password is that login's
            // now, shown and copied only as the login allows (as through the app's editor).
            if (answer.saved.is_some() || answer.updated.is_some())
                && let Some(password) = request_password(request)
                && self
                    .state
                    .borrow()
                    .generated
                    .as_ref()
                    .is_some_and(|generated| generated.as_str() == password.as_str())
            {
                self.forget_generated_result();
            }
        }
        if let Some(title) = &answer.saved {
            self.notify(notice::BROWSER_SAVED, title);
        } else if let Some(title) = &answer.updated {
            self.notify(notice::BROWSER_UPDATED, title);
        } else if let Some(title) = &answer.passkey_saved {
            self.notify(notice::BROWSER_PASSKEY_SAVED, title);
        } else if let Some(title) = &answer.passkey_used {
            self.notify(notice::BROWSER_PASSKEY_USED, title);
        } else if let Some(copy) = answer.copy {
            // Copied here, by the app: kept out of clipboard history and cleared later, and
            // never handed to the browser.
            let (secret, code) = match copy.what {
                CopyWhat::Username => (false, notice::USERNAME_COPIED),
                CopyWhat::Password => (true, notice::PASSWORD_COPIED),
                CopyWhat::Code => (true, notice::CODE_COPIED),
            };
            self.copy(copy.value, secret, code);
        } else if let Some(title) = &answer.filled
            && self.state.borrow().settings.browser_fill_notices
        {
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
        } else if let Some(title) = &answer.filled
            && self.state.borrow().settings.browser_fill_notices
        {
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

    /// An extension older than the key agreement asks to be connected: make a key, hand it
    /// over and wait for the person (`wait_for_approval`).
    fn start_pairing(&self) -> Zeroizing<Vec<u8>> {
        let Some(pending) = Pending::handed_over() else {
            return Zeroizing::new(BAD_REQUEST.to_vec());
        };
        let reply = pairing_reply(&pending.key, &pending.code);
        self.wait_for_approval(pending);
        reply
    }

    /// An extension asks to be connected (step 1 of the key agreement, pairing.rs): answer
    /// its commitment with a fresh key pair of the app. Only the latest request is kept.
    fn offer_pairing(&self, commit: &str) -> Zeroizing<Vec<u8>> {
        let Some(offer) = Offer::new(commit) else {
            return Zeroizing::new(BAD_REQUEST.to_vec());
        };
        let reply = format!(r#"{{"type":"pair_offer","key":"{}"}}"#, offer.public_hex());
        self.state.borrow_mut().browser_offer = Some(offer);
        Zeroizing::new(reply.into_bytes())
    }

    /// The extension reveals the key it committed to (step 3): the connection then waits for
    /// the person. A key that isn't the one committed to is refused, and the offer is spent.
    fn pairing_key_revealed(&self, key: &str) -> Zeroizing<Vec<u8>> {
        let offer = self.state.borrow_mut().browser_offer.take();
        let Some(pending) = offer.and_then(|offer| offer.finish(key)) else {
            return Zeroizing::new(BAD_REQUEST.to_vec());
        };
        self.wait_for_approval(pending);
        Zeroizing::new(br#"{"type":"pair_wait"}"#.to_vec())
    }

    /// A connection waits for the person: bring this window forward and ask them (the code
    /// the extension shows, their master password, and Connect). Until then its key opens
    /// nothing. With the vault locked, the question comes right after it is unlocked.
    fn wait_for_approval(&self, pending: Pending) {
        let (open, replaced) = {
            let mut state = self.state.borrow_mut();
            let replaced = state.browser_pending.replace(pending).is_some();
            (state.session.is_some(), replaced)
        };
        if open {
            self.offer_pending_pairing(true);
            // Two requests at once: one of them isn't the person's extension. The code shown
            // is the newer one's, and the dialog says so.
            if replaced {
                self.set_error(error::PAIRING_REPLACED, "");
            }
        }
        self.bring_to_front();
    }

    /// Shows the dialog for a connection that is waiting. `needs_password` is off when the
    /// master password was typed a moment ago to unlock the vault for this.
    pub(super) fn offer_pending_pairing(&self, needs_password: bool) {
        let Some((code, compared)) = self
            .state
            .borrow()
            .browser_pending
            .as_ref()
            .map(|pending| (pending.code.clone(), pending.compared))
        else {
            return;
        };
        self.clear_secret(field::PAIRING);
        let app = self.app();
        app.set_pairing_needs_password(needs_password);
        app.set_pairing_typed(SharedString::new());
        app.set_pairing_compare(compared);
        app.set_pairing_code_chars(code_chars(&code));
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
            app.set_pairing_typed(SharedString::new());
            self.set_error(error::NONE, "");
            return;
        }
        if self.state.borrow().browser_pending.is_none() {
            app.set_pairing_code(SharedString::new());
            return;
        }
        // A key agreed with the extension: the person compared the codes. A key handed over:
        // the code typed from the extension's window, not one the app showed (whatever sent
        // the request knows that code too, the person's eyes on the extension are the proof).
        let compared = self
            .state
            .borrow()
            .browser_pending
            .as_ref()
            .is_some_and(|pending| pending.compared);
        if !compared && !self.pairing_code_matches() {
            self.set_error(error::PAIRING_CODE, "");
            return;
        }
        // The request whose code was typed: only its key is stored, whatever asks meanwhile.
        let Some(approved) = self
            .state
            .borrow()
            .browser_pending
            .as_ref()
            .map(|pending| pending.key.clone())
        else {
            return;
        };
        if !app.get_pairing_needs_password() {
            return self.finish_pairing(&approved);
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
                Ok(()) => JobResult::PairingVerified { session, approved },
                Err((code, detail)) => JobResult::Failed {
                    code,
                    detail,
                    session: Some(session),
                },
            },
        );
    }

    /// The headless test's stand-in for a request to connect that arrives while the master
    /// password for the one approved is being checked. Returns the second request's reply.
    #[cfg(test)]
    pub(crate) fn pair_again_while_checking(&self) -> String {
        let approved = self
            .state
            .borrow()
            .browser_pending
            .as_ref()
            .map(|pending| pending.key.clone())
            .expect("a request waiting");
        let second = self.start_pairing();
        self.finish_pairing(&approved);
        String::from_utf8(second.to_vec()).expect("JSON")
    }

    /// Whether the code typed in the dialog is the waiting connection's (spaces aside).
    fn pairing_code_matches(&self) -> bool {
        let digits = |text: &str| -> String { text.chars().filter(char::is_ascii_digit).collect() };
        let typed = digits(&self.app().get_pairing_typed());
        self.state
            .borrow()
            .browser_pending
            .as_ref()
            .is_some_and(|pending| !typed.is_empty() && typed == digits(&pending.code))
    }

    /// Stores the connection: from now on requests signed with its key are answered.
    ///
    /// `approved` is the request whose code the person typed. Another extension (or another
    /// program) may have asked to connect while the master password was being checked: its
    /// key is never the one stored. Its own question is shown instead, to be answered with
    /// its own code.
    pub(super) fn finish_pairing(&self, approved: &PairingKey) {
        self.clear_secret(field::PAIRING);
        self.app().set_pairing_code(SharedString::new());
        self.app().set_pairing_typed(SharedString::new());
        let key = {
            let mut state = self.state.borrow_mut();
            match state.browser_pending.take() {
                Some(pending) if pending.key.as_bytes() == approved.as_bytes() => pending.key,
                other => {
                    let replaced = other.is_some();
                    state.browser_pending = other;
                    drop(state);
                    if replaced {
                        self.set_error(error::PAIRING_CODE, "");
                        self.offer_pending_pairing(true);
                    }
                    return;
                }
            }
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
            state.browser_offer = None;
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

/// Writes the DPAPI copy of the connection key, when it is missing or holds another key (an
/// extension connected again: the earlier key must stop working while locked too).
fn store_locked_pairing(vault_id: &str, key: &PairingKey) {
    let Some(path) = pairing_path_locked(vault_id) else {
        return;
    };
    let current = std::fs::read(&path)
        .ok()
        .and_then(|sealed| dpapi::unprotect(&sealed));
    if current.is_some_and(|current| current.as_slice() == key.as_bytes()) {
        return;
    }
    // Gone first: if the new copy can't be written, no earlier key is left behind.
    let _ = std::fs::remove_file(&path);
    if let Some(sealed) = dpapi::protect(key.as_bytes()) {
        let _ = storage::write_atomic(&path, &sealed);
    }
    let _ = std::fs::remove_file(storage::backup_path(&path));
}

/// A pairing code's characters, one per box (the space between its halves left out).
pub(super) fn code_chars(code: &str) -> slint::ModelRc<SharedString> {
    let chars: Vec<SharedString> = code
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| SharedString::from(c.to_string()))
        .collect();
    slint::ModelRc::new(slint::VecModel::from(chars))
}

/// `{"type":"pairing","key":…,"code":…}` for an extension older than the key agreement, in a
/// buffer wiped on drop.
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
    /// The lock was already opened in the app: nothing more is asked, nothing is closed
    /// (unless every use asks).
    app_open: bool,
    /// Windows Hello can open the item lock on this computer.
    hello: bool,
    /// Every password, code or passkey asks for the person, each time (Settings).
    always: bool,
    /// Windows Hello can verify the person here (a key of this vault on this computer).
    presence: bool,
    /// Windows Hello verified the person for this very request.
    verified: bool,
    /// What Windows Hello produced for this request, and the guard key it unwraps.
    device: Option<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    locked_out: bool,
    /// A format v5 PIN was just turned into encryption: the vault must be saved.
    save: bool,
    /// Filling while locked is wanted but has no file: Windows Hello's answer makes it.
    rebuild_fill: bool,
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
        self.always || (!self.app_open && vault.guards(item))
    }

    fn hello(&self, vault: &Vault) -> bool {
        (self.hello && vault.item_guard().encrypts()) || (self.always && self.presence)
    }

    fn always(&self) -> bool {
        self.always
    }

    /// Opens the item lock with Windows Hello's answer, or (a login outside the lock, every
    /// use asking) takes that answer as the person verified. A login the lock covers still
    /// needs the lock itself open: read after this, it comes back locked otherwise.
    fn open_hello(&mut self, vault: &mut Vault) -> bool {
        let verified = std::mem::take(&mut self.verified);
        let Some((secret, sealed)) = self.device.take() else {
            return verified;
        };
        let opened = vault
            .unlock_secrets_with_device(&secret, &sealed)
            .unwrap_or(false);
        if opened {
            *self.attempts = 0;
            // New items added while it was closed are sealed while it is open.
            self.save |= vault.seal_pending().unwrap_or(0) > 0;
            // Filling while locked, wanted but without its file: made with this same answer.
            if self.rebuild_fill {
                let _ = super::locked_fill::create(vault, &secret);
            }
        }
        opened || verified
    }

    fn open(&mut self, vault: &mut Vault, secret: &str) -> Opened {
        let legacy = vault.item_guard().is_legacy();
        match vault.unlock_guard(secret).unwrap_or(GuardOpened::Neither) {
            GuardOpened::Own => {
                *self.attempts = 0;
                self.save = legacy || vault.seal_pending().unwrap_or(0) > 0;
                return Opened::Yes;
            }
            // The PIN of a newer item lock set on another device: not a wrong try, though it
            // opens nothing here yet (the app asks for both; `close` forgets it again).
            GuardOpened::NewerOnly => {
                return Opened::No {
                    left: ItemGuard::MAX_ATTEMPTS.saturating_sub(*self.attempts),
                };
            }
            GuardOpened::Neither => {}
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
