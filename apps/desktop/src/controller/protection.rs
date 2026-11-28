//! The keyfile (a third factor next to the master password and Secret Key) and the item lock
//! (a PIN, another password or the master password before locked items show their secrets).

use std::path::PathBuf;

use slint::SharedString;
use vault_core::{
    Error as CoreError, GuardCheck, GuardOpened, ItemData, ItemGuard, Keyfile, Unlock, Vault,
    storage,
};
use vault_platform::{keyfile, quick_unlock};
use zeroize::Zeroizing;

use super::{AfterUnlock, Controller, JobResult, Runner, error, field, notice};

/// `keyfile-action` values in pages.slint.
const CREATE: i32 = 0;
const USE: i32 = 1;
const REMOVE: i32 = 2;

impl Controller {
    // -----------------------------------------------------------------------------------------
    // Keyfile
    // -----------------------------------------------------------------------------------------

    /// Unlock screen: pick the vault's keyfile.
    pub(super) fn choose_keyfile(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests: they set `keyfile-path`
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Choose the vault's keyfile")
            .pick_file()
        {
            self.app()
                .set_keyfile_path(SharedString::from(path.display().to_string()));
            self.set_error(error::NONE, "");
        }
    }

    /// The keyfile for unlocking, read from the path on the unlock screen. `Err` is an error
    /// code and detail for the screen.
    pub(super) fn keyfile_for_unlock(&self) -> Result<(Keyfile, PathBuf), (i32, String)> {
        let path = self.app().get_keyfile_path().to_string();
        if path.trim().is_empty() {
            return Err((error::KEYFILE_NEEDED, String::new()));
        }
        let path = PathBuf::from(path);
        match keyfile::read(&path) {
            Ok(key) => Ok((key, path)),
            Err(err) => Err((error::KEYFILE_UNREADABLE, format!("{err:#}"))),
        }
    }

    /// Settings: create a keyfile, switch to another file, or stop using one. Always after a
    /// master password check; the new file is opened once in memory before it is written.
    pub(super) fn keyfile_action(&self, what: i32) {
        let app = self.app();
        let current = Zeroizing::new(
            self.state.borrow().secrets[field::KEYFILE_CURRENT]
                .as_str()
                .to_owned(),
        );
        if current.is_empty() {
            self.set_error(error::WRONG_CURRENT, "");
            app.set_keyfile_failed(true);
            return;
        }
        let inline = self.state.borrow().runner == Runner::Inline;
        let target: Option<PathBuf> = match what {
            REMOVE => None,
            _ if inline => {
                let typed = app.get_keyfile_target().to_string();
                (!typed.is_empty()).then(|| PathBuf::from(typed))
            }
            CREATE => rfd::FileDialog::new()
                .set_title("Save the new keyfile (ideally on a USB stick)")
                .set_file_name("vault.keyfile")
                .save_file(),
            _ => rfd::FileDialog::new()
                .set_title("Choose the file to use as keyfile")
                .pick_file(),
        };
        if what != REMOVE && target.is_none() {
            return;
        }
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let (path, expected) = {
            let state = self.state.borrow();
            (state.path.clone(), state.file_hash)
        };
        self.run_job(move || {
            let mut session = session;
            let failed = |code: i32, detail: String, session| JobResult::KdfFailed {
                code,
                detail,
                session,
                card: 2,
            };
            if let Err((code, detail)) = super::verify_current(&path, &current, &session) {
                return failed(code, detail, session);
            }
            if !super::file_unchanged(&path, expected) {
                return failed(error::CHANGED_OUTSIDE, String::new(), session);
            }
            let new = match (what, &target) {
                (CREATE, Some(file)) => keyfile::create(file).map(Some),
                (USE, Some(file)) => keyfile::read(file).map(Some),
                _ => Ok(None),
            };
            let new = match new {
                Ok(new) => new,
                Err(err) => {
                    return failed(error::KEYFILE_UNREADABLE, format!("{err:#}"), session);
                }
            };
            // On failure the vault is put back as it is on disk: it must never need the new
            // keyfile, which is deleted below.
            let secret_key = &session.secret_key;
            let outcome = session.vault.change_unlock(|vault| {
                let kdf = vault.kdf_params().clone();
                vault.change_password(&current, secret_key, new.as_ref(), &kdf)?;
                let bytes = vault.to_bytes()?;
                let unlock = match &new {
                    Some(keyfile) => Unlock::PasswordAndKeyfile {
                        password: &current,
                        secret_key,
                        keyfile,
                    },
                    None => Unlock::Password {
                        password: &current,
                        secret_key,
                    },
                };
                Vault::open(&bytes, unlock)?;
                storage::write_atomic(&path, &bytes)
            });
            match outcome {
                Ok(()) => {
                    let id = session.vault.id_hex();
                    let _ = vault_platform::device::record_revision(&id, session.vault.revision());
                    let _ = keyfile::remember_path(&id, target.as_deref());
                    session.keyfile = new;
                    JobResult::KeyfileChanged {
                        session,
                        path: target,
                    }
                }
                Err(err) => {
                    // A keyfile made for nothing would only confuse.
                    if let (CREATE, Some(file)) = (what, &target) {
                        let _ = std::fs::remove_file(file);
                    }
                    failed(error::FILE, err.to_string(), session)
                }
            }
        });
    }

    // -----------------------------------------------------------------------------------------
    // Item lock: a PIN, another password or the master password before secrets show
    // -----------------------------------------------------------------------------------------

    /// Whether the item's secrets still wait for the check. One passed check opens every
    /// locked item until they are locked again. An item read with its secrets still sealed
    /// is locked whatever the app thinks is open: its password, codes and files are empty
    /// here, and must never be shown, edited or saved back as if they were.
    pub(super) fn item_locked(&self, item: &ItemData) -> bool {
        if item.is_locked() {
            return true;
        }
        let state = self.state.borrow();
        !state.secrets_open && state.session.as_ref().is_some_and(|s| s.vault.guards(item))
    }

    /// Checks what was typed and opens the locked items: a PIN or the other password unwraps
    /// the key their secrets are encrypted under; the master password is checked against the
    /// file.
    ///
    /// While a newer item lock set on another device waits here (`Vault::guard_waiting`), its
    /// PIN or password is no wrong try: it is kept for moving the locked items to that lock,
    /// and the person is asked for this copy's own one next.
    pub(super) fn unlock_secrets(&self, then: AfterUnlock) {
        let typed = Zeroizing::new(
            self.state.borrow().secrets[field::REPROMPT]
                .as_str()
                .to_owned(),
        );
        if typed.is_empty() {
            return;
        }
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let path = self.state.borrow().path.clone();
        self.run_job(move || {
            let mut session = session;
            let encrypted_before = session.vault.item_guard().encrypts();
            let opened = match session.vault.item_guard().check {
                GuardCheck::Master => match super::verify_current(&path, &typed, &session) {
                    Ok(()) => GuardOpened::Own,
                    Err((code, _)) if code == error::WRONG_CURRENT => GuardOpened::Neither,
                    Err((code, detail)) => {
                        return JobResult::Failed {
                            code,
                            detail,
                            session: Some(session),
                        };
                    }
                },
                GuardCheck::Pin | GuardCheck::Password => {
                    match session.vault.unlock_guard(&typed) {
                        Ok(opened) => opened,
                        Err(err) => {
                            return JobResult::Failed {
                                code: error::OTHER,
                                detail: err.to_string(),
                                session: Some(session),
                            };
                        }
                    }
                }
            };
            match opened {
                GuardOpened::Own => JobResult::ItemUnlocked {
                    upgraded: !encrypted_before && session.vault.item_guard().encrypts(),
                    session,
                    then,
                },
                GuardOpened::NewerOnly => JobResult::ItemNewerOpened { session },
                GuardOpened::Neither => JobResult::ItemRefused { session },
            }
        });
    }

    /// What was typed opened only the newer item lock waiting from another device. Its key
    /// is kept for the move as long as an opened lock stays open (the relock timer closes
    /// it with the rest); once this copy's own lock is open too, a sync round moves the
    /// locked items to it. Until then the person is told to type the earlier PIN or password.
    pub(super) fn newer_lock_opened(&self) {
        self.state.borrow_mut().summaries_stale = true;
        self.clear_secret(field::REPROMPT);
        if !self.timers.relock.running() {
            self.start_relock();
        }
        let ready = self
            .state
            .borrow()
            .session
            .as_ref()
            .is_some_and(|s| s.vault.guard_move_ready());
        if ready {
            self.set_error(error::NONE, "");
            self.sync_for_the_newer_lock();
        } else {
            self.set_error(error::GUARD_NEWER_OPENED, "");
        }
        self.sync_guard_state();
    }

    /// Opens the locked items with Windows Hello, where the item lock was set up for it:
    /// the security chip's key unwraps the key their secrets are encrypted under.
    pub(super) fn unlock_secrets_hello(&self, then: AfterUnlock) {
        let Some(verifier) = self.state.borrow().verifier.clone() else {
            return;
        };
        // Filling while locked that was wanted but has no file (removed with the file of an
        // earlier version, say) is made again with this same answer of Windows Hello.
        let rebuild = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
            .is_some_and(|id| self.locked_fill_missing(&id));
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        self.run_job(move || {
            let mut session = session;
            let id = session.vault.id_hex();
            let key_id = quick_unlock::item_lock_key_id(&id);
            let quiet = |session| JobResult::Failed {
                code: error::NONE,
                detail: String::new(),
                session: Some(session),
            };
            let Some(sealed) = quick_unlock::item_lock_load(&id) else {
                return quiet(session);
            };
            // Closed or cancelled: nothing happened, the PIN field is still there.
            let Ok(secret) = verifier.secret(&key_id) else {
                return quiet(session);
            };
            match session.vault.unlock_secrets_with_device(&secret, &sealed) {
                Ok(true) => {
                    if rebuild {
                        let _ = super::locked_fill::create(&session.vault, &secret);
                    }
                    JobResult::ItemUnlocked {
                        session,
                        upgraded: false,
                        then,
                    }
                }
                _ => {
                    // The PIN was changed elsewhere, or the device key is another one.
                    quick_unlock::item_lock_forget(&id);
                    JobResult::Failed {
                        code: error::GUARD_HELLO,
                        detail: String::new(),
                        session: Some(session),
                    }
                }
            }
        });
    }

    /// A wrong try: say how many are left, and lock the whole vault when none is. That limit
    /// is what makes a short PIN acceptable.
    pub(super) fn item_refused(&self) {
        // Typed while the lock was open (Settings asks for a newer lock's PIN then): a wrong
        // try closes it, as it closed the key in the vault.
        if self.state.borrow().secrets_open {
            self.lock_secrets();
        }
        let attempts = {
            let mut state = self.state.borrow_mut();
            state.guard_attempts += 1;
            state.guard_attempts
        };
        self.clear_secret(field::REPROMPT);
        if attempts >= ItemGuard::MAX_ATTEMPTS {
            self.lock();
            self.notify_long(notice::GUARD_LOCKED_OUT, "");
        } else {
            self.set_error(
                error::GUARD_WRONG,
                &(ItemGuard::MAX_ATTEMPTS - attempts).to_string(),
            );
        }
    }

    /// Settings: change which items are locked and what opens them, after a master password
    /// check. With a PIN or password the secrets of locked items are sealed under a new or
    /// existing key (slow hashing, so it runs with the check); the master password keeps a
    /// copy of that key to replace a forgotten PIN.
    pub(super) fn save_guard(&self) {
        let app = self.app();
        let current = Zeroizing::new(
            self.state.borrow().secrets[field::GUARD_CURRENT]
                .as_str()
                .to_owned(),
        );
        if current.is_empty() {
            self.set_error(error::WRONG_CURRENT, "");
            app.set_guard_failed(true);
            return;
        }
        let check = match app.get_guard_check() {
            1 => GuardCheck::Pin,
            2 => GuardCheck::Password,
            _ => GuardCheck::Master,
        };
        let secret = Zeroizing::new(
            self.state.borrow().secrets[field::GUARD_NEW]
                .as_str()
                .to_owned(),
        );
        let secret = (!secret.is_empty() && check != GuardCheck::Master).then_some(secret);
        // A new item password that is easy to guess is warned about first (one that isn't a
        // password at all is refused by the job, after the master password).
        if check == GuardCheck::Password
            && let Some(secret) = &secret
            && ItemGuard::check_secret(check, secret).is_ok()
            && !self.review_new_password(super::passwords::place::LOCK_SETTINGS)
        {
            return;
        }
        let all = app.get_guard_all();
        let want_hello = app.get_guard_hello();
        let verifier = self.state.borrow().verifier.clone();
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let path = self.state.borrow().path.clone();
        self.run_job(move || {
            let mut session = session;
            let failed = |code: i32, detail: String, session| JobResult::KdfFailed {
                code,
                detail,
                session,
                card: 3,
            };
            if let Err((code, detail)) = super::verify_current(&path, &current, &session) {
                return failed(code, detail, session);
            }
            let before = Box::new(session.vault.snapshot());
            let changed = session.vault.set_item_guard(
                all,
                check,
                secret.as_ref().map(|s| s.as_str()),
                Some(&current),
            );
            match changed {
                Ok(()) => {
                    // Windows Hello as another way in: a key in the security chip will wrap
                    // the guard key (open now). It is made here, off the UI thread (it asks
                    // the person); what it wraps is written only once the vault is saved
                    // (`apply_guard`), so nothing on this computer ever follows a lock that
                    // was not saved.
                    let key_id = quick_unlock::item_lock_key_id(&session.vault.id_hex());
                    let hello = (want_hello && session.vault.item_guard().encrypts())
                        .then(|| verifier.as_ref()?.enroll(&key_id).ok())
                        .flatten();
                    JobResult::GuardVerified {
                        session,
                        hello,
                        before,
                    }
                }
                Err(err) => {
                    session.vault.lock_secrets();
                    match err {
                        CoreError::InvalidGuardSecret => {
                            failed(error::GUARD_SECRET, String::new(), session)
                        }
                        CoreError::SecretsLocked => {
                            failed(error::SECRETS_LOCKED, String::new(), session)
                        }
                        err => failed(error::OTHER, err.to_string(), session),
                    }
                }
            }
        });
    }

    /// The headless test's stand-in for an item lock change whose Windows Hello prompt is
    /// answered only after the vault locked: the job changed the lock (every item behind PIN
    /// `pin`) in the vault it holds and made Windows Hello's new key, then comes back.
    #[cfg(test)]
    pub(crate) fn guard_change_finishes_after_lock(&self, pin: &str, current: &str) {
        let ticket = self.job_ticket();
        let mut session = self
            .state
            .borrow_mut()
            .session
            .take()
            .expect("an open vault");
        let before = Box::new(session.vault.snapshot());
        session
            .vault
            .set_item_guard(true, GuardCheck::Pin, Some(pin), Some(current))
            .expect("the lock changed");
        let key_id = quick_unlock::item_lock_key_id(&session.vault.id_hex());
        let verifier = self.state.borrow().verifier.clone();
        let hello = verifier.and_then(|verifier| verifier.enroll(&key_id).ok());
        self.lock();
        self.finish_job(
            JobResult::GuardVerified {
                session,
                hello,
                before,
            },
            &ticket,
        );
    }

    /// The item lock was changed in memory: write it, set Windows Hello for it up again (or
    /// remove it), and close the locked items. Not written, the vault goes back to the lock
    /// it had: memory never holds a lock the file doesn't.
    pub(super) fn apply_guard(
        &self,
        hello: Option<Zeroizing<Vec<u8>>>,
        before: vault_core::VaultSnapshot,
    ) {
        let Some(id) = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
        else {
            return;
        };
        if !self.save_vault() {
            if let Some(session) = self.state.borrow_mut().session.as_mut() {
                session.vault.roll_back(before);
                session.vault.lock_secrets();
            }
            if hello.is_some() {
                // Windows Hello's key was made anew: what it wrapped before opens no more.
                quick_unlock::item_lock_forget(&id);
                super::locked_fill::remove_index(&id);
            }
            self.state.borrow_mut().summaries_stale = true;
            self.sync_guard_state();
            self.refresh_list();
            return;
        }
        self.enroll_item_lock_hello(&id, hello.as_deref().map(Vec::as_slice));
        if let Some(session) = self.state.borrow_mut().session.as_mut() {
            session.vault.lock_secrets();
        }
        self.clear_secret(field::GUARD_NEW);
        self.clear_secret(field::GUARD_CURRENT);
        self.timers.relock.stop();
        {
            let mut state = self.state.borrow_mut();
            state.secrets_open = false;
            state.guard_attempts = 0;
            state.summaries_stale = true;
        }
        // Closed like the Lock button closes it: what a locked login may just have been given
        // doesn't stay on the generator page.
        self.forget_generated_result();
        self.show_vault_settings();
        self.sync_guard_state();
        self.refresh_list();
        self.app().set_settings_dialog(0);
        self.notify(notice::GUARD_SAVED, "");
    }

    /// After a saved item lock: Windows Hello wraps its key (open still) with `secret`, what
    /// its new key in the security chip gave; without one it is turned off for the item lock.
    /// A new PIN makes earlier copies useless, so this runs on every save. Filling while
    /// locked follows: made again with the new key from every password, or removed.
    fn enroll_item_lock_hello(&self, id: &str, secret: Option<&[u8]>) {
        let (locked_fill, verifier, runner) = {
            let state = self.state.borrow();
            (
                state.settings.browser_extension && state.settings.browser_locked_fill,
                state.verifier.clone(),
                state.runner,
            )
        };
        let was_on = quick_unlock::item_lock_enrolled(id);
        let mut on = false;
        if let Some(secret) = secret
            && let Some(session) = self.state.borrow().session.as_ref()
        {
            on = quick_unlock::item_lock_enroll(&session.vault, secret).is_ok();
            if on && locked_fill {
                let _ = super::locked_fill::create(&session.vault, secret);
            }
        }
        if !on {
            super::locked_fill::remove_index(id);
        }
        if !on && was_on {
            quick_unlock::item_lock_forget(id);
            if let Some(verifier) = verifier {
                let key_id = quick_unlock::item_lock_key_id(id);
                match runner {
                    Runner::Inline => verifier.remove(&key_id),
                    Runner::Thread => {
                        std::thread::spawn(move || verifier.remove(&key_id));
                    }
                }
            }
        }
    }
}

/// `ItemLock.waiting` values (model.slint): what opens the newer item lock waiting from
/// another device (0: none waits).
pub(super) fn waiting_code(check: GuardCheck) -> i32 {
    match check {
        GuardCheck::Pin => 1,
        GuardCheck::Password => 2,
        // Turned off, or the master password as the check: only this copy's own lock is to
        // be opened.
        GuardCheck::Master => 3,
    }
}

/// `guard-check` values in pages.slint.
pub(super) fn check_code(check: GuardCheck) -> i32 {
    match check {
        GuardCheck::Master => 0,
        GuardCheck::Pin => 1,
        GuardCheck::Password => 2,
    }
}
