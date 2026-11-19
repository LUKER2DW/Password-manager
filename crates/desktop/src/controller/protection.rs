//! The keyfile (a third factor next to the master password and Secret Key) and the item lock
//! (a PIN, another password or the master password before locked items show their secrets).

use std::path::PathBuf;

use slint::SharedString;
use vault_core::{
    Error as CoreError, GuardCheck, ItemData, ItemGuard, Keyfile, Unlock, Vault, storage,
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
    /// locked item until they are locked again.
    pub(super) fn item_locked(&self, item: &ItemData) -> bool {
        let state = self.state.borrow();
        !state.secrets_open && state.session.as_ref().is_some_and(|s| s.vault.guards(item))
    }

    /// Checks what was typed and opens the locked items: a PIN or the other password unwraps
    /// the key their secrets are encrypted under; the master password is checked against the
    /// file.
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
            let passed = match session.vault.item_guard().check {
                GuardCheck::Master => match super::verify_current(&path, &typed, &session) {
                    Ok(()) => true,
                    Err((code, _)) if code == error::WRONG_CURRENT => false,
                    Err((code, detail)) => {
                        return JobResult::Failed {
                            code,
                            detail,
                            session: Some(session),
                        };
                    }
                },
                GuardCheck::Pin | GuardCheck::Password => {
                    match session.vault.unlock_secrets(&typed) {
                        Ok(passed) => passed,
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
            if passed {
                JobResult::ItemUnlocked {
                    upgraded: !encrypted_before && session.vault.item_guard().encrypts(),
                    session,
                    then,
                }
            } else {
                JobResult::ItemRefused { session }
            }
        });
    }

    /// Opens the locked items with Windows Hello, where the item lock was set up for it:
    /// the security chip's key unwraps the key their secrets are encrypted under.
    pub(super) fn unlock_secrets_hello(&self) {
        let Some(verifier) = self.state.borrow().verifier.clone() else {
            return;
        };
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
                Ok(true) => JobResult::ItemUnlocked {
                    session,
                    upgraded: false,
                    then: AfterUnlock::Show,
                },
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
        let all = app.get_guard_all();
        let want_hello = app.get_guard_hello();
        let locked_fill = {
            let settings = &self.state.borrow().settings;
            settings.browser_extension && settings.browser_locked_fill
        };
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
            let changed = session.vault.set_item_guard(
                all,
                check,
                secret.as_ref().map(|s| s.as_str()),
                Some(&current),
            );
            if changed.is_ok() {
                // Windows Hello as another way in: the guard key (open right now) is wrapped
                // by a key in the security chip. A new PIN makes older copies useless, so it
                // is made again on every save, or removed.
                let id = session.vault.id_hex();
                let key_id = quick_unlock::item_lock_key_id(&id);
                let was_on = quick_unlock::item_lock_enrolled(&id);
                let mut on = false;
                if want_hello
                    && session.vault.item_guard().encrypts()
                    && let Some(secret) = verifier
                        .as_ref()
                        .and_then(|verifier| verifier.enroll(&key_id).ok())
                {
                    on = quick_unlock::item_lock_enroll(&session.vault, &secret).is_ok();
                    // The browser extension's fill while locked follows the item lock: made
                    // again with the new key, from every password (the lock is open now).
                    if on && locked_fill {
                        let _ = super::locked_fill::create(&session.vault, &secret);
                    }
                }
                if !on {
                    super::locked_fill::remove_index(&id);
                }
                if !on && was_on {
                    quick_unlock::item_lock_forget(&id);
                    if let Some(verifier) = &verifier {
                        verifier.remove(&key_id);
                    }
                }
            }
            session.vault.lock_secrets();
            match changed {
                Ok(()) => JobResult::GuardVerified { session },
                Err(CoreError::InvalidGuardSecret) => {
                    failed(error::GUARD_SECRET, String::new(), session)
                }
                Err(CoreError::SecretsLocked) => {
                    failed(error::SECRETS_LOCKED, String::new(), session)
                }
                Err(err) => failed(error::OTHER, err.to_string(), session),
            }
        });
    }

    /// The item lock was changed in memory: write it, and close the locked items.
    pub(super) fn apply_guard(&self) {
        if !self.save_vault() {
            return;
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
        self.show_vault_settings();
        self.sync_guard_state();
        self.refresh_list();
        self.notify(notice::GUARD_SAVED, "");
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
