//! The keyfile (a third factor next to the master password and Secret Key) and items that ask
//! for the master password again before they show anything.

use std::path::PathBuf;

use slint::SharedString;
use vault_core::{GuardCheck, ItemData, ItemGuard, ItemId, Keyfile, Unlock, Vault, storage};
use vault_platform::keyfile;
use zeroize::Zeroizing;

use super::{Controller, JobResult, Runner, error, field, notice};

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
        let path = self.state.borrow().path.clone();
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
            let outcome = (|| -> vault_core::Result<()> {
                let kdf = session.vault.kdf_params().clone();
                session
                    .vault
                    .change_password(&current, &session.secret_key, new.as_ref(), &kdf)?;
                let bytes = session.vault.to_bytes()?;
                let unlock = match &new {
                    Some(keyfile) => Unlock::PasswordAndKeyfile {
                        password: &current,
                        secret_key: &session.secret_key,
                        keyfile,
                    },
                    None => Unlock::Password {
                        password: &current,
                        secret_key: &session.secret_key,
                    },
                };
                Vault::open(&bytes, unlock)?;
                storage::write_atomic(&path, &bytes)
            })();
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

    /// Whether the item's secrets still wait for the check.
    pub(super) fn item_locked(&self, id: &ItemId, item: &ItemData) -> bool {
        let state = self.state.borrow();
        state.unlocked_item != Some(*id)
            && state.session.as_ref().is_some_and(|s| s.vault.guards(item))
    }

    pub(super) fn guards_every_item(&self) -> bool {
        self.state
            .borrow()
            .session
            .as_ref()
            .is_some_and(|s| s.vault.item_guard().all_items)
    }

    /// Checks what was typed (PIN, the other password, or the master password against the
    /// file) and opens the selected item.
    pub(super) fn unlock_item(&self) {
        let Some(id) = self.state.borrow().selected else {
            return;
        };
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
                    session.vault.item_guard().verify(&typed).unwrap_or(false)
                }
            };
            if passed {
                JobResult::ItemUnlocked { session, id }
            } else {
                JobResult::ItemRefused { session }
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
    /// check.
    pub(super) fn save_guard(&self) {
        let current = Zeroizing::new(
            self.state.borrow().secrets[field::GUARD_CURRENT]
                .as_str()
                .to_owned(),
        );
        if current.is_empty() {
            self.set_error(error::WRONG_CURRENT, "");
            self.app().set_guard_failed(true);
            return;
        }
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let path = self.state.borrow().path.clone();
        self.run_job(
            move || match super::verify_current(&path, &current, &session) {
                Ok(()) => JobResult::GuardVerified { session },
                Err((code, detail)) => JobResult::KdfFailed {
                    code,
                    detail,
                    session,
                    card: 3,
                },
            },
        );
    }

    pub(super) fn apply_guard(&self) {
        let app = self.app();
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
        let changed = self.state.borrow_mut().session.as_mut().map(|s| {
            s.vault
                .set_item_guard(all, check, secret.as_ref().map(|s| s.as_str()))
        });
        match changed {
            Some(Ok(())) => {
                if self.save_vault() {
                    self.clear_secret(field::GUARD_NEW);
                    self.clear_secret(field::GUARD_CURRENT);
                    {
                        let mut state = self.state.borrow_mut();
                        state.unlocked_item = None;
                        state.guard_attempts = 0;
                    }
                    self.show_vault_settings();
                    self.refresh_list();
                    self.notify(notice::GUARD_SAVED, "");
                }
            }
            Some(Err(_)) => {
                self.set_error(error::GUARD_SECRET, "");
                app.set_guard_failed(true);
            }
            None => {}
        }
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
