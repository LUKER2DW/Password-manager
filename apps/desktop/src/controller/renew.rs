//! Renewing the vault key (CRYPTO.md §3.8), from the Emergency kit page, and taking a key
//! renewed on another device (SYNC.md §4.7), from Settings → Sync.
//!
//! Either way the vault file is written only over what was read, and kept only together with
//! the new Secret Key: when this computer can't keep the key, the file is put back as it was.
//! Then what this computer sealed with the former key (`Vault::seal_local`: the generator's
//! history, the extension's connection key, website icons, the leak watch, the drop box, the
//! index for filling while locked) is sealed again under the new one, and Windows Hello, whose
//! copy of the key no longer opens anything, is turned off.

use std::path::Path;

use slint::SharedString;
use vault_core::{
    Error as CoreError, FormerKey, RecoveryParts, RenewedKey, SecretKey, Vault, storage,
    sync::DeviceId,
};
use vault_platform::{DeviceState, files, paths, quick_unlock, secret_store, sync};
use zeroize::Zeroizing;

use super::{
    Controller, JobResult, Session, browser, dialog, drop_box, error, field, file_hash,
    file_unchanged, generated, locked_fill, notice, show_kit_parts, watch,
};

/// What [`write_new_key`] couldn't do.
enum NotKept {
    /// The file wasn't written (changed meanwhile, or the write failed): nothing changed.
    NotWritten(i32, String),
    /// The new Secret Key couldn't be kept here; the file was put back as it was.
    PutBack(String),
    /// Neither: the file opens with the new factors only, and this computer doesn't hold them.
    OnlyNew(String),
}

/// Writes `vault` (its key just renewed, or taken) over the file while it still holds `read`,
/// then keeps `secret_key` for it on this computer; when that fails, the file is put back.
fn write_new_key(
    path: &Path,
    read: &[u8],
    vault: &mut Vault,
    secret_key: &SecretKey,
) -> Result<(), NotKept> {
    let bytes = vault
        .to_bytes()
        .map_err(|err| NotKept::NotWritten(error::OTHER, err.to_string()))?;
    storage::write_atomic_if_unchanged(path, &file_hash(read), &bytes).map_err(
        |err| match err {
            CoreError::FileChanged => NotKept::NotWritten(error::CHANGED_OUTSIDE, String::new()),
            other => NotKept::NotWritten(error::FILE, other.to_string()),
        },
    )?;
    if let Err(err) = secret_store::store(&vault.id_hex(), secret_key) {
        return Err(
            match storage::write_atomic_if_unchanged(path, &file_hash(&bytes), read) {
                Ok(()) => NotKept::PutBack(err.to_string()),
                Err(back) => NotKept::OnlyNew(format!("{err}; {back}")),
            },
        );
    }
    Ok(())
}

fn failed(code: i32, detail: String, session: Session) -> JobResult {
    JobResult::Failed {
        code,
        detail,
        session: Some(session),
    }
}

/// The job behind the Kit page's "Renew the vault key" (off the UI thread), once the master
/// password typed for it was checked: `password` is the one that opens the vault now.
pub(super) fn renew(
    path: &Path,
    expected: Option<[u8; 32]>,
    password: &str,
    mut session: Session,
) -> JobResult {
    if !file_unchanged(path, expected) {
        return failed(error::CHANGED_OUTSIDE, String::new(), session);
    }
    let read = match storage::read(path) {
        Ok(read) => read,
        Err(err) => return failed(error::FILE, err.to_string(), session),
    };
    let before = session.vault.unlock_id();
    let snapshot = session.vault.snapshot();
    let renewed = session
        .vault
        .renew_key(password, &session.secret_key, session.keyfile.as_ref());
    let RenewedKey {
        secret_key,
        parts,
        former,
    } = match renewed {
        Ok(renewed) => renewed,
        Err(CoreError::DecryptionFailed) => {
            return failed(error::WRONG_CURRENT, String::new(), session);
        }
        Err(CoreError::KeyfileRequired) => {
            return failed(error::KEYFILE_NEEDED, String::new(), session);
        }
        Err(err) => return failed(error::OTHER, err.to_string(), session),
    };
    let not_kept = match write_new_key(path, &read, &mut session.vault, &secret_key) {
        Ok(()) => None,
        Err(NotKept::OnlyNew(why)) => Some(why),
        Err(NotKept::NotWritten(code, detail)) => {
            let _ = session.vault.put_back_key(snapshot, former);
            return failed(code, detail, session);
        }
        Err(NotKept::PutBack(why)) => {
            let _ = session.vault.put_back_key(snapshot, former);
            return failed(error::KEY_NOT_KEPT, why, session);
        }
    };
    if let Ok(mut state) = DeviceState::load() {
        let id = session.vault.id_hex();
        state.retire_unlock(&id, &before);
        state.record_revision(&id, session.vault.revision());
        let _ = state.save();
    }
    session.secret_key = secret_key;
    JobResult::KeyRenewed {
        session,
        parts: Some(parts),
        former,
        not_kept,
    }
}

/// The job behind Settings → Sync's "Use the new key" (off the UI thread): `copies` are the
/// ones sealed under a key renewed on another device, `secret_key` is the one from its new kit.
pub(super) fn take(
    path: &Path,
    expected: Option<[u8; 32]>,
    password: &str,
    secret_key: SecretKey,
    copies: &[(DeviceId, Vec<u8>)],
    mut session: Session,
) -> JobResult {
    if !file_unchanged(path, expected) {
        return failed(error::CHANGED_OUTSIDE, String::new(), session);
    }
    let read = match storage::read(path) {
        Ok(read) => read,
        Err(err) => return failed(error::FILE, err.to_string(), session),
    };
    let mut state = match DeviceState::load() {
        Ok(state) => state,
        Err(err) => return failed(error::OTHER, err.to_string(), session),
    };
    let snapshot = session.vault.snapshot();
    let taken = sync::take_renewed_key(
        &mut session.vault,
        copies,
        password,
        &secret_key,
        session.keyfile.as_ref(),
        &mut state,
    );
    let former = match taken {
        Ok(Some(former)) => former,
        // The copies share this vault's key after all: nothing to take.
        Ok(None) => return failed(error::KEY_NOT_TAKEN, String::new(), session),
        Err(CoreError::KeyfileRequired) => {
            return failed(error::KEYFILE_NEEDED, String::new(), session);
        }
        Err(CoreError::DecryptionFailed) => {
            return failed(error::KEY_NOT_TAKEN, String::new(), session);
        }
        Err(err) => return failed(error::OTHER, err.to_string(), session),
    };
    let not_kept = match write_new_key(path, &read, &mut session.vault, &secret_key) {
        Ok(()) => None,
        Err(NotKept::OnlyNew(why)) => Some(why),
        Err(NotKept::NotWritten(code, detail)) => {
            let _ = session.vault.put_back_key(snapshot, former);
            return failed(code, detail, session);
        }
        Err(NotKept::PutBack(why)) => {
            let _ = session.vault.put_back_key(snapshot, former);
            return failed(error::KEY_NOT_KEPT, why, session);
        }
    };
    state.record_revision(&session.vault.id_hex(), session.vault.revision());
    let _ = state.save();
    session.secret_key = secret_key;
    JobResult::KeyRenewed {
        session,
        parts: None,
        former,
        not_kept,
    }
}

/// Seals again under the vault's key now what this computer sealed with `former`, and turns
/// off what can't be (Windows Hello's copy of the key: it needs the person to make one anew).
/// `true` when Windows Hello was on.
pub(super) fn reseal_side_files(vault: &Vault, former: &FormerKey) -> bool {
    let id = vault.id_hex();
    generated::reseal(vault, former);
    browser::reseal_pairing(vault, former);
    watch::reseal(vault, former);
    drop_box::reseal(vault, former);
    locked_fill::reseal(vault, former);
    if let Ok(dir) = paths::app_dir() {
        files::reseal(
            &dir.join(format!("icons-{id}.cache")),
            vault,
            former,
            "icons",
        );
    }
    let _ = quick_unlock::record_password_unlock(vault);
    let hello = quick_unlock::is_enrolled(&id);
    quick_unlock::forget(&id);
    hello
}

impl Controller {
    /// Settings → Sync → "Use the new key": the Secret Key and master password typed in its
    /// dialog open one of the copies sealed under the renewed key.
    pub(super) fn take_new_key(&self) {
        let (typed, password) = {
            let state = self.state.borrow();
            (
                Zeroizing::new(state.secrets[field::SECRET_KEY].as_str().to_owned()),
                Zeroizing::new(state.secrets[field::CONFIRM_MASTER].as_str().to_owned()),
            )
        };
        let secret_key = match SecretKey::parse(&typed) {
            Ok(key) => key,
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                return self.set_error(code, &detail);
            }
        };
        if password.is_empty() {
            return self.set_error(error::WRONG_CURRENT, "");
        }
        let copies = self.state.borrow().sync.renewed_copies().to_vec();
        if copies.is_empty() {
            return self.close_settings_dialog();
        }
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let (path, expected) = {
            let state = self.state.borrow();
            (state.path.clone(), state.file_hash)
        };
        self.run_job(move || take(&path, expected, &password, secret_key, &copies, session));
    }

    /// The vault key changed here (renewed on the Kit page, or taken in Settings → Sync).
    pub(super) fn key_renewed(
        &self,
        session: Session,
        parts: Option<RecoveryParts>,
        former: FormerKey,
        not_kept: Option<String>,
    ) {
        let app = self.app();
        let secret_key = SharedString::from(session.secret_key.to_display_string().as_str());
        let pdf_password =
            SharedString::from(session.vault.kit_pdf_password(&session.secret_key).as_str());
        let hello = reseal_side_files(&session.vault, &former);
        drop(former);
        if hello {
            self.turn_off_quick_unlock(&session.vault.id_hex());
        }
        self.state.borrow_mut().session = Some(session);
        self.remember_file();
        self.refresh_locked_fill();
        let renewed_here = parts.is_some();
        if let Some(parts) = parts {
            self.clear_secret(field::CURRENT);
            app.set_kit_confirming_renew(false);
            app.set_kit_secret_key(secret_key);
            app.set_kit_pdf_password(pdf_password);
            self.refresh_kit_lock();
            show_kit_parts(&app, &parts);
            app.set_vault_recovery(2);
        } else {
            self.clear_secret(field::SECRET_KEY);
            self.clear_secret(field::CONFIRM_MASTER);
            if app.get_settings_dialog() == dialog::TAKE_KEY {
                app.set_settings_dialog(dialog::NONE);
            }
        }
        // The copies refused until now are read again, under the new key; what that round
        // brings is said first, so the word about the key stays on screen.
        self.state.borrow_mut().sync.key_changed();
        self.show_sync_settings();
        self.sync_round();
        match not_kept {
            Some(why) => self.set_error(error::KEY_ONLY_KIT, &why),
            None => self.notify_long(
                if renewed_here {
                    notice::KEY_RENEWED
                } else {
                    notice::KEY_TAKEN
                },
                if hello { "1" } else { "" },
            ),
        }
    }

    /// A renewal whose result came back after the vault locked (or another opened): the file
    /// and this computer's Secret Key are the new ones already, so what it sealed is sealed
    /// again; the new kit's parts were never shown.
    pub(super) fn key_renewed_unseen(&self, session: Session, former: FormerKey) {
        if reseal_side_files(&session.vault, &former) {
            self.turn_off_quick_unlock(&session.vault.id_hex());
        }
        self.notify_long(notice::KEY_RENEWED_UNSEEN, "");
    }
}
