//! Files attached to items and SSH key items (format v9), and a login's passkeys (v10).
//!
//! In the editor, the item's files and its SSH private key are kept here, in Rust: the page
//! shows file names and sizes, and a key's public half and fingerprint. Passkeys are listed
//! (site, account, when made) and can be taken out; a passkey's key never reaches the page. A private key reaches
//! the screen only on the item page, when the person asks to see it (as a password does). A
//! file leaves the vault only through Save, to a place the person picks.

use std::path::Path;

use slint::{ModelRc, SharedString, VecModel};
use vault_core::{
    Attachment, CustomField, ItemData, ItemKind,
    ssh::{self, KeyProblem, SshKeyPair},
};
use zeroize::Zeroizing;

use super::{Controller, Runner, error, field};
use crate::{
    ui::{FileRow, PasskeyRow},
    view,
};

/// The largest key file read: a private key is a few kilobytes.
const MAX_KEY_FILE: u64 = 64 * 1024;

/// A login's passkeys as the item page and the editor list them.
pub(super) fn passkey_rows(passkeys: &[vault_core::Passkey]) -> Vec<PasskeyRow> {
    passkeys
        .iter()
        .map(|passkey| PasskeyRow {
            site: passkey.rp_id.as_str().into(),
            user: if passkey.user_name.is_empty() {
                passkey.display_name.as_str().into()
            } else {
                passkey.user_name.as_str().into()
            },
            created: view::date(passkey.created_at).into(),
            signal: 0,
            signal_name: slint::SharedString::new(),
        })
        .collect()
}

fn rows(files: &[Attachment]) -> ModelRc<FileRow> {
    let rows: Vec<FileRow> = files
        .iter()
        .map(|file| FileRow {
            name: file.name.as_str().into(),
            size: view::file_size(file.data.len()).into(),
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

/// An SSH key item's type ("Ed25519", "RSA 4096"): as kept, or read from a key kept before
/// the type was.
fn key_type_of(item: &ItemData) -> String {
    let kept = field_value(item, ssh::KEY_TYPE_FIELD);
    if !kept.is_empty() {
        return kept;
    }
    ssh::key_type_of(&item.password).unwrap_or_default()
}

fn field_value(item: &ItemData, name: &str) -> String {
    item.custom_fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.clone())
        .unwrap_or_default()
}

impl Controller {
    /// The editor opens on `item`: its files and, for an SSH key, the key.
    pub(super) fn editor_files_from(&self, item: &ItemData) {
        let is_ssh = item.kind == ItemKind::SshKey && !item.password.is_empty();
        {
            let mut state = self.state.borrow_mut();
            state.editor_files = item.attachments.clone();
            state.editor_ssh = is_ssh.then(|| Zeroizing::new(item.password.clone()));
            state.editor_passkeys = item
                .passkeys
                .iter()
                .map(|passkey| passkey.credential_id.clone())
                .zip(passkey_rows(&item.passkeys))
                .collect();
        }
        self.state.borrow_mut().ssh_pending = None;
        self.show_editor_passkeys();
        self.show_editor_ssh(
            &field_value(item, ssh::PUBLIC_KEY_FIELD),
            &field_value(item, ssh::FINGERPRINT_FIELD),
            &key_type_of(item),
        );
        self.app()
            .set_ed_files(rows(&self.state.borrow().editor_files));
    }

    /// Nothing of the edited item stays behind.
    pub(super) fn clear_editor_files(&self) {
        {
            let mut state = self.state.borrow_mut();
            state.editor_files.clear();
            state.editor_ssh = None;
            state.ssh_pending = None;
            state.editor_passkeys.clear();
        }
        let app = self.app();
        app.set_ed_files(ModelRc::default());
        app.set_ed_passkeys(ModelRc::default());
        app.set_ed_ssh_has_key(false);
        app.set_ed_ssh_waiting(false);
        app.set_ed_ssh_public(SharedString::new());
        app.set_ed_ssh_fingerprint(SharedString::new());
        app.set_ed_ssh_type(SharedString::new());
        self.clear_secret(field::SSH_PASSPHRASE);
    }

    fn show_editor_ssh(&self, public: &str, fingerprint: &str, key_type: &str) {
        let app = self.app();
        let state = self.state.borrow();
        app.set_ed_ssh_has_key(state.editor_ssh.is_some());
        app.set_ed_ssh_waiting(state.ssh_pending.is_some());
        app.set_ed_ssh_public(public.into());
        app.set_ed_ssh_fingerprint(fingerprint.into());
        app.set_ed_ssh_type(key_type.into());
    }

    /// A key the editor takes: in OpenSSH's form without a passphrase, with its public half.
    fn take_key(&self, pair: SshKeyPair) {
        {
            let mut state = self.state.borrow_mut();
            state.editor_ssh = Some(pair.private_key);
            state.ssh_pending = None;
        }
        self.clear_secret(field::SSH_PASSPHRASE);
        self.set_error(error::NONE, "");
        self.show_editor_ssh(&pair.public_key, &pair.fingerprint, &pair.key_type);
    }

    fn key_problem(&self, problem: KeyProblem) {
        let code = match problem {
            KeyProblem::PublicOnly => error::KEY_PUBLIC_ONLY,
            KeyProblem::Unsupported => error::KEY_UNSUPPORTED,
            KeyProblem::WrongPassphrase | KeyProblem::NeedsPassphrase => error::KEY_PASSPHRASE,
            KeyProblem::NotAKey => error::NOT_A_KEY,
        };
        self.set_error(code, "");
    }

    /// A private key brought in (pasted, or a file's text): read in any common form. One with
    /// a passphrase waits for it: the editor shows a field for it (`ssh_open`).
    fn set_editor_key(&self, text: Zeroizing<String>) {
        let comment = self.app().get_ed_username().trim().to_owned();
        match ssh::import(&text, None, &comment) {
            Ok(pair) => self.take_key(pair),
            Err(KeyProblem::NeedsPassphrase) => {
                self.state.borrow_mut().ssh_pending = Some(text);
                self.set_error(error::NONE, "");
                self.app().set_ed_ssh_waiting(true);
            }
            Err(problem) => self.key_problem(problem),
        }
    }

    /// The passphrase typed in the editor: the waiting key opened with it, then kept without
    /// it. The field is cleared after every try.
    pub(super) fn ssh_open(&self) {
        let Some(text) = self.state.borrow().ssh_pending.clone() else {
            return;
        };
        let passphrase = Zeroizing::new(
            self.state.borrow().secrets[field::SSH_PASSPHRASE]
                .as_str()
                .to_owned(),
        );
        self.clear_secret(field::SSH_PASSPHRASE);
        if passphrase.is_empty() {
            return self.set_error(error::KEY_PASSPHRASE, "");
        }
        let comment = self.app().get_ed_username().trim().to_owned();
        match ssh::import(&text, Some(&passphrase), &comment) {
            Ok(pair) => self.take_key(pair),
            Err(problem) => self.key_problem(problem),
        }
    }

    /// A new Ed25519 key for the edited item, with the user field as its comment.
    pub(super) fn ssh_generate(&self) {
        let comment = self.app().get_ed_username().trim().to_owned();
        match ssh::generate_ed25519(&comment) {
            Ok(pair) => self.take_key(pair),
            Err(err) => self.set_error(error::OTHER, &err.to_string()),
        }
    }

    pub(super) fn ssh_load(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Choose the SSH private key file")
            .pick_file()
        {
            self.ssh_load_from(&path);
        }
    }

    pub(crate) fn ssh_load_from(&self, path: &Path) {
        let read = std::fs::metadata(path)
            .ok()
            .filter(|meta| meta.len() <= MAX_KEY_FILE)
            .and_then(|_| std::fs::read(path).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(Zeroizing::new);
        match read {
            Some(text) => self.set_editor_key(text),
            None => self.set_error(error::NOT_A_KEY, ""),
        }
    }

    pub(super) fn ssh_paste(&self) {
        if let Some(text) = vault_platform::clipboard::paste_text() {
            self.set_editor_key(text);
        }
    }

    pub(super) fn file_add(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Attach a file")
            .pick_file()
        {
            self.file_add_from(&path);
        }
    }

    pub(crate) fn file_add_from(&self, path: &Path) {
        let too_big = std::fs::metadata(path)
            .map(|meta| meta.len() > Attachment::MAX_BYTES as u64)
            .unwrap_or(false);
        if too_big || self.state.borrow().editor_files.len() >= Attachment::MAX_PER_ITEM {
            return self.set_error(error::FILE_TOO_LARGE, "");
        }
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let file = std::fs::read(path)
            .map_err(|err| err.to_string())
            .and_then(|data| Attachment::new(&name, data).map_err(|err| err.to_string()));
        match file {
            Ok(file) => {
                self.state.borrow_mut().editor_files.push(file);
                self.set_error(error::NONE, "");
                self.app()
                    .set_ed_files(rows(&self.state.borrow().editor_files));
            }
            Err(detail) => self.set_error(error::FILE, &detail),
        }
    }

    pub(super) fn file_remove(&self, index: i32) {
        let name = usize::try_from(index).ok().and_then(|i| {
            self.state
                .borrow()
                .editor_files
                .get(i)
                .map(|f| f.name.clone())
        });
        let Some(name) = name else {
            return;
        };
        if !self.take_confirmed(super::confirm::kind::REMOVE_FILE) {
            self.ask_confirm(super::confirm::kind::REMOVE_FILE, index, &name);
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            if let Some(index) = usize::try_from(index)
                .ok()
                .filter(|i| *i < state.editor_files.len())
            {
                state.editor_files.remove(index);
            }
        }
        self.app()
            .set_ed_files(rows(&self.state.borrow().editor_files));
    }

    fn show_editor_passkeys(&self) {
        let rows: Vec<PasskeyRow> = self
            .state
            .borrow()
            .editor_passkeys
            .iter()
            .map(|(_, row)| row.clone())
            .collect();
        self.app()
            .set_ed_passkeys(ModelRc::new(VecModel::from(rows)));
    }

    /// Takes a passkey out of the edited login (gone when it is saved).
    pub(super) fn passkey_remove(&self, index: i32) {
        let user = usize::try_from(index).ok().and_then(|i| {
            self.state
                .borrow()
                .editor_passkeys
                .get(i)
                .map(|(_, row)| row.user.to_string())
        });
        let Some(user) = user else {
            return;
        };
        if !self.take_confirmed(super::confirm::kind::REMOVE_PASSKEY) {
            self.ask_confirm(super::confirm::kind::REMOVE_PASSKEY, index, &user);
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            if let Some(index) = usize::try_from(index)
                .ok()
                .filter(|i| *i < state.editor_passkeys.len())
            {
                state.editor_passkeys.remove(index);
            }
        }
        self.show_editor_passkeys();
    }

    /// Puts the editor's files, the passkeys it kept and, for an SSH key, the key and its
    /// public half into `item`.
    pub(super) fn editor_files_into(&self, item: &mut ItemData) {
        let state = self.state.borrow();
        item.attachments = state.editor_files.clone();
        item.passkeys.retain(|passkey| {
            state
                .editor_passkeys
                .iter()
                .any(|(id, _)| *id == passkey.credential_id)
        });
        if item.kind != ItemKind::SshKey {
            return;
        }
        item.password = state
            .editor_ssh
            .as_ref()
            .map(|key| key.as_str().to_owned())
            .unwrap_or_default();
        let app = self.app();
        item.custom_fields.retain(|f| {
            f.name != ssh::PUBLIC_KEY_FIELD
                && f.name != ssh::FINGERPRINT_FIELD
                && f.name != ssh::KEY_TYPE_FIELD
        });
        for (name, value) in [
            (ssh::PUBLIC_KEY_FIELD, app.get_ed_ssh_public()),
            (ssh::FINGERPRINT_FIELD, app.get_ed_ssh_fingerprint()),
            (ssh::KEY_TYPE_FIELD, app.get_ed_ssh_type()),
        ] {
            if !value.is_empty() {
                item.custom_fields.push(CustomField {
                    name: name.to_owned(),
                    value: value.to_string(),
                    sensitive: false,
                });
            }
        }
    }

    /// The item page's list of files (none while the item is locked) and of passkeys (who
    /// and where show while it is locked too).
    pub(super) fn show_detail_files(&self, item: &ItemData, locked: bool) {
        let files: &[Attachment] = if locked { &[] } else { &item.attachments };
        let app = self.app();
        app.set_detail_files(rows(files));
        let selected = self.state.borrow().selected;
        app.set_detail_passkeys(self.detail_passkey_rows(selected, &item.passkeys));
    }

    /// Saves one of the open item's files where the person picks.
    pub(super) fn file_save(&self, index: i32) {
        let Some((_, item)) = self.selected_item() else {
            return;
        };
        let Some(file) = usize::try_from(index)
            .ok()
            .and_then(|i| item.attachments.get(i))
        else {
            return;
        };
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests
        }
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save the file")
            .set_file_name(&file.name)
            .save_file()
        else {
            return;
        };
        if let Err(err) = std::fs::write(&path, &file.data) {
            self.set_error(error::FILE, &err.to_string());
        }
    }
}
