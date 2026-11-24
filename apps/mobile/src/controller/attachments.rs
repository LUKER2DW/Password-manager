//! Files attached to items and SSH key items on the phone (format v9), as on the desktop: the
//! editor keeps an item's files and its SSH private key here, in Rust; the screens show file
//! names and sizes, and a key's public half. Files come in and go out through the system's
//! picker (the shell), never anywhere else.

use slint::{ModelRc, SharedString, VecModel};
use vault_core::{
    Attachment, CustomField, ItemData, ItemKind,
    ssh::{self, KeyProblem, SshKeyPair},
};
use zeroize::Zeroizing;

use super::{Controller, error, field, notice, sheet};
use crate::{
    ui::{FileRow, PasskeyRow},
    view,
};

/// What a file chosen in the system's picker is for (the screens' `pick-file` argument).
mod pick {
    pub const ATTACHMENT: i32 = 1;
    pub const SSH_KEY: i32 = 2;
    /// Another manager's export, for Settings → Import and export.
    pub const IMPORT: i32 = 3;
    /// Recovery: a picture a recovery part was hidden in (the computer's "Keep a part in a
    /// picture").
    pub const PART_PICTURE: i32 = 4;
}

fn rows(files: &[Attachment], pdf: bool) -> ModelRc<FileRow> {
    let rows: Vec<FileRow> = files
        .iter()
        .map(|file| FileRow {
            name: file.name.as_str().into(),
            size: view::file_size(file.data.len()).into(),
            preview: super::preview::kind_of(&file.name, &file.data, pdf),
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

fn field_value(item: &ItemData, name: &str) -> String {
    item.custom_fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.clone())
        .unwrap_or_default()
}

/// An SSH key item's type ("Ed25519", "RSA 4096"): as kept, or read from a key kept before
/// the type was ("" behind the item lock, where the key isn't there).
fn key_type_of(item: &ItemData) -> String {
    let kept = field_value(item, ssh::KEY_TYPE_FIELD);
    if !kept.is_empty() {
        return kept;
    }
    ssh::key_type_of(&item.password).unwrap_or_default()
}

/// See [`Controller::editor_extras`].
pub(super) struct EditorExtras {
    files: Vec<Attachment>,
    key: Option<Zeroizing<String>>,
    public: String,
    fingerprint: String,
    key_type: String,
}

impl EditorExtras {
    pub(super) fn apply(self, item: &mut ItemData) {
        item.attachments = self.files;
        if item.kind != ItemKind::SshKey {
            return;
        }
        item.password = self
            .key
            .as_ref()
            .map(|key| key.as_str().to_owned())
            .unwrap_or_default();
        item.custom_fields.retain(|f| {
            f.name != ssh::PUBLIC_KEY_FIELD
                && f.name != ssh::FINGERPRINT_FIELD
                && f.name != ssh::KEY_TYPE_FIELD
        });
        for (name, value) in [
            (ssh::PUBLIC_KEY_FIELD, self.public),
            (ssh::FINGERPRINT_FIELD, self.fingerprint),
            (ssh::KEY_TYPE_FIELD, self.key_type),
        ] {
            if !value.is_empty() {
                item.custom_fields.push(CustomField {
                    name: name.to_owned(),
                    value,
                    sensitive: false,
                });
            }
        }
    }
}

impl Controller {
    pub(super) fn editor_files_from(&self, item: Option<&ItemData>) {
        let files = item
            .map(|item| item.attachments.clone())
            .unwrap_or_default();
        let key = item
            .filter(|item| item.kind == ItemKind::SshKey && !item.password.is_empty())
            .map(|item| Zeroizing::new(item.password.clone()));
        let (public, fingerprint, key_type) = item.map_or_else(Default::default, |item| {
            (
                field_value(item, ssh::PUBLIC_KEY_FIELD),
                field_value(item, ssh::FINGERPRINT_FIELD),
                key_type_of(item),
            )
        });
        {
            let mut state = self.state.borrow_mut();
            state.editor_files = files;
            state.editor_ssh = key;
            state.ssh_pending = None;
        }
        self.show_editor_key(&public, &fingerprint, &key_type);
        self.app()
            .set_ed_files(rows(&self.state.borrow().editor_files, false));
    }

    pub(super) fn clear_editor_files(&self) {
        {
            let mut state = self.state.borrow_mut();
            state.editor_files.clear();
            state.editor_ssh = None;
            state.ssh_pending = None;
        }
        self.app().set_ed_files(ModelRc::default());
        self.show_editor_key("", "", "");
    }

    fn show_editor_key(&self, public: &str, fingerprint: &str, key_type: &str) {
        let app = self.app();
        app.set_ed_ssh_has_key(self.state.borrow().editor_ssh.is_some());
        app.set_ed_ssh_public(SharedString::from(public));
        app.set_ed_ssh_fingerprint(SharedString::from(fingerprint));
        app.set_ed_ssh_type(SharedString::from(key_type));
    }

    /// A key the editor takes: in OpenSSH's form without a passphrase, with its public half.
    fn take_key(&self, pair: SshKeyPair) {
        self.state.borrow_mut().editor_ssh = Some(pair.private_key);
        self.set_error(error::NONE, "");
        self.show_editor_key(&pair.public_key, &pair.fingerprint, &pair.key_type);
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

    /// A private key brought in (pasted, or a file's text): read in any common form; one with
    /// a passphrase waits while the sheet asks for it (`ask(17)`).
    fn set_editor_key(&self, text: Zeroizing<String>) {
        let comment = self.app().get_ed_username().trim().to_owned();
        match ssh::import(&text, None, &comment) {
            Ok(pair) => self.take_key(pair),
            Err(KeyProblem::NeedsPassphrase) => {
                self.state.borrow_mut().ssh_pending = Some(text);
                self.app().invoke_ask(sheet::SSH_PASSPHRASE);
            }
            Err(problem) => self.key_problem(problem),
        }
    }

    /// The passphrase typed in the sheet: the waiting key opened with it (off the screen's
    /// thread: the passphrase's hashing takes a moment), then kept without it.
    pub(super) fn ssh_passphrase(&self) {
        let Some(text) = self.state.borrow().ssh_pending.clone() else {
            return self.close_sheet(sheet::SSH_PASSPHRASE);
        };
        let passphrase = self.secret(field::SSH_PASSPHRASE);
        if passphrase.is_empty() {
            return self.set_error(error::KEY_PASSPHRASE, "");
        }
        let comment = self.app().get_ed_username().trim().to_owned();
        self.set_error(error::NONE, "");
        self.run(
            move || ssh::import(&text, Some(&passphrase), &comment),
            |c, opened| {
                c.clear_fields(&[field::SSH_PASSPHRASE]);
                match opened {
                    Ok(pair) => {
                        c.state.borrow_mut().ssh_pending = None;
                        c.close_sheet(sheet::SSH_PASSPHRASE);
                        c.take_key(pair);
                    }
                    Err(problem) => c.key_problem(problem),
                }
            },
        );
    }

    pub(super) fn ssh_generate(&self) {
        let comment = self.app().get_ed_username().trim().to_owned();
        match ssh::generate_ed25519(&comment) {
            Ok(pair) => self.take_key(pair),
            Err(err) => self.set_error(error::NOT_SAVED, &err.to_string()),
        }
    }

    pub(super) fn ssh_paste(&self) {
        if let Some(text) = crate::platform::clipboard::paste_text() {
            self.set_editor_key(text);
        }
    }

    /// A file the person chose in the system's picker, for `purpose` ([`pick`]).
    pub fn picked_file(&self, purpose: i32, name: &str, bytes: Vec<u8>) {
        match purpose {
            pick::SSH_KEY => match String::from_utf8(bytes) {
                Ok(text) => self.set_editor_key(Zeroizing::new(text)),
                Err(_) => self.set_error(error::NOT_A_KEY, ""),
            },
            pick::ATTACHMENT => {
                if self.state.borrow().editor_files.len() >= Attachment::MAX_PER_ITEM {
                    return self.set_error(error::FILE_TOO_LARGE, "");
                }
                match Attachment::new(name, bytes) {
                    Ok(file) => {
                        self.state.borrow_mut().editor_files.push(file);
                        self.set_error(error::NONE, "");
                        self.app()
                            .set_ed_files(rows(&self.state.borrow().editor_files, false));
                    }
                    Err(vault_core::Error::AttachmentTooLarge) => {
                        self.set_error(error::FILE_TOO_LARGE, "");
                    }
                    Err(err) => self.set_error(error::UNREADABLE, &err.to_string()),
                }
            }
            pick::IMPORT => self.import_file(name, bytes),
            pick::PART_PICTURE => self.part_picture_picked(&bytes),
            _ => {}
        }
    }

    pub(super) fn file_remove(&self, index: i32) {
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
            .set_ed_files(rows(&self.state.borrow().editor_files, false));
    }

    /// What the editor adds to the item it saves: its files and, for an SSH key, the key and
    /// its public half. Taken before the vault is borrowed to store the item.
    pub(super) fn editor_extras(&self) -> EditorExtras {
        let app = self.app();
        let state = self.state.borrow();
        EditorExtras {
            files: state.editor_files.clone(),
            key: state.editor_ssh.clone(),
            public: app.get_ed_ssh_public().to_string(),
            fingerprint: app.get_ed_ssh_fingerprint().to_string(),
            key_type: app.get_ed_ssh_type().to_string(),
        }
    }

    pub(super) fn show_item_files(&self, item: &ItemData, open: bool) {
        let files: &[Attachment] = if open { &item.attachments } else { &[] };
        let app = self.app();
        app.set_d_files(rows(files, self.system().renders_pdf()));
        let passkeys: Vec<PasskeyRow> = item
            .passkeys
            .iter()
            .map(|passkey| PasskeyRow {
                site: passkey.rp_id.as_str().into(),
                user: if passkey.user_name.is_empty() {
                    passkey.display_name.as_str().into()
                } else {
                    passkey.user_name.as_str().into()
                },
            })
            .collect();
        app.set_d_passkeys(ModelRc::new(VecModel::from(passkeys)));
        let (public, fingerprint, key_type) = if item.kind == ItemKind::SshKey {
            (
                field_value(item, ssh::PUBLIC_KEY_FIELD),
                field_value(item, ssh::FINGERPRINT_FIELD),
                key_type_of(item),
            )
        } else {
            Default::default()
        };
        app.set_d_ssh_public(public.into());
        app.set_d_ssh_fingerprint(fingerprint.into());
        app.set_d_ssh_type(key_type.into());
    }

    /// The open item's file `index`, to be saved where the person picks (the shell).
    pub fn file_to_save(&self, index: i32) -> Option<(String, Vec<u8>)> {
        // -1: an export made in Settings → Import and export (settings.rs, `export_vault`).
        if index < 0 {
            let (name, bytes) = self.state.borrow_mut().export_pending.take()?;
            self.state.borrow_mut().file_expected = Some(super::fingerprint(&bytes));
            return Some((name, bytes.to_vec()));
        }
        let item = self.selected_item()?;
        let file = item.attachments.get(usize::try_from(index).ok()?)?;
        self.state.borrow_mut().file_expected = Some(super::fingerprint(&file.data));
        Some((file.name.clone(), file.data.clone()))
    }

    /// The file as read back from where it was saved. Returns whether it is the file: the
    /// shell deletes one that isn't.
    pub fn file_written(&self, read_back: Result<Vec<u8>, String>) -> bool {
        let expected = self.state.borrow_mut().file_expected.take();
        match read_back {
            Ok(back) if Some(super::fingerprint(&back)) == expected => {
                self.notify(notice::FILE_SAVED, "");
                true
            }
            Ok(_) => {
                self.set_error(error::UNREADABLE, "the file read back differs");
                false
            }
            Err(detail) => {
                self.set_error(error::UNREADABLE, &detail);
                false
            }
        }
    }
}
