//! Files attached to items and SSH key items on the phone (format v9), as on the desktop: the
//! editor keeps an item's files and its SSH private key here, in Rust; the screens show file
//! names and sizes, and a key's public half. Files come in and go out through the system's
//! picker (the shell), never anywhere else.

use slint::{ModelRc, SharedString, VecModel};
use vault_core::{Attachment, CustomField, ItemData, ItemKind, ssh};
use zeroize::Zeroizing;

use super::{Controller, error, notice};
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

fn is_private_key(text: &str) -> bool {
    let text = text.trim();
    text.starts_with("-----BEGIN") && text.contains("PRIVATE KEY-----")
}

fn field_value(item: &ItemData, name: &str) -> String {
    item.custom_fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.clone())
        .unwrap_or_default()
}

/// See [`Controller::editor_extras`].
pub(super) struct EditorExtras {
    files: Vec<Attachment>,
    key: Option<Zeroizing<String>>,
    public: String,
    fingerprint: String,
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
        item.custom_fields
            .retain(|f| f.name != ssh::PUBLIC_KEY_FIELD && f.name != ssh::FINGERPRINT_FIELD);
        for (name, value) in [
            (ssh::PUBLIC_KEY_FIELD, self.public),
            (ssh::FINGERPRINT_FIELD, self.fingerprint),
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
        let (public, fingerprint) = item.map_or_else(Default::default, |item| {
            (
                field_value(item, ssh::PUBLIC_KEY_FIELD),
                field_value(item, ssh::FINGERPRINT_FIELD),
            )
        });
        {
            let mut state = self.state.borrow_mut();
            state.editor_files = files;
            state.editor_ssh = key;
        }
        self.show_editor_key(&public, &fingerprint);
        self.app()
            .set_ed_files(rows(&self.state.borrow().editor_files, false));
    }

    pub(super) fn clear_editor_files(&self) {
        {
            let mut state = self.state.borrow_mut();
            state.editor_files.clear();
            state.editor_ssh = None;
        }
        self.app().set_ed_files(ModelRc::default());
        self.show_editor_key("", "");
    }

    fn show_editor_key(&self, public: &str, fingerprint: &str) {
        let app = self.app();
        app.set_ed_ssh_has_key(self.state.borrow().editor_ssh.is_some());
        app.set_ed_ssh_public(SharedString::from(public));
        app.set_ed_ssh_fingerprint(SharedString::from(fingerprint));
    }

    fn set_editor_key(&self, private: Zeroizing<String>) {
        if !is_private_key(&private) {
            return self.set_error(error::NOT_A_KEY, "");
        }
        let public = ssh::public_key_of(&private).unwrap_or_default();
        let fingerprint = ssh::fingerprint(&public).unwrap_or_default();
        self.state.borrow_mut().editor_ssh = Some(private);
        self.set_error(error::NONE, "");
        self.show_editor_key(&public, &fingerprint);
    }

    pub(super) fn ssh_generate(&self) {
        let comment = self.app().get_ed_username().trim().to_owned();
        match ssh::generate_ed25519(&comment) {
            Ok(pair) => {
                self.state.borrow_mut().editor_ssh = Some(pair.private_key);
                self.set_error(error::NONE, "");
                self.show_editor_key(&pair.public_key, &pair.fingerprint);
            }
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
            pick::IMPORT => self.import_file(bytes),
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
        let public = if item.kind == ItemKind::SshKey {
            field_value(item, ssh::PUBLIC_KEY_FIELD)
        } else {
            String::new()
        };
        app.set_d_ssh_public(public.into());
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
