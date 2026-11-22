//! Files attached to items and SSH key items (format v9).
//!
//! In the editor, the item's files and its SSH private key are kept here, in Rust: the page
//! shows file names and sizes, and a key's public half and fingerprint. A private key reaches
//! the screen only on the item page, when the person asks to see it (as a password does). A
//! file leaves the vault only through Save, to a place the person picks.

use std::path::Path;

use slint::{ModelRc, SharedString, VecModel};
use vault_core::{Attachment, CustomField, ItemData, ItemKind, ssh};
use zeroize::Zeroizing;

use super::{Controller, Runner, error};
use crate::{ui::FileRow, view};

/// The largest key file read: a private key is a few kilobytes.
const MAX_KEY_FILE: u64 = 64 * 1024;

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

/// Whether `text` looks like a private key file (OpenSSH, or the older PEM kinds).
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

impl Controller {
    /// The editor opens on `item`: its files and, for an SSH key, the key.
    pub(super) fn editor_files_from(&self, item: &ItemData) {
        let is_ssh = item.kind == ItemKind::SshKey && !item.password.is_empty();
        {
            let mut state = self.state.borrow_mut();
            state.editor_files = item.attachments.clone();
            state.editor_ssh = is_ssh.then(|| Zeroizing::new(item.password.clone()));
        }
        self.show_editor_ssh(
            &field_value(item, ssh::PUBLIC_KEY_FIELD),
            &field_value(item, ssh::FINGERPRINT_FIELD),
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
        }
        let app = self.app();
        app.set_ed_files(ModelRc::default());
        app.set_ed_ssh_has_key(false);
        app.set_ed_ssh_public(SharedString::new());
        app.set_ed_ssh_fingerprint(SharedString::new());
    }

    fn show_editor_ssh(&self, public: &str, fingerprint: &str) {
        let app = self.app();
        app.set_ed_ssh_has_key(self.state.borrow().editor_ssh.is_some());
        app.set_ed_ssh_public(public.into());
        app.set_ed_ssh_fingerprint(fingerprint.into());
    }

    /// Takes `private` as the edited item's key; its public half is read when it can be.
    fn set_editor_key(&self, private: Zeroizing<String>) {
        if !is_private_key(&private) {
            return self.set_error(error::NOT_A_KEY, "");
        }
        let public = ssh::public_key_of(&private).unwrap_or_default();
        let fingerprint = ssh::fingerprint(&public).unwrap_or_default();
        self.state.borrow_mut().editor_ssh = Some(private);
        self.set_error(error::NONE, "");
        self.show_editor_ssh(&public, &fingerprint);
    }

    /// A new Ed25519 key for the edited item, with the user field as its comment.
    pub(super) fn ssh_generate(&self) {
        let comment = self.app().get_ed_username().trim().to_owned();
        match ssh::generate_ed25519(&comment) {
            Ok(pair) => {
                self.state.borrow_mut().editor_ssh = Some(pair.private_key);
                self.set_error(error::NONE, "");
                self.show_editor_ssh(&pair.public_key, &pair.fingerprint);
            }
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

    /// Puts the editor's files and, for an SSH key, the key and its public half into `item`.
    pub(super) fn editor_files_into(&self, item: &mut ItemData) {
        let state = self.state.borrow();
        item.attachments = state.editor_files.clone();
        if item.kind != ItemKind::SshKey {
            return;
        }
        item.password = state
            .editor_ssh
            .as_ref()
            .map(|key| key.as_str().to_owned())
            .unwrap_or_default();
        let app = self.app();
        item.custom_fields
            .retain(|f| f.name != ssh::PUBLIC_KEY_FIELD && f.name != ssh::FINGERPRINT_FIELD);
        for (name, value) in [
            (ssh::PUBLIC_KEY_FIELD, app.get_ed_ssh_public()),
            (ssh::FINGERPRINT_FIELD, app.get_ed_ssh_fingerprint()),
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

    /// The item page's list of files (none while the item is locked).
    pub(super) fn show_detail_files(&self, item: &ItemData, locked: bool) {
        let files: &[Attachment] = if locked { &[] } else { &item.attachments };
        self.app().set_detail_files(rows(files));
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
