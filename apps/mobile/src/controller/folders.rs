//! Folders on the phone: the vault's own (made on either device, synced with it). Settings →
//! Folders lists them with how many items each holds, makes, renames, gives an icon to and
//! deletes them (a deleted folder's items stay, in no folder). The list filters by one, and
//! the editor puts an item in one.

use slint::{ModelRc, SharedString, VecModel};
use vault_core::FolderId;

use super::{Controller, error};
use crate::ui::FolderRow;

impl Controller {
    /// The vault's folders on screen (Settings, the list's folder filter, the editor), in
    /// the vault's order.
    pub(super) fn publish_folders(&self) {
        let (rows, ids) = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            let summaries = vault.summaries().unwrap_or_default();
            let mut rows = Vec::new();
            let mut ids = Vec::new();
            for folder in vault.folders() {
                let count = summaries
                    .iter()
                    .filter(|item| item.folder == Some(folder.id))
                    .count();
                rows.push(FolderRow {
                    name: folder.name.as_str().into(),
                    icon: folder.icon.as_str().into(),
                    color: i32::from(folder.color),
                    count: i32::try_from(count).unwrap_or(i32::MAX),
                });
                ids.push(folder.id);
            }
            (rows, ids)
        };
        let app = self.app();
        // A folder filter that points past the end (a folder deleted) goes back to all.
        if usize::try_from(app.get_folder_filter()).is_ok_and(|i| i >= ids.len()) {
            app.set_folder_filter(-1);
        }
        self.state.borrow_mut().folder_ids = ids;
        app.set_folders(ModelRc::new(VecModel::from(rows)));
    }

    /// The folder at `index` on screen (-1 = none).
    pub(super) fn folder_at(&self, index: i32) -> Option<FolderId> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.state.borrow().folder_ids.get(index).copied())
    }

    /// The index on screen of `folder` (-1 = none).
    pub(super) fn folder_index(&self, folder: Option<FolderId>) -> i32 {
        folder
            .and_then(|id| {
                self.state
                    .borrow()
                    .folder_ids
                    .iter()
                    .position(|other| *other == id)
            })
            .and_then(|i| i32::try_from(i).ok())
            .unwrap_or(-1)
    }

    /// A folder in Settings → Folders: its name and icon go into the form.
    pub(super) fn folder_edit(&self, index: i32) {
        let found = self.folder_at(index).and_then(|id| {
            let state = self.state.borrow();
            let vault = state.vault.as_ref()?;
            vault
                .folders()
                .iter()
                .find(|folder| folder.id == id)
                .map(|folder| (folder.name.clone(), folder.icon.clone()))
        });
        let Some((name, icon)) = found else {
            return;
        };
        let app = self.app();
        self.set_error(error::NONE, "");
        app.set_folder_name(name.as_str().into());
        app.set_folder_icon(icon.as_str().into());
        app.set_folder_editing(index);
    }

    /// Save in the folder form: a new folder, or the one being edited renamed and restyled.
    pub(super) fn folder_save(&self) {
        let app = self.app();
        let name = app.get_folder_name().trim().to_owned();
        if name.is_empty() {
            return self.set_error(error::NAME, "");
        }
        let icon = app.get_folder_icon().to_string();
        let editing = app.get_folder_editing();
        let existing = self.folder_at(editing);
        let done = {
            let mut state = self.state.borrow_mut();
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            let id = match existing {
                Some(id) => vault.rename_folder(&id, &name).map(|()| id),
                None => vault.add_folder(&name),
            };
            id.and_then(|id| {
                let color = vault
                    .folders()
                    .iter()
                    .find(|folder| folder.id == id)
                    .map_or(0, |folder| folder.color);
                vault.style_folder(&id, &icon, color)
            })
        };
        if let Err(err) = done {
            return self.set_error(error::NOT_SAVED, &err.to_string());
        }
        if !self.save() {
            return;
        }
        self.set_error(error::NONE, "");
        app.set_folder_editing(-2);
        app.set_folder_name(SharedString::new());
        self.publish_folders();
        self.notify(super::notice::SAVED, "");
    }

    /// "Delete this folder", confirmed: the folder goes, its items stay in no folder.
    pub(super) fn folder_delete(&self) {
        let app = self.app();
        let Some(id) = self.folder_at(app.get_folder_editing()) else {
            return;
        };
        let name = app.get_folder_name().to_string();
        let removed = {
            let mut state = self.state.borrow_mut();
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            vault.remove_folder(&id)
        };
        if let Err(err) = removed {
            return self.set_error(error::NOT_SAVED, &err.to_string());
        }
        if !self.save() {
            return;
        }
        app.set_folder_editing(-2);
        app.set_folder_name(SharedString::new());
        self.publish_folders();
        self.refresh_list();
        self.notify(super::notice::DELETED, &name);
    }
}
