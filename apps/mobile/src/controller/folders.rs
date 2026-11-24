//! Folders on the phone: the vault's own (made on either device, synced with it). Settings →
//! Folders lists them with how many items each holds, makes, renames, gives an icon and a
//! colour to and deletes them (a deleted folder's items stay, in no folder). The list filters
//! by one, and the editor puts an item in one.
//!
//! A folder can be inside another: its name is the other's, a slash and its own
//! (`Google/Work`), as other managers write it in their exports, so nothing new is stored.
//! A folder shows the items of the folders inside it too.

use slint::{Model, ModelRc, SharedString, VecModel};
use vault_core::FolderId;

use super::{Controller, error};
use crate::ui::FolderRow;

/// The folders in the order shown: each one followed by those inside it, the vault's order
/// kept otherwise. For each: its index in `names`, how deep it is, its parent (an index in
/// `names`). A folder's parent is the folder with the longest name that is the start of its
/// own followed by a slash; one whose parent isn't there is at the top, under its whole name.
pub(super) fn tree(names: &[&str]) -> Vec<(usize, usize, Option<usize>)> {
    let parent: Vec<Option<usize>> = names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            names
                .iter()
                .enumerate()
                .filter(|(j, other)| {
                    *j != i
                        && !other.is_empty()
                        && name
                            .strip_prefix(*other)
                            .is_some_and(|rest| rest.starts_with('/'))
                })
                .max_by_key(|(_, other)| other.len())
                .map(|(j, _)| j)
        })
        .collect();
    fn walk(
        at: Option<usize>,
        depth: usize,
        parent: &[Option<usize>],
        out: &mut Vec<(usize, usize, Option<usize>)>,
    ) {
        for (i, p) in parent.iter().enumerate() {
            if *p == at && !out.iter().any(|(seen, _, _)| *seen == i) {
                out.push((i, depth, *p));
                walk(Some(i), depth + 1, parent, out);
            }
        }
    }
    let mut out = Vec::with_capacity(names.len());
    walk(None, 0, &parent, &mut out);
    out
}

/// A folder's own name, without the folders it is in (`Work` for `Google/Work` in Google).
fn label<'a>(name: &'a str, parent: Option<&str>) -> &'a str {
    parent
        .and_then(|parent| name.strip_prefix(parent))
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(name)
}

/// Whether the folder named `name` is `outer` or inside it.
fn within(name: &str, outer: &str) -> bool {
    name == outer
        || name
            .strip_prefix(outer)
            .is_some_and(|rest| rest.starts_with('/'))
}

impl Controller {
    /// The vault's folders on screen (Settings, the list's folder filter, the editor): each
    /// followed by the folders inside it, with how many items it holds, theirs included.
    pub(super) fn publish_folders(&self) {
        let (rows, ids) = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            let summaries = vault.summaries().unwrap_or_default();
            let folders = vault.folders();
            let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
            let mut rows = Vec::new();
            let mut ids = Vec::new();
            for (index, depth, parent) in tree(&names) {
                let folder = &folders[index];
                let inside: Vec<FolderId> = folders
                    .iter()
                    .filter(|other| within(&other.name, &folder.name))
                    .map(|other| other.id)
                    .collect();
                let count = summaries
                    .iter()
                    .filter(|item| item.folder.is_some_and(|f| inside.contains(&f)))
                    .count();
                rows.push(FolderRow {
                    name: folder.name.as_str().into(),
                    label: label(&folder.name, parent.map(|p| names[p])).into(),
                    depth: i32::try_from(depth).unwrap_or(0),
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

    /// The folder at `index` on screen and the folders inside it (`None` for -1: every item).
    pub(super) fn folder_and_inside(&self, index: i32) -> Option<Vec<FolderId>> {
        let id = self.folder_at(index)?;
        let state = self.state.borrow();
        let folders = state.vault.as_ref()?.folders();
        let outer = folders.iter().find(|folder| folder.id == id)?.name.clone();
        Some(
            folders
                .iter()
                .filter(|folder| within(&folder.name, &outer))
                .map(|folder| folder.id)
                .collect(),
        )
    }

    /// A folder in Settings → Folders: its own name, the folder it is in, its icon and colour
    /// go into the form.
    pub(super) fn folder_edit(&self, index: i32) {
        let app = self.app();
        let Some(row) = usize::try_from(index)
            .ok()
            .and_then(|i| app.get_folders().row_data(i))
        else {
            return;
        };
        // The folder it is in: the row before it one level up.
        let parent = (0..index)
            .rev()
            .find(|&i| {
                app.get_folders()
                    .row_data(usize::try_from(i).unwrap_or(0))
                    .is_some_and(|other| other.depth < row.depth)
            })
            .filter(|_| row.depth > 0)
            .unwrap_or(-1);
        // It can't go into itself or a folder inside it.
        let not_parent: Vec<bool> = app
            .get_folders()
            .iter()
            .map(|other| within(&other.name, &row.name))
            .collect();
        self.set_error(error::NONE, "");
        app.set_folder_not_parent(ModelRc::new(VecModel::from(not_parent)));
        app.set_folder_choosing_parent(false);
        app.set_folder_name(row.label.clone());
        app.set_folder_parent(parent);
        app.set_folder_icon(row.icon.clone());
        app.set_folder_color(row.color);
        app.set_folder_icons_open(false);
        app.set_folder_editing(index);
    }

    /// Save in the folder form: a new folder, or the one being edited renamed, moved and
    /// restyled. A folder renamed or moved takes the folders inside it along.
    pub(super) fn folder_save(&self) {
        let app = self.app();
        let own = app
            .get_folder_name()
            .trim()
            .trim_matches('/')
            .trim()
            .to_owned();
        if own.is_empty() {
            return self.set_error(error::NAME, "");
        }
        let editing = app.get_folder_editing();
        let existing = self.folder_at(editing);
        let parent = usize::try_from(app.get_folder_parent())
            .ok()
            .and_then(|i| app.get_folders().row_data(i))
            .map(|row| row.name.to_string());
        let name = match &parent {
            Some(parent) => format!("{parent}/{own}"),
            None => own,
        };
        let icon = app.get_folder_icon().to_string();
        let color = u8::try_from(app.get_folder_color().clamp(0, 8)).unwrap_or(0);
        let old = existing.and_then(|id| {
            let state = self.state.borrow();
            state
                .vault
                .as_ref()?
                .folders()
                .iter()
                .find(|folder| folder.id == id)
                .map(|folder| folder.name.clone())
        });
        // Never into itself or a folder inside it.
        if let (Some(old), Some(parent)) = (&old, &parent)
            && within(parent, old)
        {
            return self.set_error(error::NAME, "");
        }
        let done = {
            let mut state = self.state.borrow_mut();
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            let id = match existing {
                Some(id) => vault.rename_folder(&id, &name).map(|()| id),
                None => vault.add_folder(&name),
            };
            id.and_then(|id| vault.style_folder(&id, &icon, color))
                .and_then(|()| {
                    // The folders inside it follow it to its new name.
                    let Some(old) = old.filter(|old| *old != name) else {
                        return Ok(());
                    };
                    let inner: Vec<(FolderId, String)> = vault
                        .folders()
                        .iter()
                        .filter_map(|folder| {
                            let rest = folder.name.strip_prefix(old.as_str())?.strip_prefix('/')?;
                            Some((folder.id, format!("{name}/{rest}")))
                        })
                        .collect();
                    inner
                        .iter()
                        .try_for_each(|(id, renamed)| vault.rename_folder(id, renamed))
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
        app.set_folder_parent(-1);
        self.publish_folders();
        self.refresh_list();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_inside_folders() {
        // Vault order: a folder inside another comes after it whatever its place.
        let names = [
            "Google/Work",
            "Money",
            "Google",
            "Google/Work/Old",
            "Games/PC",
            "Google/Home",
        ];
        let order: Vec<(usize, usize, Option<usize>)> = tree(&names);
        let shown: Vec<(&str, usize)> = order
            .iter()
            .map(|(i, depth, _)| (names[*i], *depth))
            .collect();
        assert_eq!(
            shown,
            [
                ("Money", 0),
                ("Google", 0),
                ("Google/Work", 1),
                ("Google/Work/Old", 2),
                ("Google/Home", 1),
                ("Games/PC", 0),
            ]
        );
        // Labels: a folder's own name; one whose parent isn't there keeps its whole name.
        assert_eq!(label("Google/Work/Old", Some("Google/Work")), "Old");
        assert_eq!(label("Games/PC", None), "Games/PC");
        assert!(within("Google/Work", "Google") && within("Google", "Google"));
        assert!(!within("Googler", "Google") && !within("Google", "Google/Work"));
    }
}
