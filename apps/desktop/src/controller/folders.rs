//! Folders: the dialog that creates and edits them (name, icon, colour, a picture from a
//! website or image link), deleting, and reordering by drag or from the right-click menu.

use slint::{Image, SharedString};
use vault_core::{FolderBrowser, FolderId};

use super::{CURRENT, Controller, FOLDER_CATEGORY, Runner, error, notice};
use vault_platform::website_icons::IconSource;

/// `folder-dialog` values in app.slint.
const CLOSED: i32 = -1;
const NEW: i32 = 0;
const SETTINGS: i32 = 1;
const DELETE: i32 = 2;

/// `fd-preview-state` values in dialogs.slint.
const PREVIEW_NONE: i32 = 0;
const PREVIEW_LOOKING: i32 = 1;
const PREVIEW_FOUND: i32 = 2;
const PREVIEW_MISSING: i32 = 3;

impl Controller {
    fn folder_at(&self, index: i32) -> Option<vault_core::Folder> {
        let index = usize::try_from(index).ok()?;
        let state = self.state.borrow();
        state.session.as_ref()?.vault.folders().get(index).cloned()
    }

    fn folder_index(&self, id: &FolderId) -> Option<usize> {
        let state = self.state.borrow();
        state
            .session
            .as_ref()?
            .vault
            .folders()
            .iter()
            .position(|f| f.id == *id)
    }

    /// The picture for a folder's link, when it has been downloaded.
    pub(super) fn folder_picture(&self, link: &str) -> Option<Image> {
        let key = IconSource::parse(link)?.key();
        self.cached_icon(&key)
    }

    pub(super) fn new_folder(&self) {
        self.state.borrow_mut().dialog_folder = None;
        let app = self.app();
        app.set_fd_name(SharedString::new());
        app.set_fd_icon(SharedString::new());
        app.set_fd_color(0);
        app.set_fd_link(SharedString::new());
        app.set_fd_browser(0);
        app.set_fd_paired(self.browser_pairing_id().is_some());
        self.state.borrow_mut().dialog_folder_browser = None;
        self.show_folder_preview(None, PREVIEW_NONE);
        self.set_error(error::NONE, "");
        app.set_folder_dialog(NEW);
    }

    pub(super) fn edit_folder(&self, index: i32) {
        self.open_folder_dialog(index, SETTINGS);
    }

    pub(super) fn ask_delete_folder(&self, index: i32) {
        self.open_folder_dialog(index, DELETE);
    }

    fn open_folder_dialog(&self, index: i32, mode: i32) {
        let Some(folder) = self.folder_at(index) else {
            return;
        };
        // The dialog is about the folder on screen.
        if self.app().get_category() != FOLDER_CATEGORY + index {
            self.select_category(FOLDER_CATEGORY + index);
        }
        let items = self
            .state
            .borrow()
            .summaries
            .iter()
            .filter(|s| s.folder == Some(folder.id))
            .count();
        self.state.borrow_mut().dialog_folder = Some(folder.id);
        let app = self.app();
        app.set_fd_name(SharedString::from(folder.name.as_str()));
        app.set_fd_icon(SharedString::from(folder.icon.as_str()));
        app.set_fd_color(i32::from(folder.color));
        app.set_fd_link(SharedString::from(folder.icon_url.as_str()));
        app.set_fd_items(i32::try_from(items).unwrap_or(i32::MAX));
        app.set_fd_browser(match folder.browser {
            FolderBrowser::Any => 0,
            FolderBrowser::Never => 1,
            FolderBrowser::Only(_) => 2,
        });
        app.set_fd_paired(self.browser_pairing_id().is_some());
        // Kept to a pairing: kept as it is unless the person picks another choice.
        self.state.borrow_mut().dialog_folder_browser = Some(folder.browser);
        let picture = self.folder_picture(&folder.icon_url);
        let state = if picture.is_some() {
            PREVIEW_FOUND
        } else {
            PREVIEW_NONE
        };
        self.show_folder_preview(picture, state);
        self.set_error(error::NONE, "");
        app.set_folder_dialog(mode);
    }

    fn show_folder_preview(&self, picture: Option<Image>, state: i32) {
        let app = self.app();
        app.set_fd_has_preview(picture.is_some());
        app.set_fd_preview(picture.unwrap_or_default());
        app.set_fd_preview_state(state);
    }

    pub(super) fn close_folder_dialog(&self) {
        self.state.borrow_mut().dialog_folder = None;
        let app = self.app();
        app.set_folder_dialog(CLOSED);
        self.show_folder_preview(None, PREVIEW_NONE);
        self.set_error(error::NONE, "");
    }

    /// Downloads the picture for the typed link to show it before saving (and keeps it in the
    /// encrypted icon cache, so saving doesn't download it again).
    pub(super) fn fetch_folder_preview(&self) {
        let link = self.app().get_fd_link();
        if link.trim().is_empty() {
            self.show_folder_preview(None, PREVIEW_NONE);
            return;
        }
        let Some(source) = IconSource::parse(&link) else {
            self.set_error(error::FOLDER_LINK, "");
            return;
        };
        self.set_error(error::NONE, "");
        let key = source.key();
        if let Some(picture) = self.cached_icon(&key) {
            self.show_folder_preview(Some(picture), PREVIEW_FOUND);
            return;
        }
        self.show_folder_preview(None, PREVIEW_LOOKING);
        let runner = self.state.borrow().runner;
        match runner {
            Runner::Inline => {
                let icon = source.fetch();
                self.folder_preview_fetched(key, icon);
            }
            Runner::Thread => {
                std::thread::spawn(move || {
                    let icon = source.fetch();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                            controller.folder_preview_fetched(key, icon);
                        }
                    });
                });
            }
        }
    }

    fn folder_preview_fetched(&self, key: String, icon: vault_platform::website_icons::Fetched) {
        if self.state.borrow().session.is_none() {
            return; // locked meanwhile
        }
        let found = icon.shows();
        self.state.borrow_mut().icons.insert(key.clone(), icon);
        if found {
            self.save_icon_cache();
            self.refresh_list();
        }
        let app = self.app();
        let still_asked = app.get_folder_dialog() >= 0
            && IconSource::parse(&app.get_fd_link()).is_some_and(|s| s.key() == key);
        if still_asked {
            if found {
                self.show_folder_preview(self.cached_icon(&key), PREVIEW_FOUND);
            } else {
                self.show_folder_preview(None, PREVIEW_MISSING);
            }
        }
    }

    pub(super) fn save_folder_dialog(&self) {
        let app = self.app();
        let name = app.get_fd_name().trim().to_owned();
        if name.is_empty() {
            self.set_error(error::FOLDER_NAME, "");
            return;
        }
        let link = app.get_fd_link().trim().to_owned();
        if !link.is_empty() && IconSource::parse(&link).is_none() {
            self.set_error(error::FOLDER_LINK, "");
            return;
        }
        let icon = app.get_fd_icon().to_string();
        let color = u8::try_from(app.get_fd_color().clamp(0, 15)).unwrap_or(0);
        let kept = self.state.borrow().dialog_folder_browser;
        let browser = match app.get_fd_browser() {
            1 => FolderBrowser::Never,
            2 => match (kept, self.browser_pairing_id()) {
                (Some(FolderBrowser::Only(id)), _) => FolderBrowser::Only(id),
                (_, Some(id)) => FolderBrowser::Only(id),
                // No extension connected: kept out rather than open to any.
                (_, None) => FolderBrowser::Never,
            },
            _ => FolderBrowser::Any,
        };
        let editing = self.state.borrow().dialog_folder;
        let result = self.state.borrow_mut().session.as_mut().map(|s| {
            let id = match editing {
                Some(id) => s.vault.rename_folder(&id, &name).map(|()| id),
                None => s.vault.add_folder(&name),
            }?;
            s.vault.style_folder(&id, &icon, color)?;
            s.vault.set_folder_icon_url(&id, &link)?;
            s.vault.set_folder_browser(&id, browser)?;
            Ok(id)
        });
        match result {
            Some(Ok(id)) => {
                if !self.save_vault() {
                    return;
                }
                self.close_folder_dialog();
                match (editing, self.folder_index(&id)) {
                    // A new folder opens right away.
                    (None, Some(index)) => {
                        self.select_category(FOLDER_CATEGORY + i32::try_from(index).unwrap_or(0));
                    }
                    _ => {
                        self.refresh_list();
                        self.show_detail();
                    }
                }
                if !link.is_empty() {
                    self.start_icon_fetch();
                }
                self.notify(notice::SAVED, "");
            }
            Some(Err(err)) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
            }
            None => {}
        }
    }

    pub(super) fn delete_folder_dialog(&self) {
        let Some(id) = self.state.borrow().dialog_folder else {
            return;
        };
        let removed = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| s.vault.remove_folder(&id));
        if matches!(removed, Some(Ok(()))) && self.save_vault() {
            self.close_folder_dialog();
            self.app().set_category(0);
            self.refresh_list();
            self.show_detail();
            // Places point at folders by position, which just shifted.
            self.reset_history();
            self.notify(notice::FOLDER_DELETED, "");
        }
    }

    /// Moves the folder at `from` to position `to`; the folder being browsed stays selected.
    pub(super) fn move_folder(&self, from: i32, to: i32) {
        let (Some(folder), Ok(to)) = (self.folder_at(from), usize::try_from(to)) else {
            return;
        };
        let browsing = self.browsed_folder();
        let moved = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| s.vault.move_folder(&folder.id, to));
        if !matches!(moved, Some(Ok(()))) || !self.save_vault() {
            return;
        }
        if let Some(index) = browsing.and_then(|id| self.folder_index(&id)) {
            self.app()
                .set_category(FOLDER_CATEGORY + i32::try_from(index).unwrap_or(0));
        }
        // Places in the history point at folders by position: keep only what still matches.
        self.reset_history();
        self.refresh_list();
    }
}
