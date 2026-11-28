//! The title bar's toolbar (app.slint, `TitleBar`): the sidebar shown or hidden (kept on this
//! computer), the search focused from anywhere, and the vault's mark: its name (the file's
//! while locked, since the vault's own is inside the encrypted body) and the icon chosen for it
//! on this computer (device state, never the vault file), or the name's initial.

use std::time::Duration;

use slint::{ComponentHandle, SharedString};
use vault_platform::DeviceState;

use super::{Controller, Panel, Screen, error};

/// The first letter of `name`, as the vault's mark shows it ("" for none).
pub(super) fn initial(name: &str) -> String {
    name.trim()
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_default()
}

impl Controller {
    /// The vault's mark in the title bar: the file's name, the icon chosen here, the initial
    /// of the name shown (the vault's own once it is open).
    pub(super) fn show_vault_mark(&self) {
        let app = self.app();
        let stem = self
            .state
            .borrow()
            .path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        app.set_vault_stem(SharedString::from(stem.as_str()));
        let name = app.get_vault_name();
        let shown = if app.get_screen() == Screen::Vault && !name.is_empty() {
            name.to_string()
        } else {
            stem
        };
        app.set_vault_initial(SharedString::from(initial(&shown)));
        let id = app.get_vault_id();
        let icon = if id.is_empty() {
            String::new()
        } else {
            DeviceState::load()
                .map(|state| state.vault_icon(&id))
                .unwrap_or_default()
        };
        app.set_vault_icon(SharedString::from(icon));
    }

    /// Settings → This vault, or the vault menu: the icon of this vault on this computer ("" for
    /// its initial).
    pub(super) fn vault_icon_chosen(&self, icon: &str) {
        let id = self.app().get_vault_id();
        if id.is_empty() {
            return;
        }
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.set_vault_icon(&id, icon);
        if let Err(err) = device_state.save() {
            self.set_error(error::FILE, &err.to_string());
            return;
        }
        self.show_vault_mark();
    }

    /// The vault menu's "Icon on this computer…": Settings → This vault, where the icons are.
    pub(super) fn choose_vault_icon(&self) {
        if self.app().get_screen() != Screen::Vault {
            return;
        }
        self.open_settings();
        self.app().set_settings_section(1);
    }

    /// An alert of the title bar's panel: `kind` 0–4 is a Password health group (shown alone,
    /// as its filter does), 10 is Settings → Sync.
    pub(super) fn open_alert(&self, kind: i32) {
        let app = self.app();
        if app.get_screen() != Screen::Vault {
            return;
        }
        app.set_alerts_panel(false);
        match kind {
            0..=4 => {
                app.set_health_filter(kind);
                self.open_health();
            }
            10 => {
                self.open_settings();
                app.set_settings_section(2);
            }
            _ => {}
        }
    }

    /// The toolbar's sidebar button and Ctrl+B: the index hidden or shown, kept on this
    /// computer (that setting alone is saved).
    pub(super) fn toggle_sidebar(&self) {
        let app = self.app();
        let hidden = !app.get_sidebar_hidden();
        app.set_sidebar_hidden(hidden);
        self.state.borrow_mut().settings.sidebar_hidden = hidden;
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.settings.sidebar_hidden = hidden;
        if let Err(err) = device_state.save() {
            self.set_error(error::FILE, &err.to_string());
        }
    }

    /// The toolbar's search and Ctrl+F: the item list's search takes the focus, the list shown
    /// first when a tool page was open.
    pub(super) fn search_now(&self) {
        let app = self.app();
        if app.get_screen() != Screen::Vault
            || app.get_panel() == Panel::Editor
            || app.get_folder_dialog() >= 0
        {
            return;
        }
        if app.get_panel() != Panel::Detail {
            self.select_category(app.get_category());
        }
        // Once the list is there (it is made when the item page shows).
        let weak = app.as_weak();
        slint::Timer::single_shot(Duration::ZERO, move || {
            if let Some(app) = weak.upgrade() {
                app.set_focus_search(app.get_focus_search().wrapping_add(1));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::initial;

    #[test]
    fn the_mark_shows_the_names_first_letter() {
        assert_eq!(initial("personal"), "P");
        assert_eq!(initial("  ärzte"), "Ä");
        assert_eq!(initial("2026 taxes"), "2");
        assert_eq!(initial("— work"), "W");
        assert_eq!(initial(""), "");
    }
}
