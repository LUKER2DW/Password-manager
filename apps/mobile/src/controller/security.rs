//! The security log on the phone (`vault_platform::security_log`): next to the phone's vaults,
//! one file per vault, and Settings, Security lists it. The web preview keeps none.
//!
//! Recording never stops what it records: a log that can't be written is left as it is.

#[cfg(not(target_arch = "wasm32"))]
pub(super) use vault_platform::security_log::{gave, how, kind};

#[cfg(target_arch = "wasm32")]
#[allow(dead_code)]
pub(super) mod kind {
    pub const UNLOCKED: u16 = 1;
    pub const UNLOCK_FAILED: u16 = 2;
    pub const EXPORTED: u16 = 6;
    pub const DEVICE_REMOVED: u16 = 11;
    pub const KEY_RENEWED: u16 = 12;
    pub const PASSWORD_CHANGED: u16 = 15;
    pub const AUTOFILL_GAVE: u16 = 16;
    pub const PASSKEY_USED: u16 = 17;
}
#[cfg(target_arch = "wasm32")]
#[allow(dead_code)]
pub(super) mod how {
    pub const PASSWORD: &str = "password";
    pub const DEVICE: &str = "device";
    pub const RECOVERY: &str = "recovery";
}
#[cfg(target_arch = "wasm32")]
#[allow(dead_code)]
pub(super) mod gave {
    pub const LOGIN: &str = "login";
    pub const PASSKEY: &str = "passkey";
}

use slint::{ModelRc, VecModel};
use vault_core::Vault;

use super::Controller;

/// Lines shown at first, and added by each "Show older".
const PAGE: usize = 10;

#[cfg(not(target_arch = "wasm32"))]
mod log {
    use std::path::Path;

    use slint::SharedString;
    use vault_core::Vault;
    use vault_platform::security_log::{Event, Line, SecurityLog};

    use crate::{ui::SecurityLine, view};

    pub(super) fn unlocked(folder: &Path, vault: &Vault, how: &str, now: i64) {
        let log = SecurityLog::in_dir(folder, &vault.id_hex());
        if log.open(vault, now).is_ok() {
            let _ = log.record(&Event::new(super::kind::UNLOCKED, now).detail(how));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn note(
        folder: &Path,
        vault_id: &str,
        kind: u16,
        site: &str,
        title: &str,
        detail: &str,
        now: i64,
    ) {
        let event = Event::new(kind, now).site(site).title(title).detail(detail);
        let _ = SecurityLog::in_dir(folder, vault_id).record(&event);
    }

    pub(super) fn device_changes(
        folder: &Path,
        vault: &Vault,
        before: &[vault_core::sync::SyncDevice],
        now: i64,
    ) {
        let log = SecurityLog::in_dir(folder, &vault.id_hex());
        for event in vault_platform::security_log::device_changes(before, vault.sync_devices(), now)
        {
            let _ = log.record(&event);
        }
    }

    pub(super) fn lines(folder: &Path, vault: &Vault, offset: i32) -> Vec<SecurityLine> {
        SecurityLog::in_dir(folder, &vault.id_hex())
            .read(vault)
            .unwrap_or_default()
            .into_iter()
            .map(|line| match line {
                Line::Event(event) => SecurityLine {
                    kind: i32::from(event.kind),
                    at: SharedString::from(view::date_time(event.at, offset)),
                    site: SharedString::from(event.site.as_str()),
                    title: SharedString::from(event.title.as_str()),
                    detail: SharedString::from(event.detail.as_str()),
                },
                Line::Unreadable => SecurityLine::default(),
            })
            .collect()
    }

    pub(super) fn clear(folder: &Path, vault: &Vault, now: i64) {
        let _ = SecurityLog::in_dir(folder, &vault.id_hex()).clear(vault, now);
    }

    pub(super) fn reseal(folder: &Path, vault: &Vault, former: &vault_core::FormerKey) {
        let _ = SecurityLog::in_dir(folder, &vault.id_hex()).reseal(vault, former);
    }

    pub(super) fn remove(folder: &Path, vault_id: &str) {
        SecurityLog::in_dir(folder, vault_id).remove();
    }
}

#[cfg(target_arch = "wasm32")]
mod log {
    use std::path::Path;

    use vault_core::Vault;

    use crate::ui::SecurityLine;

    pub(super) fn unlocked(_: &Path, _: &Vault, _: &str, _: i64) {}
    #[allow(clippy::too_many_arguments)]
    pub(super) fn note(_: &Path, _: &str, _: u16, _: &str, _: &str, _: &str, _: i64) {}
    pub(super) fn device_changes(_: &Path, _: &Vault, _: &[vault_core::sync::SyncDevice], _: i64) {}
    pub(super) fn lines(_: &Path, _: &Vault, _: i32) -> Vec<crate::ui::SecurityLine> {
        Vec::<SecurityLine>::new()
    }
    pub(super) fn clear(_: &Path, _: &Vault, _: i64) {}
    pub(super) fn reseal(_: &Path, _: &Vault, _: &vault_core::FormerKey) {}
    pub(super) fn remove(_: &Path, _: &str) {}
}

fn now() -> i64 {
    crate::view::now_unix()
}

impl Controller {
    /// After an unlock: the log made or checked, and the unlock in it.
    pub(super) fn log_unlocked(&self, vault: &Vault, how: &str) {
        log::unlocked(&self.folder(), vault, how, now());
    }

    /// An unlock of the vault on screen failed.
    pub(super) fn log_failed(&self, how: &str) {
        let path = self.state.borrow().path.clone();
        let Some(id) = super::files::read(&path)
            .ok()
            .and_then(|bytes| Vault::inspect(&bytes).ok())
            .map(|info| info.id_hex)
        else {
            return;
        };
        log::note(&self.folder(), &id, kind::UNLOCK_FAILED, "", "", how, now());
    }

    /// Adds an entry to the open vault's log.
    pub(super) fn log_event(&self, kind: u16, site: &str, title: &str, detail: &str) {
        let Some(id) = self.state.borrow().vault.as_ref().map(Vault::id_hex) else {
            return;
        };
        log::note(&self.folder(), &id, kind, site, title, detail, now());
        self.publish_security_log();
    }

    /// After a sync round: the devices that joined or left since `before`.
    pub(super) fn log_device_changes(&self, before: &[vault_core::sync::SyncDevice]) {
        {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            log::device_changes(&self.folder(), vault, before, now());
        }
        self.publish_security_log();
    }

    /// After a renewed vault key was taken: the log's key sealed again under the new one.
    pub(super) fn reseal_security_log(&self, former: &vault_core::FormerKey) {
        let state = self.state.borrow();
        if let Some(vault) = state.vault.as_ref() {
            log::reseal(&self.folder(), vault, former);
        }
    }

    /// The vault left this phone: its log goes too.
    pub(super) fn remove_security_log(&self, vault_id: &str) {
        log::remove(&self.folder(), vault_id);
    }

    /// Settings, Security: the newest lines, up to the number asked for.
    pub(super) fn publish_security_log(&self) {
        let offset = self.system().utc_offset_minutes();
        let lines = {
            let state = self.state.borrow();
            match state.vault.as_ref() {
                Some(vault) => log::lines(&self.folder(), vault, offset),
                None => Vec::new(),
            }
        };
        let shown = self.state.borrow().security_log_shown.max(PAGE);
        let app = self.app();
        app.set_security_log_more(i32::try_from(lines.len().saturating_sub(shown)).unwrap_or(0));
        app.set_security_log(ModelRc::new(VecModel::from(
            lines.into_iter().take(shown).collect::<Vec<_>>(),
        )));
    }

    pub(super) fn security_log_more(&self) {
        {
            let mut state = self.state.borrow_mut();
            state.security_log_shown = state.security_log_shown.max(PAGE) + PAGE;
        }
        self.publish_security_log();
    }

    pub(super) fn clear_security_log(&self) {
        {
            let state = self.state.borrow();
            if let Some(vault) = state.vault.as_ref() {
                log::clear(&self.folder(), vault, now());
            }
        }
        self.state.borrow_mut().security_log_shown = PAGE;
        self.publish_security_log();
    }
}
