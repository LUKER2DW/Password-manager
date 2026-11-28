//! Auto-type (M10 F11): the selected login's username, Tab, password and Enter typed into the
//! window the person was in before this app (`vault_platform::autotype`).
//!
//! From the item page's "Auto-type" and the item's right-click menu. The window's title is
//! shown first with a 3-second countdown and Cancel; then the app brings that window forward
//! and types, only while it is still the same window. The login's secrets are reached
//! through `selected_item()` when asked and read again when the countdown ends, so a login
//! behind the item lock types nothing until the lock is open, and locking cancels it.

use std::rc::Rc;

use slint::{ComponentHandle, SharedString, TimerMode};
use vault_core::{ItemId, ItemKind};
use vault_platform::autotype::{self, Desktop, Problem, Target};
use zeroize::Zeroizing;

use super::{Controller, error, notice};

/// Seconds counted down before typing.
const COUNTDOWN: i32 = 3;

/// Typing that waits for its countdown.
pub(super) struct Pending {
    target: Target,
    item: ItemId,
    left: i32,
}

/// The desktop auto-type types into: the real one, or the tests' stand-in.
pub(super) fn system() -> Rc<dyn Desktop> {
    Rc::new(autotype::System)
}

impl Controller {
    /// The app's own window, as Windows numbers it (0 when there is none, as in the tests).
    fn own_window(&self) -> isize {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        let app = self.app();
        let handle = app.window().window_handle();
        match handle.window_handle().map(|h| h.as_raw()) {
            Ok(RawWindowHandle::Win32(win32)) => win32.hwnd.get(),
            _ => 0,
        }
    }

    /// Auto-type, asked from the item page or its menu: finds the window behind the app and
    /// starts the countdown, showing that window's title.
    pub(super) fn auto_type(&self) {
        let Some((id, item)) = self.selected_item() else {
            if self.selected_item_raw().is_some() {
                self.set_error(error::SECRETS_LOCKED, "");
            }
            return;
        };
        if item.kind != ItemKind::Login || (item.username.is_empty() && item.password.is_empty()) {
            return;
        }
        let desktop = self.state.borrow().desktop.clone();
        let Some(target) = desktop.window_behind(self.own_window()) else {
            self.set_error(error::AUTOTYPE_NO_WINDOW, "");
            return;
        };
        self.set_error(error::NONE, "");
        let app = self.app();
        app.set_autotype_title(SharedString::from(target.title.as_str()));
        app.set_autotype_left(COUNTDOWN);
        self.state.borrow_mut().autotype = Some(Pending {
            target,
            item: id,
            left: COUNTDOWN,
        });
        let weak = self.this.borrow().clone();
        self.timers.autotype.start(
            TimerMode::Repeated,
            std::time::Duration::from_secs(1),
            move || {
                if let Some(controller) = weak.upgrade() {
                    controller.autotype_tick();
                }
            },
        );
    }

    fn autotype_tick(&self) {
        let left = {
            let mut state = self.state.borrow_mut();
            let Some(pending) = state.autotype.as_mut() else {
                drop(state);
                self.timers.autotype.stop();
                return;
            };
            pending.left -= 1;
            pending.left
        };
        if left > 0 {
            self.app().set_autotype_left(left);
        } else {
            self.autotype_now();
        }
    }

    /// Cancel in the countdown, Escape, or the vault locking.
    pub(super) fn autotype_cancel(&self) {
        self.timers.autotype.stop();
        self.state.borrow_mut().autotype = None;
        self.app().set_autotype_title(SharedString::new());
    }

    /// The countdown ended: types, if the login is still open and the window still the one
    /// shown.
    pub(crate) fn autotype_now(&self) {
        self.timers.autotype.stop();
        let pending = self.state.borrow_mut().autotype.take();
        self.app().set_autotype_title(SharedString::new());
        let Some(pending) = pending else { return };
        let item = self
            .state
            .borrow()
            .session
            .as_ref()
            .and_then(|s| s.vault.get_item(&pending.item).ok());
        let Some(item) = item.filter(|item| !self.item_locked(item)) else {
            self.set_error(error::SECRETS_LOCKED, "");
            return;
        };
        let username = Zeroizing::new(item.username.clone());
        let password = Zeroizing::new(item.password.clone());
        drop(item);
        let steps = autotype::login_steps(&username, &password);
        let desktop = self.state.borrow().desktop.clone();
        match autotype::type_into(&*desktop, self.own_window(), &pending.target, &steps) {
            Ok(()) => self.notify(notice::AUTOTYPE_DONE, &pending.target.title),
            Err(problem) => self.notify_long(
                match problem {
                    Problem::OwnWindow | Problem::WindowChanged => notice::AUTOTYPE_CHANGED,
                    Problem::KeysHeld => notice::AUTOTYPE_KEYS_HELD,
                    Problem::NotSent => notice::AUTOTYPE_NOT_SENT,
                },
                &pending.target.title,
            ),
        }
    }

    /// The tests' desktop, which types into nothing.
    #[cfg(test)]
    pub(crate) fn use_desktop(&self, desktop: Rc<dyn Desktop>) {
        self.state.borrow_mut().desktop = desktop;
    }
}
