//! A question before what takes a secret away: replacing a login's saved password, removing a
//! passkey (in the editor, or because its site said it is gone), removing an attached file or
//! a hidden field, clearing a password history or the generator's. A plain yes or no in a
//! dialog (`ConfirmDialog` without the master password): the item lock and the master password
//! still guard what they guard.

use slint::SharedString;

use super::Controller;

/// What waits for the person's answer (`AppWindow.confirm-kind`).
pub(super) mod kind {
    pub const NONE: i32 = 0;
    /// Saving a login whose password was changed in the editor (the argument: its name).
    pub const SAVE_PASSWORD: i32 = 1;
    /// Taking a passkey out of the edited login (the argument: its account).
    pub const REMOVE_PASSKEY: i32 = 2;
    /// Clearing the open item's password history.
    pub const CLEAR_HISTORY: i32 = 3;
    /// Taking an attached file out of the edited item (the argument: its name).
    pub const REMOVE_FILE: i32 = 4;
    /// Removing a passkey its site said it no longer knows (the argument: its account).
    pub const FORGET_PASSKEY: i32 = 5;
    /// Taking a hidden field out of the edited item (the argument: its name).
    pub const REMOVE_FIELD: i32 = 6;
    /// Clearing the history of generated passwords.
    pub const CLEAR_GENERATED: i32 = 7;
}

impl Controller {
    /// Shows the question `what` about `index` (what it is about is `arg`); the action runs only
    /// on yes ([`Controller::confirm_answered`]).
    pub(super) fn ask_confirm(&self, what: i32, index: i32, arg: &str) {
        self.state.borrow_mut().confirm_pending = Some((what, index));
        let app = self.app();
        app.set_confirm_arg(SharedString::from(arg));
        app.set_confirm_kind(what);
    }

    /// Whether the question `what` was just answered yes: the action that asked runs once
    /// without asking again.
    pub(super) fn take_confirmed(&self, what: i32) -> bool {
        let mut state = self.state.borrow_mut();
        if state.confirm_yes == Some(what) {
            state.confirm_yes = None;
            return true;
        }
        false
    }

    pub(super) fn confirm_answered(&self, yes: bool) {
        let pending = self.state.borrow_mut().confirm_pending.take();
        self.app().set_confirm_kind(kind::NONE);
        let Some((what, index)) = pending.filter(|_| yes) else {
            return;
        };
        self.state.borrow_mut().confirm_yes = Some(what);
        match what {
            kind::SAVE_PASSWORD => self.save_item(),
            kind::REMOVE_PASSKEY => self.passkey_remove(index),
            kind::CLEAR_HISTORY => self.clear_history(),
            kind::REMOVE_FILE => self.file_remove(index),
            kind::FORGET_PASSKEY => self.passkey_signal(index, true),
            kind::REMOVE_FIELD => self.field_remove(index),
            kind::CLEAR_GENERATED => self.clear_generated_history(),
            _ => {}
        }
        // Not taken (the action had nothing to do): the next one asks again.
        self.state.borrow_mut().confirm_yes = None;
    }
}
