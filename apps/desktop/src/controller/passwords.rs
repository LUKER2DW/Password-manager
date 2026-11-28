//! A new password's review (THREAT_MODEL.md, "Passwords that guard something alone"): before a
//! new master password or item lock password is used, one below the one-factor floor
//! (`vault_core::health::holds_alone`) is warned about, with six random words offered instead;
//! the person may keep it. A new master password can also be checked against known data
//! breaches first (`NewPassword.check-leaks`, off until ticked: it uses the network), with the
//! leak check's k-anonymous query. A protected export's password below the floor is refused
//! outright (`export_password_problem`): it alone guards the file.

use slint::{ComponentHandle, Model};
use vault_core::{
    generator::{self, PassphraseOptions},
    health,
};
use zeroize::Zeroizing;

use super::{Controller, JobResult, error, field};
use crate::ui::NewPassword;

/// Which form a review is about (`NewPassword.place`): what keeping the password goes on with.
pub(super) mod place {
    pub const NONE: i32 = 0;
    /// Onboarding's master password (step 1).
    pub const ONBOARDING: i32 = 1;
    /// The recovery screen's new master password.
    pub const RECOVERY: i32 = 2;
    /// Settings → Change master password.
    pub const CHANGE: i32 = 3;
    /// Onboarding's item lock password (step 2).
    pub const LOCK_ONBOARDING: i32 = 4;
    /// Settings → Item lock.
    pub const LOCK_SETTINGS: i32 = 5;
}

/// What a review says (`NewPassword.warning`; the words are in review.slint).
pub(super) mod warning {
    pub const NONE: i32 = 0;
    pub const WEAK_MASTER: i32 = 1;
    pub const LEAKED: i32 = 2;
    pub const LEAK_CHECK_FAILED: i32 = 3;
    pub const WEAK_LOCK: i32 = 4;
}

/// The secure field that holds the new password of `place`.
fn field_of(place: i32) -> usize {
    match place {
        place::CHANGE => field::NEW,
        place::LOCK_ONBOARDING | place::LOCK_SETTINGS => field::GUARD_NEW,
        _ => field::MASTER,
    }
}

/// The field that confirms `field` (typed again), if it has one.
fn confirm_of(field: usize) -> Option<usize> {
    match field {
        field::MASTER => Some(field::CONFIRM),
        field::NEW => Some(field::NEW_AGAIN),
        _ => None,
    }
}

/// Six random words from the EFF list: the passphrase every "Use a generated passphrase" offers.
pub(super) fn passphrase() -> Option<Zeroizing<String>> {
    generator::generate_passphrase(&PassphraseOptions {
        words: 6,
        separator: "-".into(),
        ..PassphraseOptions::default()
    })
    .ok()
}

impl Controller {
    /// Before the new password of `place` is used: `true` to go on now. Otherwise a warning
    /// shows under it (an easy password, or the breach check under way or failed), and the
    /// person's answer goes on from there (`keep_reviewed_password`, `use_passphrase`).
    pub(super) fn review_new_password(&self, place: i32) -> bool {
        let field = field_of(place);
        let master = !matches!(place, place::LOCK_ONBOARDING | place::LOCK_SETTINGS);
        let (easy, leaks_due) = {
            let state = self.state.borrow();
            let easy = state.weak_kept != Some(field)
                && !health::holds_alone(state.secrets[field].as_str(), &[]);
            (easy, master && state.leaks_cleared != Some(field))
        };
        if easy {
            let what = if master {
                warning::WEAK_MASTER
            } else {
                warning::WEAK_LOCK
            };
            self.show_password_warning(place, what, "");
            return false;
        }
        if leaks_due && self.app().global::<NewPassword>().get_check_leaks() {
            let password = Zeroizing::new(self.state.borrow().secrets[field].as_str().to_owned());
            let lookup = self.state.borrow().leak_count;
            self.hide_password_warning();
            self.run_job(move || JobResult::NewPasswordLeaks {
                place,
                found: lookup(&password),
            });
            return false;
        }
        self.hide_password_warning();
        true
    }

    /// The breach check's answer about the new password of `place`.
    pub(super) fn new_password_leaks(&self, place: i32, found: Result<u64, String>) {
        match found {
            Ok(0) => {
                self.state.borrow_mut().leaks_cleared = Some(field_of(place));
                self.go_on_after_review(place);
            }
            Ok(count) => self.show_password_warning(place, warning::LEAKED, &count.to_string()),
            Err(detail) => self.show_password_warning(place, warning::LEAK_CHECK_FAILED, &detail),
        }
    }

    /// "Keep this one" (or "Go on without the check"): that password, as it is typed now, is
    /// not asked about again, and what was asked goes on.
    pub(super) fn keep_reviewed_password(&self) {
        let app = self.app();
        let review = app.global::<NewPassword>();
        let place = review.get_place();
        if place == place::NONE {
            return;
        }
        let field = field_of(place);
        {
            let mut state = self.state.borrow_mut();
            match review.get_warning() {
                warning::WEAK_MASTER | warning::WEAK_LOCK => state.weak_kept = Some(field),
                _ => state.leaks_cleared = Some(field),
            }
        }
        self.hide_password_warning();
        self.go_on_after_review(place);
    }

    fn go_on_after_review(&self, place: i32) {
        match place {
            place::ONBOARDING | place::LOCK_ONBOARDING => self.create_vault(),
            place::RECOVERY => self.recover(),
            place::CHANGE => self.change_password(),
            place::LOCK_SETTINGS => self.save_guard(),
            _ => {}
        }
    }

    /// "Use a generated passphrase": six random words in `field` and the field that confirms
    /// it, shown (the eye opened), so the person sees what they will have to type.
    pub(super) fn use_passphrase(&self, field: i32) {
        let Some(index) = usize::try_from(field).ok().filter(|&i| i < field::COUNT) else {
            return;
        };
        let Some(phrase) = passphrase() else {
            return;
        };
        for target in std::iter::once(index).chain(confirm_of(index)) {
            self.edit_secret(target as i32, |buffer| {
                buffer.set(&phrase);
            });
        }
        self.showing.set_row_data(index, true);
        self.refresh_shown(index);
        self.hide_password_warning();
    }

    fn show_password_warning(&self, place: i32, what: i32, arg: &str) {
        let app = self.app();
        let review = app.global::<NewPassword>();
        review.set_place(place);
        review.set_warning(what);
        review.set_arg(arg.into());
    }

    pub(super) fn hide_password_warning(&self) {
        let app = self.app();
        let review = app.global::<NewPassword>();
        review.set_place(place::NONE);
        review.set_warning(warning::NONE);
        review.set_arg("".into());
    }

    /// A new password form is done or gone: the breach check is unticked for the next one.
    pub(super) fn forget_review(&self) {
        self.hide_password_warning();
        self.app().global::<NewPassword>().set_check_leaks(false);
        let mut state = self.state.borrow_mut();
        state.weak_kept = None;
        state.leaks_cleared = None;
    }

    /// The text of secure field `index` changed: what was decided about it no longer counts,
    /// and a warning about it goes.
    pub(super) fn new_password_edited(&self, index: usize) {
        {
            let mut state = self.state.borrow_mut();
            if state.weak_kept == Some(index) {
                state.weak_kept = None;
            }
            if state.leaks_cleared == Some(index) {
                state.leaks_cleared = None;
            }
        }
        let place = self.app().global::<NewPassword>().get_place();
        if place != place::NONE && field_of(place) == index {
            self.hide_password_warning();
        }
    }

    /// Tests: how the breach check of a new master password asks.
    #[cfg(test)]
    pub(crate) fn set_leak_count(&self, lookup: fn(&str) -> Result<u64, String>) {
        self.state.borrow_mut().leak_count = lookup;
    }

    /// What is wrong with a protected export's password (fields NEW and NEW_AGAIN), as an
    /// error code: too short, not typed the same twice, or below the one-factor floor.
    pub(super) fn export_password_problem(&self) -> Option<i32> {
        let state = self.state.borrow();
        let (password, again) = (&state.secrets[field::NEW], &state.secrets[field::NEW_AGAIN]);
        if password.char_count() < super::MIN_MASTER_PASSWORD_CHARS {
            Some(error::TOO_SHORT)
        } else if !password.matches(again) {
            Some(error::MISMATCH)
        } else if !vault_core::sealed_export::password_holds(password.as_str()) {
            Some(error::WEAK_EXPORT)
        } else {
            None
        }
    }
}
