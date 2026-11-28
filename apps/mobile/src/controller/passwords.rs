//! A new master password's review on the phone, as on the desktop (THREAT_MODEL.md,
//! "Passwords that guard something alone"): one below the one-factor floor
//! (`vault_core::health::holds_alone`) is warned about, with six random words offered instead,
//! and the person may keep it; it can be checked against known data breaches first (the box
//! next to it, off until ticked: it uses the network). A protected export's password below the
//! floor is refused outright: it alone guards the file.

use vault_core::{
    generator::{PassphraseOptions, generate_passphrase},
    health,
};
use zeroize::Zeroizing;

use super::{Controller, error, field};

/// Which screen a review is about (`pw-place`): what keeping the password goes on with.
pub(super) mod place {
    pub const NONE: i32 = 0;
    /// Settings, Master password (the sheet).
    pub const CHANGE: i32 = 1;
    /// Recovery with the three parts: the new master password.
    pub const RECOVERY: i32 = 2;
}

/// What a review says (`pw-warning`; the words are in app.slint).
pub(super) mod warning {
    pub const NONE: i32 = 0;
    pub const WEAK: i32 = 1;
    pub const LEAKED: i32 = 2;
    pub const LEAK_CHECK_FAILED: i32 = 3;
}

/// Six random words from the EFF list: what "Use a generated passphrase" puts in.
fn passphrase() -> Option<Zeroizing<String>> {
    generate_passphrase(&PassphraseOptions {
        words: 6,
        separator: "-".into(),
        ..PassphraseOptions::default()
    })
    .ok()
}

impl Controller {
    /// Before the new master password of `place` (field NEW) is used: `true` to go on now.
    /// Otherwise a warning shows under it, and the person's answer goes on from there.
    pub(super) fn review_new_password(&self, place: i32) -> bool {
        let (easy, leaks_due) = {
            let state = self.state.borrow();
            let easy = state.weak_kept != Some(field::NEW)
                && !health::holds_alone(state.secrets[field::NEW].as_str(), &[]);
            (easy, state.leaks_cleared != Some(field::NEW))
        };
        if easy {
            self.show_review(place, warning::WEAK, "");
            return false;
        }
        if leaks_due && self.app().get_check_new_leaks() {
            let password = self.secret(field::NEW);
            let lookup = self.state.borrow().leak_lookup;
            self.hide_review();
            self.run_in_session(
                move || lookup(&password),
                move |c, found| c.new_password_leaks(place, found),
            );
            return false;
        }
        self.hide_review();
        true
    }

    fn new_password_leaks(&self, place: i32, found: Result<u64, String>) {
        match found {
            Ok(0) => {
                self.state.borrow_mut().leaks_cleared = Some(field::NEW);
                self.go_on_after_review(place);
            }
            Ok(count) => self.show_review(place, warning::LEAKED, &count.to_string()),
            Err(detail) => self.show_review(place, warning::LEAK_CHECK_FAILED, &detail),
        }
    }

    /// "Keep this one" (or "Go on without the check").
    pub(super) fn keep_new_password(&self) {
        let app = self.app();
        let place = app.get_pw_place();
        if place == place::NONE {
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            if app.get_pw_warning() == warning::WEAK {
                state.weak_kept = Some(field::NEW);
            } else {
                state.leaks_cleared = Some(field::NEW);
            }
        }
        self.hide_review();
        self.go_on_after_review(place);
    }

    fn go_on_after_review(&self, place: i32) {
        match place {
            place::CHANGE => self.change_password(),
            place::RECOVERY => self.recover(),
            _ => {}
        }
    }

    /// "Use a generated passphrase": six random words in `field` (and in the field that
    /// confirms it), shown, so the person sees what they will have to type.
    pub(super) fn use_passphrase(&self, field: i32) {
        let Some(index) = usize::try_from(field).ok().filter(|&i| i < field::COUNT) else {
            return;
        };
        let Some(phrase) = passphrase() else {
            return;
        };
        let targets: &[usize] = if index == field::NEW {
            &[field::NEW, field::NEW_AGAIN]
        } else {
            &[index]
        };
        for &target in targets {
            self.with_secret(target as i32, |buffer| {
                buffer.set(&phrase);
            });
        }
        self.state.borrow_mut().showing[index] = true;
        self.publish_lengths();
        self.set_error(error::NONE, "");
    }

    fn show_review(&self, place: i32, what: i32, arg: &str) {
        let app = self.app();
        app.set_pw_place(place);
        app.set_pw_warning(what);
        app.set_pw_warning_arg(arg.into());
    }

    pub(super) fn hide_review(&self) {
        let app = self.app();
        app.set_pw_place(place::NONE);
        app.set_pw_warning(warning::NONE);
        app.set_pw_warning_arg("".into());
    }

    /// A new password form is done or gone: the breach check is unticked for the next one.
    pub(super) fn forget_review(&self) {
        self.hide_review();
        self.app().set_check_new_leaks(false);
        let mut state = self.state.borrow_mut();
        state.weak_kept = None;
        state.leaks_cleared = None;
    }

    /// The text of secure field `index` changed: what was decided about it no longer counts,
    /// and a warning about it goes.
    pub(super) fn new_password_edited(&self, index: usize) {
        if index != field::NEW {
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            state.weak_kept = None;
            state.leaks_cleared = None;
        }
        if self.app().get_pw_place() != place::NONE {
            self.hide_review();
        }
    }
}
