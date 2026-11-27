//! Settings → Security → "Ask for the fingerprint or screen lock every time" (on by default):
//! each use of a secret asks the phone's own check first, in that very action, and nothing is
//! remembered between two uses. A use is showing or copying a password (a card's PIN, an SSH
//! private key), showing or copying a one-time code (shown only until that code runs out),
//! showing or copying a card's number or security code, showing a secure note, viewing or
//! saving an attached file, opening an item in the editor (which shows every field), and
//! showing or copying the generator's history.
//!
//! The check is Android's prompt (a strong biometric or the screen lock, `System::check_person`).
//! A phone with no screen lock can't ask it: the item lock's PIN or password is asked instead,
//! in a sheet, for that use only; with no item lock either, nothing shows until a screen lock is
//! set or the setting is turned off. A computer's window and the web preview have no such check
//! at all (`checks_person` is `None`): nothing is asked there.
//!
//! The item lock works as it did: its check ("Show the secrets") opens the item's secrets for
//! the visit. With this setting it also shows them (the password, the card's number), so that
//! one action never asks twice: every later use asks the phone again.

use slint::{ComponentHandle, Model};
use vault_core::{GuardCheck, ItemId, ItemKind, Vault, totp::Totp};

use super::{Controller, error, field, fingerprint, grouped, notice, sheet};
use crate::{system::PromptWords, ui::Words, view};

/// One use of a secret that asks first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Use {
    /// The item page's eye on the password (a card's PIN, an SSH private key).
    ShowPassword,
    /// The card's number and security code.
    ShowCard,
    /// A secure note's text.
    ShowNote,
    /// The open item's one-time code, and one on the Codes page: shown until that code runs
    /// out (the next time step, or a counter-based code's next one).
    ShowCode,
    ShowCodeOf(ItemId),
    /// The item page's copy buttons (`copy`'s `what`: 1 password, 2 code, 5 card number,
    /// 6 security code).
    Copy(i32),
    /// A code on the Codes page.
    CopyCode(ItemId),
    /// The item opened in the editor, every field of it on screen.
    Edit,
    /// An attached file: View, and Save (handed to the shell's "save as").
    PreviewFile(i32),
    SaveFile(i32),
    /// The generator's history unmasked, and one of its passwords copied (by its
    /// fingerprint: the list may change while the check is asked).
    ShowGenerated,
    CopyGenerated([u8; 32]),
}

impl Use {
    /// Whether it is about the item open on the item page (its answer is used only while that
    /// item is still the one open).
    fn on_item_page(self) -> bool {
        !matches!(
            self,
            Self::CopyCode(_) | Self::ShowCodeOf(_) | Self::ShowGenerated | Self::CopyGenerated(_)
        )
    }

    /// What the check's title says it is for (app.slint `Words.use-title`).
    fn words(self) -> i32 {
        match self {
            Self::ShowPassword => 1,
            Self::Copy(1) => 2,
            Self::Copy(2) | Self::CopyCode(_) => 3,
            Self::ShowCard => 4,
            Self::Copy(5) => 5,
            Self::Copy(6) => 6,
            Self::ShowNote => 7,
            Self::Edit => 8,
            Self::PreviewFile(_) => 9,
            Self::SaveFile(_) => 10,
            Self::ShowGenerated => 11,
            Self::CopyGenerated(_) => 12,
            Self::ShowCode | Self::ShowCodeOf(_) => 13,
            Self::Copy(_) => 0,
        }
    }
}

/// What one use asks first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ask {
    /// Nothing: the setting is off, or nothing here can check (a computer's window, the web
    /// preview).
    Nothing,
    /// The phone's own check.
    Phone,
    /// No screen lock: the item lock's PIN (2) or password (3), typed in the sheet.
    ItemLock(i32),
    /// No screen lock, and no item lock with a PIN or password: nothing shows.
    Refused,
}

/// What Settings says about the setting (app.slint `ask-each-use-state`).
mod state {
    /// The phone asks its own check.
    pub const PHONE: i32 = 0;
    /// No screen lock: the item PIN is asked instead.
    pub const ITEM_PIN: i32 = 1;
    /// No screen lock: the item password is asked instead.
    pub const ITEM_PASSWORD: i32 = 2;
    /// No screen lock and no item lock to ask: secrets wait.
    pub const NOTHING_ASKS: i32 = 3;
    /// Nothing on this device can ask (a computer's window, the web preview).
    pub const NOT_HERE: i32 = 4;
}

/// An item's one-time code as the screens show it now.
pub(super) struct CodeNow {
    /// Its digits, grouped, or as many dots while it waits for its eye.
    pub(super) text: String,
    /// Seconds it has left (0 for a counter-based code, which stays until the next one).
    pub(super) left: u64,
    pub(super) period: u64,
    pub(super) hidden: bool,
}

/// Which code of `totp` is the current one at `now` (Unix seconds): its time step, or the
/// counter of a counter-based code.
fn which_code(totp: &Totp, now: u64) -> u64 {
    totp.counter().unwrap_or(now / totp.period().max(1))
}

fn now() -> u64 {
    u64::try_from(view::now_unix()).unwrap_or(0)
}

/// A code's place, kept: `digits` dots grouped as the digits are.
fn dots(digits: usize) -> String {
    let dots = "•".repeat(digits);
    if digits < 6 {
        return dots;
    }
    let half = digits.div_ceil(2);
    format!("{} {}", "•".repeat(half), "•".repeat(digits - half))
}

/// A use waiting for its check: what it is, the item open then, and the session it was asked
/// in (a vault locked or opened since makes it nothing).
#[derive(Debug, Clone, Copy)]
pub(super) struct Waiting {
    act: Use,
    item: Option<ItemId>,
    session: u64,
}

/// The item lock's own check when it is typed (2 PIN, 3 password); `None` for one that asks
/// the master password, or no item lock.
fn typed_check(vault: &Vault) -> Option<i32> {
    let guard = vault.item_guard();
    if !(guard.encrypts() || guard.is_legacy()) {
        return None;
    }
    match guard.check {
        GuardCheck::Pin => Some(2),
        GuardCheck::Password => Some(3),
        GuardCheck::Master => None,
    }
}

impl Controller {
    /// What a use of a secret asks first right now.
    pub(super) fn each_use_asks(&self) -> Ask {
        if !self.state.borrow().prefs.ask_each_use {
            return Ask::Nothing;
        }
        let state = self.state.borrow();
        match state.person_check {
            None => Ask::Nothing,
            Some(true) => Ask::Phone,
            Some(false) => match state.vault.as_ref().and_then(typed_check) {
                Some(check) => Ask::ItemLock(check),
                None => Ask::Refused,
            },
        }
    }

    /// Asks the system again whether it can check the person (a screen lock set or removed
    /// meanwhile), and shows what follows: Settings → Security (the switch, and what it does on
    /// this phone now), the codes (dots or not).
    pub(super) fn refresh_each_use(&self) {
        let check = self.system().checks_person();
        let on = {
            let mut state = self.state.borrow_mut();
            state.person_check = check;
            state.prefs.ask_each_use
        };
        let shown = match check {
            None => state::NOT_HERE,
            Some(true) => state::PHONE,
            Some(false) => {
                let state = self.state.borrow();
                match state.vault.as_ref().and_then(typed_check) {
                    Some(2) => state::ITEM_PIN,
                    Some(_) => state::ITEM_PASSWORD,
                    None => state::NOTHING_ASKS,
                }
            }
        };
        let app = self.app();
        app.set_ask_each_use(on);
        app.set_ask_each_use_state(shown);
        if self.state.borrow().vault.is_some() {
            self.refresh_codes();
        }
    }

    pub(super) fn ask_each_use_changed(&self, on: bool) {
        self.change_prefs(|prefs| prefs.ask_each_use = on);
        self.refresh_each_use();
        // What waited for a check before it shows (a secure note's text) shows or waits now.
        if self.state.borrow().selected.is_some() {
            self.show_item();
        }
    }

    /// Does `act` now, or once the check it needs has passed. Nothing is remembered: the
    /// next use asks again.
    pub(super) fn ask_first(&self, act: Use) {
        match self.each_use_asks() {
            Ask::Nothing => self.use_now(act),
            Ask::Phone => {
                self.wait_for_check(act);
                let app = self.app();
                let (kind, title) = {
                    let state = self.state.borrow();
                    let item = state
                        .vault
                        .as_ref()
                        .zip(match act {
                            Use::CopyCode(id) => Some(id),
                            _ if act.on_item_page() => state.selected,
                            _ => None,
                        })
                        .and_then(|(vault, id)| vault.get_item(&id).ok());
                    (
                        item.as_ref().map_or(0, |item| super::kind_index(item.kind)),
                        item.map(|item| item.title.clone()).unwrap_or_default(),
                    )
                };
                let words = PromptWords {
                    title: app
                        .global::<Words>()
                        .invoke_use_title(act.words(), kind)
                        .into(),
                    detail: title,
                    cancel: app.get_use_cancel().into(),
                };
                if let Err(detail) = self.system().check_person(&words) {
                    self.state.borrow_mut().each_use = None;
                    self.check_failed(&detail);
                }
            }
            Ask::ItemLock(check) => {
                self.wait_for_check(act);
                let app = self.app();
                app.set_use_check(check);
                app.set_use_what(act.words());
                app.invoke_ask(sheet::USE_CHECK);
            }
            Ask::Refused => {
                self.refresh_each_use();
                self.notify(notice::NO_SCREEN_LOCK, "");
            }
        }
    }

    fn wait_for_check(&self, act: Use) {
        let mut state = self.state.borrow_mut();
        let item = if act.on_item_page() {
            state.selected
        } else {
            None
        };
        let session = state.session;
        state.each_use = Some(Waiting { act, item, session });
    }

    /// The shell's answer to [`crate::System::check_person`]: the person passed it, or why
    /// not ("" when cancelled, "no_lock" when the phone has no screen lock any more).
    pub fn person_checked(&self, answer: Result<(), String>) {
        let Some(waiting) = self.state.borrow_mut().each_use.take() else {
            return;
        };
        match answer {
            Ok(()) => {
                if self.still_for(&waiting) {
                    self.use_now(waiting.act);
                }
            }
            Err(detail) if detail.is_empty() => {}
            Err(detail) => self.check_failed(&detail),
        }
    }

    /// The check couldn't be asked, or didn't pass: nothing shows, and the person hears why.
    fn check_failed(&self, detail: &str) {
        self.refresh_each_use();
        if detail == "no_lock" {
            self.notify(notice::NO_SCREEN_LOCK, "");
        } else {
            self.notify(notice::CHECK_FAILED, detail);
        }
    }

    /// The use is still about what is on screen: the same vault, still open, and for the item
    /// page, the same item.
    fn still_for(&self, waiting: &Waiting) -> bool {
        let state = self.state.borrow();
        state.vault.is_some()
            && state.session == waiting.session
            && (!waiting.act.on_item_page() || state.selected == waiting.item)
    }

    /// The item lock's PIN or password typed for one use, on a phone with no screen lock
    /// (the sheet, `ask(20)`). It opens the lock just long enough for that use when it was
    /// closed.
    pub(super) fn use_lock_checked(&self) {
        if self.app().get_busy() {
            return;
        }
        let typed = self.secret(field::ITEM_CHECK);
        if typed.is_empty() {
            return self.set_error(error::WRONG_CHECK, "");
        }
        let was_open = self
            .state
            .borrow()
            .vault
            .as_ref()
            .is_some_and(Vault::secrets_open);
        let right = self.open_item_lock(&typed);
        self.clear_fields(&[field::ITEM_CHECK]);
        if !right {
            // A wrong PIN closes the lock (the core forgets its key): what it showed goes.
            if was_open {
                self.show_item();
            }
            return self.set_error(error::WRONG_CHECK, "");
        }
        self.set_error(error::NONE, "");
        self.close_sheet(sheet::USE_CHECK);
        // An item the lock covers stays open for the rest of its visit, as after "Show the
        // secrets" (a wrong try before this one closed it); for anything else the lock opened
        // only for this use.
        let keeps_open = was_open || {
            let state = self.state.borrow();
            state
                .vault
                .as_ref()
                .zip(state.selected)
                .and_then(|(vault, id)| vault.get_item(&id).ok().map(|item| vault.guards(&item)))
                .unwrap_or(false)
        };
        let waiting = self.state.borrow_mut().each_use.take();
        if let Some(waiting) = waiting
            && self.still_for(&waiting)
        {
            self.use_now(waiting.act);
        }
        if !keeps_open {
            if let Some(vault) = self.state.borrow_mut().vault.as_mut() {
                vault.lock_secrets();
            }
            self.publish_generated();
        }
    }

    /// The sheet of [`Controller::use_lock_checked`] closed without its check: the use waits
    /// no more.
    pub(super) fn use_check_dropped(&self) {
        self.state.borrow_mut().each_use = None;
    }

    /// The use itself, its check passed (or not needed).
    fn use_now(&self, act: Use) {
        match act {
            Use::ShowPassword => {
                self.state.borrow_mut().show_password = true;
                self.show_item();
            }
            Use::ShowCard => {
                self.state.borrow_mut().show_card = true;
                self.show_item();
            }
            Use::ShowNote => {
                self.state.borrow_mut().show_note = true;
                self.show_item();
            }
            Use::ShowCode => {
                let selected = self.state.borrow().selected;
                if let Some(id) = selected {
                    self.show_code_now(id);
                }
            }
            Use::ShowCodeOf(id) => self.show_code_now(id),
            Use::Copy(what) => self.copy_now(what),
            Use::CopyCode(id) => self.copy_code_now(id),
            Use::Edit => {
                let selected = self.state.borrow().selected;
                self.open_editor(selected);
            }
            Use::PreviewFile(index) => self.preview_file_now(index),
            Use::SaveFile(index) => self.app().invoke_save_file(index),
            Use::ShowGenerated => {
                self.app().set_gen_history_shown(true);
                self.publish_generated();
            }
            Use::CopyGenerated(which) => self.copy_generated_now(&which),
        }
    }

    /// A use of the open item's secrets: asked first when the item shows them (nothing is
    /// asked, nor done, while it waits for the item lock).
    pub(super) fn use_of_item(&self, act: Use) {
        if self.selected_item().is_some() {
            self.ask_first(act);
        }
    }

    /// A code on the Codes page, copied: asked first, unless it waits for the item lock.
    pub(super) fn copy_code(&self, index: i32) {
        let id = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            usize::try_from(index)
                .ok()
                .and_then(|index| state.code_ids.get(index).copied())
                .filter(|id| {
                    vault
                        .get_item(id)
                        .is_ok_and(|item| self.check_for(vault, &item) == 0)
                })
        };
        if let Some(id) = id {
            self.ask_first(Use::CopyCode(id));
        }
    }

    fn copy_code_now(&self, id: ItemId) {
        let code = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            vault
                .get_item(&id)
                .ok()
                .filter(|item| self.check_for(vault, item) == 0)
                .and_then(|item| Totp::parse(&item.totp).ok())
                .map(|totp| totp.now().0)
        };
        if let Some(code) = code {
            self.copy_secret(&code, notice::CODE_COPIED);
        }
    }

    // ---- one-time codes ----

    /// `totp`'s code now, for the item `id`: its digits, or dots when codes `hide` (every use
    /// asks) and this one wasn't asked for since it came.
    pub(super) fn code_now(&self, id: ItemId, totp: &Totp, hide: bool) -> CodeNow {
        let now = now();
        let which = which_code(totp, now);
        let period = totp.period().max(1);
        let left = if totp.is_counter_based() {
            0
        } else {
            period - now % period
        };
        let hidden = hide && !self.state.borrow().codes_shown.contains(&(id, which));
        let text = if hidden {
            dots(usize::try_from(totp.digits()).unwrap_or(6))
        } else {
            grouped(&totp.code_for(which))
        };
        CodeNow {
            text,
            left,
            period,
            hidden,
        }
    }

    /// The item's current code counts as asked for, until it runs out (nothing while the item
    /// waits for the item lock, or has no code).
    pub(super) fn mark_code_shown(&self, id: ItemId) {
        let mut state = self.state.borrow_mut();
        let which = state
            .vault
            .as_ref()
            .and_then(|vault| vault.get_item(&id).ok())
            .filter(|item| !item.is_locked())
            .and_then(|item| Totp::parse(&item.totp).ok())
            .map(|totp| which_code(&totp, now()));
        if let Some(which) = which
            && !state.codes_shown.contains(&(id, which))
        {
            state.codes_shown.push((id, which));
        }
    }

    /// Shows the item's current code, its check passed: on its page and on the Codes page.
    fn show_code_now(&self, id: ItemId) {
        self.mark_code_shown(id);
        self.show_codes_again(id);
    }

    /// The item page (when `id` is open) and the Codes page, drawn again.
    fn show_codes_again(&self, id: ItemId) {
        if self.state.borrow().selected == Some(id) {
            self.show_item();
        }
        self.refresh_codes();
    }

    /// Codes shown after their check go back to dots once a newer code is the current one
    /// (the time step passed, or a counter-based code moved on). Never asked again by itself.
    pub(super) fn forget_spent_codes(&self) {
        let now = now();
        let mut state = self.state.borrow_mut();
        if state.codes_shown.is_empty() {
            return;
        }
        let state = &mut *state;
        let vault = state.vault.as_ref();
        state.codes_shown.retain(|(id, which)| {
            vault
                .and_then(|vault| vault.get_item(id).ok())
                .and_then(|item| Totp::parse(&item.totp).ok())
                .is_some_and(|totp| which_code(&totp, now) == *which)
        });
    }

    /// The item page's eye on the code: shown (asked first) or hidden (never asked).
    pub(super) fn toggle_code(&self) {
        let Some(id) = self.state.borrow().selected else {
            return;
        };
        if self.app().get_d_code_hidden() {
            self.use_of_item(Use::ShowCode);
        } else {
            self.hide_code(id);
        }
    }

    /// A Codes page row's eye: that code only.
    pub(super) fn toggle_code_at(&self, index: i32) {
        let row = usize::try_from(index).ok();
        let id = row.and_then(|row| self.state.borrow().code_ids.get(row).copied());
        let (Some(row), Some(id)) = (row, id) else {
            return;
        };
        let hidden = self.app().get_codes().row_data(row).map(|row| row.hidden);
        match hidden {
            Some(true) => {
                let open = {
                    let state = self.state.borrow();
                    state.vault.as_ref().is_some_and(|vault| {
                        vault
                            .get_item(&id)
                            .is_ok_and(|item| self.check_for(vault, &item) == 0)
                    })
                };
                if open {
                    self.ask_first(Use::ShowCodeOf(id));
                }
            }
            Some(false) => self.hide_code(id),
            None => {}
        }
    }

    fn hide_code(&self, id: ItemId) {
        self.state
            .borrow_mut()
            .codes_shown
            .retain(|(shown, _)| *shown != id);
        self.show_codes_again(id);
    }

    /// The tests: every code shown counts as one that ran out (as once its time step passed),
    /// and the screens are drawn again as each second does.
    #[cfg(test)]
    pub(crate) fn codes_run_out(&self) {
        for (_, which) in &mut self.state.borrow_mut().codes_shown {
            *which = which.wrapping_sub(1);
        }
        self.forget_spent_codes();
        if self.state.borrow().selected.is_some() {
            self.show_item();
        }
        self.refresh_codes();
    }

    /// The generator's history, shown (the screens flipped `gen-history-shown` already) or
    /// hidden again.
    pub(super) fn gen_history_toggled(&self) {
        let app = self.app();
        if app.get_gen_history_shown() && self.each_use_asks() != Ask::Nothing {
            // Masked until the check passes.
            app.set_gen_history_shown(false);
            self.publish_generated();
            return self.ask_first(Use::ShowGenerated);
        }
        self.publish_generated();
    }

    /// A password of the generator's history, copied: asked first.
    pub(super) fn copy_generated_entry(&self, index: i32) {
        if let Some(password) = self.generated_at(index) {
            self.ask_first(Use::CopyGenerated(fingerprint(password.as_bytes())));
        }
    }

    /// Whether the open item is a secure note whose text waits for a check (with this
    /// setting, it shows only once asked for).
    pub(super) fn note_waits(&self, kind: ItemKind, asks: Ask) -> bool {
        kind == ItemKind::SecureNote && asks != Ask::Nothing && !self.state.borrow().show_note
    }
}
