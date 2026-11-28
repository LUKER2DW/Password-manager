//! The security log (`vault_platform::security_log`): what is recorded on this computer, and
//! Settings → Security → Security log, newest first, with a way to clear it.
//!
//! Recording never stops what it records: a log that can't be written is left as it is.

use slint::{ModelRc, SharedString, VecModel};
use vault_browser::{protocol::CopyWhat, service::Answer};
use vault_core::Vault;
use vault_platform::security_log::{Event, Line, SecurityLog, gave, kind};

use super::{Controller, view};
use crate::ui::SecurityLine;

/// Lines shown at first, and added by each "Show more".
const PAGE: usize = 30;

fn log_of(vault_id: &str) -> Option<SecurityLog> {
    SecurityLog::for_vault(vault_id).ok()
}

/// After an unlock (off the UI thread too): the log made or checked, and the unlock in it.
pub(super) fn unlocked(vault: &Vault, how: &str) {
    if let Some(log) = log_of(&vault.id_hex()) {
        let now = view::now_unix();
        if log.open(vault, now).is_ok() {
            let _ = log.record(&Event::new(kind::UNLOCKED, now).detail(how));
        }
    }
}

/// A new vault: its log starts now.
pub(super) fn started(vault: &Vault) {
    if let Some(log) = log_of(&vault.id_hex()) {
        let _ = log.open(vault, view::now_unix());
    }
}

/// A failed unlock of vault `vault_id` (written with the log's public key alone).
pub(super) fn failed(vault_id: &str, how: &str) {
    note(
        vault_id,
        &Event::new(kind::UNLOCK_FAILED, view::now_unix()).detail(how),
    );
}

/// Adds `event` to vault `vault_id`'s log, if it has one.
pub(super) fn note(vault_id: &str, event: &Event) {
    if let Some(log) = log_of(vault_id) {
        let _ = log.record(event);
    }
}

/// After a renewal of the vault key: the log's key sealed again under the new one.
pub(super) fn reseal(vault: &Vault, former: &vault_core::FormerKey) {
    if let Some(log) = log_of(&vault.id_hex()) {
        let _ = log.reseal(vault, former);
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Asked {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    id: String,
}

/// What an answer to the browser extension gave or changed, as an entry: the site it was for,
/// the item's title and what was handed over (never the value itself). `title_of` finds an
/// item's title by its id (a copy names none). `None` when nothing was given.
pub(super) fn extension_event(
    request: &[u8],
    answer: &Answer,
    title_of: impl Fn(&str) -> Option<String>,
    locked: bool,
) -> Option<Event> {
    let asked: Asked = serde_json::from_slice(request).unwrap_or_default();
    let now = view::now_unix();
    let site = view::site_name(&asked.url);
    let event = |kind: u16, title: &str, what: &str| {
        Some(Event::new(kind, now).site(&site).title(title).detail(what))
    };
    let gave_kind = if locked {
        kind::LOCKED_FILL
    } else {
        kind::EXTENSION_GAVE
    };
    if let Some(title) = &answer.saved {
        return event(kind::EXTENSION_SAVED, title, gave::LOGIN);
    }
    if let Some(title) = &answer.updated {
        return event(kind::EXTENSION_SAVED, title, "update");
    }
    if let Some(title) = &answer.passkey_saved {
        return event(kind::EXTENSION_SAVED, title, gave::PASSKEY);
    }
    if let Some(title) = &answer.passkey_used {
        return event(gave_kind, title, gave::PASSKEY);
    }
    if let Some(copy) = &answer.copy {
        // A generated password copied names no item: nothing of the vault was given.
        if asked.kind != "copy" {
            return None;
        }
        let what = match copy.what {
            CopyWhat::Username => gave::USERNAME,
            CopyWhat::Password => gave::PASSWORD,
            CopyWhat::Code => gave::CODE,
        };
        let title = title_of(&asked.id).unwrap_or_default();
        return event(gave_kind, &title, what);
    }
    let title = answer.filled.as_ref()?;
    let what = match asked.kind.as_str() {
        "code" => gave::CODE,
        "reveal" => "shown",
        // A card or an identity typed into a page (F5).
        "card_fill" => gave::CARD,
        "identity_fill" => gave::IDENTITY,
        _ => gave::LOGIN,
    };
    event(gave_kind, title, what)
}

impl Controller {
    /// The open vault's id, or the id of the vault this window would unlock.
    fn log_vault_id(&self) -> Option<String> {
        let open = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex());
        open.or_else(|| self.locked_vault_id())
    }

    /// Adds `event` to this vault's log.
    pub(super) fn log_event(&self, event: Event) {
        if let Some(id) = self.log_vault_id() {
            note(&id, &event);
        }
    }

    /// An event of `kind` now, with `detail`.
    pub(super) fn log_now(&self, kind: u16, detail: &str) {
        self.log_event(Event::new(kind, view::now_unix()).detail(detail));
    }

    /// An item's title, by its id (hex), from the list the app shows.
    pub(super) fn title_of(&self, id: &str) -> Option<String> {
        let state = self.state.borrow();
        state
            .summaries
            .iter()
            .find(|s| s.id.to_hex() == id)
            .map(|s| s.title.clone())
    }

    /// Settings → Security → Security log: the newest lines, up to the number asked for.
    pub(super) fn show_security_log(&self) {
        let lines = {
            let state = self.state.borrow();
            let Some(session) = state.session.as_ref() else {
                return;
            };
            log_of(&session.vault.id_hex())
                .and_then(|log| log.read(&session.vault).ok())
                .unwrap_or_default()
        };
        let shown = self.state.borrow().security_log_shown.max(PAGE);
        let offset = vault_platform::locale::utc_offset_minutes();
        let rows: Vec<SecurityLine> = lines
            .iter()
            .take(shown)
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
            .collect();
        let app = self.app();
        app.set_security_log_more(i32::try_from(lines.len().saturating_sub(shown)).unwrap_or(0));
        app.set_security_log(ModelRc::new(VecModel::from(rows)));
    }

    pub(super) fn security_log_more(&self) {
        {
            let mut state = self.state.borrow_mut();
            state.security_log_shown = state.security_log_shown.max(PAGE) + PAGE;
        }
        self.show_security_log();
    }

    /// The unlock screen's "Type it on a secure desktop": the master password typed in a
    /// window on a desktop of its own (`vault_platform::secure_desktop`), off the UI thread,
    /// then put in the master password's field and the vault unlocked with it. Never in the
    /// headless tests: they don't switch the real desktop.
    pub(super) fn secure_unlock(&self) {
        let app = self.app();
        if app.get_busy() || self.state.borrow().runner == super::Runner::Inline {
            return;
        }
        #[cfg(windows)]
        {
            use slint::ComponentHandle;
            use vault_platform::secure_desktop::{self, PromptWords};

            let messages = app.global::<crate::ui::Messages>();
            let words = PromptWords {
                title: messages.invoke_secure_prompt(0).into(),
                lead: messages.invoke_secure_prompt(1).into(),
                keys: messages.invoke_secure_prompt(2).into(),
            };
            self.set_error(super::error::NONE, "");
            super::syncing::off_thread(
                super::Runner::Thread,
                move || secure_desktop::ask(&words).map_err(|err| format!("{err:#}")),
                |controller, result| controller.secure_typed(result),
            );
        }
    }

    #[cfg(windows)]
    fn secure_typed(&self, result: Result<vault_platform::secure_desktop::Prompted, String>) {
        use vault_platform::secure_desktop::Prompted;
        match result {
            Ok(Prompted::Typed(typed)) => {
                // Still on the unlock screen (the vault wasn't opened another way meanwhile).
                if self.app().get_screen() != crate::ui::Screen::Unlock || typed.is_empty() {
                    return;
                }
                self.edit_secret_at(super::field::MASTER as i32, |buffer, caret| {
                    buffer.set(typed.as_str());
                    *caret = buffer.char_count();
                });
                drop(typed);
                self.unlock();
            }
            Ok(Prompted::Cancelled) => {}
            Err(why) => self.set_error(super::error::SECURE_DESKTOP, &why),
        }
    }

    /// Empties the log (one line says when).
    pub(super) fn clear_security_log(&self) {
        {
            let state = self.state.borrow();
            let Some(session) = state.session.as_ref() else {
                return;
            };
            if let Some(log) = log_of(&session.vault.id_hex()) {
                let _ = log.clear(&session.vault, view::now_unix());
            }
        }
        self.state.borrow_mut().security_log_shown = PAGE;
        self.show_security_log();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_browser::service::Copy;
    use zeroize::Zeroizing;

    fn answer() -> Answer {
        Answer {
            bytes: Zeroizing::new(Vec::new()),
            filled: None,
            copy: None,
            saved: None,
            updated: None,
            kept: None,
            passkey_saved: None,
            passkey_used: None,
            lock: false,
            signals: Vec::new(),
        }
    }

    #[test]
    fn what_the_extension_was_given_is_named_never_the_value() {
        let title = |_: &str| Some("Mail".to_owned());
        let fill = Answer {
            filled: Some("Mail".into()),
            ..answer()
        };
        let request = br#"{"type":"fill","url":"https://www.example.com/login","id":"ab"}"#;
        let event = extension_event(request, &fill, title, false).unwrap();
        assert_eq!(
            (event.kind, event.site.as_str(), event.title.as_str()),
            (kind::EXTENSION_GAVE, "example.com", "Mail")
        );
        assert_eq!(event.detail, gave::LOGIN);
        // A card or an address typed into a page is named as one.
        let request = br#"{"type":"card_fill","url":"https://shop.example","id":"ab"}"#;
        let event = extension_event(request, &fill, title, false).unwrap();
        assert_eq!(event.detail, gave::CARD);
        let request = br#"{"type":"identity_fill","url":"https://shop.example","id":"ab"}"#;
        let event = extension_event(request, &fill, title, false).unwrap();
        assert_eq!(event.detail, gave::IDENTITY);
        let request = br#"{"type":"code","url":"https://example.com","id":"ab"}"#;
        let event = extension_event(request, &fill, title, true).unwrap();
        assert_eq!(
            (event.kind, event.detail.as_str()),
            (kind::LOCKED_FILL, gave::CODE)
        );

        let copied = Answer {
            copy: Some(Copy {
                what: CopyWhat::Password,
                value: Zeroizing::new("hunter2".into()),
            }),
            ..answer()
        };
        let request = br#"{"type":"copy","id":"ab","what":"password"}"#;
        let event = extension_event(request, &copied, title, false).unwrap();
        assert_eq!(
            (event.title.as_str(), event.detail.as_str()),
            ("Mail", gave::PASSWORD)
        );
        assert!(!format!("{event:?}").contains("hunter2"));
        // A generated password copied, or nothing given: nothing logged.
        assert!(extension_event(br#"{"type":"keep","id":"x"}"#, &copied, title, false).is_none());
        assert!(extension_event(br#"{"type":"logins"}"#, &answer(), title, false).is_none());
    }
}
