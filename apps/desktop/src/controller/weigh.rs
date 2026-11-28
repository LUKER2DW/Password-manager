//! A new password weighed before it is kept (F18): whether other logins of the vault have it,
//! and whether it turned up in known breaches. For the editor (a line under the strength) and
//! for the extension's save card (`weigh`).
//!
//! The breach check is the leak check's own (k-anonymous: 5 hex characters of the password's
//! SHA-1 leave the computer, the answer is padded) and is made only while the person has the
//! leak watch on (Settings → Security), off the UI thread. Each prefix's answer is kept in
//! memory for a few minutes, so a password weighed again asks nothing; it holds no password.

use std::time::{Duration, Instant};

use vault_browser::origin::{Origin, item_matches};
use vault_core::{ItemId, ItemKind, health::BreachQuery};
use zeroize::Zeroizing;

use super::{CURRENT, Controller, Runner};

/// How long a prefix's answer from the breach service is used.
const RANGE_KEPT_FOR: Duration = Duration::from_secs(10 * 60);
/// Passwords shorter than this are not weighed: a PIN matches others by chance.
const SHORTEST_WEIGHED: usize = 6;
/// The editor weighs against leaks once typing has paused this long.
const PAUSE: Duration = Duration::from_millis(1200);

impl Controller {
    /// How many logins other than `except` (and other than those saved for `page`) have
    /// `password`. Logins whose secrets the item lock keeps closed are not compared.
    pub(super) fn reused_count(
        &self,
        password: &str,
        except: Option<ItemId>,
        page: Option<&Origin>,
    ) -> usize {
        if password.chars().count() < SHORTEST_WEIGHED {
            return 0;
        }
        let state = self.state.borrow();
        let Some(session) = state.session.as_ref() else {
            return 0;
        };
        let vault = &session.vault;
        vault
            .item_ids()
            .filter(|id| Some(*id) != except)
            .filter_map(|id| vault.get_item(&id).ok())
            .filter(|item| {
                item.kind == ItemKind::Login
                    && !item.is_locked()
                    && item.password == password
                    && page.is_none_or(|page| !item_matches(&item.urls, page))
            })
            .count()
    }

    /// How often `password` turned up in known breaches: `None` while the leak watch is off
    /// (nothing is asked), `Some(None)` while the breach service is asked (`then` runs when it
    /// answered), `Some(Some(n))` once known.
    pub(super) fn leak_count(&self, password: &str, then: fn(&Controller)) -> Option<Option<u64>> {
        if !self.state.borrow().settings.leak_watch || password.chars().count() < SHORTEST_WEIGHED {
            return None;
        }
        let query = BreachQuery::new(password);
        let prefix = query.prefix().to_owned();
        {
            let mut state = self.state.borrow_mut();
            state.leak_ranges.retain(|_, kept| {
                kept.as_ref()
                    .is_none_or(|(at, _)| at.elapsed() < RANGE_KEPT_FOR)
            });
            match state.leak_ranges.get(&prefix) {
                Some(Some((_, body))) => return Some(Some(query.count_in(body))),
                Some(None) => return Some(None),
                None => {}
            }
            // No network in the headless tests.
            if state.runner == Runner::Inline {
                return None;
            }
            state.leak_ranges.insert(prefix.clone(), None);
        }
        std::thread::spawn(move || {
            let answer = vault_platform::leak_check::range(&prefix);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    let mut state = controller.state.borrow_mut();
                    match answer {
                        Ok(body) => {
                            state
                                .leak_ranges
                                .insert(prefix, Some((Instant::now(), body)));
                        }
                        // Asked again the next time.
                        Err(_) => {
                            state.leak_ranges.remove(&prefix);
                        }
                    }
                    drop(state);
                    then(&controller);
                }
            });
        });
        Some(None)
    }

    /// The editor's password: its reuse at once, its leaks once typing pauses.
    pub(super) fn weigh_editor_soon(&self) {
        let reused = {
            let state = self.state.borrow();
            let password = Zeroizing::new(
                state.secrets[super::field::ITEM_PASSWORD]
                    .as_str()
                    .to_owned(),
            );
            let except = state.editing.flatten();
            drop(state);
            if self.app().get_ed_kind() == 0 {
                self.reused_count(&password, except, None)
            } else {
                0
            }
        };
        let app = self.app();
        app.set_ed_reused(i32::try_from(reused).unwrap_or(i32::MAX));
        app.set_ed_leaked(-1);
        self.timers
            .weigh
            .start(slint::TimerMode::SingleShot, PAUSE, || {
                if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                    controller.weigh_editor_leaks();
                }
            });
    }

    fn weigh_editor_leaks(&self) {
        let app = self.app();
        if app.get_ed_kind() != 0 {
            return;
        }
        let password = Zeroizing::new(
            self.state.borrow().secrets[super::field::ITEM_PASSWORD]
                .as_str()
                .to_owned(),
        );
        let found = self.leak_count(&password, |c| c.weigh_editor_leaks());
        app.set_ed_leaked(match found {
            Some(Some(count)) => i32::try_from(count).unwrap_or(i32::MAX),
            _ => -1,
        });
    }
}
