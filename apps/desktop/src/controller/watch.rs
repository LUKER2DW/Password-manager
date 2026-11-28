//! The leak watch (Settings, off until turned on): once a day while the vault is open, every
//! login's password is checked against the breach service's newest data (k-anonymous: 5 hex
//! characters of its SHA-1 leave the computer, `vault_platform::leak_check`). What was found is
//! kept sealed per vault on this computer (`leak-watch-<vault id>.bin`, a vault subkey), Password
//! health shows it, and a password that turns up in more breaches than before is told at once.

use std::{collections::HashMap, path::PathBuf, time::Duration};

use slint::TimerMode;
use vault_core::{ItemId, ItemKind, health::BreachQuery};
use vault_platform::{leak_check::Watch, paths};

use super::{Controller, notice, syncing::off_thread, view};

/// While the vault is open, how often the app looks whether a day has passed.
const LOOK_EVERY: Duration = Duration::from_secs(60 * 60);

/// The leak watch's check of every login: [`batch_default`], or a test's stand-in.
pub(super) type Batch = fn(&[(usize, BreachQuery)]) -> Result<Vec<(usize, u64)>, String>;

/// The leak watch's check of every login as the app makes it (the tests put a stand-in in its
/// place).
pub(super) fn batch_default(queries: &[(usize, BreachQuery)]) -> Result<Vec<(usize, u64)>, String> {
    vault_platform::leak_check::lookup(queries)
}

fn watch_path(vault_id: &str) -> Option<PathBuf> {
    Some(
        paths::app_dir()
            .ok()?
            .join(format!("leak-watch-{vault_id}.bin")),
    )
}

/// After a renewal of the vault key: what the watch found, sealed again under the new key.
pub(super) fn reseal(vault: &vault_core::Vault, former: &vault_core::FormerKey) {
    if let Some(path) = watch_path(&vault.id_hex()) {
        vault_platform::files::reseal(
            &path,
            vault,
            former,
            vault_platform::leak_check::WATCH_PURPOSE,
        );
    }
}

/// What a check hands back.
struct Checked {
    vault_id: String,
    keys: Vec<(String, ItemId)>,
    found: Result<Vec<(usize, u64)>, String>,
}

impl Controller {
    /// At unlock: the watch looks now and then every hour while the vault is open.
    pub(super) fn start_leak_watch(&self) {
        let weak = self.weak();
        self.timers
            .leak_watch
            .start(TimerMode::Repeated, LOOK_EVERY, move || {
                if let Some(controller) = weak.upgrade() {
                    controller.watch_leaks();
                }
            });
        self.watch_leaks();
    }

    /// The counts the last check found go to Password health; when a day has passed, all
    /// logins are checked again (off the UI thread).
    pub(super) fn watch_leaks(&self) {
        if !self.state.borrow().settings.leak_watch {
            return;
        }
        let (vault_id, watch, queries) = {
            let state = self.state.borrow();
            let Some(session) = state.session.as_ref() else {
                return;
            };
            let vault = &session.vault;
            let vault_id = vault.id_hex();
            let watch = watch_path(&vault_id)
                .and_then(|path| std::fs::read(path).ok())
                .map(|sealed| Watch::open(vault, &sealed))
                .unwrap_or_default();
            let queries: Vec<(ItemId, BreachQuery)> = vault
                .item_ids()
                .filter_map(|id| {
                    let item = vault.get_item(&id).ok()?;
                    (item.kind == ItemKind::Login && !item.password.is_empty())
                        .then(|| (id, BreachQuery::new(&item.password)))
                })
                .collect();
            (vault_id, watch, queries)
        };
        self.show_watch(&watch);
        if !watch.due(view::now_unix()) || queries.is_empty() {
            return;
        }
        let keys: Vec<(String, ItemId)> = queries
            .iter()
            .map(|(id, query)| (Watch::key(&id.to_hex(), query), *id))
            .collect();
        let indexed: Vec<(usize, BreachQuery)> = queries
            .into_iter()
            .enumerate()
            .map(|(i, (_, query))| (i, query))
            .collect();
        let (runner, lookup) = {
            let state = self.state.borrow();
            (state.runner, state.leak_batch)
        };
        off_thread(
            runner,
            move || Checked {
                vault_id,
                keys,
                found: lookup(&indexed),
            },
            |controller, checked| controller.leaks_watched(checked),
        );
    }

    /// Password health shows what the watch found (every login it checked).
    fn show_watch(&self, watch: &Watch) {
        if watch.checked_at == 0 {
            return;
        }
        let counts: HashMap<ItemId, u64> = watch
            .counts
            .iter()
            .filter_map(|(key, count)| Some((ItemId::from_hex(key.split(':').next()?)?, *count)))
            .collect();
        self.state.borrow_mut().leaks = counts;
        self.app().set_leaks_checked(true);
        self.refresh_health();
    }

    fn leaks_watched(&self, checked: Checked) {
        let Ok(found) = checked.found else {
            return; // no network now: the next hour's look tries again
        };
        let mut watch = {
            let state = self.state.borrow();
            let Some(session) = state
                .session
                .as_ref()
                .filter(|s| s.vault.id_hex() == checked.vault_id)
            else {
                return;
            };
            watch_path(&checked.vault_id)
                .and_then(|path| std::fs::read(path).ok())
                .map(|sealed| Watch::open(&session.vault, &sealed))
                .unwrap_or_default()
        };
        let counts: Vec<(String, u64)> = found
            .iter()
            .filter_map(|(i, count)| Some((checked.keys.get(*i)?.0.clone(), *count)))
            .collect();
        let newly = watch.record(&counts, view::now_unix());
        let sealed = {
            let state = self.state.borrow();
            state
                .session
                .as_ref()
                .and_then(|session| watch.seal(&session.vault))
        };
        if let (Some(sealed), Some(path)) = (sealed, watch_path(&checked.vault_id)) {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = vault_core::storage::write_atomic(&path, &sealed);
        }
        self.show_watch(&watch);
        if !newly.is_empty() {
            self.notify_long(notice::LEAKS_NEW, &newly.len().to_string());
            self.tell_windows_of_leaks(newly.len());
        }
    }

    /// The tests' stand-in for the breach service.
    #[cfg(test)]
    pub(crate) fn set_leak_batch(&self, lookup: Batch) {
        self.state.borrow_mut().leak_batch = lookup;
    }
}
