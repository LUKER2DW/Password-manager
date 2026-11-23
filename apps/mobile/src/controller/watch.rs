//! The leak watch on the phone (Settings → Security, off until turned on): once a day while the
//! vault is open, every login's password is checked against the breach service's newest data
//! (k-anonymous: 5 hex characters of its SHA-1 leave the phone, `vault_platform::leak_check`),
//! and the person is told as soon as one turns up in more breaches than before. What was found
//! is kept sealed with a vault subkey (`leak-watch-<vault id>.bin`); leaked logins are marked
//! in the list. Not in the browser preview, which uses no network.

#[cfg(target_arch = "wasm32")]
impl super::Controller {
    pub(super) fn watch_leaks(&self) {}
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::collections::HashSet;

    use vault_core::{ItemId, ItemKind, health::BreachQuery};
    use vault_platform::leak_check::Watch;
    use web_time::Instant;

    use super::super::{Controller, notice};
    use crate::{platform::files, view};

    /// While the watch is on, how often the phone looks whether a day has passed.
    const LOOK_EVERY: std::time::Duration = std::time::Duration::from_secs(60 * 60);

    /// What a check hands back: the vault it was for, each login's key and id, and the counts.
    pub(in crate::controller) struct Checked {
        vault_id: String,
        keys: Vec<(String, ItemId)>,
        found: Result<Vec<(usize, u64)>, String>,
    }

    impl Controller {
        fn watch_file(&self, vault_id: &str) -> std::path::PathBuf {
            self.folder().join(format!("leak-watch-{vault_id}.bin"))
        }

        /// Marks the logins whose password the last check found in a breach.
        fn mark_leaked(&self, watch: &Watch) {
            let leaked: HashSet<ItemId> = watch
                .counts
                .iter()
                .filter(|(_, count)| **count > 0)
                .filter_map(|(key, _)| ItemId::from_hex(key.split(':').next()?))
                .collect();
            let changed = self.state.borrow().leaked != leaked;
            self.state.borrow_mut().leaked = leaked;
            if changed {
                self.refresh_list();
            }
        }

        /// Checks when the watch is on and a day has passed since the last check; otherwise
        /// only marks what the last check found. Called at unlock and every hour while open.
        pub(in crate::controller) fn watch_leaks(&self) {
            let on = self.state.borrow().prefs.leak_watch;
            self.state.borrow_mut().watch_looked = Some(Instant::now());
            let folder = self.folder();
            let (watch, vault_id, queries) = {
                let state = self.state.borrow();
                let Some(vault) = state.vault.as_ref() else {
                    return;
                };
                if !on {
                    drop(state);
                    self.state.borrow_mut().leaked.clear();
                    return self.refresh_list();
                }
                let vault_id = vault.id_hex();
                let watch = files::read_any(&folder.join(format!("leak-watch-{vault_id}.bin")))
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
                (watch, vault_id, queries)
            };
            self.mark_leaked(&watch);
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
            let lookup = self.state.borrow().leak_batch;
            self.run_quietly(
                move || Checked {
                    vault_id,
                    keys,
                    found: lookup(&indexed),
                },
                |c, checked| c.leaks_watched(checked),
            );
        }

        fn leaks_watched(&self, checked: Checked) {
            let Ok(found) = checked.found else {
                return; // no network now: the next hour's look tries again
            };
            let mut watch = {
                let state = self.state.borrow();
                let Some(vault) = state
                    .vault
                    .as_ref()
                    .filter(|v| v.id_hex() == checked.vault_id)
                else {
                    return;
                };
                files::read_any(&self.watch_file(&checked.vault_id))
                    .map(|sealed| Watch::open(vault, &sealed))
                    .unwrap_or_default()
            };
            let counts: Vec<(String, u64)> = found
                .iter()
                .filter_map(|(i, count)| Some((checked.keys.get(*i)?.0.clone(), *count)))
                .collect();
            let newly = watch.record(&counts, view::now_unix());
            let sealed = {
                let state = self.state.borrow();
                state.vault.as_ref().and_then(|vault| watch.seal(vault))
            };
            if let Some(sealed) = sealed {
                let _ = files::write_atomic(&self.watch_file(&checked.vault_id), &sealed);
            }
            self.mark_leaked(&watch);
            if !newly.is_empty() {
                self.notify(notice::LEAKS_NEW, &newly.len().to_string());
            }
        }

        /// The hourly look, from the once-a-second tick.
        pub(in crate::controller) fn watch_tick(&self) {
            let due = {
                let state = self.state.borrow();
                state.prefs.leak_watch
                    && state.vault.is_some()
                    && state
                        .watch_looked
                        .is_none_or(|at| at.elapsed() >= LOOK_EVERY)
            };
            if due {
                self.watch_leaks();
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl super::Controller {
    pub(super) fn watch_tick(&self) {}
}
