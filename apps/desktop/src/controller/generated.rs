//! The history of generated passwords: the ones copied or used here, and the ones the browser
//! extension used. Kept for each vault on this computer, in a file sealed with the vault's key
//! (as the extension's connection key is), newest first, at most [`KEEP`], until cleared.
//!
//! A generated password usually becomes some item's password, so the list is shown behind the
//! item lock whenever one is in use.

use std::{path::PathBuf, rc::Rc};

use serde::{Deserialize, Serialize};
use slint::{ModelRc, SharedString, VecModel};
use vault_core::storage;
use vault_platform::paths;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{Controller, error, notice, view};
use crate::ui::GeneratedRow;

const PURPOSE: &str = "generated-history";
const KEEP: usize = 50;

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(super) struct GeneratedEntry {
    password: String,
    /// The site it was made for ("" when made in the app).
    #[zeroize(skip)]
    site: String,
    #[zeroize(skip)]
    at: i64,
}

fn history_path(vault_id: &str) -> Option<PathBuf> {
    Some(
        paths::app_dir()
            .ok()?
            .join(format!("generated-{vault_id}.bin")),
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// What the history file holds for a vault.
enum Loaded {
    /// No file yet.
    Missing,
    Entries(Vec<GeneratedEntry>),
    /// A file that can't be read or opened (damaged, another vault's, held by another
    /// program). Never written over: it may still be the person's history.
    Unreadable,
}

fn load(vault: &vault_core::Vault) -> Loaded {
    let Some(path) = history_path(&vault.id_hex()) else {
        return Loaded::Missing;
    };
    let sealed = match std::fs::read(&path) {
        Ok(sealed) => sealed,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Loaded::Missing,
        Err(_) => return Loaded::Unreadable,
    };
    vault
        .open_local(PURPOSE, &sealed)
        .ok()
        .and_then(|plain| postcard::from_bytes::<Vec<GeneratedEntry>>(&plain).ok())
        .map_or(Loaded::Unreadable, Loaded::Entries)
}

impl Controller {
    /// The history, read once per unlock from its sealed file. A file that can't be opened
    /// is set aside (renamed, not deleted) so a new history can start without losing it.
    fn generated_entries(&self) -> Vec<GeneratedEntry> {
        if let Some(list) = &self.state.borrow().generated_history {
            return list.clone();
        }
        let loaded = {
            let state = self.state.borrow();
            match state.session.as_ref() {
                Some(session) => (load(&session.vault), session.vault.id_hex()),
                None => (Loaded::Missing, String::new()),
            }
        };
        let list = match loaded {
            (Loaded::Missing, _) => Vec::new(),
            (Loaded::Entries(list), _) => list,
            (Loaded::Unreadable, id) => {
                let set_aside = history_path(&id).is_some_and(|path| {
                    let aside = path.with_file_name(format!("generated-{id}.unreadable.bin"));
                    std::fs::rename(&path, aside).is_ok()
                });
                if !set_aside {
                    // Still there and still unreadable: not cached, so nothing is written
                    // over it (see `store_generated`) and it is tried again next time.
                    return Vec::new();
                }
                Vec::new()
            }
        };
        self.state.borrow_mut().generated_history = Some(list.clone());
        list
    }

    fn store_generated(&self, list: Vec<GeneratedEntry>) {
        let unreadable = self
            .state
            .borrow()
            .session
            .as_ref()
            .is_some_and(|session| matches!(load(&session.vault), Loaded::Unreadable));
        if unreadable {
            self.set_error(
                error::OTHER,
                "the history of generated passwords could not be read, so it was not changed",
            );
            return;
        }
        let written = {
            let state = self.state.borrow();
            state.session.as_ref().and_then(|session| {
                // Sized up front so the plain bytes are never copied by a growing buffer.
                let size = 8 + list
                    .iter()
                    .map(|entry| entry.password.len() + entry.site.len() + 24)
                    .sum::<usize>();
                let mut buffer = Zeroizing::new(vec![0u8; size]);
                let used = postcard::to_slice(&list, &mut buffer).ok()?.len();
                let sealed = session.vault.seal_local(PURPOSE, &buffer[..used]).ok()?;
                let path = history_path(&session.vault.id_hex())?;
                std::fs::create_dir_all(path.parent()?).ok()?;
                storage::write_atomic(&path, &sealed).ok()
            })
        };
        if written.is_none() {
            self.set_error(
                error::OTHER,
                "the history of generated passwords could not be saved",
            );
        }
        self.state.borrow_mut().generated_history = Some(list);
    }

    /// Adds a password that was just used (copied, put into an item, filled by the extension).
    pub(super) fn record_generated(&self, password: &str, site: &str) {
        if password.is_empty() {
            return;
        }
        if self.state.borrow().session.is_none() {
            // The extension used one while the vault was locked: kept until it is open.
            if let Some(id) = self.locked_vault_id() {
                let mut state = self.state.borrow_mut();
                if state.generated_pending.len() < KEEP {
                    state.generated_pending.push((
                        id,
                        Zeroizing::new(password.to_owned()),
                        site.to_owned(),
                    ));
                }
            }
            return;
        }
        let mut list = self.generated_entries();
        if list.first().is_some_and(|entry| entry.password == password) {
            return;
        }
        list.insert(
            0,
            GeneratedEntry {
                password: password.to_owned(),
                site: site.to_owned(),
                at: now(),
            },
        );
        list.truncate(KEEP);
        self.store_generated(list);
        self.fill_generated_history();
    }

    /// Adds what the extension used while this vault was locked, oldest first.
    pub(super) fn record_pending_generated(&self) {
        let pending = std::mem::take(&mut self.state.borrow_mut().generated_pending);
        let id = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|session| session.vault.id_hex());
        for (vault, password, site) in &pending {
            if id.as_deref() == Some(vault.as_str()) {
                self.record_generated(password, site);
            }
        }
    }

    /// Whether the history waits for the item lock: one is in use and not open.
    fn generated_locked(&self) -> bool {
        let state = self.state.borrow();
        let Some(session) = state.session.as_ref() else {
            return true;
        };
        let guard = session.vault.item_guard();
        let in_use = guard.encrypts()
            || guard.all_items
            || state.summaries.iter().any(|summary| summary.reprompt);
        in_use && !state.secrets_open
    }

    /// The generator page's list.
    pub(super) fn fill_generated_history(&self) {
        let locked = self.generated_locked();
        let shown = self.state.borrow().generated_shown;
        let rows: Vec<GeneratedRow> = self
            .generated_entries()
            .iter()
            .enumerate()
            .map(|(i, entry)| GeneratedRow {
                password: if !locked && shown == Some(i) {
                    SharedString::from(entry.password.as_str())
                } else {
                    SharedString::new()
                },
                site: SharedString::from(entry.site.as_str()),
                date: SharedString::from(view::date(entry.at)),
            })
            .collect();
        let app = self.app();
        app.set_gen_history_locked(locked);
        app.set_gen_history(ModelRc::from(Rc::new(VecModel::from(rows))));
    }

    /// Shows one entry (or hides it again). One at a time.
    pub(super) fn reveal_generated(&self, index: i32) {
        if self.generated_locked() {
            return;
        }
        let index = usize::try_from(index).ok();
        {
            let mut state = self.state.borrow_mut();
            state.generated_shown = if state.generated_shown == index {
                None
            } else {
                index
            };
        }
        self.fill_generated_history();
    }

    pub(super) fn copy_generated_entry(&self, index: i32) {
        if self.generated_locked() {
            return;
        }
        let value = usize::try_from(index).ok().and_then(|i| {
            self.generated_entries()
                .get(i)
                .map(|entry| Zeroizing::new(entry.password.clone()))
        });
        if let Some(value) = value {
            self.copy(value, true, notice::GENERATED_COPIED);
        }
    }

    /// Clears the whole history, file included.
    pub(super) fn clear_generated_history(&self) {
        let id = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex());
        if let Some(path) = id.as_deref().and_then(history_path) {
            let _ = std::fs::remove_file(storage::backup_path(&path));
            let _ = std::fs::remove_file(path);
        }
        {
            let mut state = self.state.borrow_mut();
            state.generated_history = Some(Vec::new());
            state.generated_shown = None;
        }
        self.fill_generated_history();
        self.notify(notice::GENERATED_CLEARED, "");
    }
}
