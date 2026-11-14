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

impl Controller {
    /// The history, read once per unlock from its sealed file.
    fn generated_entries(&self) -> Vec<GeneratedEntry> {
        if let Some(list) = &self.state.borrow().generated_history {
            return list.clone();
        }
        let list = {
            let state = self.state.borrow();
            state
                .session
                .as_ref()
                .and_then(|session| {
                    let sealed = std::fs::read(history_path(&session.vault.id_hex())?).ok()?;
                    let plain = session.vault.open_local(PURPOSE, &sealed).ok()?;
                    postcard::from_bytes::<Vec<GeneratedEntry>>(&plain).ok()
                })
                .unwrap_or_default()
        };
        self.state.borrow_mut().generated_history = Some(list.clone());
        list
    }

    fn store_generated(&self, list: Vec<GeneratedEntry>) {
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
        if password.is_empty() || self.state.borrow().session.is_none() {
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
