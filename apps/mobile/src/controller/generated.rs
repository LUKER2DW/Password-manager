//! The generator's history on the phone: the passwords copied or used from it, newest first,
//! at most [`KEEP`], in a file sealed with the vault's key next to the phone's copy (as the
//! desktop keeps its own). One that an item uses leaves the list for good, once that item's
//! secrets are read here: it is in the vault now, shown and copied only as the item allows.
//! While some item's secrets are behind the item lock, any entry may be that item's password,
//! so the list stays masked and nothing in it is copied (as on the desktop). The list is
//! masked until the person asks to see it; one entry or all can be deleted.

use std::path::PathBuf;

use slint::{ModelRc, VecModel};
use vault_core::storage;
use zeroize::Zeroizing;

use super::{Controller, notice};
use crate::{ui::GenRow, view};

/// What the history is sealed for (`Vault::seal_local`).
pub(super) const PURPOSE: &str = "generated-history";
const KEEP: usize = 50;

/// One password and when it was copied or used (Unix seconds).
pub(super) struct Entry {
    password: Zeroizing<String>,
    at: i64,
}

/// The list as bytes: for each entry its time (8 bytes) and length (4 bytes, little-endian),
/// then the password. The buffer is sized exactly first, so no copy of it is left behind.
fn encode(list: &[Entry]) -> Zeroizing<Vec<u8>> {
    let size: usize = list.iter().map(|entry| 12 + entry.password.len()).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    for entry in list {
        out.extend_from_slice(&entry.at.to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(entry.password.len())
                .unwrap_or(0)
                .to_le_bytes(),
        );
        out.extend_from_slice(entry.password.as_bytes());
    }
    out
}

fn decode(bytes: &[u8]) -> Vec<Entry> {
    let mut list = Vec::new();
    let mut rest = bytes;
    while rest.len() >= 12 {
        let at = i64::from_le_bytes(rest[..8].try_into().unwrap_or_default());
        let len = u32::from_le_bytes(rest[8..12].try_into().unwrap_or_default()) as usize;
        let Some(password) = rest.get(12..12 + len) else {
            break;
        };
        let Ok(password) = std::str::from_utf8(password) else {
            break;
        };
        list.push(Entry {
            password: Zeroizing::new(password.to_owned()),
            at,
        });
        rest = &rest[12 + len..];
    }
    list
}

impl Controller {
    fn generated_path(&self) -> Option<PathBuf> {
        let state = self.state.borrow();
        let id = state.vault.as_ref()?.id_hex();
        Some(state.path.with_file_name(format!("generated-{id}.history")))
    }

    fn generated_entries(&self) -> Vec<Entry> {
        let Some(path) = self.generated_path() else {
            return Vec::new();
        };
        let Ok(sealed) = std::fs::read(path) else {
            return Vec::new();
        };
        let state = self.state.borrow();
        state
            .vault
            .as_ref()
            .and_then(|vault| vault.open_local(PURPOSE, &sealed).ok())
            .map(|plain| decode(&plain))
            .unwrap_or_default()
    }

    fn store_generated(&self, list: &[Entry]) {
        let Some(path) = self.generated_path() else {
            return;
        };
        if list.is_empty() {
            let _ = std::fs::remove_file(storage::backup_path(&path));
            let _ = std::fs::remove_file(path);
            return;
        }
        let sealed = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            vault.seal_local(PURPOSE, &encode(list))
        };
        if let Ok(sealed) = sealed {
            let _ = storage::write_atomic(&path, &sealed);
        }
    }

    /// A password copied or used from the generator goes first in the list.
    pub(super) fn record_generated(&self, password: &str) {
        if password.is_empty() {
            return;
        }
        let mut list = self.generated_entries();
        list.retain(|entry| entry.password.as_str() != password);
        list.insert(
            0,
            Entry {
                password: Zeroizing::new(password.to_owned()),
                at: view::now_unix(),
            },
        );
        list.truncate(KEEP);
        self.store_generated(&list);
        self.publish_generated();
    }

    /// The entries listed: the ones no item uses, and whether they wait for the item lock.
    ///
    /// An entry that an item's password is, as far as the secrets read now tell, leaves the
    /// file for good. While some item's secrets are sealed behind the item lock, the entries
    /// left may still be such an item's password (one used before this rule, or on another
    /// device): they wait (`true`), masked and not copied, until the lock is open.
    fn shown_generated(&self) -> (Vec<Entry>, bool) {
        // The passwords the items use, as fingerprints (no copy of a password is kept).
        let (used, waits) = {
            let state = self.state.borrow();
            let mut used = std::collections::HashSet::new();
            let mut waits = false;
            if let Some(vault) = state.vault.as_ref() {
                for item in vault.item_ids().filter_map(|id| vault.get_item(&id).ok()) {
                    if item.is_locked() {
                        waits = true;
                    } else if !item.password.is_empty() {
                        used.insert(super::fingerprint(item.password.as_bytes()));
                    }
                }
            }
            (used, waits)
        };
        let (gone, kept): (Vec<Entry>, Vec<Entry>) = self
            .generated_entries()
            .into_iter()
            .partition(|entry| used.contains(&super::fingerprint(entry.password.as_bytes())));
        if !gone.is_empty() {
            self.store_generated(&kept);
        }
        (kept, waits)
    }

    /// The list on the generator page, masked unless asked to show (and always while it waits
    /// for the item lock).
    pub(super) fn publish_generated(&self) {
        let app = self.app();
        let offset = self.system().utc_offset_minutes();
        let (entries, waits) = self.shown_generated();
        if waits {
            // Masked again once the lock is open, until asked.
            app.set_gen_history_shown(false);
        }
        let shown = app.get_gen_history_shown();
        let rows: Vec<GenRow> = entries
            .iter()
            .map(|entry| GenRow {
                text: if shown {
                    entry.password.as_str().into()
                } else {
                    "•".repeat(entry.password.chars().count().min(24)).into()
                },
                when: view::date_time(entry.at, offset).into(),
            })
            .collect();
        app.set_gen_history_locked(waits);
        app.set_gen_history(ModelRc::new(VecModel::from(rows)));
    }

    pub(super) fn copy_generated_entry(&self, index: i32) {
        let (entries, waits) = self.shown_generated();
        if waits {
            return;
        }
        let entry = usize::try_from(index)
            .ok()
            .and_then(|index| entries.into_iter().nth(index));
        if let Some(entry) = entry {
            self.copy_secret(&entry.password, notice::COPIED);
        }
    }

    pub(super) fn delete_generated_entry(&self, index: i32) {
        let Some(gone) = usize::try_from(index)
            .ok()
            .and_then(|index| self.shown_generated().0.into_iter().nth(index))
        else {
            return;
        };
        let mut list = self.generated_entries();
        list.retain(|entry| entry.password != gone.password);
        self.store_generated(&list);
        self.publish_generated();
    }

    pub(super) fn clear_generated(&self) {
        self.store_generated(&[]);
        self.app().set_gen_history_shown(false);
        self.publish_generated();
    }

    /// Takes the history off the screen (the vault locked).
    pub(super) fn forget_generated_rows(&self) {
        let app = self.app();
        app.set_gen_history_shown(false);
        app.set_gen_history_locked(false);
        app.set_gen_history(ModelRc::default());
    }
}
