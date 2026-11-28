//! What sites said of the vault's passkeys through the WebAuthn Signal API (F23): a passkey the
//! site no longer knows, or the account's new names. Nothing is changed by itself: the note
//! shows on the item's page under that passkey, and the person removes it, takes the names, or
//! keeps it as it is. Notes are kept in memory while the app runs (a site says it again at its
//! next sign-in); a passkey is never deleted silently.

use slint::{ModelRc, VecModel};
use vault_browser::service::{PasskeyNote, Said};
use vault_core::{ItemId, Passkey};

use super::{Controller, notice};
use crate::ui::PasskeyRow;

/// Most notes kept: a site can't fill memory by signalling.
const MAX_NOTES: usize = 64;

impl Controller {
    /// Keeps what a site said (one note per passkey, the newest), and tells the person.
    pub(super) fn note_passkey_signals(&self, notes: Vec<PasskeyNote>) {
        if notes.is_empty() {
            return;
        }
        let title = {
            let mut state = self.state.borrow_mut();
            for note in &notes {
                state
                    .passkey_notes
                    .retain(|kept| !(kept.item == note.item && kept.credential == note.credential));
            }
            state.passkey_notes.extend(notes.iter().cloned());
            let excess = state.passkey_notes.len().saturating_sub(MAX_NOTES);
            state.passkey_notes.drain(..excess);
            state
                .session
                .as_ref()
                .and_then(|s| s.vault.get_item(&notes[0].item).ok())
                .map(|item| item.title.clone())
                .unwrap_or_default()
        };
        self.notify_long(notice::PASSKEY_SIGNAL, &title);
        let selected = self.state.borrow().selected;
        if notes.iter().any(|note| Some(note.item) == selected) {
            self.show_detail();
        }
    }

    /// The item page's passkey rows of item `id`, each with what its site said, if anything.
    pub(super) fn detail_passkey_rows(
        &self,
        id: Option<ItemId>,
        passkeys: &[Passkey],
    ) -> ModelRc<PasskeyRow> {
        let state = self.state.borrow();
        let rows: Vec<PasskeyRow> = super::attachments::passkey_rows(passkeys)
            .into_iter()
            .zip(passkeys)
            .map(|(mut row, passkey)| {
                let note = state
                    .passkey_notes
                    .iter()
                    .find(|note| Some(note.item) == id && note.credential == passkey.credential_id);
                match note.map(|note| &note.said) {
                    Some(Said::Gone) => row.signal = 1,
                    Some(Said::Renamed { name, .. }) => {
                        row.signal = 2;
                        row.signal_name = name.as_str().into();
                    }
                    None => {}
                }
                row
            })
            .collect();
        ModelRc::new(VecModel::from(rows))
    }

    /// The person's answer to a site's note on passkey `index` of the open item: `accept`
    /// removes it (gone) or takes the names (renamed); otherwise the note is dropped and the
    /// passkey kept as it is. Changing the item needs its secrets open (the item lock).
    pub(super) fn passkey_signal(&self, index: i32, accept: bool) {
        let Some(id) = self.state.borrow().selected else {
            return;
        };
        // Removing a passkey asks first; taking new names doesn't.
        if accept && !self.take_confirmed(super::confirm::kind::FORGET_PASSKEY) {
            let gone = {
                let state = self.state.borrow();
                state
                    .session
                    .as_ref()
                    .and_then(|s| s.vault.get_item(&id).ok())
                    .and_then(|item| {
                        let passkey = usize::try_from(index)
                            .ok()
                            .and_then(|i| item.passkeys.get(i))?;
                        state
                            .passkey_notes
                            .iter()
                            .any(|note| {
                                note.item == id
                                    && note.credential == passkey.credential_id
                                    && note.said == Said::Gone
                            })
                            .then(|| passkey.user_name.clone())
                    })
            };
            if let Some(user) = gone {
                self.ask_confirm(super::confirm::kind::FORGET_PASSKEY, index, &user);
                return;
            }
        }
        let credential = {
            let state = self.state.borrow();
            let Some(item) = state
                .session
                .as_ref()
                .and_then(|s| s.vault.get_item(&id).ok())
            else {
                return;
            };
            let Some(passkey) = usize::try_from(index)
                .ok()
                .and_then(|i| item.passkeys.get(i))
            else {
                return;
            };
            passkey.credential_id.clone()
        };
        let note = {
            let mut state = self.state.borrow_mut();
            let at = state
                .passkey_notes
                .iter()
                .position(|note| note.item == id && note.credential == credential);
            at.map(|at| state.passkey_notes.remove(at))
        };
        let Some(note) = note else {
            return;
        };
        if accept {
            // The secrets must be readable to write the item back (a locked item asks first).
            let Some((_, mut item)) = self.selected_item() else {
                // Kept for when it is open.
                self.state.borrow_mut().passkey_notes.push(note);
                self.notify(notice::PASSKEY_SIGNAL_LOCKED, "");
                return;
            };
            match &note.said {
                Said::Gone => item.passkeys.retain(|p| p.credential_id != credential),
                Said::Renamed { name, display_name } => {
                    for passkey in item
                        .passkeys
                        .iter_mut()
                        .filter(|p| p.credential_id == credential)
                    {
                        passkey.user_name.clone_from(name);
                        passkey.display_name.clone_from(display_name);
                    }
                }
            }
            let updated = self
                .state
                .borrow_mut()
                .session
                .as_mut()
                .is_some_and(|s| s.vault.update_item(&id, &item).is_ok());
            if updated {
                self.state.borrow_mut().summaries_stale = true;
                if self.save_vault() {
                    self.notify(notice::SAVED, "");
                }
                self.refresh_list();
            }
        }
        self.show_detail();
    }
}
