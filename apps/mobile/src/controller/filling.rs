//! Autofill from the open vault: the Android shell asks on autofill's behalf, `crate::autofill`
//! decides who would receive a login and which ones belong there. Nothing here fills anything
//! by itself: the shell confirms with a fingerprint or the phone's lock before a password
//! leaves.

use vault_core::VaultSnapshot;

use crate::autofill::{self, Kept, Login, Recipient};

use super::{Controller, notice};

impl Controller {
    /// The logins of the open vault saved for `to`; `None` while the vault is locked.
    pub fn autofill_logins(&self, to: &Recipient) -> Option<Vec<Login>> {
        let state = self.state.borrow();
        let vault = state.vault.as_ref()?;
        Some(autofill::logins_for(vault, to))
    }

    /// One login of the open vault by its id, only while it still belongs to `to`.
    pub fn autofill_login(&self, id: &str, to: &Recipient) -> Option<Login> {
        let login = {
            let state = self.state.borrow();
            let vault = state.vault.as_ref()?;
            autofill::login_by_id(vault, id, to)?
        };
        self.log_event(
            super::security::kind::AUTOFILL_GAVE,
            to.name(),
            &login.title,
            super::security::gave::LOGIN,
        );
        Some(login)
    }

    /// "Save to Vault?" from another app, with the vault open: the login is added (or its
    /// password changed, when it isn't behind the item lock) and saved. `None` while the vault
    /// is locked or it couldn't be saved: the open vault is then as it was (the drop box keeps
    /// the login instead, and a later save doesn't bring it in a second time).
    pub fn autofill_save(&self, from: &Recipient, username: &str, password: &str) -> Option<Kept> {
        let (kept, before) = {
            let mut state = self.state.borrow_mut();
            let vault = state.vault.as_mut()?;
            let before = vault.snapshot();
            (
                autofill::save_into(vault, from, username, password).ok()?,
                before,
            )
        };
        if kept != Kept::Same {
            if !self.save() {
                self.take_out_again(before);
                return None;
            }
            self.refresh_list();
            self.notify(notice::SAVED, "");
        }
        Some(kept)
    }

    /// At unlock: the logins saved from other apps while the vault was locked come in (and
    /// the drop box is made when there is none yet).
    pub(super) fn add_dropped_logins(&self) {
        let folder = self.folder();
        let (items, id) = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            (autofill::dropped_logins(&folder, vault), vault.id_hex())
        };
        if items.is_empty() {
            return;
        }
        let (added, before) = {
            let mut state = self.state.borrow_mut();
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            let before = vault.snapshot();
            let added = items
                .iter()
                .filter(|item| vault.add_item(item).is_ok())
                .count();
            (added, before)
        };
        // Emptied only once they are safe in the saved vault; until then they are only there.
        if self.save() {
            autofill::empty_drop_box(&folder, &id);
            self.refresh_list();
            self.notify(notice::DROPPED, &added.to_string());
        } else {
            self.take_out_again(before);
        }
    }

    /// What another app saved couldn't be written: the open vault goes back to what it was.
    fn take_out_again(&self, before: VaultSnapshot) {
        if let Some(vault) = self.state.borrow_mut().vault.as_mut() {
            vault.roll_back(before);
        }
    }
}
