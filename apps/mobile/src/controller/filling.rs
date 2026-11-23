//! Autofill from the open vault: the Android shell asks on autofill's behalf, `crate::autofill`
//! decides which logins belong to the place asking. Nothing here fills anything by itself: the
//! shell confirms with a fingerprint or the phone's lock before a password leaves.

use crate::autofill::{self, Login};

use super::{Controller, notice};

impl Controller {
    /// The logins of the open vault for the place asking (a website's domain, else the app's
    /// package); `None` while the vault is locked.
    pub fn autofill_logins(&self, domain: Option<&str>, app: &str) -> Option<Vec<Login>> {
        let state = self.state.borrow();
        let vault = state.vault.as_ref()?;
        Some(autofill::logins_for(vault, domain, app))
    }

    /// One login of the open vault by its id, only while it still belongs to the place asking.
    pub fn autofill_login(&self, id: &str, domain: Option<&str>, app: &str) -> Option<Login> {
        let state = self.state.borrow();
        let vault = state.vault.as_ref()?;
        autofill::login_by_id(vault, id, domain, app)
    }

    /// "Save to Vault?" from another app, with the vault open: the login is added (or its
    /// password changed) and saved. `false` while the vault is locked or it couldn't be saved.
    pub fn autofill_save(
        &self,
        domain: Option<&str>,
        app: &str,
        username: &str,
        password: &str,
    ) -> bool {
        let changed = {
            let mut state = self.state.borrow_mut();
            let Some(vault) = state.vault.as_mut() else {
                return false;
            };
            autofill::save_into(vault, domain, app, username, password)
        };
        match changed {
            Ok(false) => true,
            Ok(true) => {
                if !self.save() {
                    return false;
                }
                self.refresh_list();
                self.notify(notice::SAVED, "");
                true
            }
            Err(_) => false,
        }
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
        let added = {
            let mut state = self.state.borrow_mut();
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            items
                .iter()
                .filter(|item| vault.add_item(item).is_ok())
                .count()
        };
        // Emptied only once they are safe in the saved vault.
        if self.save() {
            autofill::empty_drop_box(&folder, &id);
            self.refresh_list();
            self.notify(notice::DROPPED, &added.to_string());
        }
    }
}
