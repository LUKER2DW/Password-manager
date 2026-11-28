//! Passkeys for the phone's browsers and apps, from the open vault: the Android shell asks on
//! Credential Manager's behalf, `crate::passkeys` decides which passkeys answer whom. Nothing is
//! signed or made before the shell has the person confirm with a fingerprint or the phone's
//! lock.

use zeroize::Zeroizing;

use crate::passkeys::{self, Caller, Made, Offer, Refusal};

use super::{Controller, notice};

impl Controller {
    /// Whether a vault is open in the app.
    pub fn vault_open(&self) -> bool {
        self.state.borrow().vault.is_some()
    }

    /// The passkeys of the open vault that may answer `request` from `caller`; `None` while the
    /// vault is locked.
    pub fn passkey_offers(&self, caller: &Caller, request: &str) -> Option<Vec<Offer>> {
        let state = self.state.borrow();
        let vault = state.vault.as_ref()?;
        Some(passkeys::offers(vault, caller, request))
    }

    /// Signs in with passkey `credential` of login `item` in the open vault, once the person
    /// confirmed. `None` while the vault is locked or when that passkey doesn't answer there.
    pub fn passkey_assertion(
        &self,
        caller: &Caller,
        item: &str,
        credential: &str,
        request: &str,
        sent_hash: Option<&[u8]>,
    ) -> Option<Zeroizing<String>> {
        let (signed, title) = {
            let state = self.state.borrow();
            let vault = state.vault.as_ref()?;
            let signed = passkeys::assertion(vault, caller, item, credential, request, sent_hash)?;
            let title = vault
                .summaries()
                .unwrap_or_default()
                .into_iter()
                .find(|s| s.id.to_hex() == item)
                .map(|s| s.title.clone())
                .unwrap_or_default();
            (signed, title)
        };
        self.log_event(
            super::security::kind::PASSKEY_USED,
            &caller.origin(),
            &title,
            super::security::gave::PASSKEY,
        );
        Some(signed)
    }

    /// Makes a passkey in the open vault and saves the vault (and syncs it), once the person
    /// confirmed. `None` while the vault is locked; a vault that couldn't be saved is put back
    /// as it was.
    pub fn passkey_create(
        &self,
        caller: &Caller,
        request: &str,
        sent_hash: Option<&[u8]>,
    ) -> Option<Result<Made, Refusal>> {
        let (made, before) = {
            let mut state = self.state.borrow_mut();
            let vault = state.vault.as_mut()?;
            let before = vault.snapshot();
            (passkeys::create(vault, caller, request, sent_hash), before)
        };
        let made = match made {
            Ok(made) => made,
            Err(refusal) => return Some(Err(refusal)),
        };
        if !self.save() {
            if let Some(vault) = self.state.borrow_mut().vault.as_mut() {
                vault.roll_back(before);
            }
            return Some(Err(Refusal::NotKept));
        }
        self.refresh_list();
        self.notify(notice::PASSKEY_SAVED, &made.title);
        Some(Ok(made))
    }
}
