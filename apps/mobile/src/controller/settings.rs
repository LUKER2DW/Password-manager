//! Settings that reach past one screen: the vaults this phone keeps, fingerprint unlock,
//! locking when the app is left, screenshots, autofill, the language, importing another
//! manager's export, and "Check this password" on the item page.

use std::{
    path::{Path, PathBuf},
    rc::Rc,
};

use slint::{ModelRc, SharedString, VecModel};
use vault_core::{Vault, health};
use zeroize::Zeroizing;

use super::{Controller, Opened, error, field, fingerprint, notice};
use crate::{
    bio::{self, BioUnlock},
    i18n,
    platform::{files, secret_store},
    prefs,
    system::{PromptWords, System},
    ui::{Page, Screen, VaultRow},
    view,
};

/// What a fingerprint prompt that is still open was for.
#[derive(Debug, Default)]
pub(super) enum BioPending {
    #[default]
    None,
    /// Turning it on: the vault's id and its key sealed under the secret being sealed.
    Sealing(String, Vec<u8>),
    /// Opening the vault with this id.
    Opening(String),
}

/// The leak check as the app makes it (the tests put a stand-in in its place).
pub(super) fn leak_lookup_default(password: &str) -> Result<u64, String> {
    crate::platform::leak_check::count(password)
}

/// The leak watch's check of every login as the app makes it.
pub(super) fn leak_batch_default(
    queries: &[(usize, vault_core::health::BreachQuery)],
) -> Result<Vec<(usize, u64)>, String> {
    crate::platform::leak_check::lookup(queries)
}

fn unix_now() -> i64 {
    view::now_unix()
}

/// Where the vault with this id syncs, as a host ("vault.example.net"), or "".
#[cfg(not(target_arch = "wasm32"))]
fn sync_host(vault_id: &str) -> String {
    if vault_id.is_empty() {
        return String::new();
    }
    let Some(place) = crate::platform::DeviceState::load()
        .ok()
        .and_then(|state| state.sync_place(vault_id))
    else {
        return String::new();
    };
    let address = place.to.describe();
    let rest = address
        .split_once("://")
        .map_or(address.as_str(), |(_, rest)| rest);
    rest.split(['/', '#', '?'])
        .next()
        .unwrap_or(rest)
        .to_owned()
}

#[cfg(target_arch = "wasm32")]
fn sync_host(_vault_id: &str) -> String {
    String::new()
}

/// The backup copy `files::write_atomic` keeps next to `path`.
fn bak(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".bak");
    path.with_file_name(name)
}

impl Controller {
    // ---- the system ----

    /// What only the phone's own system can do (the Android activity), once the window is
    /// up. Applies the settings that live there, and offers fingerprint unlock if the
    /// unlock screen is showing.
    pub fn set_system(&self, system: Rc<dyn System>) {
        *self.system.borrow_mut() = system;
        let (allow_capture, language) = {
            let state = self.state.borrow();
            (state.prefs.allow_capture, state.prefs.language.clone())
        };
        self.system().keep_off_screenshots(!allow_capture);
        if let Some(version) = self.system().app_version() {
            self.app().set_app_version(version.into());
        }
        self.apply_language(&language);
        self.refresh_autofill();
        self.refresh_security();
        if self.app().get_screen() == Screen::Unlock {
            self.offer_biometrics(true);
        }
    }

    pub(super) fn system(&self) -> Rc<dyn System> {
        self.system.borrow().clone()
    }

    /// The app left the screen (another app, Home, the screen turned off; not the system's
    /// own pickers and prompts, which the shell leaves out).
    pub fn left_app(&self) {
        let lock = self.state.borrow().prefs.lock_on_leave && self.is_unlocked();
        if lock {
            self.lock();
        }
    }

    /// The app is on screen again: Android's settings may have changed (autofill), and a
    /// locked vault offers the fingerprint at once (not when the app comes back from one of
    /// its own system screens, a picker or a settings page).
    pub fn came_back(&self, ask_fingerprint: bool) {
        self.refresh_autofill();
        if self.app().get_screen() == Screen::Unlock {
            self.offer_biometrics(ask_fingerprint);
        }
    }

    // ---- settings that are only a switch ----

    pub(super) fn lock_on_leave_changed(&self, on: bool) {
        self.change_prefs(|prefs| prefs.lock_on_leave = on);
    }

    pub(super) fn allow_capture_changed(&self, on: bool) {
        self.change_prefs(|prefs| prefs.allow_capture = on);
        self.system().keep_off_screenshots(!on);
    }

    pub(super) fn refresh_autofill(&self) {
        let app = self.app();
        let autofill = self.system().autofill();
        app.set_autofill_available(autofill.is_some());
        app.set_autofill_on(autofill == Some(true));
    }

    pub(super) fn language_changed(&self, index: i32) {
        let language = i18n::setting_of(index);
        self.change_prefs(|prefs| prefs.language = language.to_owned());
        self.apply_language(language);
    }

    /// Shows the app in `setting`'s language ("" = the phone's): the Settings choice and every
    /// word on the screens (see `src/i18n.rs`).
    pub(super) fn apply_language(&self, setting: &str) {
        self.app().set_language_choice(i18n::choice_of(setting));
        let system = self
            .system()
            .language()
            .or_else(crate::platform::system_language);
        i18n::apply(setting, system.as_deref());
    }

    // ---- the vaults on this phone ----

    /// The folder the phone keeps its vaults in (next to `settings.json`).
    pub(super) fn folder(&self) -> PathBuf {
        let state = self.state.borrow();
        state
            .path
            .parent()
            .map_or_else(|| PathBuf::from("."), ToOwned::to_owned)
    }

    fn current_file(&self) -> String {
        self.state
            .borrow()
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// The vault chooser: every vault this phone keeps (a file that is still there), in the
    /// order they came, where each syncs, and the current one.
    pub(super) fn publish_vaults(&self) {
        let folder = self.folder();
        let current = self.current_file();
        let open = self.is_unlocked();
        let kept: Vec<prefs::KnownVault> = {
            let state = self.state.borrow();
            state
                .prefs
                .vaults
                .iter()
                .filter(|v| v.file == current || folder.join(&v.file).exists())
                .cloned()
                .collect()
        };
        let index = kept.iter().position(|v| v.file == current);
        let rows: Vec<VaultRow> = kept
            .iter()
            .map(|known| VaultRow {
                name: known.name.as_str().into(),
                initial: super::initial(&known.name),
                tint: super::tint(vault_core::ItemKind::Login, &known.name),
                place: sync_host(&known.id).into(),
                open: open && known.file == current,
            })
            .collect();
        let app = self.app();
        // A locked vault is still called by the name it had when it was last open.
        if !open {
            app.set_vault_name(
                index
                    .and_then(|i| kept.get(i))
                    .map(|v| v.name.as_str().into())
                    .unwrap_or_default(),
            );
        }
        app.set_vaults(ModelRc::new(VecModel::from(rows)));
        app.set_vault_current(index.map_or(-1, |i| i32::try_from(i).unwrap_or(0)));
    }

    /// The vault that just opened is one this phone keeps, under its name.
    pub(super) fn remember_open_vault(&self) {
        let file = self.current_file();
        let (id, name) = self
            .state
            .borrow()
            .vault
            .as_ref()
            .map(|vault| (vault.id_hex(), vault.settings().name.clone()))
            .unwrap_or_default();
        self.change_prefs(|prefs| {
            prefs.remember_vault(&file, &id, &name);
            prefs.current.clone_from(&file);
        });
        self.state.borrow_mut().previous = None;
        self.app().set_adding_vault(false);
        self.publish_vaults();
    }

    /// The vault chooser's row `index`: locks what is open and shows that vault's unlock.
    pub(super) fn switch_vault(&self, index: i32) {
        let folder = self.folder();
        let current = self.current_file();
        let file = {
            let state = self.state.borrow();
            state
                .prefs
                .vaults
                .iter()
                .filter(|v| v.file == current || folder.join(&v.file).exists())
                .nth(usize::try_from(index).unwrap_or(usize::MAX))
                .map(|v| v.file.clone())
        };
        let Some(file) = file.filter(|f| prefs::is_vault_file(f)) else {
            return;
        };
        let app = self.app();
        app.set_choosing_vault(false);
        app.set_settings_section(-1);
        if file == current {
            return;
        }
        if self.is_unlocked() {
            self.lock();
        }
        self.open_slot(folder.join(&file));
        self.change_prefs(|prefs| prefs.current.clone_from(&file));
        self.offer_biometrics(true);
    }

    /// Points the window at the vault file `path` (nothing open, nothing waiting).
    fn open_slot(&self, path: PathBuf) {
        {
            let mut state = self.state.borrow_mut();
            state.path = path;
            state.incoming = None;
            state.file_hash = None;
        }
        let app = self.app();
        app.set_backup_confirmed(SharedString::new());
        app.set_confirm_remove_vault(false);
        app.set_import_added(-1);
        self.show_entry();
        self.publish_vaults();
    }

    /// "Add a vault": the start screen for a new file, with a way back to the current vault.
    pub(super) fn add_vault(&self) {
        let folder = self.folder();
        let file = self.state.borrow().prefs.free_file(&folder);
        if self.is_unlocked() {
            self.lock();
        }
        let previous = self.state.borrow().path.clone();
        self.open_slot(folder.join(file));
        self.state.borrow_mut().previous = Some(previous);
        self.app().set_adding_vault(true);
    }

    /// Back from adding a vault, to the one before.
    pub(super) fn cancel_add_vault(&self) {
        let Some(previous) = self.state.borrow_mut().previous.take() else {
            return;
        };
        self.app().set_adding_vault(false);
        self.open_slot(previous);
        self.offer_biometrics(false);
    }

    /// "Remove this vault from the phone": its copy, its Secret Key, its fingerprint unlock
    /// and its sync place leave the phone; the next vault (or the start screen) shows.
    pub(super) fn remove_vault(&self) {
        let (path, id, name) = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            (
                state.path.clone(),
                vault.id_hex(),
                vault.settings().name.clone(),
            )
        };
        self.sync_stop();
        self.forget_biometrics(&id);
        let _ = secret_store::forget(&id);
        self.lock();
        files::remove(&path);
        files::remove(&bak(&path));
        let file = self.current_file();
        self.change_prefs(|prefs| {
            prefs.vaults.retain(|v| v.file != file);
            prefs.current.clear();
        });
        let folder = self.folder();
        let next = {
            let state = self.state.borrow();
            state
                .prefs
                .vaults
                .iter()
                .find(|v| folder.join(&v.file).exists())
                .map(|v| v.file.clone())
        };
        let next_file = next.unwrap_or_else(|| prefs::FIRST_VAULT.to_owned());
        self.change_prefs(|prefs| prefs.current.clone_from(&next_file));
        self.open_slot(folder.join(next_file));
        self.notify(notice::VAULT_REMOVED, &name);
    }

    /// The vault's size and the settings that follow the open vault.
    pub(super) fn publish_vault_facts(&self) {
        let size = {
            let state = self.state.borrow();
            files::read_any(&state.path)
                .map(|bytes| super::size_text(bytes.len()))
                .unwrap_or_default()
        };
        self.app().set_vault_size(size.into());
        self.refresh_security();
    }

    // ---- fingerprint unlock ----

    fn read_bio(&self, vault_id: &str) -> Option<BioUnlock> {
        bio::read(&self.folder(), vault_id)
    }

    fn write_bio(&self, vault_id: &str, unlock: &BioUnlock) -> Result<(), String> {
        bio::write(&self.folder(), vault_id, unlock)
    }

    pub(super) fn forget_biometrics(&self, vault_id: &str) {
        let path = bio::path(&self.folder(), vault_id);
        files::remove(&path);
        files::remove(&bak(&path));
        self.system().forget_biometrics(vault_id);
    }

    /// The master password was typed: fingerprint unlock may go on for another 14 days.
    pub(super) fn password_typed(&self, vault_id: &str) {
        if let Some(mut bio) = self.read_bio(vault_id) {
            bio.password_at = unix_now();
            let _ = self.write_bio(vault_id, &bio);
        }
    }

    /// The master password changed: its fingerprint unlock opens nothing any more (it was
    /// bound to the old password slot), so it goes.
    pub(super) fn biometrics_revoked(&self, vault_id: &str) {
        if self.read_bio(vault_id).is_some() {
            self.forget_biometrics(vault_id);
            self.notify(notice::BIO_REVOKED, "");
        }
        self.refresh_security();
    }

    /// Settings → Security for the open vault.
    pub(super) fn refresh_security(&self) {
        let app = self.app();
        app.set_bio_available(self.system().biometrics());
        let id = self.state.borrow().vault.as_ref().map(Vault::id_hex);
        if let Some(id) = id {
            app.set_bio_on(self.read_bio(&id).is_some());
        }
        let prefs = self.state.borrow().prefs.clone();
        app.set_lock_on_leave(prefs.lock_on_leave);
        app.set_allow_capture(prefs.allow_capture);
    }

    /// The unlock screen: whether the fingerprint can open this vault now, or waits for the
    /// master password (every 14 days). With `ask`, the prompt shows at once.
    pub(super) fn offer_biometrics(&self, ask: bool) {
        let app = self.app();
        let (incoming, path) = {
            let state = self.state.borrow();
            (state.incoming.is_some(), state.path.clone())
        };
        let id = files::read(&path)
            .ok()
            .and_then(|bytes| Vault::inspect(&bytes).ok())
            .map(|info| info.id_hex);
        let bio = id.as_deref().and_then(|id| self.read_bio(id));
        let available = self.system().biometrics();
        let ready = !incoming
            && available
            && app.get_screen() == Screen::Unlock
            && bio.as_ref().is_some_and(|b| b.fresh(unix_now()));
        app.set_bio_ready(ready);
        app.set_bio_stale(available && bio.as_ref().is_some_and(|b| !b.fresh(unix_now())));
        if ready && ask && !app.get_busy() {
            self.bio_unlock();
        }
    }

    /// Turns fingerprint unlock on or off for the open vault.
    pub(super) fn bio_toggled(&self, on: bool) {
        let app = self.app();
        let Some(id) = self.state.borrow().vault.as_ref().map(Vault::id_hex) else {
            return;
        };
        self.set_error(error::NONE, "");
        if !on {
            self.forget_biometrics(&id);
            app.set_bio_on(false);
            return;
        }
        let made = (|| {
            let secret = Vault::new_device_secret().map_err(|e| e.to_string())?;
            let state = self.state.borrow();
            let vault = state.vault.as_ref().ok_or("the vault is locked")?;
            let sealed_key = vault
                .seal_for_device(secret.as_ref())
                .map_err(|e| e.to_string())?;
            Ok::<_, String>((secret, sealed_key))
        })();
        let (secret, sealed_key) = match made {
            Ok(made) => made,
            Err(detail) => {
                app.set_bio_on(false);
                return self.set_error(error::BIOMETRICS, &detail);
            }
        };
        self.state.borrow_mut().bio = BioPending::Sealing(id.clone(), sealed_key);
        let words = PromptWords {
            title: app.get_bio_enrol_title().into(),
            detail: app.get_vault_name().into(),
            cancel: app.get_bio_cancel().into(),
        };
        if let Err(detail) = self
            .system()
            .seal_with_biometrics(&id, secret.as_ref(), &words)
        {
            self.state.borrow_mut().bio = BioPending::None;
            app.set_bio_on(false);
            self.set_error(error::BIOMETRICS, &detail);
        }
    }

    /// The shell's answer to [`System::seal_with_biometrics`]: the sealed secret, or why not
    /// ("" when the person cancelled).
    pub fn biometric_sealed(&self, sealed: Result<Vec<u8>, String>) {
        let pending = std::mem::take(&mut self.state.borrow_mut().bio);
        let BioPending::Sealing(id, sealed_key) = pending else {
            return;
        };
        let app = self.app();
        let written = sealed.and_then(|hardware| {
            self.write_bio(
                &id,
                &BioUnlock {
                    sealed_key,
                    hardware,
                    password_at: unix_now(),
                },
            )
        });
        match written {
            Ok(()) => {
                app.set_bio_on(true);
                self.notify(notice::BIO_ON, "");
            }
            Err(detail) => {
                app.set_bio_on(false);
                if !detail.is_empty() {
                    self.set_error(error::BIOMETRICS, &detail);
                }
            }
        }
    }

    /// "Unlock with fingerprint": the shell asks for it and opens the device secret.
    pub(super) fn bio_unlock(&self) {
        let app = self.app();
        let path = self.state.borrow().path.clone();
        let Some(id) = files::read(&path)
            .ok()
            .and_then(|bytes| Vault::inspect(&bytes).ok())
            .map(|info| info.id_hex)
        else {
            return;
        };
        let Some(bio) = self.read_bio(&id).filter(|b| b.fresh(unix_now())) else {
            return self.offer_biometrics(false);
        };
        self.set_error(error::NONE, "");
        self.state.borrow_mut().bio = BioPending::Opening(id.clone());
        let words = PromptWords {
            title: app.get_bio_unlock_title().into(),
            detail: app.get_vault_name().into(),
            cancel: app.get_bio_cancel().into(),
        };
        if let Err(detail) = self
            .system()
            .open_with_biometrics(&id, &bio.hardware, &words)
        {
            self.state.borrow_mut().bio = BioPending::None;
            self.set_error(error::BIOMETRICS, &detail);
        }
    }

    /// The shell's answer to [`System::open_with_biometrics`]: the device secret, or why not
    /// ("" when the person chose the master password instead; "invalidated" when the phone's
    /// fingerprints changed since, which retires the key).
    pub fn biometric_opened(&self, secret: Result<Zeroizing<Vec<u8>>, String>) {
        let pending = std::mem::take(&mut self.state.borrow_mut().bio);
        let BioPending::Opening(id) = pending else {
            return;
        };
        let secret = match secret {
            Ok(secret) => secret,
            Err(detail) if detail.is_empty() => return,
            Err(detail) => {
                if detail == "invalidated" {
                    self.forget_biometrics(&id);
                    self.offer_biometrics(false);
                    return self.set_error(
                        error::BIOMETRICS,
                        "the phone's fingerprints changed; type the master password and turn it on again",
                    );
                }
                return self.set_error(error::BIOMETRICS, &detail);
            }
        };
        let path = self.state.borrow().path.clone();
        let opened = (|| {
            let bytes = files::read(&path).map_err(|e| e.to_string())?;
            if Vault::inspect(&bytes).map_err(|e| e.to_string())?.id_hex != id {
                return Err("another vault is showing now".to_owned());
            }
            let bio = self
                .read_bio(&id)
                .ok_or("fingerprint unlock was turned off")?;
            let secret_key = secret_store::load(&id)
                .ok()
                .flatten()
                .ok_or("this phone no longer has the vault's Secret Key")?;
            Ok((bytes, bio, secret_key))
        })();
        let (bytes, bio, secret_key) = match opened {
            Ok(opened) => opened,
            Err(detail) => return self.set_error(error::BIOMETRICS, &detail),
        };
        match Vault::open_with_device(&bytes, &secret, &bio.sealed_key) {
            Ok(vault) => self.opened(Opened {
                vault: Ok(vault),
                secret_key,
                typed_key: false,
                hash: fingerprint(&bytes),
                by_password: false,
            }),
            Err(_) => {
                // The master password changed (here or on another device): the key is bound
                // to the old one.
                self.forget_biometrics(&id);
                self.offer_biometrics(false);
                self.notify(notice::BIO_REVOKED, "");
            }
        }
    }

    // ---- import ----

    /// A file to import (Settings → Import and export): read with the file's password, if
    /// it has one, off the UI thread; logins already in the vault are skipped.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn import_file(&self, bytes: Vec<u8>) {
        if !self.is_unlocked() || self.app().get_busy() {
            return;
        }
        let format = vault_import::detect_format(&bytes);
        let password = self.secret(field::IMPORT_PASSWORD);
        if format.needs_password() && password.is_empty() {
            return self.set_error(error::IMPORT_PASSWORD, "");
        }
        self.set_error(error::NONE, "");
        self.app().set_import_added(-1);
        self.run(
            move || vault_import::import(&bytes, format, &password, None),
            |c, report| c.imported(report),
        );
    }

    #[cfg(target_arch = "wasm32")]
    pub(super) fn import_file(&self, _bytes: Vec<u8>) {
        self.set_error(error::IMPORT, "the browser preview imports nothing");
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn imported(&self, report: Result<vault_import::ImportReport, vault_import::ImportError>) {
        use vault_import::ImportError;
        let report = match report {
            Ok(report) => report,
            Err(ImportError::SealedExport) => return self.set_error(error::IMPORT_PASSWORD, ""),
            Err(err) => return self.set_error(error::IMPORT, &err.to_string()),
        };
        let outcome = {
            let mut state = self.state.borrow_mut();
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            report.add_to_vault(vault)
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(err) => return self.set_error(error::IMPORT, &err.to_string()),
        };
        if outcome.added > 0 && !self.save() {
            return;
        }
        self.state.borrow_mut().secrets[field::IMPORT_PASSWORD].clear();
        self.publish_lengths();
        let app = self.app();
        app.set_import_added(i32::try_from(outcome.added).unwrap_or(i32::MAX));
        app.set_import_skipped(i32::try_from(outcome.duplicates).unwrap_or(i32::MAX));
        self.refresh_list();
        self.publish_vault_facts();
    }

    // ---- "Check this password" ----

    /// The tests' stand-in for the breach service.
    #[cfg(test)]
    pub(crate) fn set_leak_lookup(&self, lookup: fn(&str) -> Result<u64, String>) {
        self.state.borrow_mut().leak_lookup = lookup;
    }

    /// The tests' stand-in for the leak watch's check of every login.
    #[cfg(test)]
    pub(crate) fn set_leak_batch(&self, lookup: super::LeakBatch) {
        self.state.borrow_mut().leak_batch = lookup;
    }

    /// The open item's password: its strength here, then the leak check (5 hex characters of
    /// its SHA-1 sent, `vault_platform::leak_check`), on the person's tap only.
    pub(super) fn check_password(&self) {
        let Some(item) = self.selected_item() else {
            return;
        };
        if item.password.is_empty() {
            return;
        }
        let app = self.app();
        let strength = health::strength(
            &item.password,
            &[item.title.as_str(), item.username.as_str()],
        );
        let bits = strength.bits;
        let (unit, amount) = view::crack_time(bits);
        app.set_d_bits(bits.round() as i32);
        app.set_d_crack_unit(unit);
        app.set_d_crack_amount(amount);
        app.set_d_crack_comparison(view::crack_comparison(bits));
        app.set_d_weakness(view::weakness_code(&strength));
        app.set_d_leak(-1);
        app.set_d_checked(true);
        let password = Zeroizing::new(item.password.clone());
        let (lookup, selected) = {
            let state = self.state.borrow();
            (state.leak_lookup, state.selected)
        };
        self.state.borrow_mut().leak_for = selected;
        self.run(
            move || lookup(&password),
            |c, found| {
                let still = {
                    let state = c.state.borrow();
                    state.leak_for.is_some() && state.leak_for == state.selected
                };
                let app = c.app();
                if !still || app.get_page() != Page::Item {
                    return;
                }
                match found {
                    Ok(count) => {
                        app.set_d_leak(i32::try_from(count).unwrap_or(i32::MAX));
                        app.set_d_leak_count(super::grouped_count(count).into());
                    }
                    Err(_) => app.set_d_leak(-2),
                }
            },
        );
    }
}
