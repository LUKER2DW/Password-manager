//! Settings that reach past one screen: the vaults this phone keeps, fingerprint unlock,
//! locking when the app is left, screenshots, autofill, the language, importing another
//! manager's export, and "Check this password" on the item page.

use std::{
    path::{Path, PathBuf},
    rc::Rc,
};

use slint::{ModelRc, SharedString, VecModel};
use vault_core::{Error as CoreError, SecretKey, Unlock, Vault, health};
use zeroize::Zeroizing;

use super::{Controller, Opened, error, field, fingerprint, notice, scan, sheet};
use crate::{
    bio::{self, BioUnlock},
    i18n,
    platform::{files, secret_store},
    prefs,
    system::{PromptWords, System},
    ui::{ExportCounts, Page, Screen, VaultRow},
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
        self.app().set_can_scan(self.system().scans_codes());
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
    /// own pickers and prompts, which the shell leaves out). With "Lock as soon as I leave the
    /// app", the vault locks, also while a job holds it (an export, a new master password, a
    /// confirmation: its result is dropped when it comes back), and an unlock still on its
    /// way opens nothing.
    pub fn left_app(&self) {
        if !self.state.borrow().prefs.lock_on_leave {
            return;
        }
        if self.is_unlocked() {
            self.lock();
        } else {
            self.new_session();
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

    /// "Scan the QR code": the system's code scanner, for the invite line a computer shows under
    /// Add a device.
    pub(super) fn scan_invite(&self, purpose: i32) {
        self.set_error(0, "");
        if let Err(detail) = self.system().scan_code(purpose) {
            self.set_error(error::CAMERA, &detail);
        }
    }

    /// The camera read a QR code: its line goes where the scan was asked for, and is used at
    /// once, as if pasted and confirmed.
    pub fn code_scanned(&self, purpose: i32, text: &str) {
        // A part or the Secret Key from the emergency kit goes into its secure field, never
        // into the screen's text.
        if purpose == scan::PART || purpose == scan::SECRET_KEY {
            return self.kit_code_scanned(purpose, text);
        }
        let app = self.app();
        let line = SharedString::from(text.trim());
        match purpose {
            scan::SETUP => {
                app.set_setup_invite(line);
                self.setup_from_server();
            }
            scan::JOIN => {
                app.set_sync_invite_typed(line);
                self.sync_join();
            }
            scan::OTP => {
                let text = line.to_string();
                app.set_ed_totp(line);
                self.otp_names_into_editor(&text);
            }
            _ => {}
        }
    }

    /// The QR code couldn't be scanned ("unavailable": the phone has no Google Play services).
    pub fn scan_failed(&self, detail: &str) {
        self.set_error(error::CAMERA, detail);
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
        // A vault's icon on this phone, with its colours (`view::IconLook`, as `home:2:5`).
        let look = |spec: &str| crate::view::IconLook::parse(spec).unwrap_or_default();
        let rows: Vec<VaultRow> = kept
            .iter()
            .map(|known| VaultRow {
                icon: look(&known.icon).name.as_str().into(),
                icon_color: look(&known.icon).color,
                icon_bg: look(&known.icon).background,
                name: known.name.as_str().into(),
                initial: super::initial(&known.name),
                tint: super::tint(vault_core::ItemKind::Login, &known.name),
                place: sync_host(&known.id).into(),
                open: open && known.file == current,
            })
            .collect();
        let app = self.app();
        // A locked vault is still called by the name it had when it was last open (and shows
        // no titles from its last import).
        if !open {
            self.forget_import_warnings();
            app.set_vault_name(
                index
                    .and_then(|i| kept.get(i))
                    .map(|v| v.name.as_str().into())
                    .unwrap_or_default(),
            );
        }
        let own = index
            .and_then(|i| kept.get(i))
            .map(|v| look(&v.icon))
            .unwrap_or_default();
        app.set_vault_icon(own.name.as_str().into());
        app.set_vault_icon_color(own.color);
        app.set_vault_icon_bg(own.background);
        app.set_vaults(ModelRc::new(VecModel::from(rows)));
        app.set_vault_current(index.map_or(-1, |i| i32::try_from(i).unwrap_or(0)));
    }

    /// Settings → Vaults → Icon on this phone, and its colours: kept with this phone's list of
    /// vaults ("" = its initial).
    pub(super) fn vault_icon_changed(&self, name: &str, color: i32, background: i32) {
        let current = self.current_file();
        let name = name.chars().take(32).collect::<String>();
        let spec = if name.is_empty() {
            String::new()
        } else {
            crate::view::IconLook::new(&name, color, background).spec()
        };
        self.change_prefs(|prefs| {
            if let Some(known) = prefs.vaults.iter_mut().find(|v| v.file == current) {
                known.icon = spec;
            }
        });
        self.publish_vaults();
    }

    /// Settings → Vaults → Name: the vault's own name, kept in the vault (so it syncs) and in
    /// this phone's list of vaults.
    pub(super) fn vault_rename(&self) {
        let app = self.app();
        let name = app.get_vault_new_name().trim().to_owned();
        if name.is_empty() {
            return self.set_error(error::NAME, "");
        }
        let renamed = {
            let mut state = self.state.borrow_mut();
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            let mut settings = vault.settings().clone();
            settings.name.clone_from(&name);
            vault.set_settings(settings)
        };
        if let Err(err) = renamed {
            return self.set_error(error::NOT_SAVED, &err.to_string());
        }
        if !self.save() {
            return;
        }
        self.set_error(error::NONE, "");
        app.set_vault_renaming(false);
        app.set_vault_name(name.as_str().into());
        self.remember_open_vault();
        self.notify(super::notice::SAVED, "");
    }

    /// An export, confirmed (app.slint `ask`): 0 protected (.vaultx, sealed under the password
    /// typed for it), 1 plain JSON, 2 plain CSV. As on the desktop, the master password is
    /// checked again against the vault file first, and nothing goes out while items are
    /// behind the item lock (their secrets would be missing). The bytes wait in memory while
    /// the shell asks where to save them (`save-file` with -1), and are wiped once saved.
    ///
    /// -1 only counts (the sheet just opened): what the file would leave out and what anyone
    /// who gets it reads, for the sheet to say before it is confirmed.
    pub(super) fn export_vault(&self, format: i32) {
        if format < 0 {
            return self.count_export();
        }
        if self.app().get_busy() {
            return;
        }
        let master = self.secret(field::EXPORT_MASTER);
        if master.is_empty() {
            return self.set_error(error::WRONG_CURRENT, "");
        }
        let password = self.secret(field::EXPORT_PASSWORD);
        if format == 0 && password.chars().count() < super::MIN_MASTER_PASSWORD_CHARS {
            return self.set_error(error::EXPORT_PASSWORD, "");
        }
        let locked = self.state.borrow().vault.as_ref().is_some_and(|vault| {
            vault
                .summaries()
                .is_ok_and(|all| all.iter().any(|item| item.locked))
        });
        if locked {
            return self.set_error(error::EXPORT_LOCKED, "");
        }
        self.set_error(error::NONE, "");
        // The file must hold what the sheet says: changed since (a sync), that is shown first
        // and confirmed again.
        let counts = match self.export_counts(format) {
            Ok(counts) => counts,
            Err(err) => return self.set_error(error::EXPORT, &err.to_string()),
        };
        if counts != self.app().get_export_counts() {
            self.app().set_export_counts(counts);
            self.app().set_export_recounted(true);
            return;
        }
        let Some((vault, secret_key, session)) = self.lend_vault() else {
            return;
        };
        let path = self.state.borrow().path.clone();
        struct Exported {
            vault: Vault,
            secret_key: SecretKey,
            /// The file's name and bytes, or the error code and detail.
            outcome: Result<Export, (i32, String)>,
        }
        self.run(
            move || {
                let outcome = (|| {
                    let bytes = files::read(&path).map_err(|e| (error::EXPORT, e.to_string()))?;
                    // The master password, checked against the file itself.
                    Vault::open(
                        &bytes,
                        Unlock::Password {
                            password: &master,
                            secret_key: &secret_key,
                        },
                    )
                    .map_err(|err| match err {
                        CoreError::DecryptionFailed => (error::WRONG_CURRENT, String::new()),
                        other => (error::EXPORT, other.to_string()),
                    })?;
                    make_export(&vault, format, &password).map_err(|detail| (error::EXPORT, detail))
                })();
                Exported {
                    vault,
                    secret_key,
                    outcome,
                }
            },
            move |c, exported| {
                // Locked meanwhile (the app was left): it stays locked, and the export is
                // wiped unsaved.
                if !c.take_back(exported.vault, exported.secret_key, session) {
                    return;
                }
                // The master password is typed again after every try.
                c.clear_fields(&[field::EXPORT_MASTER]);
                match exported.outcome {
                    Ok(export) => {
                        c.clear_fields(&[field::EXPORT_PASSWORD]);
                        let open = c.app().get_confirming();
                        if (sheet::EXPORT_JSON..=sheet::EXPORT_CSV).contains(&open) {
                            c.close_sheet(open);
                        }
                        c.state.borrow_mut().export_pending = Some(export);
                        c.app().invoke_save_file(-1);
                    }
                    Err((code, detail)) => c.set_error(code, &detail),
                }
            },
        );
    }

    /// An export's sheet opened: counts what its file would leave out and what anyone who
    /// gets it would read. Items behind the item lock can't be counted (nor exported): that
    /// is told at once.
    fn count_export(&self) {
        let app = self.app();
        app.set_export_recounted(false);
        let format = match app.get_confirming() {
            sheet::EXPORT_JSON => 1,
            sheet::EXPORT_CSV => 2,
            _ => 0,
        };
        match self.export_counts(format) {
            Ok(counts) => app.set_export_counts(counts),
            Err(err) => {
                app.set_export_counts(ExportCounts::default());
                match err {
                    CoreError::SecretsLocked => self.set_error(error::EXPORT_LOCKED, ""),
                    other => self.set_error(error::EXPORT, &other.to_string()),
                }
            }
        }
    }

    /// The counts of an export of the open vault (`format` as in `export_vault`): numbers only.
    #[cfg(not(target_arch = "wasm32"))]
    fn export_counts(&self, format: i32) -> Result<ExportCounts, CoreError> {
        use vault_import::ExportFormat;
        let report = match self.state.borrow().vault.as_ref() {
            Some(vault) => vault_import::export_report(
                vault,
                match format {
                    0 => ExportFormat::Sealed,
                    1 => ExportFormat::Json,
                    _ => ExportFormat::Csv,
                },
            )?,
            None => return Ok(ExportCounts::default()),
        };
        let count = |n: usize| i32::try_from(n).unwrap_or(i32::MAX);
        let (out, clear) = (&report.left_out, &report.in_clear);
        Ok(ExportCounts {
            attachments: count(out.attachments),
            passkeys: count(out.passkeys),
            earlier_passwords: count(out.earlier_passwords),
            extra_websites: count(out.extra_websites),
            dates: out.dates,
            hidden_marks: count(out.hidden_marks),
            recovery_code_lists: count(out.recovery_code_lists),
            kinds_changed: count(out.kinds_changed),
            passwords: count(clear.passwords),
            otp_secrets: count(clear.otp_secrets),
            hidden_fields: count(clear.hidden_fields),
            recovery_codes: count(clear.recovery_codes),
            notes: count(clear.notes),
            formula_like: count(clear.formula_like),
        })
    }

    /// The browser preview makes no exports.
    #[cfg(target_arch = "wasm32")]
    fn export_counts(&self, _format: i32) -> Result<ExportCounts, CoreError> {
        Ok(ExportCounts::default())
    }

    /// A sensitive change confirmed in the sheet with the master password (app.slint `ask`):
    /// removing the vault from the phone, stopping sync, removing a device or the backup
    /// server, adding a device. As for an export, the password is checked against the vault
    /// file first; then the sheet closes and the change is made.
    pub(super) fn check_master_then(&self, kind: i32) {
        if self.app().get_busy() {
            return;
        }
        let master = self.secret(field::EXPORT_MASTER);
        if master.is_empty() {
            return self.set_error(error::WRONG_CURRENT, "");
        }
        self.set_error(error::NONE, "");
        let Some((vault, secret_key, session)) = self.lend_vault() else {
            return;
        };
        let path = self.state.borrow().path.clone();
        struct Checked {
            vault: Vault,
            secret_key: SecretKey,
            kind: i32,
            outcome: Result<(), (i32, String)>,
        }
        self.run(
            move || {
                let outcome = files::read(&path)
                    .map_err(|e| (error::UNREADABLE, e.to_string()))
                    .and_then(|bytes| {
                        Vault::open(
                            &bytes,
                            Unlock::Password {
                                password: &master,
                                secret_key: &secret_key,
                            },
                        )
                        .map(drop)
                        .map_err(|err| match err {
                            CoreError::DecryptionFailed => (error::WRONG_CURRENT, String::new()),
                            other => (error::UNREADABLE, other.to_string()),
                        })
                    });
                Checked {
                    vault,
                    secret_key,
                    kind,
                    outcome,
                }
            },
            move |c, checked| {
                // Locked meanwhile (the app was left): it stays locked, and the change waits
                // for a new confirmation.
                if !c.take_back(checked.vault, checked.secret_key, session) {
                    return;
                }
                c.clear_fields(&[field::EXPORT_MASTER]);
                if let Err((code, detail)) = checked.outcome {
                    return c.set_error(code, &detail);
                }
                c.close_sheet(checked.kind);
                let app = c.app();
                match checked.kind {
                    sheet::REMOVE_VAULT => c.remove_vault(),
                    sheet::STOP_SYNC => c.sync_stop(),
                    sheet::REMOVE_DEVICE => {
                        let index = app.get_sync_removing();
                        app.set_sync_removing(-1);
                        c.sync_remove_device(index);
                    }
                    sheet::REMOVE_BACKUP => c.sync_remove_backup(),
                    sheet::ADD_DEVICE => c.sync_add_device(),
                    _ => {}
                }
            },
        );
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

    /// Points the window at the vault file `path` (nothing open, nothing waiting; an unlock
    /// still on its way for the one before opens nothing).
    fn open_slot(&self, path: PathBuf) {
        self.new_session();
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
            prefs.password_typed_at.remove(&id);
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

    /// The master password was typed and opened the vault: fingerprint unlock may go on for
    /// another 14 days. The only place that time moves forward.
    pub(super) fn password_typed(&self, vault_id: &str) {
        let now = unix_now();
        self.change_prefs(|prefs| {
            prefs.password_typed_at.insert(vault_id.to_owned(), now);
        });
        if let Some(mut bio) = self.read_bio(vault_id) {
            bio.password_at = now;
            let _ = self.write_bio(vault_id, &bio);
        }
    }

    /// The tests: as if the master password was last typed for `vault_id` at `at`.
    #[cfg(test)]
    pub(crate) fn set_password_typed_at(&self, vault_id: &str, at: i64) {
        self.change_prefs(|prefs| {
            prefs.password_typed_at.insert(vault_id.to_owned(), at);
        });
    }

    /// When the master password was last typed here for the vault `vault_id` (0: not that
    /// this phone knows, which counts as long ago).
    fn password_typed_at(&self, vault_id: &str) -> i64 {
        self.state
            .borrow()
            .prefs
            .password_typed_at
            .get(vault_id)
            .copied()
            .unwrap_or(0)
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
        // One prompt at a time: while one waits for its answer, it is the one.
        let waiting = matches!(self.state.borrow().bio, BioPending::Opening(_));
        if ready && ask && !app.get_busy() && !waiting {
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
    ///
    /// The 14 days run from when the master password was last typed, as before it was turned
    /// on: turning it off and on again with the phone's own lock renews nothing.
    pub fn biometric_sealed(&self, sealed: Result<Vec<u8>, String>) {
        let pending = std::mem::take(&mut self.state.borrow_mut().bio);
        let BioPending::Sealing(id, sealed_key) = pending else {
            return;
        };
        let app = self.app();
        let password_at = self.password_typed_at(&id);
        let written = sealed.and_then(|hardware| {
            self.write_bio(
                &id,
                &BioUnlock {
                    sealed_key,
                    hardware,
                    password_at,
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
        let bio = self.read_bio(&id);
        if bio.as_ref().is_some_and(|bio| !bio.fresh(unix_now())) {
            // The 14 days ran out while the prompt was open (or the clock moved): the master
            // password first.
            return self.offer_biometrics(false);
        }
        let opened = (|| {
            let bytes = files::read(&path).map_err(|e| e.to_string())?;
            if Vault::inspect(&bytes).map_err(|e| e.to_string())?.id_hex != id {
                return Err("another vault is showing now".to_owned());
            }
            let bio = bio.ok_or("fingerprint unlock was turned off")?;
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
                used_parts: None,
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

    /// A file to import (Settings → Import and export), read off the UI thread; logins
    /// already in the vault are skipped. A file that needs a password (a KeePass database, a
    /// protected export) waits in memory while the sheet asks for it (`import_retry`).
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn import_file(&self, name: &str, bytes: Vec<u8>) {
        if !self.is_unlocked() || self.app().get_busy() {
            return;
        }
        let bytes = Zeroizing::new(bytes);
        if vault_import::detect_format(&bytes).needs_password() {
            self.state.borrow_mut().import_pending = Some(bytes);
            let app = self.app();
            app.set_import_added(-1);
            self.forget_import_warnings();
            app.set_import_name(name.into());
            app.invoke_ask(sheet::IMPORT);
            return;
        }
        self.start_import(bytes, Zeroizing::new(String::new()));
    }

    #[cfg(target_arch = "wasm32")]
    pub(super) fn import_file(&self, _name: &str, _bytes: Vec<u8>) {
        self.set_error(error::IMPORT, "the browser preview imports nothing");
    }

    /// The file that waits for its password, with the one typed in the sheet.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn import_retry(&self) {
        if self.app().get_busy() {
            return;
        }
        let password = self.secret(field::IMPORT_PASSWORD);
        if password.is_empty() {
            return self.set_error(error::IMPORT_PASSWORD, "");
        }
        let Some(bytes) = self.state.borrow().import_pending.clone() else {
            return;
        };
        self.start_import(bytes, password);
    }

    #[cfg(target_arch = "wasm32")]
    pub(super) fn import_retry(&self) {}

    #[cfg(not(target_arch = "wasm32"))]
    fn start_import(&self, bytes: Zeroizing<Vec<u8>>, password: Zeroizing<String>) {
        let format = vault_import::detect_format(&bytes);
        self.set_error(error::NONE, "");
        self.app().set_import_added(-1);
        self.forget_import_warnings();
        // Added to the vault open now, not to one opened after a lock.
        self.run_in_session(
            move || vault_import::import(&bytes, format, &password, None),
            |c, report| c.imported(report),
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn imported(&self, report: Result<vault_import::ImportReport, vault_import::ImportError>) {
        use vault_import::ImportError;
        // A wrong password is typed again; the file keeps waiting until the sheet closes.
        self.clear_fields(&[field::IMPORT_PASSWORD]);
        let report = match report {
            Ok(report) => report,
            Err(ImportError::SealedExport) => return self.set_error(error::IMPORT_PASSWORD, ""),
            Err(err) => return self.set_error(error::IMPORT, &err.to_string()),
        };
        let (first, more) = import_warnings(&report.warnings);
        let (outcome, before) = {
            let mut state = self.state.borrow_mut();
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            let before = vault.snapshot();
            (report.add_to_vault(vault), before)
        };
        // Not all of it came in, or it couldn't be saved: the open vault is as it was, or the
        // next try would find every item "already in the vault" and the person delete the file.
        let outcome = match outcome {
            Ok(outcome) if outcome.added == 0 || self.save() => outcome,
            failed => {
                if let Some(vault) = self.state.borrow_mut().vault.as_mut() {
                    vault.roll_back(before);
                }
                if let Err(err) = failed {
                    self.set_error(error::IMPORT, &err.to_string());
                }
                return;
            }
        };
        self.state.borrow_mut().import_pending = None;
        // What was left behind is there before the sheet closes: the person may delete the
        // file next.
        let app = self.app();
        app.set_import_warnings(first.into());
        app.set_import_more(more);
        app.set_import_added(i32::try_from(outcome.added).unwrap_or(i32::MAX));
        app.set_import_skipped(i32::try_from(outcome.duplicates).unwrap_or(i32::MAX));
        self.close_sheet(sheet::IMPORT);
        app.set_import_name(SharedString::new());
        self.refresh_list();
        self.publish_vault_facts();
    }

    /// Another import starts, or the vault locked: the last one's warnings (they name items)
    /// leave the screen.
    fn forget_import_warnings(&self) {
        let app = self.app();
        app.set_import_warnings(SharedString::new());
        app.set_import_more(0);
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

/// How many of an import's warnings are shown, as on the computer, and how long each may be:
/// the titles in them come from the file.
#[cfg(not(target_arch = "wasm32"))]
const WARNINGS_SHOWN: usize = 4;
#[cfg(not(target_arch = "wasm32"))]
const WARNING_CHARS: usize = 400;

/// An import's warnings for the screen: the first ones, a line each, and how many more.
#[cfg(not(target_arch = "wasm32"))]
fn import_warnings(warnings: &[String]) -> (String, i32) {
    let line = |warning: &String| {
        let mut chars = warning.chars();
        let mut line: String = chars
            .by_ref()
            .take(WARNING_CHARS)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        if chars.next().is_some() {
            line.push('…');
        }
        line
    };
    let first: Vec<String> = warnings.iter().take(WARNINGS_SHOWN).map(line).collect();
    let more = warnings.len().saturating_sub(WARNINGS_SHOWN);
    (first.join("\n"), i32::try_from(more).unwrap_or(i32::MAX))
}

/// An export's file name and bytes.
type Export = (String, Zeroizing<Vec<u8>>);

/// An export: 0 protected (.vaultx), 1 plain JSON, 2 plain CSV.
#[cfg(not(target_arch = "wasm32"))]
fn make_export(vault: &Vault, format: i32, password: &str) -> Result<Export, String> {
    use vault_import as export;
    let day = crate::view::date(crate::view::now_unix());
    let made = match format {
        0 => export::export_sealed(vault, password)
            .map(|bytes| (format!("vault-export-{day}.vaultx"), Zeroizing::new(bytes))),
        1 => export::export_json(vault).map(|text| {
            (
                format!("vault-export-{day}.json"),
                Zeroizing::new(text.as_bytes().to_vec()),
            )
        }),
        _ => export::export_csv(vault).map(|text| {
            (
                format!("vault-export-{day}.csv"),
                Zeroizing::new(text.as_bytes().to_vec()),
            )
        }),
    };
    made.map_err(|err| err.to_string())
}

/// The browser preview makes no exports.
#[cfg(target_arch = "wasm32")]
fn make_export(_vault: &Vault, _format: i32, _password: &str) -> Result<Export, String> {
    Err("the browser preview makes no exports".to_owned())
}
