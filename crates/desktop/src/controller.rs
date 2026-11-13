//! Connects the Slint window to the vault: every callback, every background job, every timer.
//!
//! Secrets typed by the user live only in `SecretBuffer`s (locked, zeroized). Slow work (Argon2id)
//! runs on a worker thread; its result comes back to the UI thread through `finish_job`.

use std::{
    cell::RefCell,
    collections::HashMap,
    path::PathBuf,
    rc::{Rc, Weak},
    sync::Arc,
    time::Duration,
};

use slint::{
    ComponentHandle, Image, Model, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString, Timer,
    TimerMode, VecModel,
};
use vault_core::{
    CustomField, Error as CoreError, FolderId, ItemData, ItemId, ItemKind, KdfParams, RecoveryCode,
    RecoveryKey, SecretKey, Unlock, Vault,
    card::{self, CardDetails, CardProblem},
    generator::{self, PassphraseOptions, PasswordOptions},
    storage,
    totp::Totp,
};
use vault_platform::{
    DeviceState, RollbackStatus, SecretBuffer, clipboard, device, files,
    kit_pdf::{self, KitContents},
    quick_unlock::{self, DeviceVerifier, QuickUnlockError},
    secret_store,
};
use zeroize::Zeroizing;

use crate::{
    favicon::{self, IconCache},
    ui::{
        AppWindow, AuthRow, CodeRow, DetailField, EditField, FolderRow, ItemRow, Panel,
        RecentVault, Screen, Secrets, Theme,
    },
    view,
};

/// What to draw next to an item.
struct IconVisual {
    image: Image,
    has_image: bool,
    initial: SharedString,
    tint: slint::Color,
}

/// Secure field ids (must match `Secrets` in theme.slint).
mod field {
    pub const MASTER: usize = 0;
    pub const CONFIRM: usize = 1;
    pub const SECRET_KEY: usize = 2;
    pub const RECOVERY_KEY: usize = 3;
    pub const ITEM_PASSWORD: usize = 4;
    pub const CURRENT: usize = 5;
    pub const NEW: usize = 6;
    pub const NEW_AGAIN: usize = 7;
    pub const IMPORT: usize = 8;
    pub const COUNT: usize = 9;
}

/// Error codes (texts live in model.slint → Messages.error).
mod error {
    pub const NONE: i32 = 0;
    pub const WRONG_PASSWORD: i32 = 1;
    pub const SECRET_KEY_TYPO: i32 = 2;
    pub const SECRET_KEY_FORMAT: i32 = 3;
    pub const MISMATCH: i32 = 4;
    pub const TOO_SHORT: i32 = 5;
    pub const ROLLBACK: i32 = 6;
    pub const FILE: i32 = 7;
    pub const RECOVERY_KEY: i32 = 8;
    pub const TITLE_REQUIRED: i32 = 9;
    pub const BAD_TOTP: i32 = 10;
    pub const WRONG_CURRENT: i32 = 11;
    pub const CLIPBOARD: i32 = 12;
    pub const OTHER: i32 = 13;
    pub const HELLO_FAILED: i32 = 14;
    pub const HELLO_REVOKED: i32 = 15;
    pub const PASSWORD_DUE: i32 = 16;
    pub const HELLO_UNAVAILABLE: i32 = 17;
    pub const HELLO_KEY_GONE: i32 = 18;
    pub const IMPORT: i32 = 19;
    pub const CARD_NUMBER: i32 = 20;
    pub const CARD_EXPIRY: i32 = 21;
    pub const CARD_CODE: i32 = 22;
    pub const CARD_PIN: i32 = 23;
    pub const CHANGED_OUTSIDE: i32 = 24;
}

/// Notice codes (texts live in model.slint → Messages.notice).
mod notice {
    pub const PASSWORD_COPIED: i32 = 1;
    pub const USERNAME_COPIED: i32 = 2;
    pub const CODE_COPIED: i32 = 3;
    pub const CLIPBOARD_CLEARED: i32 = 4;
    pub const SAVED: i32 = 5;
    pub const DELETED: i32 = 6;
    pub const PASSWORD_CHANGED: i32 = 7;
    pub const RECOVERY_ISSUED: i32 = 8;
    pub const FIELD_COPIED: i32 = 10;
    pub const GENERATED_COPIED: i32 = 11;
    pub const HELLO_ON: i32 = 12;
    pub const HELLO_OFF: i32 = 13;
    pub const HELLO_NOT_ON: i32 = 14;
    pub const PASSWORD_CHANGED_HELLO_OFF: i32 = 15;
    pub const KIT_OPENED: i32 = 16;
    pub const KIT_SAVED: i32 = 17;
    pub const NOT_SAVED: i32 = 23;
    pub const RECOVERY_CODE_COPIED: i32 = 18;
    pub const IMPORTED: i32 = 19;
    pub const BACKUP_SAVED: i32 = 20;
    pub const EXPORTED: i32 = 21;
    pub const SOURCE_WIPED: i32 = 22;
}

const MIN_MASTER_PASSWORD_CHARS: usize = 12;
/// Index categories at or above this value browse a folder (100 = the first folder).
const FOLDER_CATEGORY: i32 = 100;
const REVEAL_SECONDS: i32 = 15;
const NOTICE_DURATION: Duration = Duration::from_millis(3500);
const KDF_MEMORY_KIB: u32 = 256 * 1024;
const KDF_TARGET: Duration = Duration::from_millis(1000);

/// How slow jobs run: on a worker thread (the app) or inline (headless tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runner {
    Thread,
    Inline,
}

struct Session {
    vault: Vault,
    secret_key: SecretKey,
}

/// Results of background work, sent back to the UI thread.
enum JobResult {
    Created {
        session: Session,
        recovery_key: RecoveryKey,
    },
    Unlocked {
        session: Session,
        typed_secret_key: bool,
    },
    QuickUnlockEnabled {
        session: Session,
    },
    ImportParsed {
        report: vault_import::ImportReport,
    },
    ExportVerified {
        session: Session,
    },
    /// `reason` is `None` when the person cancelled the prompt.
    QuickUnlockNotEnabled {
        session: Session,
        reason: Option<String>,
    },
    Recovered {
        session: Session,
    },
    PasswordChanged {
        session: Session,
    },
    KitVerified {
        session: Session,
    },
    RecoveryIssued {
        session: Session,
        recovery_key: RecoveryKey,
    },
    /// `session` is handed back when the job borrowed an open vault.
    Failed {
        code: i32,
        detail: String,
        session: Option<Session>,
    },
}

struct State {
    path: PathBuf,
    runner: Runner,
    secrets: Vec<SecretBuffer>,
    session: Option<Session>,
    /// Onboarding step 2 shows the kit; the vault opens when the user confirms.
    pending: Option<Session>,
    summaries: Vec<vault_core::ItemSummary>,
    /// Set whenever the vault changes; the next list refresh decrypts the summaries again.
    summaries_stale: bool,
    visible: Vec<ItemId>,
    selected: Option<ItemId>,
    /// `Some(None)` = new item, `Some(Some(id))` = editing `id`.
    editing: Option<Option<ItemId>>,
    copied: Option<Zeroizing<String>>,
    suggestion: Option<Zeroizing<String>>,
    generated: Option<Zeroizing<String>>,
    totp: Option<Totp>,
    /// A file being imported: chosen, maybe parsed, waiting for confirmation.
    pending_import: Option<PendingImport>,
    /// SHA-256 of the vault file as this window last read or wrote it; a different file on disk
    /// means someone else changed it, and saving would silently overwrite their change.
    file_hash: Option<[u8; 32]>,
    /// Extra fields while an item is being edited (card details excluded).
    edit_fields: Vec<CustomField>,
    /// The chooser's rows, in order.
    recent_paths: Vec<PathBuf>,
    /// Items with a one-time code, while the Authenticator page is open.
    auth: Vec<AuthEntry>,
    /// The item whose recovery codes are on screen.
    codes_shown: Option<ItemId>,
    settings: device::Settings,
    /// Website icons for this vault (decrypted cache) and the images built from them.
    icons: IconCache,
    icon_images: HashMap<String, Image>,
    fetching_icons: bool,
    /// Windows Hello (or a fake in tests); `quick_available` caches whether it is set up.
    verifier: Option<Arc<dyn DeviceVerifier>>,
    quick_available: bool,
}

#[derive(Default)]
struct Timers {
    reveal: Timer,
    clipboard: Timer,
    notice: Timer,
    auto_lock: Timer,
    totp: Timer,
    auth: Timer,
}

pub struct Controller {
    app: slint::Weak<AppWindow>,
    state: RefCell<State>,
    timers: Timers,
    lengths: Rc<VecModel<i32>>,
    items: Rc<VecModel<ItemRow>>,
    this: RefCell<Weak<Controller>>,
}

thread_local! {
    /// Lets worker-thread results find the controller once they are back on the UI thread.
    static CURRENT: RefCell<Weak<Controller>> = const { RefCell::new(Weak::new()) };
}

impl Drop for Controller {
    fn drop(&mut self) {
        // A kit printed during this session must not outlive it.
        files::wipe_print_dir();
    }
}

impl std::fmt::Debug for Controller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Controller")
    }
}

impl Controller {
    /// `verifier` is the device's user verification for quick unlock
    /// (`quick_unlock::system_verifier()` in the app, a fake in tests, `None` to disable).
    pub fn install(
        app: &AppWindow,
        path: PathBuf,
        runner: Runner,
        verifier: Option<Arc<dyn DeviceVerifier>>,
    ) -> anyhow::Result<Rc<Self>> {
        let settings = DeviceState::load().map(|s| s.settings).unwrap_or_default();
        // Left over from a crash or a viewer that kept the file open last time.
        files::wipe_print_dir();
        // Asking Windows whether Hello is set up can take a moment: never on the UI thread.
        let quick_available =
            runner == Runner::Inline && verifier.as_ref().is_some_and(|v| v.is_available());
        app.set_quick_unlock_available(quick_available);
        if runner == Runner::Thread {
            if let Some(verifier) = verifier.clone() {
                std::thread::spawn(move || {
                    let available = verifier.is_available();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                            controller.set_quick_available(available);
                        }
                    });
                });
            }
        }
        let controller = Rc::new(Self {
            app: app.as_weak(),
            state: RefCell::new(State {
                path,
                runner,
                secrets: (0..field::COUNT).map(|_| SecretBuffer::new()).collect(),
                session: None,
                pending: None,
                summaries: Vec::new(),
                summaries_stale: true,
                visible: Vec::new(),
                selected: None,
                editing: None,
                copied: None,
                suggestion: None,
                generated: None,
                totp: None,
                codes_shown: None,
                auth: Vec::new(),
                file_hash: None,
                recent_paths: Vec::new(),
                edit_fields: Vec::new(),
                pending_import: None,
                settings,
                icons: IconCache::default(),
                icon_images: HashMap::new(),
                fetching_icons: false,
                verifier,
                quick_available,
            }),
            timers: Timers::default(),
            lengths: Rc::new(VecModel::from(vec![0; field::COUNT])),
            items: Rc::new(VecModel::default()),
            this: RefCell::new(Weak::new()),
        });
        *controller.this.borrow_mut() = Rc::downgrade(&controller);
        CURRENT.with(|current| *current.borrow_mut() = Rc::downgrade(&controller));

        app.global::<Secrets>()
            .set_lengths(ModelRc::from(controller.lengths.clone()));
        app.set_items(ModelRc::from(controller.items.clone()));
        app.global::<Theme>()
            .set_dark(controller.state.borrow().settings.dark_theme);
        controller.wire(app);
        controller.show_start_screen();
        Ok(controller)
    }

    fn app(&self) -> AppWindow {
        self.app
            .upgrade()
            .expect("the window outlives the controller")
    }

    fn weak(&self) -> Weak<Controller> {
        self.this.borrow().clone()
    }

    // -----------------------------------------------------------------------------------------
    // Wiring
    // -----------------------------------------------------------------------------------------

    fn wire(self: &Rc<Self>, app: &AppWindow) {
        macro_rules! on {
            ($setter:ident, |$c:ident $(, $arg:ident)*| $body:expr) => {{
                let weak = Rc::downgrade(self);
                app.$setter(move |$($arg),*| {
                    if let Some($c) = weak.upgrade() {
                        $c.touch_activity();
                        $body
                    }
                });
            }};
        }

        let secrets = app.global::<Secrets>();
        {
            let weak = Rc::downgrade(self);
            secrets.on_insert(move |field, text| {
                if let Some(c) = weak.upgrade() {
                    c.edit_secret(field, |buffer| {
                        buffer.push_str(&text);
                    });
                }
            });
        }
        {
            let weak = Rc::downgrade(self);
            secrets.on_backspace(move |field| {
                if let Some(c) = weak.upgrade() {
                    c.edit_secret(field, SecretBuffer::backspace);
                }
            });
        }
        {
            let weak = Rc::downgrade(self);
            secrets.on_clear(move |field| {
                if let Some(c) = weak.upgrade() {
                    c.edit_secret(field, SecretBuffer::clear);
                }
            });
        }

        on!(on_create_vault, |c| c.create_vault());
        on!(on_suggest_passphrase, |c| c.suggest_passphrase());
        on!(on_use_suggestion, |c| c.use_suggestion());
        on!(on_finish_onboarding, |c| c.finish_onboarding());
        on!(on_unlock, |c| c.unlock());
        on!(on_quick_unlock, |c| c.quick_unlock());
        on!(on_quick_unlock_toggled, |c, on| c.set_quick_unlock(on));
        on!(on_show_recovery, |c| c.show_screen(Screen::Recover));
        on!(on_back_to_unlock, |c| c.show_screen(Screen::Unlock));
        on!(on_recover, |c| c.recover());

        on!(on_search, |c, _text| c.refresh_list());
        on!(on_select_category, |c, category| c
            .select_category(category));
        on!(on_select, |c, index| c.select(index));
        on!(on_new_item, |c| c.open_editor(None));
        on!(on_open_generator, |c| c.open_generator());
        on!(on_open_settings, |c| c.open_settings());
        on!(on_open_kit, |c| c.open_kit());
        on!(on_print_kit, |c| c.print_kit());
        on!(on_save_kit, |c| c.save_kit());
        on!(on_open_transfer, |c| c.open_transfer());
        on!(on_import_choose, |c| c.import_choose());
        on!(on_import_open, |c| c.parse_import());
        on!(on_import_confirm, |c| c.import_confirm());
        on!(on_import_cancel, |c| c.import_cancel());
        on!(on_import_wipe, |c| c.import_wipe());
        on!(on_export_backup, |c| c.export_backup());
        on!(on_export_plain, |c| c.verify_then(KitAction::Export));
        on!(on_lock, |c| c.lock());

        on!(on_edit_item, |c| {
            let selected = c.state.borrow().selected;
            if let Some(id) = selected {
                c.open_editor(Some(id));
            }
        });
        on!(on_toggle_favorite, |c| c.toggle_favorite());
        on!(on_create_folder, |c, name| c.create_folder(&name));
        on!(on_rename_folder, |c, name| c.rename_folder(&name));
        on!(on_delete_folder, |c| c.delete_folder());
        on!(on_show_codes, |c| c.show_codes());
        on!(on_hide_codes, |c| c.hide_codes());
        on!(on_copy_code, |c, index| c
            .copy_from_selected(CopyWhat::RecoveryCode(index)));
        on!(on_toggle_code_used, |c, index| c.toggle_code_used(index));
        on!(on_delete_item, |c| c.delete_selected());
        on!(on_reveal, |c| c.reveal());
        on!(on_conceal, |c| c.conceal());
        on!(on_copy_username, |c| c
            .copy_from_selected(CopyWhat::Username));
        on!(on_copy_password, |c| c
            .copy_from_selected(CopyWhat::Password));
        on!(on_copy_totp, |c| c.copy_from_selected(CopyWhat::Totp));
        on!(on_copy_field, |c, index| c
            .copy_from_selected(CopyWhat::Field(index)));

        on!(on_save_item, |c| c.save_item());
        on!(on_card_number_edited, |c, text| c.app().set_ed_card_brand(
            SharedString::from(card::detect_brand(&card::digits(&text)).name())
        ));
        on!(on_open_authenticator, |c| c.open_authenticator());
        on!(on_pick_vault, |c, index| c.pick_vault(index));
        on!(on_field_edited, |c, index, is_name, text| c.edit_field(
            index,
            |f| {
                if is_name {
                    f.name = text.to_string();
                } else {
                    f.value = text.to_string();
                }
            }
        ));
        on!(on_field_hidden, |c, index, on| {
            c.edit_field(index, |f| f.sensitive = on);
            c.show_edit_fields();
        });
        on!(on_field_remove, |c, index| {
            if let Ok(i) = usize::try_from(index) {
                let mut state = c.state.borrow_mut();
                if i < state.edit_fields.len() {
                    state.edit_fields.remove(i);
                }
            }
            c.show_edit_fields();
        });
        on!(on_field_add, |c| {
            c.state
                .borrow_mut()
                .edit_fields
                .push(CustomField::default());
            c.show_edit_fields();
        });
        on!(on_forget_vault, |c, index| c.forget_vault(index));
        on!(on_open_vault_file, |c| c.open_vault_file());
        on!(on_new_vault_file, |c| c.new_vault_file());
        on!(on_switch_vault, |c| {
            c.lock();
            c.refresh_recents();
            c.app().set_choosing_vault(true);
        });
        on!(on_auth_search_changed, |c, _text| c.tick_auth());
        on!(on_auth_copy, |c, index| c.auth_copy(index));
        on!(on_auth_open, |c, index| c.auth_open(index));
        on!(on_cancel_edit, |c| c.close_editor());
        on!(on_toggle_show_password, |c| c.toggle_show_password());
        on!(on_generate_for_item, |c| c.generate_for_item());

        on!(on_regenerate, |c| c.regenerate());
        on!(on_copy_generated, |c| c.copy_generated());
        on!(on_use_generated, |c| c.use_generated());

        on!(on_settings_changed, |c| c.save_settings());
        on!(on_appearance_changed, |c, dark| c.set_appearance(dark));
        on!(on_change_password, |c| c.change_password());
        on!(on_show_kit, |c| c.verify_then(KitAction::Show));
        on!(on_hide_kit, |c| {
            let app = c.app();
            app.set_kit_secret_key(SharedString::new());
            app.set_kit_recovery_key(SharedString::new());
        });
        on!(on_new_recovery_key, |c| c
            .verify_then(KitAction::NewRecoveryKey));
    }

    fn edit_secret(&self, field: i32, edit: impl FnOnce(&mut SecretBuffer)) {
        let Some(index) = usize::try_from(field).ok().filter(|&i| i < field::COUNT) else {
            return;
        };
        let length = {
            let mut state = self.state.borrow_mut();
            edit(&mut state.secrets[index]);
            state.secrets[index].char_count()
        };
        self.lengths
            .set_row_data(index, i32::try_from(length).unwrap_or(i32::MAX));
        // A shown password in the editor must follow the buffer.
        if index == field::ITEM_PASSWORD && !self.app().get_editor_password_shown().is_empty() {
            let text = SharedString::from(self.state.borrow().secrets[index].as_str());
            self.app().set_editor_password_shown(text);
        }
        self.set_error(error::NONE, "");
        self.touch_activity();
    }

    fn clear_secret(&self, index: usize) {
        self.state.borrow_mut().secrets[index].clear();
        self.lengths.set_row_data(index, 0);
    }

    fn clear_all_secrets(&self) {
        for index in 0..field::COUNT {
            self.clear_secret(index);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Screens, errors, notices
    // -----------------------------------------------------------------------------------------

    fn show_start_screen(&self) {
        let app = self.app();
        let path = self.state.borrow().path.clone();
        app.set_vault_path(SharedString::from(path.display().to_string()));
        self.refresh_recents();
        match storage::read(&path)
            .ok()
            .and_then(|bytes| Vault::inspect(&bytes).ok())
        {
            Some(info) => {
                let known = secret_store::load(&info.id_hex).ok().flatten().is_some();
                app.set_quick_unlock_on(
                    self.state.borrow().quick_available && quick_unlock::is_enrolled(&info.id_hex),
                );
                app.set_vault_id(SharedString::from(info.id_hex));
                app.set_needs_secret_key(!known);
                self.show_screen(Screen::Unlock);
            }
            None if path.exists() => {
                self.show_screen(Screen::Unlock);
                self.set_error(error::FILE, "not a vault file");
            }
            None => {
                app.set_vault_id(SharedString::new());
                app.set_quick_unlock_on(false);
                app.set_needs_secret_key(false);
                app.set_onboarding_step(1);
                self.show_screen(Screen::Onboarding);
            }
        }
    }

    fn show_screen(&self, screen: Screen) {
        self.set_error(error::NONE, "");
        self.app().set_screen(screen);
    }

    fn set_error(&self, code: i32, detail: &str) {
        let app = self.app();
        app.set_error_code(code);
        app.set_error_detail(SharedString::from(detail));
    }

    /// A notice that stays longer (something went wrong and needs reading).
    fn notify_long(&self, code: i32, arg: &str) {
        self.notify(code, arg);
        let weak = self.app.clone();
        self.timers
            .notice
            .start(TimerMode::SingleShot, NOTICE_DURATION * 3, move || {
                if let Some(app) = weak.upgrade() {
                    app.set_notice_code(0);
                }
            });
    }

    fn notify(&self, code: i32, arg: &str) {
        let app = self.app();
        app.set_notice_code(code);
        app.set_notice_arg(SharedString::from(arg));
        let weak = self.app.clone();
        self.timers
            .notice
            .start(TimerMode::SingleShot, NOTICE_DURATION, move || {
                if let Some(app) = weak.upgrade() {
                    app.set_notice_code(0);
                }
            });
    }

    fn core_error(&self, err: &CoreError) -> (i32, String) {
        match err {
            CoreError::DecryptionFailed => (error::WRONG_PASSWORD, String::new()),
            CoreError::KeyChecksumMismatch => (error::SECRET_KEY_TYPO, String::new()),
            CoreError::InvalidKeyFormat => (error::SECRET_KEY_FORMAT, String::new()),
            CoreError::InvalidTotp => (error::BAD_TOTP, String::new()),
            CoreError::Io(io) => (error::FILE, io.to_string()),
            other => (error::OTHER, other.to_string()),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Background jobs
    // -----------------------------------------------------------------------------------------

    fn run_job(&self, job: impl FnOnce() -> JobResult + Send + 'static) {
        self.app().set_busy(true);
        self.set_error(error::NONE, "");
        let runner = self.state.borrow().runner;
        match runner {
            Runner::Inline => self.finish_job(job()),
            Runner::Thread => {
                std::thread::spawn(move || {
                    let result = job();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                            controller.finish_job(result);
                        }
                    });
                });
            }
        }
    }

    fn finish_job(&self, result: JobResult) {
        let app = self.app();
        app.set_busy(false);
        app.set_quick_waiting(false);
        match result {
            JobResult::Created {
                session,
                recovery_key,
            } => {
                self.clear_secret(field::MASTER);
                self.clear_secret(field::CONFIRM);
                self.state.borrow_mut().suggestion = None;
                app.set_suggestion(SharedString::new());
                app.set_vault_id(SharedString::from(session.vault.id_hex()));
                app.set_kit_secret_key(SharedString::from(
                    session.secret_key.to_display_string().as_str(),
                ));
                app.set_kit_recovery_key(SharedString::from(
                    recovery_key.to_display_string().as_str(),
                ));
                app.set_recovered(false);
                app.set_kit_saved(false);
                app.set_onboarding_step(2);
                self.state.borrow_mut().pending = Some(session);
            }
            JobResult::Recovered { session } => {
                app.set_quick_unlock_on(false);
                self.clear_secret(field::MASTER);
                self.clear_secret(field::CONFIRM);
                self.clear_secret(field::RECOVERY_KEY);
                app.set_kit_secret_key(SharedString::from(
                    session.secret_key.to_display_string().as_str(),
                ));
                app.set_kit_recovery_key(SharedString::new());
                app.set_recovered(true);
                app.set_kit_saved(false);
                app.set_onboarding_step(2);
                self.state.borrow_mut().pending = Some(session);
                self.show_screen(Screen::Onboarding);
            }
            JobResult::Unlocked {
                session,
                typed_secret_key,
            } => {
                let id = session.vault.id_hex();
                let revision = session.vault.revision();
                let mut device_state = DeviceState::load().unwrap_or_default();
                if let RollbackStatus::Older {
                    revision,
                    highest_seen,
                } = device_state.check_rollback(&id, revision)
                {
                    self.set_error(error::ROLLBACK, &format!("{revision} < {highest_seen}"));
                    return;
                }
                device_state.record_revision(&id, revision);
                let _ = device_state.save();
                if typed_secret_key {
                    if let Err(err) = secret_store::store(&id, &session.secret_key) {
                        self.set_error(error::OTHER, &err.to_string());
                    }
                    app.set_needs_secret_key(false);
                }
                self.clear_secret(field::MASTER);
                self.clear_secret(field::SECRET_KEY);
                self.enter_vault(session);
            }
            JobResult::PasswordChanged { session } => {
                for index in [field::CURRENT, field::NEW, field::NEW_AGAIN] {
                    self.clear_secret(index);
                }
                // The device unlock is bound to the old password slot and no longer opens the
                // vault; remove it so the switch shows the truth.
                let id = session.vault.id_hex();
                let had_quick_unlock = quick_unlock::is_enrolled(&id);
                self.state.borrow_mut().session = Some(session);
                self.remember_file();
                if had_quick_unlock {
                    self.turn_off_quick_unlock(&id);
                    self.notify(notice::PASSWORD_CHANGED_HELLO_OFF, "");
                } else {
                    self.notify(notice::PASSWORD_CHANGED, "");
                }
            }
            JobResult::ImportParsed { report } => self.import_parsed(report),
            JobResult::ExportVerified { session } => self.export_verified(session),
            JobResult::QuickUnlockEnabled { session } => {
                self.state.borrow_mut().session = Some(session);
                app.set_quick_unlock_on(true);
                self.notify(notice::HELLO_ON, "");
            }
            JobResult::QuickUnlockNotEnabled { session, reason } => {
                self.state.borrow_mut().session = Some(session);
                app.set_quick_unlock_on(false);
                if let Some(reason) = reason {
                    self.notify(notice::HELLO_NOT_ON, &reason);
                }
            }
            JobResult::KitVerified { session } => {
                self.clear_secret(field::CURRENT);
                app.set_kit_secret_key(SharedString::from(
                    session.secret_key.to_display_string().as_str(),
                ));
                app.set_kit_recovery_key(SharedString::new());
                self.state.borrow_mut().session = Some(session);
            }
            JobResult::RecoveryIssued {
                session,
                recovery_key,
            } => {
                self.clear_secret(field::CURRENT);
                app.set_kit_secret_key(SharedString::from(
                    session.secret_key.to_display_string().as_str(),
                ));
                app.set_kit_recovery_key(SharedString::from(
                    recovery_key.to_display_string().as_str(),
                ));
                self.state.borrow_mut().session = Some(session);
                self.remember_file();
                self.notify(notice::RECOVERY_ISSUED, "");
            }
            JobResult::Failed {
                code,
                detail,
                session,
            } => {
                if session.is_some() {
                    self.state.borrow_mut().session = session;
                }
                if code == error::HELLO_REVOKED || code == error::HELLO_KEY_GONE {
                    app.set_quick_unlock_on(false);
                }
                self.set_error(code, &detail);
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Onboarding, unlock, recovery
    // -----------------------------------------------------------------------------------------

    /// Checks the two new-password fields; returns the password on success.
    fn new_password_from(&self, first: usize, second: usize) -> Option<Zeroizing<String>> {
        let state = self.state.borrow();
        let (a, b) = (&state.secrets[first], &state.secrets[second]);
        if a.char_count() < MIN_MASTER_PASSWORD_CHARS {
            drop(state);
            self.set_error(error::TOO_SHORT, "");
            return None;
        }
        if !a.matches(b) {
            drop(state);
            self.set_error(error::MISMATCH, "");
            return None;
        }
        Some(Zeroizing::new(a.as_str().to_owned()))
    }

    fn create_vault(&self) {
        let Some(password) = self.new_password_from(field::MASTER, field::CONFIRM) else {
            return;
        };
        let path = self.state.borrow().path.clone();
        let fast = self.state.borrow().runner == Runner::Inline;
        self.run_job(move || {
            let result = (|| -> Result<JobResult, (i32, String)> {
                let kdf = if fast {
                    KdfParams::minimum()
                } else {
                    KdfParams::calibrate(
                        KDF_MEMORY_KIB,
                        KdfParams::default_parallelism(),
                        KDF_TARGET,
                    )
                }
                .map_err(|e| (error::OTHER, e.to_string()))?;
                let secret_key =
                    SecretKey::generate().map_err(|e| (error::OTHER, e.to_string()))?;
                let recovery_key =
                    RecoveryKey::generate().map_err(|e| (error::OTHER, e.to_string()))?;
                let mut vault = Vault::create(&password, &secret_key, Some(&recovery_key), kdf)
                    .map_err(|e| (error::OTHER, e.to_string()))?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| (error::FILE, e.to_string()))?;
                }
                let bytes = vault
                    .to_bytes()
                    .map_err(|e| (error::OTHER, e.to_string()))?;
                storage::write_atomic(&path, &bytes).map_err(|e| (error::FILE, e.to_string()))?;
                secret_store::store(&vault.id_hex(), &secret_key)
                    .map_err(|e| (error::OTHER, e.to_string()))?;
                device::record_revision(&vault.id_hex(), vault.revision())
                    .map_err(|e| (error::FILE, e.to_string()))?;
                let _ = quick_unlock::record_password_unlock(&vault);
                Ok(JobResult::Created {
                    session: Session { vault, secret_key },
                    recovery_key,
                })
            })();
            result.unwrap_or_else(|(code, detail)| JobResult::Failed {
                code,
                detail,
                session: None,
            })
        });
    }

    fn suggest_passphrase(&self) {
        let options = PassphraseOptions {
            words: 6,
            separator: "-".into(),
            ..PassphraseOptions::default()
        };
        if let Ok(phrase) = generator::generate_passphrase(&options) {
            self.app()
                .set_suggestion(SharedString::from(phrase.as_str()));
            self.state.borrow_mut().suggestion = Some(phrase);
        }
    }

    fn use_suggestion(&self) {
        let Some(phrase) = self.state.borrow().suggestion.clone() else {
            return;
        };
        for index in [field::MASTER, field::CONFIRM] {
            self.edit_secret(index as i32, |buffer| {
                buffer.set(&phrase);
            });
        }
    }

    fn finish_onboarding(&self) {
        let Some(session) = self.state.borrow_mut().pending.take() else {
            return;
        };
        let app = self.app();
        app.set_kit_secret_key(SharedString::new());
        app.set_kit_recovery_key(SharedString::new());
        app.set_kit_saved(false);
        app.set_needs_secret_key(false);
        self.enter_vault(session);
    }

    fn unlock(&self) {
        let path = self.state.borrow().path.clone();
        let bytes = match storage::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
                return;
            }
        };
        let info = match Vault::inspect(&bytes) {
            Ok(info) => info,
            Err(err) => {
                self.set_error(error::FILE, &err.to_string());
                return;
            }
        };
        let (secret_key, typed) = match secret_store::load(&info.id_hex) {
            Ok(Some(key)) => (key, false),
            Ok(None) => {
                let parsed =
                    SecretKey::parse(self.state.borrow().secrets[field::SECRET_KEY].as_str());
                match parsed {
                    Ok(key) => (key, true),
                    Err(err) => {
                        self.app().set_needs_secret_key(true);
                        let (code, detail) = self.core_error(&err);
                        self.set_error(code, &detail);
                        return;
                    }
                }
            }
            Err(err) => {
                self.set_error(error::OTHER, &err.to_string());
                return;
            }
        };
        let password = Zeroizing::new(
            self.state.borrow().secrets[field::MASTER]
                .as_str()
                .to_owned(),
        );
        if password.is_empty() {
            return;
        }
        self.run_job(move || {
            match Vault::open(
                &bytes,
                Unlock::Password {
                    password: &password,
                    secret_key: &secret_key,
                },
            ) {
                Ok(vault) => {
                    let _ = quick_unlock::record_password_unlock(&vault);
                    JobResult::Unlocked {
                        session: Session { vault, secret_key },
                        typed_secret_key: typed,
                    }
                }
                Err(CoreError::DecryptionFailed) => JobResult::Failed {
                    code: error::WRONG_PASSWORD,
                    detail: String::new(),
                    session: None,
                },
                Err(other) => JobResult::Failed {
                    code: error::OTHER,
                    detail: other.to_string(),
                    session: None,
                },
            }
        });
    }

    fn recover(&self) {
        let recovery_key =
            match RecoveryKey::parse(self.state.borrow().secrets[field::RECOVERY_KEY].as_str()) {
                Ok(key) => key,
                Err(_) => {
                    self.set_error(error::RECOVERY_KEY, "");
                    return;
                }
            };
        let Some(password) = self.new_password_from(field::MASTER, field::CONFIRM) else {
            return;
        };
        let path = self.state.borrow().path.clone();
        self.run_job(move || {
            let result = (|| -> Result<JobResult, (i32, String)> {
                let bytes = storage::read(&path).map_err(|e| (error::FILE, e.to_string()))?;
                let mut vault =
                    Vault::open(&bytes, Unlock::Recovery(&recovery_key)).map_err(|e| match e {
                        CoreError::DecryptionFailed | CoreError::NoMatchingSlot => {
                            (error::RECOVERY_KEY, String::new())
                        }
                        other => (error::OTHER, other.to_string()),
                    })?;
                // The old Secret Key may be lost or exposed: always issue a new one.
                let secret_key =
                    SecretKey::generate().map_err(|e| (error::OTHER, e.to_string()))?;
                let kdf = vault.kdf_params().clone();
                vault
                    .change_password(&password, &secret_key, &kdf)
                    .map_err(|e| (error::OTHER, e.to_string()))?;
                let bytes = vault
                    .to_bytes()
                    .map_err(|e| (error::OTHER, e.to_string()))?;
                storage::write_atomic(&path, &bytes).map_err(|e| (error::FILE, e.to_string()))?;
                secret_store::store(&vault.id_hex(), &secret_key)
                    .map_err(|e| (error::OTHER, e.to_string()))?;
                device::record_revision(&vault.id_hex(), vault.revision())
                    .map_err(|e| (error::FILE, e.to_string()))?;
                // The new password revoked any device unlock; drop its file too.
                quick_unlock::forget(&vault.id_hex());
                let _ = quick_unlock::record_password_unlock(&vault);
                Ok(JobResult::Recovered {
                    session: Session { vault, secret_key },
                })
            })();
            result.unwrap_or_else(|(code, detail)| JobResult::Failed {
                code,
                detail,
                session: None,
            })
        });
    }

    // -----------------------------------------------------------------------------------------
    // Quick unlock (Windows Hello); see vault_platform::quick_unlock for the design
    // -----------------------------------------------------------------------------------------

    fn set_quick_available(&self, available: bool) {
        self.state.borrow_mut().quick_available = available;
        let app = self.app();
        app.set_quick_unlock_available(available);
        app.set_quick_unlock_on(available && quick_unlock::is_enrolled(&app.get_vault_id()));
    }

    fn quick_unlock(&self) {
        let Some(verifier) = self.state.borrow().verifier.clone() else {
            return;
        };
        let app = self.app();
        let path = self.state.borrow().path.clone();
        let bytes = match storage::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
                return;
            }
        };
        let id = match Vault::inspect(&bytes) {
            Ok(info) => info.id_hex,
            Err(err) => {
                self.set_error(error::FILE, &err.to_string());
                return;
            }
        };
        let Ok(Some(secret_key)) = secret_store::load(&id) else {
            app.set_needs_secret_key(true);
            return;
        };
        let Some(sealed) = quick_unlock::load(&id) else {
            app.set_quick_unlock_on(false);
            return;
        };
        app.set_quick_waiting(true);
        self.run_job(move || {
            let failed = |code: i32, detail: String| JobResult::Failed {
                code,
                detail,
                session: None,
            };
            let secret = match verifier.secret(&id) {
                Ok(secret) => secret,
                Err(QuickUnlockError::Cancelled) => return failed(error::NONE, String::new()),
                Err(QuickUnlockError::Unavailable) => {
                    return failed(error::HELLO_UNAVAILABLE, String::new());
                }
                Err(QuickUnlockError::NotEnrolled) => {
                    quick_unlock::forget(&id);
                    return failed(error::HELLO_KEY_GONE, String::new());
                }
                Err(QuickUnlockError::Failed(detail)) => {
                    return failed(error::HELLO_FAILED, detail);
                }
            };
            match Vault::open_with_device(&bytes, &secret, &sealed) {
                Ok(vault) if quick_unlock::password_is_recent(&vault) => JobResult::Unlocked {
                    session: Session { vault, secret_key },
                    typed_secret_key: false,
                },
                Ok(_) => failed(
                    error::PASSWORD_DUE,
                    quick_unlock::PASSWORD_INTERVAL_DAYS.to_string(),
                ),
                Err(CoreError::DecryptionFailed) => {
                    // The master password changed (maybe on another device): this device
                    // unlock is dead for good.
                    quick_unlock::forget(&id);
                    verifier.remove(&id);
                    failed(error::HELLO_REVOKED, String::new())
                }
                Err(other) => failed(error::HELLO_FAILED, other.to_string()),
            }
        });
    }

    fn set_quick_unlock(&self, on: bool) {
        let Some(verifier) = self.state.borrow().verifier.clone() else {
            return;
        };
        let Some(id) = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| s.vault.id_hex())
        else {
            return;
        };
        if !on {
            self.turn_off_quick_unlock(&id);
            self.notify(notice::HELLO_OFF, "");
            return;
        }
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        self.run_job(move || {
            let outcome = verifier.enroll(&id).and_then(|secret| {
                quick_unlock::enroll(&session.vault, &secret)
                    .map_err(|e| QuickUnlockError::Failed(e.to_string()))
            });
            match outcome {
                Ok(()) => JobResult::QuickUnlockEnabled { session },
                Err(QuickUnlockError::Cancelled) => JobResult::QuickUnlockNotEnabled {
                    session,
                    reason: None,
                },
                Err(err) => JobResult::QuickUnlockNotEnabled {
                    session,
                    reason: Some(err.to_string()),
                },
            }
        });
    }

    /// Deletes the wrapped key file now and the OS key in the background.
    fn turn_off_quick_unlock(&self, id: &str) {
        quick_unlock::forget(id);
        self.app().set_quick_unlock_on(false);
        let (verifier, runner) = {
            let state = self.state.borrow();
            (state.verifier.clone(), state.runner)
        };
        if let Some(verifier) = verifier {
            let id = id.to_owned();
            match runner {
                Runner::Inline => verifier.remove(&id),
                Runner::Thread => {
                    std::thread::spawn(move || verifier.remove(&id));
                }
            }
        }
    }

    fn enter_vault(&self, session: Session) {
        let app = self.app();
        let id = session.vault.id_hex();
        app.set_quick_unlock_on(
            self.state.borrow().quick_available && quick_unlock::is_enrolled(&id),
        );
        app.set_vault_id(SharedString::from(id));
        {
            let mut state = self.state.borrow_mut();
            state.session = Some(session);
            state.summaries_stale = true;
            state.file_hash = None;
            state.selected = None;
            state.editing = None;
        }
        app.set_search_text(SharedString::new());
        app.set_category(0);
        app.set_panel(Panel::Detail);
        self.remember_file();
        if let Ok(mut device_state) = DeviceState::load() {
            device_state.remember_vault(&self.state.borrow().path);
            let _ = device_state.save();
        }
        self.load_icon_cache();
        self.refresh_list();
        self.show_detail();
        self.show_screen(Screen::Vault);
        self.restart_auto_lock();
        self.start_icon_fetch();
    }

    fn lock(&self) {
        for timer in [
            &self.timers.reveal,
            &self.timers.auto_lock,
            &self.timers.totp,
            &self.timers.auth,
        ] {
            timer.stop();
        }
        {
            let mut state = self.state.borrow_mut();
            state.session = None;
            state.pending = None;
            state.summaries.clear();
            state.summaries_stale = true;
            state.visible.clear();
            state.selected = None;
            state.editing = None;
            state.generated = None;
            state.totp = None;
            state.auth.clear();
            state.file_hash = None;
            state.icons = IconCache::default();
            state.icon_images.clear();
        }
        self.clear_all_secrets();
        files::wipe_print_dir();
        self.state.borrow_mut().pending_import = None;
        self.app().set_import_stage(0);
        self.items.set_vec(Vec::new());
        let app = self.app();
        app.set_selected(-1);
        app.set_has_selection(false);
        app.set_revealed_password(SharedString::new());
        app.set_detail_notes(SharedString::new());
        app.set_detail_fields(ModelRc::default());
        app.set_detail_urls(ModelRc::default());
        app.set_totp_code(SharedString::new());
        app.set_gen_result(SharedString::new());
        app.set_editor_password_shown(SharedString::new());
        app.set_kit_secret_key(SharedString::new());
        app.set_kit_recovery_key(SharedString::new());
        app.set_ed_title(SharedString::new());
        app.set_ed_username(SharedString::new());
        app.set_ed_url(SharedString::new());
        app.set_ed_totp(SharedString::new());
        app.set_ed_notes(SharedString::new());
        app.set_ed_recovery_codes(SharedString::new());
        app.set_ed_card_number(SharedString::new());
        app.set_ed_card_expiry(SharedString::new());
        app.set_ed_card_code(SharedString::new());
        app.set_detail_codes(ModelRc::default());
        app.set_auth_rows(ModelRc::default());
        app.set_auth_search(SharedString::new());
        app.set_folders(ModelRc::default());
        app.set_folder_name(SharedString::new());
        app.set_search_text(SharedString::new());
        app.set_panel(Panel::Detail);
        self.show_screen(Screen::Unlock);
    }

    fn touch_activity(&self) {
        if self.state.borrow().session.is_some() {
            self.restart_auto_lock();
        }
    }

    fn restart_auto_lock(&self) {
        let minutes = u64::from(self.state.borrow().settings.auto_lock_minutes.max(1));
        let weak = self.weak();
        self.timers.auto_lock.start(
            TimerMode::SingleShot,
            Duration::from_secs(minutes * 60),
            move || {
                if let Some(controller) = weak.upgrade() {
                    controller.lock();
                }
            },
        );
    }

    // -----------------------------------------------------------------------------------------
    // List and detail
    // -----------------------------------------------------------------------------------------

    fn refresh_list(&self) {
        let app = self.app();
        let category = app.get_category();
        let query = app.get_search_text().to_string();
        // Decrypting every item is the expensive part; it only happens after a change, not on
        // every keystroke in the search box.
        if self.state.borrow().summaries_stale {
            let fresh = self
                .state
                .borrow()
                .session
                .as_ref()
                .map(|s| s.vault.summaries());
            match fresh {
                Some(Ok(fresh)) => {
                    let mut state = self.state.borrow_mut();
                    state.summaries = fresh;
                    state.summaries_stale = false;
                }
                Some(Err(err)) => {
                    let (code, detail) = self.core_error(&err);
                    self.set_error(code, &detail);
                    return;
                }
                None => return,
            }
        }
        let summaries = std::mem::take(&mut self.state.borrow_mut().summaries);

        // Folders: the index shows each with its count; category 100 + n browses folder n.
        let folders: Vec<(FolderId, String)> = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| {
                s.vault
                    .folders()
                    .iter()
                    .map(|f| (f.id, f.name.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let mut category = category;
        let mut browsing = None;
        if category >= FOLDER_CATEGORY {
            match usize::try_from(category - FOLDER_CATEGORY)
                .ok()
                .and_then(|i| folders.get(i))
            {
                Some((id, name)) => browsing = Some((*id, name.clone())),
                None => {
                    category = 0;
                    app.set_category(0);
                }
            }
        }
        let folder_rows: Vec<FolderRow> = folders
            .iter()
            .map(|(id, name)| FolderRow {
                name: SharedString::from(name.as_str()),
                count: i32::try_from(summaries.iter().filter(|s| s.folder == Some(*id)).count())
                    .unwrap_or(0),
            })
            .collect();
        app.set_folders(ModelRc::from(Rc::new(VecModel::from(folder_rows))));
        app.set_folder_name(SharedString::from(
            browsing
                .as_ref()
                .map(|(_, name)| name.as_str())
                .unwrap_or_default(),
        ));

        let (visible, counts) =
            view::filter(&summaries, category, browsing.map(|(id, _)| id), &query);
        let rows: Vec<ItemRow> = visible
            .iter()
            .map(|&i| {
                let s = &summaries[i];
                let visual = self.icon_for(s.kind, &s.url, &s.title);
                ItemRow {
                    title: SharedString::from(s.title.as_str()),
                    subtitle: SharedString::from(view::subtitle(s)),
                    kind: view::kind_to_int(s.kind),
                    favorite: s.favorite,
                    icon: visual.image,
                    has_icon: visual.has_image,
                    initial: visual.initial,
                    tint: visual.tint,
                }
            })
            .collect();
        let ids: Vec<ItemId> = visible.iter().map(|&i| summaries[i].id).collect();
        let selected_index = {
            let mut state = self.state.borrow_mut();
            state.visible = ids;
            state.summaries = summaries;
            state
                .selected
                .and_then(|id| state.visible.iter().position(|v| *v == id))
                .map_or(-1, |i| i as i32)
        };
        self.items.set_vec(rows);
        app.set_counts(ModelRc::from(Rc::new(VecModel::from(counts.to_vec()))));
        app.set_total_items(self.state.borrow().summaries.len() as i32);
        app.set_totp_count(
            i32::try_from(
                self.state
                    .borrow()
                    .summaries
                    .iter()
                    .filter(|s| s.has_totp)
                    .count(),
            )
            .unwrap_or(0),
        );
        app.set_selected(selected_index);
    }

    fn select_category(&self, category: i32) {
        let app = self.app();
        app.set_category(category);
        if matches!(
            app.get_panel(),
            Panel::Generator | Panel::Settings | Panel::Kit
        ) {
            app.set_panel(Panel::Detail);
        }
        self.refresh_list();
    }

    fn select(&self, index: i32) {
        let id = usize::try_from(index)
            .ok()
            .and_then(|i| self.state.borrow().visible.get(i).copied());
        let Some(id) = id else { return };
        {
            let mut state = self.state.borrow_mut();
            state.selected = Some(id);
            state.editing = None;
        }
        let app = self.app();
        app.set_selected(index);
        app.set_editing_item(false);
        app.set_panel(Panel::Detail);
        self.show_detail();
    }

    fn selected_item(&self) -> Option<(ItemId, ItemData)> {
        let state = self.state.borrow();
        let id = state.selected?;
        let item = state.session.as_ref()?.vault.get_item(&id).ok()?;
        Some((id, item))
    }

    fn show_detail(&self) {
        let app = self.app();
        self.conceal();
        self.timers.totp.stop();
        app.set_notes_shown(false);
        app.set_confirming_delete(false);
        let Some((id, item)) = self.selected_item() else {
            app.set_has_selection(false);
            self.state.borrow_mut().totp = None;
            self.state.borrow_mut().codes_shown = None;
            app.set_detail_codes(ModelRc::default());
            return;
        };
        app.set_has_selection(true);
        app.set_detail_title(SharedString::from(item.title.as_str()));
        app.set_detail_kind(view::kind_to_int(item.kind));
        self.apply_detail_icon(&item);
        app.set_detail_favorite(item.favorite);
        app.set_detail_username(SharedString::from(item.username.as_str()));
        app.set_detail_has_password(!item.password.is_empty());
        app.set_detail_notes(SharedString::from(item.notes.as_str()));
        let urls: Vec<SharedString> = item
            .urls
            .iter()
            .map(|u| SharedString::from(u.as_str()))
            .collect();
        app.set_detail_urls(ModelRc::from(Rc::new(VecModel::from(urls))));
        let fields: Vec<DetailField> = view::detail_fields(&item, view::now_month_year())
            .into_iter()
            .map(|f| DetailField {
                label: SharedString::from(f.label),
                value: SharedString::from(f.value),
                sensitive: f.sensitive,
                index: i32::try_from(f.index).unwrap_or(-1),
                warning: f.warning,
            })
            .collect();
        app.set_detail_fields(ModelRc::from(Rc::new(VecModel::from(fields))));
        app.set_detail_folder(SharedString::from(
            item.folder
                .and_then(|folder| self.folder_name(&folder))
                .unwrap_or_default(),
        ));
        app.set_detail_codes_total(i32::try_from(item.recovery_codes.len()).unwrap_or(0));
        app.set_detail_codes_left(i32::try_from(item.recovery_codes_left()).unwrap_or(0));
        if self.state.borrow().codes_shown == Some(id) {
            self.fill_codes(&item);
        } else {
            self.state.borrow_mut().codes_shown = None;
            app.set_detail_codes(ModelRc::default());
        }

        let totp = (!item.totp.is_empty())
            .then(|| Totp::parse(&item.totp).ok())
            .flatten();
        self.state.borrow_mut().totp = totp;
        self.tick_totp();
        if self.state.borrow().totp.is_some() {
            let weak = self.weak();
            self.timers
                .totp
                .start(TimerMode::Repeated, Duration::from_secs(1), move || {
                    if let Some(controller) = weak.upgrade() {
                        controller.tick_totp();
                    }
                });
        }
    }

    fn tick_totp(&self) {
        let app = self.app();
        match self.state.borrow().totp.as_ref().map(Totp::now) {
            Some((code, left)) => {
                app.set_totp_code(SharedString::from(view::group_code(&code)));
                app.set_totp_left(i32::try_from(left).unwrap_or(0));
            }
            None => app.set_totp_code(SharedString::new()),
        }
    }

    fn reveal(&self) {
        let Some((_, item)) = self.selected_item() else {
            return;
        };
        let app = self.app();
        app.set_revealed_password(SharedString::from(item.password.as_str()));
        app.set_reveal_left(REVEAL_SECONDS);
        let weak = self.weak();
        self.timers
            .reveal
            .start(TimerMode::Repeated, Duration::from_secs(1), move || {
                if let Some(controller) = weak.upgrade() {
                    let app = controller.app();
                    let left = app.get_reveal_left() - 1;
                    if left <= 0 {
                        controller.conceal();
                    } else {
                        app.set_reveal_left(left);
                    }
                }
            });
    }

    fn conceal(&self) {
        self.timers.reveal.stop();
        let app = self.app();
        app.set_revealed_password(SharedString::new());
        app.set_reveal_left(0);
    }

    fn copy_from_selected(&self, what: CopyWhat) {
        let Some((_, item)) = self.selected_item() else {
            return;
        };
        let (value, secret, code) = match what {
            CopyWhat::Username => (
                Zeroizing::new(item.username.clone()),
                false,
                notice::USERNAME_COPIED,
            ),
            CopyWhat::Password => (
                Zeroizing::new(item.password.clone()),
                true,
                notice::PASSWORD_COPIED,
            ),
            CopyWhat::Totp => match self.state.borrow().totp.as_ref() {
                Some(totp) => (totp.now().0, true, notice::CODE_COPIED),
                None => return,
            },
            CopyWhat::Field(index) => {
                let Some(field) = usize::try_from(index)
                    .ok()
                    .and_then(|i| item.custom_fields.get(i))
                else {
                    return;
                };
                (
                    Zeroizing::new(field.value.clone()),
                    field.sensitive,
                    notice::FIELD_COPIED,
                )
            }
            CopyWhat::RecoveryCode(index) => {
                let Some(code) = usize::try_from(index)
                    .ok()
                    .and_then(|i| item.recovery_codes.get(i))
                else {
                    return;
                };
                (
                    Zeroizing::new(code.code.clone()),
                    true,
                    notice::RECOVERY_CODE_COPIED,
                )
            }
        };
        self.copy(value, secret, code);
    }

    fn copy(&self, value: Zeroizing<String>, secret: bool, code: i32) {
        let result = if secret {
            clipboard::copy_secret(&value)
        } else {
            clipboard::copy_plain(&value)
        };
        if result.is_err() {
            self.set_error(error::CLIPBOARD, "");
            return;
        }
        let seconds = self.state.borrow().settings.clipboard_clear_seconds.max(5);
        self.notify(code, &seconds.to_string());
        if !secret {
            return;
        }
        self.state.borrow_mut().copied = Some(value);
        let weak = self.weak();
        self.timers.clipboard.start(
            TimerMode::SingleShot,
            Duration::from_secs(u64::from(seconds)),
            move || {
                if let Some(controller) = weak.upgrade() {
                    let copied = controller.state.borrow_mut().copied.take();
                    if copied.is_some_and(|value| clipboard::clear_if(&value)) {
                        controller.notify(notice::CLIPBOARD_CLEARED, "");
                    }
                }
            },
        );
    }

    fn save_vault(&self) -> bool {
        if self.changed_outside() {
            self.set_error(error::CHANGED_OUTSIDE, "");
            self.notify_long(notice::NOT_SAVED, "");
            return false;
        }
        let result = {
            let mut state = self.state.borrow_mut();
            state.summaries_stale = true;
            let path = state.path.clone();
            match state.session.as_mut() {
                Some(session) => session.vault.to_bytes().and_then(|bytes| {
                    storage::write_atomic(&path, &bytes)?;
                    Ok((
                        session.vault.id_hex(),
                        session.vault.revision(),
                        file_hash(&bytes),
                    ))
                }),
                None => return false,
            }
        };
        match result {
            Ok((id, revision, hash)) => {
                self.state.borrow_mut().file_hash = Some(hash);
                let _ = device::record_revision(&id, revision);
                if self.app().get_error_code() == error::CHANGED_OUTSIDE {
                    self.set_error(error::NONE, "");
                }
                true
            }
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
                self.notify_long(notice::NOT_SAVED, &detail);
                false
            }
        }
    }

    /// Remembers the vault file as it is on disk now (after opening it, or after a background
    /// job wrote it).
    fn remember_file(&self) {
        let path = self.state.borrow().path.clone();
        let hash = std::fs::read(&path).ok().map(|bytes| file_hash(&bytes));
        self.state.borrow_mut().file_hash = hash;
    }

    /// Whether the file on disk differs from the one this window last read or wrote.
    fn changed_outside(&self) -> bool {
        let (path, expected) = {
            let state = self.state.borrow();
            (state.path.clone(), state.file_hash)
        };
        match (expected, std::fs::read(&path)) {
            (Some(expected), Ok(bytes)) => file_hash(&bytes) != expected,
            // Deleted or unreadable: writing it again is the safe move.
            _ => false,
        }
    }

    fn toggle_favorite(&self) {
        let Some((id, mut item)) = self.selected_item() else {
            return;
        };
        item.favorite = !item.favorite;
        item.touch();
        let updated = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| s.vault.update_item(&id, &item));
        if matches!(updated, Some(Ok(()))) && self.save_vault() {
            self.refresh_list();
            self.show_detail();
        }
    }

    fn delete_selected(&self) {
        let Some((id, item)) = self.selected_item() else {
            return;
        };
        let removed = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| s.vault.remove_item(&id));
        if matches!(removed, Some(Ok(()))) && self.save_vault() {
            self.state.borrow_mut().selected = None;
            self.refresh_list();
            self.show_detail();
            self.notify(notice::DELETED, &item.title);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Extra fields in the editor
    // -----------------------------------------------------------------------------------------

    /// Changes one extra field as the user types. The rows are not rebuilt (that would drop the
    /// caret); `show_edit_fields` rebuilds them when a row is added, removed or toggled.
    fn edit_field(&self, index: i32, change: impl FnOnce(&mut CustomField)) {
        let mut state = self.state.borrow_mut();
        if let Some(field) = usize::try_from(index)
            .ok()
            .and_then(|i| state.edit_fields.get_mut(i))
        {
            change(field);
        }
    }

    fn show_edit_fields(&self) {
        let rows: Vec<EditField> = self
            .state
            .borrow()
            .edit_fields
            .iter()
            .map(|f| EditField {
                name: SharedString::from(f.name.as_str()),
                value: SharedString::from(f.value.as_str()),
                hidden: f.sensitive,
            })
            .collect();
        self.app()
            .set_ed_fields(ModelRc::from(Rc::new(VecModel::from(rows))));
    }

    // -----------------------------------------------------------------------------------------
    // Several vaults
    // -----------------------------------------------------------------------------------------

    /// Fills the chooser with the vaults this computer has opened (the current one included).
    fn refresh_recents(&self) {
        let current = self.state.borrow().path.clone();
        let mut paths = DeviceState::load()
            .map(|s| s.recent_vaults())
            .unwrap_or_default();
        if !paths.iter().any(|p| same_path(p, &current)) {
            paths.insert(0, current.clone());
        }
        let rows: Vec<RecentVault> = paths
            .iter()
            .map(|path| RecentVault {
                name: SharedString::from(
                    path.file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                ),
                location: SharedString::from(
                    path.parent()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                ),
                current: same_path(path, &current),
                missing: !path.exists() && !same_path(path, &current),
            })
            .collect();
        self.state.borrow_mut().recent_paths = paths;
        self.app()
            .set_recent_vaults(ModelRc::from(Rc::new(VecModel::from(rows))));
    }

    /// Locks whatever is open and shows `path`: its lock screen, or onboarding when there is no
    /// vault there yet. (The chooser's buttons call this; tests call it directly.)
    pub fn switch_vault(&self, path: PathBuf) {
        if self.state.borrow().session.is_some() {
            self.lock();
        }
        self.clear_all_secrets();
        {
            let mut state = self.state.borrow_mut();
            state.path = path;
            state.pending = None;
            state.suggestion = None;
        }
        let app = self.app();
        app.set_choosing_vault(false);
        app.set_suggestion(SharedString::new());
        app.set_kit_secret_key(SharedString::new());
        app.set_kit_recovery_key(SharedString::new());
        app.set_recovered(false);
        self.show_start_screen();
    }

    fn pick_vault(&self, index: i32) {
        let path = usize::try_from(index)
            .ok()
            .and_then(|i| self.state.borrow().recent_paths.get(i).cloned());
        let Some(path) = path else { return };
        if same_path(&path, &self.state.borrow().path) {
            self.app().set_choosing_vault(false);
        } else {
            self.switch_vault(path);
        }
    }

    fn forget_vault(&self, index: i32) {
        let path = usize::try_from(index)
            .ok()
            .and_then(|i| self.state.borrow().recent_paths.get(i).cloned());
        let Some(path) = path else { return };
        if let Ok(mut device_state) = DeviceState::load() {
            device_state.forget_vault(&path);
            let _ = device_state.save();
        }
        self.refresh_recents();
    }

    fn open_vault_file(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open a vault")
            .add_filter("Vault", &["vault"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            self.switch_vault(path);
        }
    }

    fn new_vault_file(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        let Some(mut path) = rfd::FileDialog::new()
            .set_title("Where to keep the new vault")
            .set_file_name("My vault.vault")
            .add_filter("Vault", &["vault"])
            .save_file()
        else {
            return;
        };
        if path.extension().is_none() {
            path.set_extension("vault");
        }
        if path.exists() && Vault::inspect(&storage::read(&path).unwrap_or_default()).is_err() {
            // Never write a vault over some other file.
            self.set_error(error::FILE, &format!("{} already exists", path.display()));
            return;
        }
        self.switch_vault(path);
    }

    // -----------------------------------------------------------------------------------------
    // Authenticator page
    // -----------------------------------------------------------------------------------------

    fn open_authenticator(&self) {
        let ids: Vec<ItemId> = self
            .state
            .borrow()
            .summaries
            .iter()
            .filter(|s| s.has_totp)
            .map(|s| s.id)
            .collect();
        let mut entries = Vec::with_capacity(ids.len());
        for id in ids {
            let item = {
                let state = self.state.borrow();
                let Some(session) = state.session.as_ref() else {
                    return;
                };
                match session.vault.get_item(&id) {
                    Ok(item) => item,
                    Err(_) => continue,
                }
            };
            // A broken secret is reported on the item page; here it is simply left out.
            let Ok(totp) = Totp::parse(&item.totp) else {
                continue;
            };
            let url = item.urls.first().map(String::as_str).unwrap_or_default();
            let visual = self.icon_for(item.kind, url, &item.title);
            let host = url.split_once("://").map_or(url, |(_, rest)| rest);
            let subtitle = if item.username.is_empty() {
                host.split('/').next().unwrap_or_default().to_owned()
            } else {
                item.username.clone()
            };
            entries.push(AuthEntry {
                id,
                title: item.title.clone(),
                subtitle,
                totp,
                visual,
            });
        }
        entries.sort_by_key(|e| e.title.to_lowercase());
        self.state.borrow_mut().auth = entries;
        let app = self.app();
        app.set_auth_search(SharedString::new());
        app.set_panel(Panel::Authenticator);
        self.set_error(error::NONE, "");
        self.tick_auth();
        let weak = self.weak();
        self.timers
            .auth
            .start(TimerMode::Repeated, Duration::from_secs(1), move || {
                if let Some(controller) = weak.upgrade() {
                    controller.tick_auth();
                }
            });
    }

    /// Entries matching the page's search box, in display order.
    fn visible_auth(&self) -> Vec<usize> {
        let query = self.app().get_auth_search().trim().to_lowercase();
        let state = self.state.borrow();
        (0..state.auth.len())
            .filter(|&i| {
                let e = &state.auth[i];
                query.is_empty()
                    || e.title.to_lowercase().contains(&query)
                    || e.subtitle.to_lowercase().contains(&query)
            })
            .collect()
    }

    /// Recomputes every visible code (once a second while the page is open).
    fn tick_auth(&self) {
        let app = self.app();
        if app.get_panel() != Panel::Authenticator {
            // Left the page: stop and forget the secrets.
            self.timers.auth.stop();
            self.state.borrow_mut().auth.clear();
            app.set_auth_rows(ModelRc::default());
            return;
        }
        let visible = self.visible_auth();
        let state = self.state.borrow();
        let rows: Vec<AuthRow> = visible
            .iter()
            .map(|&i| {
                let e = &state.auth[i];
                let (code, left) = e.totp.now();
                AuthRow {
                    title: SharedString::from(e.title.as_str()),
                    subtitle: SharedString::from(e.subtitle.as_str()),
                    code: SharedString::from(view::group_code(&code)),
                    left: i32::try_from(left).unwrap_or(0),
                    period: i32::try_from(e.totp.period()).unwrap_or(30),
                    kind: view::kind_to_int(ItemKind::Login),
                    icon: e.visual.image.clone(),
                    has_icon: e.visual.has_image,
                    initial: e.visual.initial.clone(),
                    tint: e.visual.tint,
                }
            })
            .collect();
        drop(state);
        app.set_auth_rows(ModelRc::from(Rc::new(VecModel::from(rows))));
    }

    fn auth_copy(&self, index: i32) {
        let visible = self.visible_auth();
        let code = usize::try_from(index)
            .ok()
            .and_then(|i| visible.get(i))
            .map(|&i| self.state.borrow().auth[i].totp.now().0);
        if let Some(code) = code {
            self.copy(code, true, notice::CODE_COPIED);
        }
    }

    /// Opens the item behind a code on the item page.
    fn auth_open(&self, index: i32) {
        let visible = self.visible_auth();
        let Some(id) = usize::try_from(index)
            .ok()
            .and_then(|i| visible.get(i))
            .map(|&i| self.state.borrow().auth[i].id)
        else {
            return;
        };
        let app = self.app();
        app.set_category(0);
        app.set_search_text(SharedString::new());
        app.set_panel(Panel::Detail);
        self.tick_auth(); // stops the page's timer
        self.state.borrow_mut().selected = Some(id);
        self.refresh_list();
        self.show_detail();
    }

    // -----------------------------------------------------------------------------------------
    // Folders
    // -----------------------------------------------------------------------------------------

    fn folder_name(&self, id: &FolderId) -> Option<String> {
        let state = self.state.borrow();
        let vault = &state.session.as_ref()?.vault;
        vault
            .folders()
            .iter()
            .find(|f| f.id == *id)
            .map(|f| f.name.clone())
    }

    /// The folder being browsed in the index, if any.
    fn browsed_folder(&self) -> Option<FolderId> {
        let index = usize::try_from(self.app().get_category() - FOLDER_CATEGORY).ok()?;
        let state = self.state.borrow();
        state
            .session
            .as_ref()?
            .vault
            .folders()
            .get(index)
            .map(|f| f.id)
    }

    fn create_folder(&self, name: &str) {
        let created = self.state.borrow_mut().session.as_mut().map(|s| {
            s.vault
                .add_folder(name)
                .map(|_| s.vault.folders().len() - 1)
        });
        match created {
            Some(Ok(index)) if self.save_vault() => {
                // Open the new folder right away.
                self.select_category(FOLDER_CATEGORY + i32::try_from(index).unwrap_or(0));
            }
            Some(Err(err)) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
            }
            _ => {}
        }
    }

    fn rename_folder(&self, name: &str) {
        let Some(id) = self.browsed_folder() else {
            return;
        };
        let renamed = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| s.vault.rename_folder(&id, name));
        if matches!(renamed, Some(Ok(()))) && self.save_vault() {
            self.refresh_list();
            self.show_detail();
        }
    }

    fn delete_folder(&self) {
        let Some(id) = self.browsed_folder() else {
            return;
        };
        let removed = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| s.vault.remove_folder(&id));
        if matches!(removed, Some(Ok(()))) && self.save_vault() {
            self.app().set_category(0);
            self.refresh_list();
            self.show_detail();
        }
    }

    // -----------------------------------------------------------------------------------------
    // Recovery codes
    // -----------------------------------------------------------------------------------------

    fn fill_codes(&self, item: &ItemData) {
        let rows: Vec<CodeRow> = item
            .recovery_codes
            .iter()
            .map(|c| CodeRow {
                code: SharedString::from(c.code.as_str()),
                used: c.used,
            })
            .collect();
        self.app()
            .set_detail_codes(ModelRc::from(Rc::new(VecModel::from(rows))));
    }

    fn show_codes(&self) {
        let Some((id, item)) = self.selected_item() else {
            return;
        };
        self.state.borrow_mut().codes_shown = Some(id);
        self.fill_codes(&item);
    }

    fn hide_codes(&self) {
        self.state.borrow_mut().codes_shown = None;
        self.app().set_detail_codes(ModelRc::default());
    }

    fn toggle_code_used(&self, index: i32) {
        let Some((id, mut item)) = self.selected_item() else {
            return;
        };
        let Some(code) = usize::try_from(index)
            .ok()
            .and_then(|i| item.recovery_codes.get_mut(i))
        else {
            return;
        };
        code.used = !code.used;
        item.touch();
        let updated = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| s.vault.update_item(&id, &item));
        if matches!(updated, Some(Ok(()))) && self.save_vault() {
            self.show_detail();
        }
    }

    // -----------------------------------------------------------------------------------------
    // Editor
    // -----------------------------------------------------------------------------------------

    fn open_editor(&self, id: Option<ItemId>) {
        let app = self.app();
        self.conceal();
        let item = id.and_then(|id| {
            self.state
                .borrow()
                .session
                .as_ref()?
                .vault
                .get_item(&id)
                .ok()
        });
        let item = item.unwrap_or_else(|| ItemData::new(vault_core::ItemKind::Login, ""));
        app.set_ed_kind(view::kind_to_int(item.kind).min(2));
        app.set_ed_title(SharedString::from(item.title.as_str()));
        app.set_ed_username(SharedString::from(item.username.as_str()));
        app.set_ed_url(SharedString::from(
            item.urls.first().map(String::as_str).unwrap_or_default(),
        ));
        app.set_ed_totp(SharedString::from(item.totp.as_str()));
        app.set_ed_notes(SharedString::from(item.notes.as_str()));
        app.set_ed_favorite(item.favorite);
        // Folder picker: "" (shown as "No folder") first, then every folder. A new item
        // starts in the folder being browsed.
        let folders: Vec<(FolderId, String)> = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| {
                s.vault
                    .folders()
                    .iter()
                    .map(|f| (f.id, f.name.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let mut options = vec![SharedString::new()];
        options.extend(
            folders
                .iter()
                .map(|(_, name)| SharedString::from(name.as_str())),
        );
        app.set_ed_folder_options(ModelRc::from(Rc::new(VecModel::from(options))));
        let current = if id.is_some() {
            item.folder
        } else {
            self.browsed_folder()
        };
        let folder_index = current
            .and_then(|folder| folders.iter().position(|(f, _)| *f == folder))
            .map_or(0, |i| i + 1);
        app.set_ed_folder(i32::try_from(folder_index).unwrap_or(0));
        let codes: Vec<&str> = item
            .recovery_codes
            .iter()
            .map(|c| c.code.as_str())
            .collect();
        app.set_ed_recovery_codes(SharedString::from(codes.join("\n")));
        // Extra fields; a card's own details have their own boxes.
        let is_card = item.kind == ItemKind::Card;
        self.state.borrow_mut().edit_fields = item
            .custom_fields
            .iter()
            .filter(|f| {
                !is_card
                    || !card::RESERVED
                        .iter()
                        .any(|r| f.name.eq_ignore_ascii_case(r))
            })
            .cloned()
            .collect();
        self.show_edit_fields();
        let details = CardDetails::from_item(&item);
        app.set_ed_card_number(SharedString::from(card::group(&details.number)));
        app.set_ed_card_expiry(SharedString::from(
            card::parse_expiry(&details.expiry).map_or(details.expiry.clone(), card::format_expiry),
        ));
        app.set_ed_card_code(SharedString::from(details.security_code.as_str()));
        app.set_ed_card_brand(SharedString::from(
            card::detect_brand(&details.number).name(),
        ));
        app.set_editor_password_shown(SharedString::new());
        self.edit_secret(field::ITEM_PASSWORD as i32, |buffer| {
            buffer.set(&item.password);
        });
        self.state.borrow_mut().editing = Some(id);
        app.set_editor_is_new(id.is_none());
        app.set_editing_item(true);
        app.set_panel(Panel::Editor);
        self.set_error(error::NONE, "");
    }

    fn close_editor(&self) {
        self.state.borrow_mut().editing = None;
        self.clear_secret(field::ITEM_PASSWORD);
        let app = self.app();
        app.set_editor_password_shown(SharedString::new());
        app.set_ed_recovery_codes(SharedString::new());
        app.set_ed_card_number(SharedString::new());
        app.set_ed_card_expiry(SharedString::new());
        app.set_ed_card_code(SharedString::new());
        app.set_ed_fields(ModelRc::default());
        self.state.borrow_mut().edit_fields.clear();
        app.set_editing_item(false);
        app.set_panel(Panel::Detail);
        self.show_detail();
    }

    fn save_item(&self) {
        let app = self.app();
        let title = app.get_ed_title().trim().to_owned();
        if title.is_empty() {
            self.set_error(error::TITLE_REQUIRED, "");
            return;
        }
        let totp = app.get_ed_totp().trim().to_owned();
        if !totp.is_empty() && Totp::parse(&totp).is_err() {
            self.set_error(error::BAD_TOTP, "");
            return;
        }
        let Some(editing) = self.state.borrow().editing else {
            return;
        };
        let existing = editing.and_then(|id| {
            self.state
                .borrow()
                .session
                .as_ref()?
                .vault
                .get_item(&id)
                .ok()
        });
        let kind = view::int_to_kind(app.get_ed_kind());
        let mut item = existing.unwrap_or_else(|| ItemData::new(kind, &title));
        item.kind = kind;
        item.title = title;
        item.username = app.get_ed_username().to_string();
        item.password = self.state.borrow().secrets[field::ITEM_PASSWORD]
            .as_str()
            .to_owned();
        let url = app.get_ed_url().trim().to_owned();
        match (url.is_empty(), item.urls.is_empty()) {
            (true, _) => item.urls.clear(),
            (false, true) => item.urls.push(url),
            (false, false) => item.urls[0] = url,
        }
        item.totp = totp;
        item.notes = app.get_ed_notes().to_string();
        item.favorite = app.get_ed_favorite();
        item.folder = usize::try_from(app.get_ed_folder() - 1).ok().and_then(|i| {
            let state = self.state.borrow();
            state.session.as_ref()?.vault.folders().get(i).map(|f| f.id)
        });
        // Extra fields as edited (a field needs a name or a value to be kept).
        item.custom_fields = self
            .state
            .borrow()
            .edit_fields
            .iter()
            .filter(|f| !f.name.trim().is_empty() || !f.value.is_empty())
            .map(|f| CustomField {
                name: if f.name.trim().is_empty() {
                    "Field".to_owned()
                } else {
                    f.name.trim().to_owned()
                },
                value: f.value.clone(),
                sensitive: f.sensitive,
            })
            .collect();
        if kind == ItemKind::Card {
            let details = CardDetails {
                number: app.get_ed_card_number().to_string(),
                expiry: app.get_ed_card_expiry().to_string(),
                security_code: app.get_ed_card_code().to_string(),
            };
            if let Err(problem) = details.validate(&item.password) {
                self.set_error(
                    match problem {
                        CardProblem::Number => error::CARD_NUMBER,
                        CardProblem::Expiry => error::CARD_EXPIRY,
                        CardProblem::SecurityCode => error::CARD_CODE,
                        CardProblem::Pin => error::CARD_PIN,
                    },
                    "",
                );
                return;
            }
            details.apply(&mut item);
        }
        if kind == ItemKind::Login {
            // Codes kept from before stay marked as used.
            let mut codes = RecoveryCode::parse_list(&app.get_ed_recovery_codes());
            for code in &mut codes {
                code.used = item
                    .recovery_codes
                    .iter()
                    .any(|old| old.used && old.code == code.code);
            }
            item.recovery_codes = codes;
        }
        item.touch();

        let result = {
            let mut state = self.state.borrow_mut();
            let Some(session) = state.session.as_mut() else {
                return;
            };
            match editing {
                Some(id) => session.vault.update_item(&id, &item).map(|()| id),
                None => session.vault.add_item(&item),
            }
        };
        match result {
            Ok(id) => {
                if self.save_vault() {
                    self.state.borrow_mut().selected = Some(id);
                    self.close_editor();
                    self.refresh_list();
                    self.show_detail();
                    self.notify(notice::SAVED, "");
                    self.start_icon_fetch();
                }
            }
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
            }
        }
    }

    fn toggle_show_password(&self) {
        let app = self.app();
        if app.get_editor_password_shown().is_empty() {
            let text =
                SharedString::from(self.state.borrow().secrets[field::ITEM_PASSWORD].as_str());
            app.set_editor_password_shown(text);
        } else {
            app.set_editor_password_shown(SharedString::new());
        }
    }

    fn generate_for_item(&self) {
        if let Some(password) = self.generate() {
            self.edit_secret(field::ITEM_PASSWORD as i32, |buffer| {
                buffer.set(&password);
            });
            self.app()
                .set_editor_password_shown(SharedString::from(password.as_str()));
        }
    }

    // -----------------------------------------------------------------------------------------
    // Generator
    // -----------------------------------------------------------------------------------------

    fn generate(&self) -> Option<Zeroizing<String>> {
        let app = self.app();
        let result = if app.get_gen_mode() == 1 {
            let options = PassphraseOptions {
                words: usize::try_from(app.get_gen_words()).unwrap_or(6),
                separator: match app.get_gen_separator() {
                    1 => ".",
                    2 => "_",
                    3 => " ",
                    _ => "-",
                }
                .into(),
                capitalize: app.get_gen_capitalize(),
                include_number: app.get_gen_number(),
            };
            set_strength(&app, options.entropy_bits());
            generator::generate_passphrase(&options)
        } else {
            let mut options = PasswordOptions {
                length: usize::try_from(app.get_gen_length()).unwrap_or(24),
                lowercase: app.get_gen_lowercase(),
                uppercase: app.get_gen_uppercase(),
                digits: app.get_gen_digits(),
                symbols: app.get_gen_symbols(),
                avoid_ambiguous: app.get_gen_avoid_ambiguous(),
            };
            if !(options.lowercase || options.uppercase || options.digits || options.symbols) {
                options.lowercase = true;
                app.set_gen_lowercase(true);
            }
            set_strength(&app, options.entropy_bits());
            generator::generate_password(&options)
        };
        result.ok()
    }

    fn regenerate(&self) {
        if let Some(value) = self.generate() {
            self.app()
                .set_gen_result(SharedString::from(value.as_str()));
            self.state.borrow_mut().generated = Some(value);
        }
    }

    fn open_generator(&self) {
        let app = self.app();
        app.set_panel(Panel::Generator);
        if app.get_gen_result().is_empty() {
            self.regenerate();
        }
    }

    fn copy_generated(&self) {
        let value = self.state.borrow().generated.clone();
        if let Some(value) = value {
            self.copy(value, true, notice::GENERATED_COPIED);
        }
    }

    fn use_generated(&self) {
        let value = self.state.borrow().generated.clone();
        let editing = self.state.borrow().editing.is_some();
        if let (Some(value), true) = (value, editing) {
            self.edit_secret(field::ITEM_PASSWORD as i32, |buffer| {
                buffer.set(&value);
            });
            let app = self.app();
            app.set_editor_password_shown(SharedString::from(value.as_str()));
            app.set_panel(Panel::Editor);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------------------------------

    fn open_settings(&self) {
        let app = self.app();
        let settings = self.state.borrow().settings.clone();
        app.set_auto_lock_minutes(settings.auto_lock_minutes as i32);
        app.set_clipboard_seconds(settings.clipboard_clear_seconds as i32);
        app.set_website_icons(settings.website_icons);
        app.set_kit_secret_key(SharedString::new());
        app.set_kit_recovery_key(SharedString::new());
        app.set_panel(Panel::Settings);
        self.set_error(error::NONE, "");
    }

    // -----------------------------------------------------------------------------------------
    // Import & export
    // -----------------------------------------------------------------------------------------

    fn open_transfer(&self) {
        let app = self.app();
        self.clear_secret(field::CURRENT);
        if self.state.borrow().pending_import.is_none() {
            app.set_import_stage(0);
        }
        app.set_panel(Panel::Transfer);
        self.set_error(error::NONE, "");
    }

    fn import_choose(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests: they call start_import directly
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Import from another password manager")
            .add_filter("Password exports", &["json", "csv", "kdbx"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            self.start_import(path);
        }
    }

    /// Reads the chosen file; KeePass databases first ask for their password. (The "Choose a
    /// file" button calls this after its dialog; tests and the screenshot tool call it directly.)
    pub fn start_import(&self, path: PathBuf) {
        let app = self.app();
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(err) => {
                self.set_error(error::IMPORT, &err.to_string());
                return;
            }
        };
        let format = vault_import::detect_format(&bytes);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        app.set_import_file(SharedString::from(name));
        app.set_import_plaintext(format != vault_import::Format::Kdbx);
        self.set_error(error::NONE, "");
        self.state.borrow_mut().pending_import = Some(PendingImport {
            path,
            bytes,
            format,
            report: None,
        });
        if format == vault_import::Format::Kdbx {
            self.clear_secret(field::IMPORT);
            app.set_import_stage(1);
        } else {
            self.parse_import();
        }
    }

    /// Parses the pending file (KeePass: with the typed password) on a worker thread.
    fn parse_import(&self) {
        let (bytes, format) = match self.state.borrow().pending_import.as_ref() {
            Some(pending) => (pending.bytes.clone(), pending.format),
            None => return,
        };
        let password = Zeroizing::new(
            self.state.borrow().secrets[field::IMPORT]
                .as_str()
                .to_owned(),
        );
        self.run_job(move || {
            use vault_import::Format;
            let parsed = match format {
                Format::BitwardenJson => vault_import::import_bitwarden_json(&bytes),
                Format::Csv => vault_import::import_csv(&bytes),
                Format::Kdbx => vault_import::import_kdbx(&bytes, &password, None),
            };
            match parsed {
                Ok(report) => JobResult::ImportParsed { report },
                Err(err) => JobResult::Failed {
                    code: error::IMPORT,
                    detail: err.to_string(),
                    session: None,
                },
            }
        });
    }

    fn import_parsed(&self, report: vault_import::ImportReport) {
        self.clear_secret(field::IMPORT);
        let app = self.app();
        let preview = {
            let state = self.state.borrow();
            let Some(session) = state.session.as_ref() else {
                return;
            };
            report.preview(&session.vault)
        };
        match preview {
            Ok(outcome) => {
                app.set_import_found(i32::try_from(outcome.added).unwrap_or(i32::MAX));
                app.set_import_new_folders(i32::try_from(outcome.new_folders).unwrap_or(0));
                app.set_import_duplicates(i32::try_from(outcome.duplicates).unwrap_or(0));
                let mut warnings: Vec<&str> =
                    report.warnings.iter().take(4).map(String::as_str).collect();
                let more = report.warnings.len().saturating_sub(4);
                let more_text = format!("… and {more} more");
                if more > 0 {
                    warnings.push(&more_text);
                }
                app.set_import_warnings(SharedString::from(warnings.join("\n")));
                app.set_import_stage(2);
            }
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
                return;
            }
        }
        if let Some(pending) = self.state.borrow_mut().pending_import.as_mut() {
            pending.report = Some(report);
        }
    }

    fn import_confirm(&self) {
        let Some(report) = self
            .state
            .borrow_mut()
            .pending_import
            .as_mut()
            .and_then(|p| p.report.take())
        else {
            return;
        };
        let outcome = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| report.add_to_vault(&mut s.vault));
        match outcome {
            Some(Ok(outcome)) => {
                if !self.save_vault() {
                    return;
                }
                let app = self.app();
                app.set_import_added(i32::try_from(outcome.added).unwrap_or(i32::MAX));
                app.set_import_stage(3);
                self.refresh_list();
                self.notify(notice::IMPORTED, &outcome.added.to_string());
                self.start_icon_fetch();
            }
            Some(Err(err)) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
            }
            None => {}
        }
    }

    fn import_cancel(&self) {
        self.state.borrow_mut().pending_import = None;
        self.clear_secret(field::IMPORT);
        self.app().set_import_stage(0);
        self.set_error(error::NONE, "");
    }

    /// Overwrites and deletes the unencrypted export that was just imported.
    fn import_wipe(&self) {
        let path = self
            .state
            .borrow()
            .pending_import
            .as_ref()
            .map(|p| p.path.clone());
        if let Some(path) = path {
            match files::wipe(&path) {
                Ok(()) => self.notify(notice::SOURCE_WIPED, ""),
                Err(err) => {
                    self.set_error(error::FILE, &err.to_string());
                    return;
                }
            }
        }
        self.import_cancel();
    }

    /// A copy of the (encrypted) vault file, wherever the user wants it.
    fn export_backup(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return;
        }
        let source = self.state.borrow().path.clone();
        let Some(target) = rfd::FileDialog::new()
            .set_title("Save a backup copy of the vault")
            .set_file_name("vault-backup.vault")
            .add_filter("Vault", &["vault"])
            .save_file()
        else {
            return;
        };
        match storage::read(&source).and_then(|bytes| storage::write_atomic(&target, &bytes)) {
            Ok(()) => self.notify(notice::BACKUP_SAVED, &target.display().to_string()),
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
            }
        }
    }

    /// After the master password check: writes the unencrypted export to a file the user picks.
    fn export_verified(&self, session: Session) {
        self.clear_secret(field::CURRENT);
        let app = self.app();
        let csv = app.get_export_format() == 1;
        let text = if csv {
            vault_import::export_csv(&session.vault)
        } else {
            vault_import::export_bitwarden_json(&session.vault)
        };
        let (runner, vault_path) = {
            let state = self.state.borrow();
            (state.runner, state.path.clone())
        };
        self.state.borrow_mut().session = Some(session);
        let text = match text {
            Ok(text) => text,
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
                return;
            }
        };
        let extension = if csv { "csv" } else { "json" };
        let target = match runner {
            // Headless tests: next to the test vault.
            Runner::Inline => Some(vault_path.with_extension(format!("export.{extension}"))),
            Runner::Thread => rfd::FileDialog::new()
                .set_title("Export without encryption")
                .set_file_name(format!("vault-export.{extension}"))
                .add_filter(if csv { "CSV" } else { "JSON" }, &[extension])
                .save_file(),
        };
        let Some(target) = target else { return };
        match std::fs::write(&target, text.as_bytes()) {
            Ok(()) => self.notify(notice::EXPORTED, &target.display().to_string()),
            Err(err) => self.set_error(error::FILE, &err.to_string()),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Emergency kit page, printing and PDF
    // -----------------------------------------------------------------------------------------

    fn open_kit(&self) {
        let app = self.app();
        app.set_kit_secret_key(SharedString::new());
        app.set_kit_recovery_key(SharedString::new());
        self.clear_secret(field::CURRENT);
        app.set_panel(Panel::Kit);
        self.set_error(error::NONE, "");
    }

    /// The kit currently on screen as a PDF, with a file name. `None` until the keys are shown.
    fn kit_pdf(&self) -> Option<(String, Zeroizing<Vec<u8>>)> {
        let app = self.app();
        let secret_key = app.get_kit_secret_key();
        if secret_key.is_empty() {
            return None;
        }
        let recovery_key = app.get_kit_recovery_key();
        let vault_id = app.get_vault_id();
        let vault_path = app.get_vault_path();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let bytes = kit_pdf::render(&KitContents {
            secret_key: &secret_key,
            recovery_key: (!recovery_key.is_empty()).then_some(recovery_key.as_str()),
            vault_id: &vault_id,
            vault_path: &vault_path,
            created_at,
        });
        let short_id: String = vault_id.chars().take(8).collect();
        Some((format!("emergency-kit-{short_id}.pdf"), bytes))
    }

    /// Writes the kit to the print folder (wiped when the vault locks) and opens it in the PDF
    /// viewer, where it can be printed.
    fn print_kit(&self) {
        let Some((name, bytes)) = self.kit_pdf() else {
            return;
        };
        match files::write_for_printing(&name, &bytes) {
            Ok(path) => {
                // Headless tests stop at writing the file.
                if self.state.borrow().runner == Runner::Thread {
                    if let Err(err) = files::open_with_default_app(&path) {
                        self.set_error(error::OTHER, &err.to_string());
                        return;
                    }
                }
                self.notify(notice::KIT_OPENED, "");
            }
            Err(err) => self.set_error(error::FILE, &err.to_string()),
        }
    }

    fn save_kit(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests
        }
        let Some((name, bytes)) = self.kit_pdf() else {
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save emergency kit")
            .set_file_name(&name)
            .add_filter("PDF", &["pdf"])
            .save_file()
        else {
            return;
        };
        match std::fs::write(&path, &*bytes) {
            Ok(()) => self.notify(notice::KIT_SAVED, &path.display().to_string()),
            Err(err) => self.set_error(error::FILE, &err.to_string()),
        }
    }

    fn set_appearance(&self, dark: bool) {
        self.app().global::<Theme>().set_dark(dark);
        self.save_settings();
    }

    fn save_settings(&self) {
        let app = self.app();
        let settings = device::Settings {
            auto_lock_minutes: u32::try_from(app.get_auto_lock_minutes().clamp(1, 60)).unwrap_or(5),
            clipboard_clear_seconds: u32::try_from(app.get_clipboard_seconds().clamp(5, 120))
                .unwrap_or(20),
            dark_theme: app.global::<Theme>().get_dark(),
            website_icons: app.get_website_icons(),
        };
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.settings = settings.clone();
        if let Err(err) = device_state.save() {
            self.set_error(error::FILE, &err.to_string());
        }
        let icons_were_on = self.state.borrow().settings.website_icons;
        self.state.borrow_mut().settings = settings.clone();
        self.restart_auto_lock();
        match (icons_were_on, settings.website_icons) {
            (false, true) => {
                self.refresh_list();
                self.start_icon_fetch();
            }
            (true, false) => {
                // Turning icons off also forgets them on this device.
                self.forget_icons();
                self.refresh_list();
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------------------------
    // Website icons (opt-in; see favicon.rs for the privacy model)
    // -----------------------------------------------------------------------------------------

    fn icon_for(&self, kind: ItemKind, url: &str, title: &str) -> IconVisual {
        let host = favicon::host_of(url);
        let key = host.as_deref().map(favicon::cache_key);
        let (r, g, b) = view::tint(kind, key.as_deref().unwrap_or(title));
        let mut visual = IconVisual {
            image: Image::default(),
            has_image: false,
            initial: SharedString::from(view::initial(title)),
            tint: slint::Color::from_rgb_u8(r, g, b),
        };
        let mut state = self.state.borrow_mut();
        if kind != ItemKind::Login || !state.settings.website_icons {
            return visual;
        }
        let Some(key) = key else { return visual };
        if let Some(image) = state.icon_images.get(&key) {
            visual.image = image.clone();
            visual.has_image = true;
        } else if let Some(pixels) = state.icons.get(&key).map(<[u8]>::to_vec) {
            let image = Image::from_rgba8(SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
                &pixels,
                favicon::ICON_SIZE,
                favicon::ICON_SIZE,
            ));
            state.icon_images.insert(key, image.clone());
            visual.image = image;
            visual.has_image = true;
        }
        visual
    }

    fn apply_detail_icon(&self, item: &ItemData) {
        let url = item.urls.first().map(String::as_str).unwrap_or_default();
        let visual = self.icon_for(item.kind, url, &item.title);
        let app = self.app();
        app.set_detail_icon(visual.image);
        app.set_detail_has_icon(visual.has_image);
        app.set_detail_initial(visual.initial);
        app.set_detail_tint(visual.tint);
    }

    fn icon_cache_path(&self) -> Option<PathBuf> {
        let id = self.state.borrow().session.as_ref()?.vault.id_hex();
        Some(
            vault_platform::paths::app_dir()
                .ok()?
                .join(format!("icons-{id}.cache")),
        )
    }

    fn load_icon_cache(&self) {
        let loaded = self.icon_cache_path().and_then(|path| {
            let sealed = std::fs::read(path).ok()?;
            let state = self.state.borrow();
            let plain = state
                .session
                .as_ref()?
                .vault
                .open_local("icons", &sealed)
                .ok()?;
            IconCache::from_bytes(&plain)
        });
        let mut state = self.state.borrow_mut();
        state.icons = loaded.unwrap_or_default();
        state.icon_images.clear();
    }

    fn save_icon_cache(&self) {
        let Some(path) = self.icon_cache_path() else {
            return;
        };
        let sealed = {
            let state = self.state.borrow();
            let Some(session) = state.session.as_ref() else {
                return;
            };
            session.vault.seal_local("icons", &state.icons.to_bytes())
        };
        if let Ok(sealed) = sealed {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = storage::write_atomic(&path, &sealed);
        }
    }

    fn forget_icons(&self) {
        if let Some(path) = self.icon_cache_path() {
            let _ = std::fs::remove_file(storage::backup_path(&path));
            let _ = std::fs::remove_file(path);
        }
        let mut state = self.state.borrow_mut();
        state.icons = IconCache::default();
        state.icon_images.clear();
    }

    /// Fetches icons for saved sites that don't have one yet, one site at a time.
    fn start_icon_fetch(&self) {
        let (hosts, runner) = {
            let state = self.state.borrow();
            if !state.settings.website_icons || state.fetching_icons || state.session.is_none() {
                return;
            }
            let mut seen = std::collections::BTreeSet::new();
            let hosts: Vec<(String, String)> = state
                .summaries
                .iter()
                .filter(|s| s.kind == ItemKind::Login)
                .filter_map(|s| favicon::host_of(&s.url))
                .filter_map(|host| {
                    let key = favicon::cache_key(&host);
                    (state.icons.needs_fetch(&key) && seen.insert(key.clone()))
                        .then_some((key, host))
                })
                .collect();
            (hosts, state.runner)
        };
        if hosts.is_empty() {
            return;
        }
        self.state.borrow_mut().fetching_icons = true;
        match runner {
            Runner::Inline => {
                for (key, host) in hosts {
                    let icon = favicon::fetch(&host);
                    self.icon_fetched(key, icon);
                }
                self.icons_done();
            }
            Runner::Thread => {
                std::thread::spawn(move || {
                    for (key, host) in hosts {
                        let icon = favicon::fetch(&host);
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                                controller.icon_fetched(key, icon);
                            }
                        });
                    }
                    let _ = slint::invoke_from_event_loop(|| {
                        if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                            controller.icons_done();
                        }
                    });
                });
            }
        }
    }

    fn icon_fetched(&self, key: String, icon: Option<Vec<u8>>) {
        if self.state.borrow().session.is_none() {
            return; // locked meanwhile: drop the result
        }
        let found = icon.is_some();
        self.state.borrow_mut().icons.insert(key, icon);
        if found {
            self.refresh_list();
            if let Some((_, item)) = self.selected_item() {
                self.apply_detail_icon(&item);
            }
        }
    }

    fn icons_done(&self) {
        self.state.borrow_mut().fetching_icons = false;
        self.save_icon_cache();
    }

    fn change_password(&self) {
        let Some(new_password) = self.new_password_from(field::NEW, field::NEW_AGAIN) else {
            return;
        };
        let current = Zeroizing::new(
            self.state.borrow().secrets[field::CURRENT]
                .as_str()
                .to_owned(),
        );
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let path = self.state.borrow().path.clone();
        self.run_job(move || {
            let mut session = session;
            if let Err(failure) = verify_current(&path, &current, &session) {
                return JobResult::Failed {
                    code: failure.0,
                    detail: failure.1,
                    session: Some(session),
                };
            }
            let kdf = session.vault.kdf_params().clone();
            let outcome = session
                .vault
                .change_password(&new_password, &session.secret_key, &kdf)
                .and_then(|()| session.vault.to_bytes())
                .and_then(|bytes| storage::write_atomic(&path, &bytes));
            match outcome {
                Ok(()) => {
                    let _ =
                        device::record_revision(&session.vault.id_hex(), session.vault.revision());
                    JobResult::PasswordChanged { session }
                }
                Err(err) => JobResult::Failed {
                    code: error::FILE,
                    detail: err.to_string(),
                    session: Some(session),
                },
            }
        });
    }

    fn verify_then(&self, action: KitAction) {
        let current = Zeroizing::new(
            self.state.borrow().secrets[field::CURRENT]
                .as_str()
                .to_owned(),
        );
        if current.is_empty() {
            self.set_error(error::WRONG_CURRENT, "");
            return;
        }
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let path = self.state.borrow().path.clone();
        self.run_job(move || {
            let mut session = session;
            if let Err(failure) = verify_current(&path, &current, &session) {
                return JobResult::Failed {
                    code: failure.0,
                    detail: failure.1,
                    session: Some(session),
                };
            }
            match action {
                KitAction::Show => JobResult::KitVerified { session },
                KitAction::Export => JobResult::ExportVerified { session },
                KitAction::NewRecoveryKey => {
                    let outcome = RecoveryKey::generate().and_then(|key| {
                        session.vault.set_recovery_key(Some(&key))?;
                        let bytes = session.vault.to_bytes()?;
                        storage::write_atomic(&path, &bytes)?;
                        Ok(key)
                    });
                    match outcome {
                        Ok(recovery_key) => {
                            let _ = device::record_revision(
                                &session.vault.id_hex(),
                                session.vault.revision(),
                            );
                            JobResult::RecoveryIssued {
                                session,
                                recovery_key,
                            }
                        }
                        Err(err) => JobResult::Failed {
                            code: error::FILE,
                            detail: err.to_string(),
                            session: Some(session),
                        },
                    }
                }
            }
        });
    }
}

#[derive(Debug, Clone, Copy)]
enum CopyWhat {
    Username,
    Password,
    Totp,
    Field(i32),
    RecoveryCode(i32),
}

#[derive(Debug, Clone, Copy)]
enum KitAction {
    Show,
    NewRecoveryKey,
    /// Unencrypted export (the file is chosen after the password check).
    Export,
}

/// One code on the Authenticator page.
struct AuthEntry {
    id: ItemId,
    title: String,
    subtitle: String,
    totp: Totp,
    visual: IconVisual,
}

/// An import in progress. The file's bytes are wiped when this is dropped.
struct PendingImport {
    path: PathBuf,
    bytes: Zeroizing<Vec<u8>>,
    format: vault_import::Format,
    report: Option<vault_import::ImportReport>,
}

/// Windows paths compare without regard to case.
fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

fn file_hash(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Shows a generated secret's strength: bits and the estimated time to crack it.
fn set_strength(app: &AppWindow, bits: f64) {
    app.set_gen_bits(bits as i32);
    let (unit, amount) = view::crack_time(bits);
    app.set_gen_crack_unit(unit);
    app.set_gen_crack_amount(amount);
    app.set_gen_crack_comparison(view::crack_comparison(bits));
}

/// Re-derives the key from the file with the typed password: proof the person at the keyboard
/// knows the master password, not just that the vault happens to be open.
fn verify_current(
    path: &std::path::Path,
    password: &str,
    session: &Session,
) -> Result<(), (i32, String)> {
    if password.is_empty() {
        return Err((error::WRONG_CURRENT, String::new()));
    }
    let bytes = storage::read(path).map_err(|e| (error::FILE, e.to_string()))?;
    Vault::open(
        &bytes,
        Unlock::Password {
            password,
            secret_key: &session.secret_key,
        },
    )
    .map(drop)
    .map_err(|e| match e {
        CoreError::DecryptionFailed => (error::WRONG_CURRENT, String::new()),
        other => (error::OTHER, other.to_string()),
    })
}
