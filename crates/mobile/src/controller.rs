//! Wires the phone's screens to the vault.
//!
//! The phone opens a vault made on the computer; it never makes one. A file the person
//! brings in replaces the phone's copy only after it opened with their keys and proved no
//! older than what this phone saw (docs/MOBILE.md §6).
//!
//! Rules it keeps (AGENTS.md §4.1): typed secrets live in locked buffers and never in Slint
//! strings; a secret is put on screen only while the person asked to see it; an item behind
//! the item lock shows nothing secret before its check; a vault file changed by something
//! else is never overwritten.

use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    rc::{Rc, Weak},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use slint::{Color, ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use vault_core::{
    Error as CoreError, GuardCheck, ItemData, ItemId, ItemKind, SecretKey, Unlock, Vault,
    generator::{
        PassphraseOptions, PasswordOptions, WordCase, generate_passphrase, generate_password,
    },
    storage,
    totp::Totp,
};
use vault_platform::{
    DeviceState, RollbackStatus, SecretBuffer, StateFile, clipboard, secret_store,
};
use zeroize::Zeroizing;

use crate::{
    sketch,
    ui::{CodeRow, ItemRow, Page, PhoneWindow, Place, Screen, Secrets, Sketch, Theme},
};

/// Secure field ids (the `field` of each `SecretField` in app.slint).
mod field {
    pub const MASTER: usize = 0;
    pub const SECRET_KEY: usize = 1;
    pub const ITEM_CHECK: usize = 2;
    pub const ITEM_PASSWORD: usize = 3;
    pub const COUNT: usize = 4;
}

/// Error codes (texts live in app.slint → Words.error).
mod error {
    pub const NONE: i32 = 0;
    pub const WRONG: i32 = 1;
    pub const NOT_A_VAULT: i32 = 2;
    pub const SECRET_KEY: i32 = 3;
    pub const UNREADABLE: i32 = 4;
    pub const NAME: i32 = 5;
    pub const NOT_SAVED: i32 = 6;
    pub const WRONG_CHECK: i32 = 7;
    pub const OLDER: i32 = 8;
    pub const KEYFILE: i32 = 9;
    pub const TOTP: i32 = 10;
    pub const NO_CHARACTERS: i32 = 11;
}

/// Notice codes (texts live in app.slint → Words.notice).
mod notice {
    pub const PASSWORD_COPIED: i32 = 1;
    pub const USERNAME_COPIED: i32 = 2;
    pub const SAVED: i32 = 3;
    pub const DELETED: i32 = 4;
    pub const CODE_COPIED: i32 = 5;
    pub const WEBSITE_COPIED: i32 = 6;
    pub const COPIED: i32 = 7;
    pub const STATE_RESET: i32 = 8;
}

/// A copied secret leaves the clipboard after this long.
const CLIPBOARD_SECONDS: u64 = 30;
const NOTICE_FOR: Duration = Duration::from_secs(3);
const LOCK_CHOICES: [Duration; 3] = [
    Duration::from_secs(60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
];

/// Muted colours behind an item's initial: the desktop's palette, so a service keeps its
/// colour on both.
const TINTS: [(u8, u8, u8); 8] = [
    (0x3D, 0x6F, 0xD6),
    (0x7B, 0x5C, 0xD6),
    (0x16, 0x93, 0x72),
    (0xD2, 0x63, 0x35),
    (0xC0, 0x4A, 0x84),
    (0x17, 0x8A, 0xB0),
    (0xC8, 0x45, 0x45),
    (0x5B, 0x7F, 0x2E),
];

fn tint(kind: ItemKind, key: &str) -> Color {
    let (r, g, b) = match kind {
        ItemKind::Card => (0x4A, 0x5D, 0x7E),
        ItemKind::SecureNote => (0x2F, 0x7D, 0x68),
        ItemKind::Passkey => (0x5C, 0x4B, 0x7A),
        ItemKind::Login => {
            // FNV-1a: tiny, stable across runs and platforms.
            let hash = key.to_lowercase().bytes().fold(0x811C_9DC5u32, |h, b| {
                (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
            });
            TINTS[hash as usize % TINTS.len()]
        }
    };
    Color::from_rgb_u8(r, g, b)
}

fn initial(title: &str) -> SharedString {
    title
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect::<String>())
        .unwrap_or_else(|| "•".to_owned())
        .into()
}

fn kind_index(kind: ItemKind) -> i32 {
    match kind {
        ItemKind::Login => 0,
        ItemKind::Card => 1,
        ItemKind::SecureNote => 2,
        ItemKind::Passkey => 3,
    }
}

/// `123456` as `123 456`, so the digits are read in two glances.
fn grouped(code: &str) -> String {
    let half = code.len().div_ceil(2);
    if code.len() < 6 {
        return code.to_owned();
    }
    format!("{} {}", &code[..half], &code[half..])
}

fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

struct State {
    /// Slow work (password hashing) runs inline: headless tests and screenshots.
    inline: bool,
    /// The phone's copy of the vault file.
    path: PathBuf,
    /// A vault file the person chose, waiting to prove itself before it replaces the copy.
    incoming: Option<Vec<u8>>,
    vault: Option<Vault>,
    secret_key: Option<SecretKey>,
    /// SHA-256 of the vault file as last read or written here.
    file_hash: Option<[u8; 32]>,
    secrets: [SecretBuffer; field::COUNT],
    /// The items behind the list's rows and the Codes rows, in order.
    shown: Vec<ItemId>,
    code_ids: Vec<ItemId>,
    selected: Option<ItemId>,
    editing: Option<ItemId>,
    /// The master password was just checked for an item the lock covers (no extra encryption).
    master_checked: bool,
    show_password: bool,
    confirm_delete: bool,
    generated: Zeroizing<String>,
    /// What this app put on the clipboard, and when it takes it back.
    copied: Option<(Zeroizing<String>, Instant)>,
    notice_until: Option<Instant>,
    last_touch: Instant,
    lock_after: Duration,
}

thread_local! {
    /// The controller of this thread's window, for work that finishes on another thread.
    static CURRENT: RefCell<Weak<Controller>> = const { RefCell::new(Weak::new()) };
}

pub struct Controller {
    app: slint::Weak<PhoneWindow>,
    state: RefCell<State>,
    tick: Timer,
}

impl std::fmt::Debug for Controller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller").finish_non_exhaustive()
    }
}

/// What the slow part of opening a vault hands back.
struct Opened {
    vault: Result<Vault, CoreError>,
    secret_key: SecretKey,
    typed_key: bool,
    hash: [u8; 32],
}

impl Controller {
    /// Wires the window and shows the first screen for the phone's copy of the vault at
    /// `path`. `inline` runs slow work on the calling thread (tests, screenshots).
    ///
    /// The window's `pick-vault` callback is left to the shell: it shows the system's file
    /// picker and hands the chosen file to [`Controller::bring_vault`].
    pub fn start(app: &PhoneWindow, path: PathBuf, inline: bool) -> Rc<Self> {
        let controller = Rc::new(Self {
            app: app.as_weak(),
            state: RefCell::new(State {
                inline,
                path,
                incoming: None,
                vault: None,
                secret_key: None,
                file_hash: None,
                secrets: std::array::from_fn(|_| SecretBuffer::new()),
                shown: Vec::new(),
                code_ids: Vec::new(),
                selected: None,
                editing: None,
                master_checked: false,
                show_password: false,
                confirm_delete: false,
                generated: Zeroizing::new(String::new()),
                copied: None,
                notice_until: None,
                last_touch: Instant::now(),
                lock_after: LOCK_CHOICES[1],
            }),
            tick: Timer::default(),
        });
        CURRENT.with(|current| *current.borrow_mut() = Rc::downgrade(&controller));
        app.global::<Theme>().set_touch(true);
        let sketches = sketch::Sketches::generate();
        let global = app.global::<Sketch>();
        global.set_marker_a(sketches.markers[0].as_str().into());
        global.set_marker_b(sketches.markers[1].as_str().into());
        global.set_marker_c(sketches.markers[2].as_str().into());
        global.set_padlock(sketches.padlock.as_str().into());
        global.set_check(sketches.check.as_str().into());
        global.set_star(sketches.star.as_str().into());
        app.set_app_version(env!("CARGO_PKG_VERSION").into());
        app.set_lock_choice(1);
        controller.wire(app);
        controller.show_entry();
        controller
    }

    fn app(&self) -> PhoneWindow {
        self.app
            .upgrade()
            .expect("the window outlives its controller")
    }

    fn wire(self: &Rc<Self>, app: &PhoneWindow) {
        // Every callback counts as the person being there, for the auto-lock.
        macro_rules! on {
            ($setter:ident, |$c:ident $(, $arg:ident)*| $body:expr) => {{
                let weak = Rc::downgrade(self);
                app.$setter(move |$($arg),*| {
                    if let Some($c) = weak.upgrade() {
                        $c.state.borrow_mut().last_touch = Instant::now();
                        $body
                    }
                });
            }};
        }
        on!(on_cancel_incoming, |c| {
            c.state.borrow_mut().incoming = None;
            c.show_entry();
        });
        on!(on_unlock, |c| c.unlock());
        on!(on_search_changed, |c, _text| c.refresh_list());
        on!(on_filter_changed, |c, _index| c.refresh_list());
        on!(on_open_item, |c, index| c.open_item(index));
        on!(on_new_item, |c| c.open_editor(None));
        on!(on_close_item, |c| c.close_item());
        on!(on_edit_item, |c| {
            let selected = c.state.borrow().selected;
            c.open_editor(selected);
        });
        on!(on_toggle_favorite, |c| c.toggle_favorite());
        on!(on_toggle_password, |c| {
            let shown = !c.state.borrow().show_password;
            c.state.borrow_mut().show_password = shown;
            c.show_item();
        });
        on!(on_copy, |c, what| c.copy(what));
        on!(on_unlock_item, |c| c.unlock_item());
        on!(on_ed_toggle_password, |c| {
            let shown = !c.app().get_ed_password().is_empty();
            c.show_editor_password(!shown);
        });
        on!(on_ed_generate, |c| c.editor_generate());
        on!(on_save_item, |c| c.save_item());
        on!(on_cancel_edit, |c| c.close_editor());
        on!(on_delete_item, |c| c.delete_item());
        on!(on_copy_code, |c, index| c.copy_code(index));
        on!(on_gen_changed, |c| c.generate());
        on!(on_gen_copy, |c| c.copy_generated());
        on!(on_theme_changed, |c, dark| c
            .app()
            .global::<Theme>()
            .set_dark(dark));
        on!(on_lock_choice_changed, |c, index| {
            let after = LOCK_CHOICES[usize::try_from(index).unwrap_or(1).min(2)];
            c.state.borrow_mut().lock_after = after;
        });
        on!(on_lock_now, |c| c.lock());

        // Secure fields: each key goes straight into its locked buffer.
        let secrets = app.global::<Secrets>();
        let weak = Rc::downgrade(self);
        secrets.on_insert(move |id, text| {
            if let Some(c) = weak.upgrade() {
                c.with_secret(id, |buffer| {
                    buffer.push_str(&text);
                });
            }
        });
        let weak = Rc::downgrade(self);
        secrets.on_backspace(move |id| {
            if let Some(c) = weak.upgrade() {
                c.with_secret(id, SecretBuffer::backspace);
            }
        });
        let weak = Rc::downgrade(self);
        secrets.on_clear(move |id| {
            if let Some(c) = weak.upgrade() {
                c.with_secret(id, SecretBuffer::clear);
            }
        });
        let weak = Rc::downgrade(self);
        secrets.on_paste(move |id, replace| {
            if let Some(c) = weak.upgrade() {
                let Some(pasted) = clipboard::paste_text() else {
                    return;
                };
                let line = pasted.lines().next().unwrap_or_default().to_owned();
                let line = Zeroizing::new(line);
                c.with_secret(id, |buffer| {
                    if replace {
                        buffer.clear();
                    }
                    buffer.push_str(&line);
                });
            }
        });

        // Once a second: codes move on, a copied secret leaves the clipboard, a notice goes
        // away, an idle vault locks.
        let weak = Rc::downgrade(self);
        self.tick
            .start(TimerMode::Repeated, Duration::from_secs(1), move || {
                if let Some(c) = weak.upgrade() {
                    c.every_second();
                }
            });
    }

    // ---- secure fields ----

    fn with_secret(&self, id: i32, change: impl FnOnce(&mut SecretBuffer)) {
        let Some(index) = usize::try_from(id).ok().filter(|i| *i < field::COUNT) else {
            return;
        };
        {
            let mut state = self.state.borrow_mut();
            state.last_touch = Instant::now();
            change(&mut state.secrets[index]);
        }
        // A password typed over a shown one is no longer the one on screen.
        if index == field::ITEM_PASSWORD && !self.app().get_ed_password().is_empty() {
            self.show_editor_password(true);
        }
        self.publish_lengths();
    }

    fn publish_lengths(&self) {
        // The UI learns how many characters each field holds, nothing more.
        let mut lengths = vec![0i32; 15];
        for (slot, buffer) in lengths.iter_mut().zip(&self.state.borrow().secrets) {
            *slot = i32::try_from(buffer.char_count()).unwrap_or(i32::MAX);
        }
        self.app()
            .global::<Secrets>()
            .set_lengths(ModelRc::new(VecModel::from(lengths)));
    }

    fn clear_secrets(&self) {
        for buffer in &mut self.state.borrow_mut().secrets {
            buffer.clear();
        }
        self.publish_lengths();
    }

    fn secret(&self, index: usize) -> Zeroizing<String> {
        Zeroizing::new(self.state.borrow().secrets[index].as_str().to_owned())
    }

    // ---- messages ----

    fn set_error(&self, code: i32, detail: &str) {
        let app = self.app();
        app.set_error_code(code);
        app.set_error_detail(detail.into());
    }

    fn notify(&self, code: i32, arg: &str) {
        let app = self.app();
        app.set_notice_code(code);
        app.set_notice_arg(arg.into());
        self.state.borrow_mut().notice_until = Some(Instant::now() + NOTICE_FOR);
    }

    // ---- slow work ----

    /// Runs `work` off the UI thread and hands its result to `done` back on it (or both here,
    /// when inline). The window shows it is busy meanwhile.
    fn run<R: Send + 'static>(
        &self,
        work: impl FnOnce() -> R + Send + 'static,
        done: fn(&Controller, R),
    ) {
        self.app().set_busy(true);
        if self.state.borrow().inline {
            let result = work();
            self.app().set_busy(false);
            done(self, result);
            return;
        }
        std::thread::spawn(move || {
            let result = work();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(controller) = CURRENT.with(|current| current.borrow().upgrade()) {
                    controller.app().set_busy(false);
                    done(&controller, result);
                }
            });
        });
    }

    // ---- entry: bringing a vault in, unlock ----

    /// The screen for a locked or missing vault, or for a chosen file waiting to open.
    fn show_entry(&self) {
        self.clear_secrets();
        self.set_error(error::NONE, "");
        let app = self.app();
        app.set_page(Page::None);
        let (incoming, path) = {
            let state = self.state.borrow();
            (state.incoming.clone(), state.path.clone())
        };
        app.set_incoming(incoming.is_some());
        app.set_has_copy(path.exists());
        let Some(bytes) = incoming.or_else(|| storage::read(&path).ok()) else {
            app.set_screen(Screen::Start);
            return;
        };
        let known = Vault::inspect(&bytes)
            .ok()
            .and_then(|info| secret_store::load(&info.id_hex).ok().flatten())
            .is_some();
        app.set_needs_secret_key(!known);
        app.set_screen(Screen::Unlock);
    }

    /// A vault file the person chose (from the system's file picker, or shared to the app).
    /// It is only looked at here; it replaces the phone's copy once it opens with the
    /// person's keys and is no older than the copy this phone saw last.
    pub fn bring_vault(&self, bytes: Vec<u8>) {
        if self.app().get_busy() {
            return;
        }
        let info = match Vault::inspect(&bytes) {
            Ok(info) => info,
            Err(err) => return self.set_error(error::NOT_A_VAULT, &err.to_string()),
        };
        if info.needs_keyfile {
            return self.set_error(error::KEYFILE, "");
        }
        self.state.borrow_mut().incoming = Some(bytes);
        if self.is_unlocked() {
            // A newer copy for an open vault: what is open now leaves memory first.
            self.lock();
        } else {
            self.show_entry();
        }
    }

    /// [`Controller::bring_vault`] for a file on a path (the computer's file dialog).
    pub fn bring_vault_file(&self, file: &Path) {
        match std::fs::read(file) {
            Ok(bytes) => self.bring_vault(bytes),
            Err(err) => self.set_error(error::UNREADABLE, &err.to_string()),
        }
    }

    fn unlock(&self) {
        if self.app().get_busy() {
            return;
        }
        self.set_error(error::NONE, "");
        let (incoming, path) = {
            let state = self.state.borrow();
            (state.incoming.clone(), state.path.clone())
        };
        let bytes = match incoming.map_or_else(|| storage::read(&path), Ok) {
            Ok(bytes) => bytes,
            Err(err) => return self.set_error(error::UNREADABLE, &err.to_string()),
        };
        let info = match Vault::inspect(&bytes) {
            Ok(info) => info,
            Err(err) => return self.set_error(error::UNREADABLE, &err.to_string()),
        };
        if info.needs_keyfile {
            return self.set_error(error::KEYFILE, "");
        }
        let (secret_key, typed_key) = match secret_store::load(&info.id_hex).ok().flatten() {
            Some(key) => (key, false),
            None => match SecretKey::parse(self.secret(field::SECRET_KEY).trim()) {
                Ok(key) => (key, true),
                Err(_) => return self.set_error(error::SECRET_KEY, ""),
            },
        };
        let password = self.secret(field::MASTER);
        self.run(
            move || {
                let vault = Vault::open(
                    &bytes,
                    Unlock::Password {
                        password: &password,
                        secret_key: &secret_key,
                    },
                );
                Opened {
                    vault,
                    secret_key,
                    typed_key,
                    hash: fingerprint(&bytes),
                }
            },
            |c, opened| c.opened(opened),
        );
    }

    fn opened(&self, opened: Opened) {
        let vault = match opened.vault {
            Ok(vault) => vault,
            Err(CoreError::KeyfileRequired) => return self.set_error(error::KEYFILE, ""),
            Err(_) => {
                self.state.borrow_mut().secrets[field::MASTER].clear();
                self.publish_lengths();
                return self.set_error(error::WRONG, "");
            }
        };
        let id = vault.id_hex();
        // An older file than the one opened here before: refused, it may be an old copy put
        // in its place.
        // A damaged record of the newest revisions is set aside, never written over.
        let (mut device, state_file) = DeviceState::load_or_set_aside();
        if let RollbackStatus::Older { .. } = device.check_rollback(&id, vault.revision()) {
            return self.set_error(error::OLDER, "");
        }
        // A chosen file proved itself: it becomes the phone's copy (the old one stays as
        // `.bak` next to it).
        let incoming = self.state.borrow_mut().incoming.take();
        if let Some(bytes) = incoming {
            let path = self.state.borrow().path.clone();
            let written = path
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .map_err(|e| e.to_string())
                .and_then(|()| storage::write_atomic(&path, &bytes).map_err(|e| e.to_string()));
            if let Err(detail) = written {
                self.state.borrow_mut().incoming = Some(bytes);
                return self.set_error(error::NOT_SAVED, &detail);
            }
        }
        device.record_revision(&id, vault.revision());
        if state_file != StateFile::Unreadable {
            let _ = device.save();
        }
        if opened.typed_key {
            let _ = secret_store::store(&id, &opened.secret_key);
        }
        {
            let mut state = self.state.borrow_mut();
            state.vault = Some(vault);
            state.secret_key = Some(opened.secret_key);
            state.file_hash = Some(opened.hash);
        }
        self.enter_vault();
        if state_file != StateFile::Read {
            self.notify(notice::STATE_RESET, "");
        }
    }

    fn enter_vault(&self) {
        self.clear_secrets();
        self.set_error(error::NONE, "");
        let app = self.app();
        let (name, path) = {
            let mut state = self.state.borrow_mut();
            state.last_touch = Instant::now();
            state.selected = None;
            state.editing = None;
            let name = state
                .vault
                .as_ref()
                .map(|vault| vault.settings().name.clone())
                .unwrap_or_default();
            (name, state.path.display().to_string())
        };
        app.set_vault_name(name.into());
        app.set_vault_path(path.into());
        app.set_incoming(false);
        app.set_has_copy(true);
        app.set_search(SharedString::new());
        app.set_filter(0);
        app.set_place(Place::Items);
        app.set_page(Page::None);
        app.set_screen(Screen::Vault);
        self.refresh_list();
    }

    /// Locks: the vault and everything read from it leave memory and the screen.
    pub fn lock(&self) {
        {
            let mut state = self.state.borrow_mut();
            state.vault = None;
            state.secret_key = None;
            state.shown.clear();
            state.code_ids.clear();
            state.selected = None;
            state.editing = None;
            state.master_checked = false;
            state.show_password = false;
            state.generated = Zeroizing::new(String::new());
        }
        let app = self.app();
        app.set_items(ModelRc::default());
        app.set_codes(ModelRc::default());
        app.set_total(0);
        app.set_vault_name(SharedString::new());
        app.set_gen_password(SharedString::new());
        app.set_notice_code(0);
        self.clear_item_page();
        self.clear_editor();
        self.show_entry();
    }

    // ---- saving ----

    /// Writes the vault file. Refused when something else changed the file since this app
    /// read or wrote it: the person's other device (or a sync tool) wins, nothing is lost.
    fn save(&self) -> bool {
        let outcome = (|| -> Result<(), String> {
            let mut state = self.state.borrow_mut();
            let state = &mut *state;
            let vault = state.vault.as_mut().ok_or("the vault is locked")?;
            if let Some(expected) = state.file_hash {
                let now = storage::read(&state.path).map_err(|e| e.to_string())?;
                if fingerprint(&now) != expected {
                    return Err("the file was changed by something else".into());
                }
            }
            let bytes = vault.to_bytes().map_err(|e| e.to_string())?;
            if let Some(parent) = state.path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            storage::write_atomic(&state.path, &bytes).map_err(|e| e.to_string())?;
            state.file_hash = Some(fingerprint(&bytes));
            let _ = vault_platform::device::record_revision(&vault.id_hex(), vault.revision());
            Ok(())
        })();
        match outcome {
            Ok(()) => true,
            Err(detail) => {
                self.set_error(error::NOT_SAVED, &detail);
                false
            }
        }
    }

    // ---- the list ----

    fn refresh_list(&self) {
        let app = self.app();
        let words: Vec<String> = app
            .get_search()
            .to_lowercase()
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let filter = app.get_filter();
        let (rows, ids, total) = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            let mut summaries = vault.summaries().unwrap_or_default();
            let total = summaries.len();
            summaries.sort_by_key(|item| item.title.to_lowercase());
            let mut rows = Vec::new();
            let mut ids = Vec::new();
            for item in &summaries {
                let fits = match filter {
                    1 => item.favorite,
                    2 => item.kind == ItemKind::Login,
                    3 => item.kind == ItemKind::Card,
                    4 => item.kind == ItemKind::SecureNote,
                    _ => true,
                };
                let text = format!("{} {} {}", item.title, item.username, item.url).to_lowercase();
                if !fits || !words.iter().all(|word| text.contains(word)) {
                    continue;
                }
                let detail = [&item.username, &item.card_hint, &item.url]
                    .into_iter()
                    .find(|text| !text.is_empty())
                    .cloned()
                    .unwrap_or_default();
                rows.push(ItemRow {
                    title: item.title.as_str().into(),
                    detail: detail.into(),
                    initial: initial(&item.title),
                    tint: tint(
                        item.kind,
                        if item.url.is_empty() {
                            &item.title
                        } else {
                            &item.url
                        },
                    ),
                    kind: kind_index(item.kind),
                    favorite: item.favorite,
                    locked: item.locked,
                });
                ids.push(item.id);
            }
            (rows, ids, total)
        };
        self.state.borrow_mut().shown = ids;
        app.set_items(ModelRc::new(VecModel::from(rows)));
        app.set_total(i32::try_from(total).unwrap_or(i32::MAX));
        self.refresh_codes();
    }

    // ---- one item ----

    /// What stands between the person and this item's secrets: 0 nothing, 1 the master
    /// password, 2 the item PIN, 3 the item password.
    fn check_for(&self, vault: &Vault, item: &ItemData) -> i32 {
        let guard = vault.item_guard();
        if !item.is_locked() && !vault.guards(item) {
            return 0;
        }
        if guard.encrypts() || item.is_locked() {
            if vault.secrets_open() && !item.is_locked() {
                return 0;
            }
            return if guard.check == GuardCheck::Pin { 2 } else { 3 };
        }
        if self.state.borrow().master_checked {
            0
        } else {
            1
        }
    }

    /// The selected item with its secrets, or nothing while it waits for its check.
    fn selected_item(&self) -> Option<ItemData> {
        let state = self.state.borrow();
        let vault = state.vault.as_ref()?;
        let item = vault.get_item(state.selected.as_ref()?).ok()?;
        (self.check_for(vault, &item) == 0).then_some(item)
    }

    fn open_item(&self, index: i32) {
        let id = usize::try_from(index)
            .ok()
            .and_then(|index| self.state.borrow().shown.get(index).copied());
        let Some(id) = id else {
            return;
        };
        {
            let mut state = self.state.borrow_mut();
            state.selected = Some(id);
            state.show_password = false;
        }
        self.set_error(error::NONE, "");
        self.show_item();
        self.app().set_page(Page::Item);
    }

    fn show_item(&self) {
        let app = self.app();
        let state = self.state.borrow();
        let (Some(vault), Some(id)) = (state.vault.as_ref(), state.selected.as_ref()) else {
            return;
        };
        let Ok(item) = vault.get_item(id) else {
            return;
        };
        let check = self.check_for(vault, &item);
        let open = check == 0;
        let website = item.urls.first().cloned().unwrap_or_default();
        app.set_d_title(item.title.as_str().into());
        app.set_d_initial(initial(&item.title));
        app.set_d_tint(tint(
            item.kind,
            if website.is_empty() {
                &item.title
            } else {
                &website
            },
        ));
        app.set_d_kind(kind_index(item.kind));
        app.set_d_favorite(item.favorite);
        app.set_d_username(item.username.as_str().into());
        app.set_d_website(website.into());
        app.set_d_check(check);
        // A note's text is the secret of a note: it waits for the check too.
        let notes_wait = !open && item.kind == ItemKind::SecureNote;
        app.set_d_notes(if notes_wait { "" } else { item.notes.as_str() }.into());
        let card = if item.kind == ItemKind::Card {
            let number = vault_core::card::CardDetails::from_item(&item).number;
            if open && number.len() >= 4 {
                vault_core::card::masked(&number)
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        app.set_d_card(card.into());
        app.set_d_has_password(open && !item.password.is_empty());
        app.set_d_password(if open && state.show_password {
            item.password.as_str().into()
        } else {
            SharedString::new()
        });
        let code = open
            .then(|| Totp::parse(&item.totp).ok())
            .flatten()
            .map(|totp| (totp.now(), totp.period()));
        app.set_d_has_code(code.is_some());
        match code {
            Some(((digits, left), period)) => {
                app.set_d_code(grouped(&digits).into());
                app.set_d_code_left(i32::try_from(left).unwrap_or(0));
                app.set_d_code_period(i32::try_from(period).unwrap_or(30));
            }
            None => app.set_d_code(SharedString::new()),
        }
    }

    fn clear_item_page(&self) {
        let app = self.app();
        for clear in [
            PhoneWindow::set_d_title,
            PhoneWindow::set_d_username,
            PhoneWindow::set_d_password,
            PhoneWindow::set_d_website,
            PhoneWindow::set_d_notes,
            PhoneWindow::set_d_card,
            PhoneWindow::set_d_code,
        ] {
            clear(&app, SharedString::new());
        }
        app.set_d_has_password(false);
        app.set_d_has_code(false);
        app.set_d_check(0);
    }

    /// Leaves the item: what the item lock opened for it is closed again.
    fn close_item(&self) {
        {
            let mut state = self.state.borrow_mut();
            state.selected = None;
            state.show_password = false;
            state.master_checked = false;
            if let Some(vault) = state.vault.as_mut() {
                vault.lock_secrets();
            }
            state.secrets[field::ITEM_CHECK].clear();
        }
        self.publish_lengths();
        self.set_error(error::NONE, "");
        self.clear_item_page();
        self.app().set_page(Page::None);
        self.refresh_list();
    }

    /// The item lock's check, typed on the item's page.
    fn unlock_item(&self) {
        if self.app().get_busy() {
            return;
        }
        let typed = self.secret(field::ITEM_CHECK);
        if typed.is_empty() {
            return self.set_error(error::WRONG_CHECK, "");
        }
        let check = self.app().get_d_check();
        if check == 1 {
            // The master password, tried against the vault file itself.
            let (path, secret_key) = {
                let state = self.state.borrow();
                // A copy for the check's own thread, made from its printed form.
                let key = state
                    .secret_key
                    .as_ref()
                    .and_then(|key| SecretKey::parse(&key.to_display_string()).ok());
                (state.path.clone(), key)
            };
            let Some(secret_key) = secret_key else {
                return;
            };
            return self.run(
                move || {
                    storage::read(&path).is_ok_and(|bytes| {
                        Vault::open(
                            &bytes,
                            Unlock::Password {
                                password: &typed,
                                secret_key: &secret_key,
                            },
                        )
                        .is_ok()
                    })
                },
                |c, right| c.item_checked(right),
            );
        }
        let right = {
            let mut state = self.state.borrow_mut();
            state
                .vault
                .as_mut()
                .is_some_and(|vault| vault.unlock_secrets(&typed).unwrap_or(false))
        };
        if right {
            // Items added while the lock was closed are sealed under it now.
            let sealed = {
                let mut state = self.state.borrow_mut();
                state
                    .vault
                    .as_mut()
                    .and_then(|vault| vault.seal_pending().ok())
                    .unwrap_or(0)
            };
            if sealed > 0 {
                self.save();
            }
        }
        self.item_checked(right);
    }

    fn item_checked(&self, right: bool) {
        self.state.borrow_mut().secrets[field::ITEM_CHECK].clear();
        self.publish_lengths();
        if !right {
            return self.set_error(error::WRONG_CHECK, "");
        }
        if self.app().get_d_check() == 1 {
            self.state.borrow_mut().master_checked = true;
        }
        self.set_error(error::NONE, "");
        self.show_item();
    }

    fn toggle_favorite(&self) {
        let changed = {
            let mut state = self.state.borrow_mut();
            let state = &mut *state;
            let (Some(vault), Some(id)) = (state.vault.as_mut(), state.selected) else {
                return;
            };
            // Read as it is (locked or not) and written back: only the mark changes.
            vault.get_item(&id).is_ok_and(|mut item| {
                item.favorite = !item.favorite;
                item.touch();
                vault.update_item(&id, &item).is_ok()
            })
        };
        if changed && self.save() {
            self.show_item();
        }
    }

    // ---- copying ----

    /// Puts a secret on the clipboard (out of its history where the system allows) and
    /// remembers to take it back.
    fn copy_secret(&self, value: &str, code: i32) {
        if clipboard::copy_secret(value).is_err() {
            return;
        }
        self.state.borrow_mut().copied = Some((
            Zeroizing::new(value.to_owned()),
            Instant::now() + Duration::from_secs(CLIPBOARD_SECONDS),
        ));
        self.notify(code, &CLIPBOARD_SECONDS.to_string());
    }

    fn copy(&self, what: i32) {
        // Username and website show while the item is locked; the rest goes through
        // `selected_item`, which gives nothing before the check.
        let plain = {
            let state = self.state.borrow();
            state
                .vault
                .as_ref()
                .zip(state.selected.as_ref())
                .and_then(|(vault, id)| vault.get_item(id).ok())
        };
        match what {
            0 | 3 => {
                let Some(item) = plain else {
                    return;
                };
                let (value, code) = if what == 0 {
                    (item.username.clone(), notice::USERNAME_COPIED)
                } else {
                    (
                        item.urls.first().cloned().unwrap_or_default(),
                        notice::WEBSITE_COPIED,
                    )
                };
                if clipboard::copy_plain(&value).is_ok() {
                    self.notify(code, "");
                }
            }
            1 => {
                if let Some(item) = self.selected_item() {
                    self.copy_secret(&item.password, notice::PASSWORD_COPIED);
                }
            }
            2 => {
                let code = self
                    .selected_item()
                    .and_then(|item| Totp::parse(&item.totp).ok())
                    .map(|totp| totp.now().0);
                if let Some(code) = code {
                    self.copy_secret(&code, notice::CODE_COPIED);
                }
            }
            _ => {}
        }
    }

    // ---- codes ----

    fn refresh_codes(&self) {
        let (rows, ids) = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            let mut summaries = vault.summaries().unwrap_or_default();
            summaries.retain(|item| item.has_totp);
            summaries.sort_by_key(|item| item.title.to_lowercase());
            let mut rows = Vec::new();
            let mut ids = Vec::new();
            for summary in &summaries {
                let Ok(item) = vault.get_item(&summary.id) else {
                    continue;
                };
                // Behind the item lock: the row says so instead of showing digits.
                let code = (self.check_for(vault, &item) == 0)
                    .then(|| Totp::parse(&item.totp).ok())
                    .flatten()
                    .map(|totp| (totp.now(), totp.period()));
                let (digits, left, period) = match code {
                    Some(((digits, left), period)) => (grouped(&digits), left, period),
                    None => (String::new(), 0, 30),
                };
                rows.push(CodeRow {
                    title: summary.title.as_str().into(),
                    account: summary.username.as_str().into(),
                    code: digits.into(),
                    left: i32::try_from(left).unwrap_or(0),
                    period: i32::try_from(period).unwrap_or(30),
                    initial: initial(&summary.title),
                    tint: tint(
                        summary.kind,
                        if summary.url.is_empty() {
                            &summary.title
                        } else {
                            &summary.url
                        },
                    ),
                });
                ids.push(summary.id);
            }
            (rows, ids)
        };
        self.state.borrow_mut().code_ids = ids;
        self.app().set_codes(ModelRc::new(VecModel::from(rows)));
    }

    fn copy_code(&self, index: i32) {
        let code = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            usize::try_from(index)
                .ok()
                .and_then(|index| state.code_ids.get(index))
                .and_then(|id| vault.get_item(id).ok())
                .filter(|item| self.check_for(vault, item) == 0)
                .and_then(|item| Totp::parse(&item.totp).ok())
                .map(|totp| totp.now().0)
        };
        if let Some(code) = code {
            self.copy_secret(&code, notice::CODE_COPIED);
        }
    }

    // ---- the editor ----

    fn clear_editor(&self) {
        let app = self.app();
        for clear in [
            PhoneWindow::set_ed_title,
            PhoneWindow::set_ed_username,
            PhoneWindow::set_ed_website,
            PhoneWindow::set_ed_totp,
            PhoneWindow::set_ed_notes,
            PhoneWindow::set_ed_password,
        ] {
            clear(&app, SharedString::new());
        }
        app.set_ed_favorite(false);
        app.set_ed_confirm_delete(false);
    }

    /// Opens the editor on a new item, or on `id` (whose secrets must be open).
    fn open_editor(&self, id: Option<ItemId>) {
        let item = match id {
            Some(_) => match self.selected_item() {
                Some(item) => Some(item),
                None => return,
            },
            None => None,
        };
        self.clear_editor();
        self.set_error(error::NONE, "");
        let app = self.app();
        app.set_ed_new(item.is_none());
        app.set_ed_kind(match item.as_ref().map(|item| item.kind) {
            Some(ItemKind::SecureNote) => 1,
            _ => 0,
        });
        {
            let mut state = self.state.borrow_mut();
            state.editing = id;
            state.confirm_delete = false;
            let password = item.as_ref().map_or("", |item| item.password.as_str());
            state.secrets[field::ITEM_PASSWORD].set(password);
        }
        if let Some(item) = &item {
            app.set_ed_title(item.title.as_str().into());
            app.set_ed_username(item.username.as_str().into());
            app.set_ed_website(item.urls.first().cloned().unwrap_or_default().into());
            app.set_ed_totp(item.totp.as_str().into());
            app.set_ed_notes(item.notes.as_str().into());
            app.set_ed_favorite(item.favorite);
        }
        self.publish_lengths();
        app.set_page(Page::Editor);
    }

    fn show_editor_password(&self, shown: bool) {
        let text: SharedString = if shown {
            self.state.borrow().secrets[field::ITEM_PASSWORD]
                .as_str()
                .into()
        } else {
            SharedString::new()
        };
        self.app().set_ed_password(text);
    }

    fn editor_generate(&self) {
        let Ok(password) = generate_password(&PasswordOptions::default()) else {
            return;
        };
        self.state.borrow_mut().secrets[field::ITEM_PASSWORD].set(&password);
        self.publish_lengths();
        // A password nobody typed is shown, so the person sees what they are saving.
        self.show_editor_password(true);
    }

    fn close_editor(&self) {
        let back_to_item = {
            let mut state = self.state.borrow_mut();
            state.secrets[field::ITEM_PASSWORD].clear();
            state.confirm_delete = false;
            state.editing.take().is_some() && state.selected.is_some()
        };
        self.publish_lengths();
        self.clear_editor();
        self.set_error(error::NONE, "");
        if back_to_item {
            self.show_item();
            self.app().set_page(Page::Item);
        } else {
            self.app().set_page(Page::None);
            self.refresh_list();
        }
    }

    fn save_item(&self) {
        let app = self.app();
        let title = app.get_ed_title().trim().to_owned();
        if title.is_empty() {
            return self.set_error(error::NAME, "");
        }
        let note = app.get_ed_kind() == 1;
        let totp = app.get_ed_totp().trim().to_owned();
        if !note && !totp.is_empty() && Totp::parse(&totp).is_err() {
            return self.set_error(error::TOTP, "");
        }
        let password = self.secret(field::ITEM_PASSWORD);
        let stored = {
            let mut state = self.state.borrow_mut();
            let state = &mut *state;
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            let existing = state.editing.and_then(|id| vault.get_item(&id).ok());
            let mut item = existing.clone().unwrap_or_else(|| {
                ItemData::new(
                    if note {
                        ItemKind::SecureNote
                    } else {
                        ItemKind::Login
                    },
                    &title,
                )
            });
            item.title = title;
            item.notes = app.get_ed_notes().to_string();
            item.favorite = app.get_ed_favorite();
            if item.kind == ItemKind::Login {
                item.username = app.get_ed_username().trim().to_owned();
                item.password = password.to_string();
                item.totp = totp;
                let website = app.get_ed_website().trim().to_owned();
                // The first website is the one edited here; any others stay.
                match (item.urls.first_mut(), website.is_empty()) {
                    (Some(first), false) => *first = website,
                    (Some(_), true) => {
                        item.urls.remove(0);
                    }
                    (None, false) => item.urls.push(website),
                    (None, true) => {}
                }
            }
            item.touch();
            match state.editing {
                Some(id) => vault.update_item(&id, &item).map(|()| id),
                None => vault.add_item(&item),
            }
        };
        let id = match stored {
            Ok(id) => id,
            Err(err) => return self.set_error(error::NOT_SAVED, &err.to_string()),
        };
        if !self.save() {
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            state.selected = Some(id);
            state.editing = Some(id);
            state.show_password = false;
        }
        self.close_editor();
        self.notify(notice::SAVED, "");
    }

    /// Delete, asked twice: the first tap changes the button's words.
    fn delete_item(&self) {
        if !self.state.borrow().confirm_delete {
            self.state.borrow_mut().confirm_delete = true;
            self.app().set_ed_confirm_delete(true);
            return;
        }
        let removed = {
            let mut state = self.state.borrow_mut();
            let state = &mut *state;
            let (Some(vault), Some(id)) = (state.vault.as_mut(), state.editing) else {
                return;
            };
            let title = vault.get_item(&id).map(|item| item.title.clone()).ok();
            vault.remove_item(&id).ok().and(title)
        };
        let Some(title) = removed else {
            return;
        };
        if !self.save() {
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            state.editing = None;
            state.selected = None;
        }
        self.close_editor();
        self.clear_item_page();
        self.notify(notice::DELETED, &title);
    }

    // ---- generator ----

    fn generate(&self) {
        let app = self.app();
        let made = if app.get_gen_mode() == 1 {
            let options = PassphraseOptions {
                words: usize::try_from(app.get_gen_words()).unwrap_or(6),
                case: WordCase::Lower,
                ..PassphraseOptions::default()
            };
            generate_passphrase(&options).map(|phrase| (phrase, options.entropy_bits()))
        } else {
            let options = PasswordOptions {
                length: usize::try_from(app.get_gen_length()).unwrap_or(20),
                uppercase: app.get_gen_upper(),
                lowercase: app.get_gen_lower(),
                digits: app.get_gen_digits(),
                symbols: app.get_gen_symbols(),
                ..PasswordOptions::default()
            };
            generate_password(&options).map(|password| (password, options.entropy_bits()))
        };
        match made {
            Ok((password, bits)) => {
                self.set_error(error::NONE, "");
                app.set_gen_password(password.as_str().into());
                app.set_gen_bits(bits.round() as i32);
                self.state.borrow_mut().generated = password;
            }
            Err(_) => {
                app.set_gen_password(SharedString::new());
                app.set_gen_bits(0);
                self.state.borrow_mut().generated = Zeroizing::new(String::new());
                self.set_error(error::NO_CHARACTERS, "");
            }
        }
    }

    fn copy_generated(&self) {
        let password = self.state.borrow().generated.clone();
        if !password.is_empty() {
            self.copy_secret(&password, notice::COPIED);
        }
    }

    // ---- time ----

    fn every_second(&self) {
        let now = Instant::now();
        let (expired_copy, notice_over, idle) = {
            let mut state = self.state.borrow_mut();
            let expired = state
                .copied
                .take_if(|(_, until)| now >= *until)
                .map(|(value, _)| value);
            let notice_over = state.notice_until.take_if(|until| now >= *until).is_some();
            let idle =
                state.vault.is_some() && now.duration_since(state.last_touch) >= state.lock_after;
            (expired, notice_over, idle)
        };
        if let Some(value) = expired_copy {
            // Only if it is still ours: something copied since stays.
            clipboard::clear_if(&value);
        }
        if notice_over {
            self.app().set_notice_code(0);
        }
        if idle {
            return self.lock();
        }
        let app = self.app();
        if app.get_screen() != Screen::Vault {
            return;
        }
        if app.get_page() == Page::Item && app.get_d_has_code() {
            self.show_item();
        } else if app.get_page() == Page::None && app.get_place() == Place::Codes {
            self.refresh_codes();
        }
    }

    /// The vault file this window is about.
    pub fn path(&self) -> PathBuf {
        self.state.borrow().path.clone()
    }

    /// Whether a vault is open (for the shell: what to do when the app comes back).
    pub fn is_unlocked(&self) -> bool {
        self.state.borrow().vault.is_some()
    }
}
