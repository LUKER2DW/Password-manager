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
    time::Duration,
};

use sha2::{Digest, Sha256};
use slint::{Color, ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel};
use vault_core::{
    Error as CoreError, GuardCheck, ItemData, ItemId, ItemKind, SecretKey, Unlock, Vault,
    card::{self, CardDetails, CardProblem},
    generator::{
        PassphraseOptions, PasswordOptions, WordCase, generate_passphrase, generate_password,
    },
    totp::{self, Totp},
};
// The std clock on a phone or computer; the browser's in the web preview.
use web_time::Instant;
use zeroize::Zeroizing;

use crate::{
    platform::{
        DeviceState, RollbackStatus, SecretBuffer, StateFile, clipboard, files, secret_store,
    },
    prefs::{self, Prefs},
    sketch,
    system::{NoSystem, System},
    ui::{CodeRow, ItemRow, Page, PhoneWindow, Place, Screen, Secrets, Sketch, Theme},
    view,
};

/// Secure field ids (the `field` of each `SecretField` in app.slint).
mod field {
    pub const MASTER: usize = 0;
    pub const SECRET_KEY: usize = 1;
    pub const ITEM_CHECK: usize = 2;
    pub const ITEM_PASSWORD: usize = 3;
    /// The WebDAV password in Settings → Sync.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const SYNC_PASSWORD: usize = 4;
    /// Settings → Master password: the current one, the new one and the new one again.
    pub const CURRENT: usize = 5;
    pub const NEW: usize = 6;
    pub const NEW_AGAIN: usize = 7;
    /// Settings → Import and export: the password of the file to import.
    pub const IMPORT_PASSWORD: usize = 8;
    pub const COUNT: usize = 9;
}

/// The shortest master password the phone sets (the desktop's rule).
const MIN_MASTER_PASSWORD_CHARS: usize = 12;

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
    /// Setting the phone up from the server failed (the detail says why).
    pub const SYNC_SETUP: i32 = 12;
    pub const WRONG_CURRENT: i32 = 13;
    pub const MISMATCH: i32 = 14;
    pub const TOO_SHORT: i32 = 15;
    /// A copy of the vault didn't pass its check after it was saved (it was deleted).
    pub const BACKUP_CHECK: i32 = 16;
    pub const CARD_NUMBER: i32 = 17;
    pub const CARD_EXPIRY: i32 = 18;
    pub const CARD_CODE: i32 = 19;
    pub const CARD_PIN: i32 = 20;
    pub const SETUP_KEY: i32 = 21;
    pub const NOT_A_KEY: i32 = 22;
    pub const FILE_TOO_LARGE: i32 = 23;
    pub const BIOMETRICS: i32 = 24;
    pub const IMPORT: i32 = 25;
    pub const IMPORT_PASSWORD: i32 = 26;
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const UPDATE: i32 = 27;
    /// What was pasted or scanned isn't an invite line (`vaultsync:1?…`).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const NOT_INVITE: i32 = 28;
    /// The QR code can't be scanned ("unavailable": no Google Play services, or the detail).
    pub const CAMERA: i32 = 29;
}

/// Where the line of a scanned QR code goes (the screens' `scan-invite` purpose).
pub mod scan {
    /// The start screen's "From your vault server".
    pub const SETUP: i32 = 0;
    /// Settings, Sync: joining the server with an invite.
    pub const JOIN: i32 = 1;
}

/// The editor's kinds (`ed-kind`), the desktop's: an authenticator item is a login kept for
/// its one-time codes (a setup key and no password).
mod editor {
    pub const LOGIN: i32 = 0;
    pub const CARD: i32 = 1;
    pub const NOTE: i32 = 2;
    pub const AUTHENTICATOR: i32 = 3;
    pub const SSH: i32 = 4;
}

mod attachments;
mod filling;
mod icons;
mod settings;
mod syncing;
mod watch;

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
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const SYNCED: i32 = 9;
    pub const PASSWORD_CHANGED: i32 = 10;
    pub const BACKUP_CONFIRMED: i32 = 11;
    pub const FILE_SAVED: i32 = 12;
    pub const COPIED_PLAIN: i32 = 13;
    pub const BIO_ON: i32 = 14;
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const DEVICE_REMOVED: i32 = 15;
    pub const BIO_REVOKED: i32 = 16;
    pub const VAULT_REMOVED: i32 = 17;
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const BACKUP_JOINED: i32 = 18;
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const ADDRESS_CHANGED: i32 = 19;
    pub const DROPPED: i32 = 20;
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const LEAKS_NEW: i32 = 21;
}

/// How long a copied secret may stay on the clipboard (Settings), in seconds.
const CLIPBOARD_CHOICES: [u32; 3] = [15, 30, 60];
/// What a secret field's hidden input holds instead of each character (system keyboard):
/// characters secret buffers never take, one for each UTF-8 length. A stand-in is as long as
/// the character it replaces in UTF-8 and in UTF-16, so the place the keyboard puts the
/// cursor (an offset into what it typed) still falls between two characters; anywhere else,
/// Slint's password mask panics.
const STAND_INS: [char; 4] = ['\u{1}', '\u{80}', '\u{E000}', '\u{F0000}'];

fn is_stand_in(c: char) -> bool {
    STAND_INS.contains(&c)
}

/// `text` with each character a buffer takes replaced by its stand-in; the others (stand-ins
/// already, a control character the keyboard sent) stay as they are, since they aren't in the
/// buffer either.
fn stand_ins(text: &str) -> String {
    text.chars()
        .map(|c| {
            if SecretBuffer::takes(c) {
                STAND_INS[c.len_utf8() - 1]
            } else {
                c
            }
        })
        .collect()
}
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

pub(super) fn tint(kind: ItemKind, key: &str) -> Color {
    let (r, g, b) = match kind {
        ItemKind::Card => (0x4A, 0x5D, 0x7E),
        ItemKind::SecureNote => (0x2F, 0x7D, 0x68),
        ItemKind::Passkey => (0x5C, 0x4B, 0x7A),
        ItemKind::SshKey => (0x3E, 0x4A, 0x5C),
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

pub(super) fn initial(title: &str) -> SharedString {
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
        ItemKind::SshKey => 4,
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

fn editor_kind(item: &ItemData) -> i32 {
    match item.kind {
        ItemKind::Card => editor::CARD,
        ItemKind::SecureNote => editor::NOTE,
        ItemKind::SshKey => editor::SSH,
        ItemKind::Login if item.password.is_empty() && !item.totp.is_empty() => {
            editor::AUTHENTICATOR
        }
        _ => editor::LOGIN,
    }
}

/// The leak watch's check of every login (`vault_platform::leak_check::lookup`, or a test's
/// stand-in).
type LeakBatch =
    fn(&[(usize, vault_core::health::BreachQuery)]) -> Result<Vec<(usize, u64)>, String>;

fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// "12 KB", "1.4 MB": a file's size as the screens show it.
fn size_text(len: usize) -> String {
    if len < 1024 * 1024 {
        format!("{} KB", len.div_ceil(1024))
    } else {
        format!("{:.1} MB", len as f64 / (1024.0 * 1024.0))
    }
}

/// "1,234": a count with its thousands apart.
fn grouped_count(count: u64) -> String {
    let digits = count.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
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
    /// The fields whose eye is open (their text is on screen while it is).
    showing: [bool; field::COUNT],
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
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    sync: syncing::SyncStatus,
    /// SHA-256 of the vault file handed out to be saved as a copy, until it is read back.
    backup_expected: Option<[u8; 32]>,
    /// This phone's settings (`settings.json` next to the vault copy).
    prefs: Prefs,
    /// The editor's files and SSH private key (attachments.rs), never in a Slint string.
    editor_files: Vec<vault_core::Attachment>,
    editor_ssh: Option<Zeroizing<String>>,
    /// SHA-256 of a file handed out to be saved, until it is read back.
    file_expected: Option<[u8; 32]>,
    /// While another vault is being added: the one to go back to.
    previous: Option<PathBuf>,
    /// What an open fingerprint prompt is for.
    bio: settings::BioPending,
    /// The leak check ("Check this password"), and the item it was asked for.
    leak_lookup: fn(&str) -> Result<u64, String>,
    leak_for: Option<ItemId>,
    /// The leak watch: how it asks (the tests put a stand-in in its place), the logins its last
    /// check found in a breach, and when it last looked whether a day had passed.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    leak_batch: LeakBatch,
    leaked: std::collections::HashSet<ItemId>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    watch_looked: Option<Instant>,
}

thread_local! {
    /// The controller of this thread's window, for work that finishes on another thread.
    static CURRENT: RefCell<Weak<Controller>> = const { RefCell::new(Weak::new()) };
}

pub struct Controller {
    app: slint::Weak<PhoneWindow>,
    state: RefCell<State>,
    /// Website icons found so far (apart from `state`: the list reads them while it reads
    /// the vault).
    icons: RefCell<icons::Icons>,
    tick: Timer,
    /// What only the phone's own system does (biometrics, screenshots, autofill).
    system: RefCell<Rc<dyn System>>,
    /// Sync: a round a moment after a save, and one every few minutes (not in a browser).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    sync_soon: Timer,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    sync_every: Timer,
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
    /// Opened with the master password (not the fingerprint).
    by_password: bool,
}

impl Controller {
    /// Wires the window and shows the first screen for the phone's copy of the vault at
    /// `path`. `inline` runs slow work on the calling thread (tests, screenshots).
    ///
    /// The window's `pick-vault` callback is left to the shell: it shows the system's file
    /// picker and hands the chosen file to [`Controller::bring_vault`].
    pub fn start(app: &PhoneWindow, path: PathBuf, inline: bool) -> Rc<Self> {
        let prefs = Prefs::load(&prefs::path_for(&path));
        // The vault open last, when the phone keeps more than one (they sit next to each
        // other, and to `settings.json`).
        let path = if prefs::is_vault_file(&prefs.current) {
            path.with_file_name(&prefs.current)
        } else {
            path
        };
        let controller = Rc::new(Self {
            app: app.as_weak(),
            icons: RefCell::default(),
            state: RefCell::new(State {
                inline,
                prefs: prefs.clone(),
                path,
                incoming: None,
                vault: None,
                secret_key: None,
                file_hash: None,
                secrets: std::array::from_fn(|_| SecretBuffer::new()),
                showing: [false; field::COUNT],
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
                sync: syncing::SyncStatus::default(),
                backup_expected: None,
                editor_files: Vec::new(),
                editor_ssh: None,
                file_expected: None,
                previous: None,
                bio: settings::BioPending::None,
                leak_lookup: settings::leak_lookup_default,
                leak_for: None,
                leak_batch: settings::leak_batch_default,
                leaked: std::collections::HashSet::new(),
                watch_looked: None,
                lock_after: LOCK_CHOICES[usize::from(prefs.lock_choice).min(2)],
            }),
            tick: Timer::default(),
            system: RefCell::new(Rc::new(NoSystem)),
            sync_soon: Timer::default(),
            sync_every: Timer::default(),
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
        app.global::<Theme>().set_dark(prefs.dark_theme);
        app.global::<Theme>()
            .set_backdrop(i32::from(prefs.backdrop));
        app.set_lock_choice(i32::from(prefs.lock_choice.min(2)));
        app.set_clipboard_choice(
            CLIPBOARD_CHOICES
                .iter()
                .position(|s| *s == prefs.clipboard_seconds)
                .map_or(1, |i| i32::try_from(i).unwrap_or(1)),
        );
        app.set_website_icons(prefs.website_icons);
        app.set_lock_on_leave(prefs.lock_on_leave);
        app.set_allow_capture(prefs.allow_capture);
        app.set_leak_watch(prefs.leak_watch);
        controller.show_generator(&prefs.generator);
        controller.wire(app);
        controller.apply_language(&prefs.language);
        controller.show_entry();
        controller.publish_vaults();
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
        on!(on_sync_join, |c| c.sync_join());
        on!(on_setup_from_server, |c| c.setup_from_server());
        on!(on_scan_invite, |c, purpose| c.scan_invite(purpose));
        on!(on_sync_use_webdav, |c| c.sync_use_webdav());
        on!(on_sync_now, |c| c.sync_round());
        on!(on_sync_stop, |c| c.sync_stop());
        on!(on_search_changed, |c, _text| c.refresh_list());
        on!(on_filter_changed, |c, _index| c.refresh_list());
        on!(on_open_item, |c, index| c.open_item(index));
        on!(on_new_item, |c| c.open_editor(None));
        on!(on_ed_ssh_generate, |c| c.ssh_generate());
        on!(on_ed_ssh_paste, |c| c.ssh_paste());
        on!(on_ed_file_remove, |c, index| c.file_remove(index));
        on!(on_new_code, |c| {
            c.open_editor(None);
            c.app().set_ed_kind(editor::AUTHENTICATOR);
        });
        on!(on_ed_card_number_edited, |c, text| {
            let digits = card::digits(&text);
            let brand = if digits.is_empty() {
                ""
            } else {
                card::detect_brand(&digits).name()
            };
            c.app().set_ed_card_brand(brand.into());
        });
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
        on!(on_theme_changed, |c, dark| {
            c.app().global::<Theme>().set_dark(dark);
            c.change_prefs(|prefs| prefs.dark_theme = dark);
        });
        on!(on_lock_choice_changed, |c, index| {
            let index = usize::try_from(index).unwrap_or(1).min(2);
            c.state.borrow_mut().lock_after = LOCK_CHOICES[index];
            c.change_prefs(|prefs| prefs.lock_choice = u8::try_from(index).unwrap_or(1));
        });
        on!(on_clipboard_choice_changed, |c, index| {
            let seconds = CLIPBOARD_CHOICES[usize::try_from(index).unwrap_or(1).min(2)];
            c.change_prefs(|prefs| prefs.clipboard_seconds = seconds);
        });
        on!(on_backdrop_changed, |c, on| {
            c.app().global::<Theme>().set_backdrop(i32::from(on));
            c.change_prefs(|prefs| prefs.backdrop = on);
        });
        on!(on_website_icons_changed, |c, on| {
            c.change_prefs(|prefs| prefs.website_icons = on);
            if on {
                c.load_icons();
                c.fetch_icons();
            } else {
                c.forget_icons();
            }
            c.refresh_list();
        });
        on!(on_lock_now, |c| c.lock());
        on!(on_bio_toggled, |c, on| c.bio_toggled(on));
        on!(on_bio_unlock, |c| c.bio_unlock());
        on!(on_lock_on_leave_changed, |c, on| c
            .lock_on_leave_changed(on));
        on!(on_allow_capture_changed, |c, on| c
            .allow_capture_changed(on));
        on!(on_leak_watch_changed, |c, on| {
            c.change_prefs(|prefs| prefs.leak_watch = on);
            c.watch_leaks();
        });
        on!(on_open_autofill_settings, |c| c
            .system()
            .open_autofill_settings());
        on!(on_switch_vault, |c, index| c.switch_vault(index));
        on!(on_add_vault, |c| c.add_vault());
        on!(on_cancel_add_vault, |c| c.cancel_add_vault());
        on!(on_remove_vault, |c| c.remove_vault());
        on!(on_language_changed, |c, index| c.language_changed(index));
        on!(on_check_password, |c| c.check_password());
        on!(on_sync_remove_device, |c, index| c
            .sync_remove_device(index));
        on!(on_sync_add_device, |c| c.sync_add_device());
        on!(on_sync_hide_invite, |c| c.sync_hide_invite());
        on!(on_sync_copy_invite, |c| {
            let line = c.app().get_sync_invite();
            if !line.is_empty() {
                c.copy_secret(&line, notice::COPIED);
            }
        });
        on!(on_sync_change_address, |c| c.sync_change_address());
        on!(on_sync_join_backup, |c| c.sync_join_backup());
        on!(on_sync_remove_backup, |c| c.sync_remove_backup());
        on!(on_check_update, |c| c.check_update());
        on!(on_install_update, |c| c.install_update());
        on!(on_change_password, |c| c.change_password());
        on!(on_cancel_password_change, |c| c.close_password_change());

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
        secrets.on_toggle_shown(move |id| {
            if let Some(c) = weak.upgrade()
                && let Some(index) = usize::try_from(id).ok().filter(|i| *i < field::COUNT)
            {
                {
                    let mut state = c.state.borrow_mut();
                    state.showing[index] = !state.showing[index];
                }
                c.publish_lengths();
            }
        });
        let weak = Rc::downgrade(self);
        secrets.on_clear(move |id| {
            if let Some(c) = weak.upgrade() {
                c.with_secret(id, SecretBuffer::clear);
            }
        });
        // The system keyboard (Android): each edit of the hidden input, whose cursor stays at
        // the end. Stand-ins are what the field already holds; fewer of them is that many
        // deleted, anything else is what was typed (or pasted). The input gets stand-ins back
        // at once, laid out like what came in.
        let weak = Rc::downgrade(self);
        secrets.on_typed(move |id, text| {
            let Some(c) = weak.upgrade() else {
                return SharedString::new();
            };
            let kept = text.chars().filter(|ch| is_stand_in(*ch)).count();
            c.with_secret(id, |buffer| {
                for _ in kept..buffer.char_count() {
                    buffer.backspace();
                }
                // The buffer skips the stand-ins.
                buffer.push_str(&text);
            });
            SharedString::from(stand_ins(&text).as_str())
        });
        let weak = Rc::downgrade(self);
        secrets.on_placeholders(move |id| {
            weak.upgrade()
                .map(|c| c.placeholders(id))
                .unwrap_or_default()
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

    // ---- settings ----

    fn change_prefs(&self, change: impl FnOnce(&mut Prefs)) {
        let mut state = self.state.borrow_mut();
        change(&mut state.prefs);
        state.prefs.save(&prefs::path_for(&state.path));
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

    /// A one-byte stand-in for each character field `id` holds.
    fn placeholders(&self, id: i32) -> SharedString {
        let count = usize::try_from(id)
            .ok()
            .and_then(|i| {
                self.state
                    .borrow()
                    .secrets
                    .get(i)
                    .map(SecretBuffer::char_count)
            })
            .unwrap_or(0);
        SharedString::from(STAND_INS[0].to_string().repeat(count).as_str())
    }

    fn publish_lengths(&self) {
        // The UI learns how many characters each field holds, nothing more; and the text only
        // of a field whose eye the person opened.
        let mut lengths = vec![0i32; 15];
        let state = self.state.borrow();
        for (slot, buffer) in lengths.iter_mut().zip(&state.secrets) {
            *slot = i32::try_from(buffer.char_count()).unwrap_or(i32::MAX);
        }
        let shown: Vec<SharedString> = state
            .secrets
            .iter()
            .zip(state.showing)
            .map(|(buffer, on)| {
                if on {
                    buffer.as_str().into()
                } else {
                    SharedString::new()
                }
            })
            .collect();
        let cells: Vec<ModelRc<SharedString>> = (0..field::COUNT)
            .map(|index| {
                if state.showing[index] && index == field::SECRET_KEY {
                    let cells = view::key_cells(state.secrets[index].as_str(), 4, 7);
                    ModelRc::new(VecModel::from(
                        cells
                            .iter()
                            .map(|c| c.as_str().into())
                            .collect::<Vec<SharedString>>(),
                    ))
                } else {
                    ModelRc::default()
                }
            })
            .collect();
        let showing = state.showing.to_vec();
        drop(state);
        let app = self.app();
        let secrets = app.global::<Secrets>();
        secrets.set_lengths(ModelRc::new(VecModel::from(lengths)));
        secrets.set_showing(ModelRc::new(VecModel::from(showing)));
        secrets.set_shown(ModelRc::new(VecModel::from(shown)));
        secrets.set_shown_cells(ModelRc::new(VecModel::from(cells)));
    }

    fn clear_secrets(&self) {
        {
            let mut state = self.state.borrow_mut();
            for buffer in &mut state.secrets {
                buffer.clear();
            }
            state.showing = [false; field::COUNT];
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

    /// [`Controller::run`] without showing the window as busy: work the person didn't ask for
    /// just now (the leak watch).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn run_quietly<R: Send + 'static>(
        &self,
        work: impl FnOnce() -> R + Send + 'static,
        done: fn(&Controller, R),
    ) {
        if self.state.borrow().inline {
            let result = work();
            done(self, result);
            return;
        }
        std::thread::spawn(move || {
            let result = work();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(controller) = CURRENT.with(|current| current.borrow().upgrade()) {
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
        let Some(bytes) = incoming.or_else(|| files::read(&path).ok()) else {
            app.set_bio_ready(false);
            app.set_bio_stale(false);
            app.set_screen(Screen::Start);
            return;
        };
        let known = Vault::inspect(&bytes)
            .ok()
            .and_then(|info| secret_store::load(&info.id_hex).ok().flatten())
            .is_some();
        app.set_needs_secret_key(!known);
        app.set_screen(Screen::Unlock);
        self.offer_biometrics(false);
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

    /// The shell couldn't open the file picker, or read or write a file through it.
    pub fn file_failed(&self, detail: &str) {
        self.set_error(error::UNREADABLE, detail);
    }

    /// Settings → Save a copy of the vault: the phone's vault file as it is now, and a name
    /// for it. The shell asks where to put it, writes it there, reads it back and hands what
    /// it read to [`Controller::copy_written`]. `None` while locked, or when something else
    /// changed the file (the error says so).
    pub fn copy_to_save(&self) -> Option<(String, Vec<u8>)> {
        let (bytes, expected) = {
            let state = self.state.borrow();
            state.vault.as_ref()?;
            (files::read(&state.path), state.file_hash)
        };
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(err) => {
                self.set_error(error::UNREADABLE, &err.to_string());
                return None;
            }
        };
        let hash = fingerprint(&bytes);
        if expected.is_some_and(|known| known != hash) {
            self.set_error(
                error::BACKUP_CHECK,
                "the vault file was changed by something else; lock and unlock first",
            );
            return None;
        }
        self.state.borrow_mut().backup_expected = Some(hash);
        let name = format!("vault-backup-{}.vault", view::date(view::now_unix()));
        Some((name, bytes))
    }

    /// The copy as read back from where it was saved (`place`, shown to the person), or why
    /// it couldn't be. It is confirmed only when it is the vault file byte for byte and opens
    /// with this vault's key (every byte authenticated; no password asked again). Returns
    /// whether it was: the shell deletes a copy that wasn't.
    pub fn copy_written(&self, place: &str, read_back: Result<Vec<u8>, String>) -> bool {
        let expected = self.state.borrow_mut().backup_expected.take();
        let checked = (|| -> Result<usize, String> {
            let back = read_back?;
            let expected = expected.ok_or("no copy was being saved")?;
            if fingerprint(&back) != expected {
                return Err("the copy read back differs from the vault file".into());
            }
            let state = self.state.borrow();
            let vault = state
                .vault
                .as_ref()
                .ok_or("the vault was locked meanwhile")?;
            vault.check_copy(&back).map_err(|e| e.to_string())?;
            Ok(back.len())
        })();
        match checked {
            Ok(len) => {
                let now = view::now_unix();
                let minutes = now.rem_euclid(86_400) / 60;
                let size = size_text(len);
                let line = format!(
                    "{place} · {size} · {} {:02}:{:02} UTC",
                    view::date(now),
                    minutes / 60,
                    minutes % 60
                );
                self.set_error(error::NONE, "");
                self.app().set_backup_confirmed(line.as_str().into());
                self.notify(notice::BACKUP_CONFIRMED, &line);
                true
            }
            Err(detail) => {
                self.set_error(error::BACKUP_CHECK, &detail);
                false
            }
        }
    }

    /// [`Controller::bring_vault`] for a file on a path (the computer's file dialog).
    pub fn bring_vault_file(&self, file: &Path) {
        match files::read_any(file) {
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
        let bytes = match incoming.map_or_else(|| files::read(&path), Ok) {
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
                    by_password: true,
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
                .map_or(Ok(()), files::create_dir_all)
                .map_err(|e| e.to_string())
                .and_then(|()| files::write_atomic(&path, &bytes).map_err(|e| e.to_string()));
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
        if opened.by_password {
            self.password_typed(&id);
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
        app.set_choosing_vault(false);
        app.set_settings_section(-1);
        app.set_bio_ready(false);
        app.set_bio_stale(false);
        self.remember_open_vault();
        self.add_dropped_logins();
        self.publish_vault_facts();
        self.load_icons();
        self.refresh_list();
        self.fetch_icons();
        self.start_sync();
        self.watch_leaks();
    }

    /// Items came from another device: the list, and the open item if it is still there.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn after_sync_changes(&self) {
        self.refresh_list();
        if self.app().get_page() != Page::Item {
            return;
        }
        let still_there = {
            let state = self.state.borrow();
            match (state.vault.as_ref(), state.selected.as_ref()) {
                (Some(vault), Some(id)) => vault.get_item(id).is_ok(),
                _ => false,
            }
        };
        if still_there {
            self.show_item();
        } else {
            self.close_item();
        }
    }

    /// Locks: the vault and everything read from it leave memory and the screen.
    pub fn lock(&self) {
        self.stop_sync();
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
            state.leaked.clear();
            state.watch_looked = None;
        }
        *self.icons.borrow_mut() = icons::Icons::default();
        let app = self.app();
        app.set_changing_password(false);
        app.set_choosing_vault(false);
        app.set_confirm_remove_vault(false);
        app.set_import_added(-1);
        app.set_items(ModelRc::default());
        app.set_codes(ModelRc::default());
        app.set_total(0);
        app.set_vault_name(SharedString::new());
        app.set_gen_password(SharedString::new());
        app.set_notice_code(0);
        self.clear_item_page();
        self.clear_editor();
        self.show_entry();
        self.publish_vaults();
    }

    // ---- saving ----

    /// Writes the vault file. Refused when something else changed the file since this app
    /// read or wrote it: the person's other device (or a sync tool) wins, nothing is lost.
    fn save(&self) -> bool {
        let saved = self.save_quietly();
        if saved {
            self.sync_after_save();
        }
        saved
    }

    /// [`Controller::save`] without asking for a sync round (a round's own save).
    fn save_quietly(&self) -> bool {
        let outcome = (|| -> Result<(), String> {
            let mut state = self.state.borrow_mut();
            let state = &mut *state;
            let vault = state.vault.as_mut().ok_or("the vault is locked")?;
            if let Some(expected) = state.file_hash {
                let now = files::read(&state.path).map_err(|e| e.to_string())?;
                if fingerprint(&now) != expected {
                    return Err("the file was changed by something else".into());
                }
            }
            let bytes = vault.to_bytes().map_err(|e| e.to_string())?;
            if let Some(parent) = state.path.parent() {
                files::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            files::write_atomic(&state.path, &bytes).map_err(|e| e.to_string())?;
            state.file_hash = Some(fingerprint(&bytes));
            let _ = crate::platform::device::record_revision(&vault.id_hex(), vault.revision());
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

    // ---- the master password ----

    fn close_password_change(&self) {
        for index in [field::CURRENT, field::NEW, field::NEW_AGAIN] {
            self.state.borrow_mut().secrets[index].clear();
        }
        self.publish_lengths();
        self.set_error(error::NONE, "");
        self.app().set_changing_password(false);
    }

    /// Settings → Master password: checked against the file with the current password, then
    /// the new one is set and written in one go (a failed write leaves the vault as it was),
    /// then synced. Other devices ask for the new one at their next unlock. The Secret Key
    /// and the recovery parts stay as they are.
    fn change_password(&self) {
        if self.app().get_busy() {
            return;
        }
        let current = self.secret(field::CURRENT);
        let new = self.secret(field::NEW);
        if current.is_empty() {
            return self.set_error(error::WRONG_CURRENT, "");
        }
        if new.chars().count() < MIN_MASTER_PASSWORD_CHARS {
            return self.set_error(error::TOO_SHORT, "");
        }
        if *new != *self.secret(field::NEW_AGAIN) {
            return self.set_error(error::MISMATCH, "");
        }
        self.set_error(error::NONE, "");
        let (vault, secret_key, path, expected) = {
            let mut state = self.state.borrow_mut();
            let (Some(vault), Some(secret_key)) = (state.vault.take(), state.secret_key.take())
            else {
                return;
            };
            (vault, secret_key, state.path.clone(), state.file_hash)
        };
        struct Changed {
            vault: Vault,
            secret_key: SecretKey,
            /// The new file's hash, or the error code and detail.
            outcome: Result<[u8; 32], (i32, String)>,
        }
        self.run(
            move || {
                let mut vault = vault;
                let were_open = vault.secrets_open();
                let outcome = (|| {
                    let bytes =
                        files::read(&path).map_err(|e| (error::NOT_SAVED, e.to_string()))?;
                    if expected.is_some_and(|hash| hash != fingerprint(&bytes)) {
                        return Err((
                            error::NOT_SAVED,
                            "the file was changed by something else".to_owned(),
                        ));
                    }
                    // The current password, checked against the file itself.
                    Vault::open(
                        &bytes,
                        Unlock::Password {
                            password: &current,
                            secret_key: &secret_key,
                        },
                    )
                    .map_err(|err| match err {
                        CoreError::DecryptionFailed => (error::WRONG_CURRENT, String::new()),
                        other => (error::NOT_SAVED, other.to_string()),
                    })?;
                    // The item lock's copy of its key for the master password follows it.
                    let _ = vault.unlock_secrets_with_master(&current);
                    vault
                        .change_unlock(|vault| {
                            let kdf = vault.kdf_params().clone();
                            vault.change_password(&new, &secret_key, None, &kdf)?;
                            let bytes = vault.to_bytes()?;
                            files::write_atomic(&path, &bytes)?;
                            Ok(fingerprint(&bytes))
                        })
                        .map_err(|err| (error::NOT_SAVED, err.to_string()))
                })();
                if !were_open {
                    vault.lock_secrets();
                }
                Changed {
                    vault,
                    secret_key,
                    outcome,
                }
            },
            |c, changed| {
                let revision = changed.vault.revision();
                let id = changed.vault.id_hex();
                {
                    let mut state = c.state.borrow_mut();
                    state.vault = Some(changed.vault);
                    state.secret_key = Some(changed.secret_key);
                }
                match changed.outcome {
                    Ok(hash) => {
                        c.state.borrow_mut().file_hash = Some(hash);
                        let _ = crate::platform::device::record_revision(&id, revision);
                        c.close_password_change();
                        c.notify(notice::PASSWORD_CHANGED, "");
                        c.biometrics_revoked(&id);
                        c.sync_after_save();
                    }
                    Err((code, detail)) => {
                        if code == error::WRONG_CURRENT {
                            c.state.borrow_mut().secrets[field::CURRENT].clear();
                            c.publish_lengths();
                        }
                        c.set_error(code, &detail);
                    }
                }
            },
        );
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
                    5 => item.kind == ItemKind::SshKey,
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
                let (icon, has_icon) = self.picture(&item.url);
                rows.push(ItemRow {
                    icon,
                    has_icon,
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
                    leaked: state.leaked.contains(&item.id),
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
        let (icon, has_icon) = self.picture(&website);
        app.set_d_icon(icon);
        app.set_d_has_icon(has_icon);
        app.set_d_favorite(item.favorite);
        app.set_d_username(item.username.as_str().into());
        app.set_d_website(website.into());
        app.set_d_check(check);
        // A note's text is the secret of a note: it waits for the check too.
        let notes_wait = !open && item.kind == ItemKind::SecureNote;
        app.set_d_notes(if notes_wait { "" } else { item.notes.as_str() }.into());
        let card = if item.kind == ItemKind::Card {
            let number = CardDetails::from_item(&item).number;
            if open && number.len() >= 4 {
                card::masked(&number)
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        app.set_d_card(card.into());
        let expiry = if open && item.kind == ItemKind::Card {
            CardDetails::from_item(&item).expiry
        } else {
            String::new()
        };
        app.set_d_card_expiry(expiry.into());
        self.show_item_files(&item, open);
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
            PhoneWindow::set_d_card_expiry,
            PhoneWindow::set_d_ssh_public,
            PhoneWindow::set_d_code,
        ] {
            clear(&app, SharedString::new());
        }
        app.set_d_has_password(false);
        app.set_d_has_code(false);
        app.set_d_check(0);
        app.set_d_files(ModelRc::default());
        app.set_d_passkeys(ModelRc::default());
        app.set_d_checked(false);
        app.set_d_leak(0);
        self.state.borrow_mut().leak_for = None;
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
                    files::read(&path).is_ok_and(|bytes| {
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
        let seconds = self.state.borrow().prefs.clipboard_seconds;
        self.state.borrow_mut().copied = Some((
            Zeroizing::new(value.to_owned()),
            Instant::now() + Duration::from_secs(u64::from(seconds)),
        ));
        self.notify(code, &seconds.to_string());
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
            4 => {
                let public = self.app().get_d_ssh_public();
                if !public.is_empty() && clipboard::copy_plain(&public).is_ok() {
                    self.notify(notice::COPIED_PLAIN, "");
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
                let (icon, has_icon) = self.picture(&summary.url);
                rows.push(CodeRow {
                    icon,
                    has_icon,
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
            PhoneWindow::set_ed_card_number,
            PhoneWindow::set_ed_card_expiry,
            PhoneWindow::set_ed_card_code,
            PhoneWindow::set_ed_card_brand,
        ] {
            clear(&app, SharedString::new());
        }
        app.set_ed_favorite(false);
        app.set_ed_confirm_delete(false);
        self.clear_editor_files();
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
        app.set_ed_kind(item.as_ref().map_or(editor::LOGIN, editor_kind));
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
            if item.kind == ItemKind::Card {
                let details = CardDetails::from_item(item);
                app.set_ed_card_number(card::group(&details.number).into());
                app.set_ed_card_expiry(details.expiry.as_str().into());
                app.set_ed_card_code(details.security_code.as_str().into());
                if !details.number.is_empty() {
                    app.set_ed_card_brand(card::detect_brand(&details.number).name().into());
                }
            }
        }
        self.editor_files_from(item.as_ref());
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
        let kind = app.get_ed_kind();
        let totp = app.get_ed_totp().trim().to_owned();
        let website = app.get_ed_website().trim().to_owned();
        if kind == editor::AUTHENTICATOR && totp.is_empty() {
            return self.set_error(error::SETUP_KEY, "");
        }
        if (kind == editor::LOGIN || kind == editor::AUTHENTICATOR)
            && !totp.is_empty()
            && Totp::parse(&totp).is_err()
        {
            return self.set_error(error::TOTP, "");
        }
        let mut title = app.get_ed_title().trim().to_owned();
        if title.is_empty() && kind == editor::AUTHENTICATOR {
            title = view::authenticator_title(&totp, &website);
        }
        if title.is_empty() {
            return self.set_error(error::NAME, "");
        }
        let password = self.secret(field::ITEM_PASSWORD);
        let extras = self.editor_extras();
        let card_details = CardDetails {
            number: app.get_ed_card_number().to_string(),
            expiry: app.get_ed_card_expiry().to_string(),
            security_code: app.get_ed_card_code().to_string(),
        };
        if kind == editor::CARD
            && let Err(problem) = card_details.validate(&password)
        {
            return self.set_error(
                match problem {
                    CardProblem::Number => error::CARD_NUMBER,
                    CardProblem::Expiry => error::CARD_EXPIRY,
                    CardProblem::SecurityCode => error::CARD_CODE,
                    CardProblem::Pin => error::CARD_PIN,
                },
                "",
            );
        }
        let stored = {
            let mut state = self.state.borrow_mut();
            let state = &mut *state;
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            let existing = state.editing.and_then(|id| vault.get_item(&id).ok());
            let mut item = existing.clone().unwrap_or_else(|| {
                ItemData::new(
                    match kind {
                        editor::CARD => ItemKind::Card,
                        editor::NOTE => ItemKind::SecureNote,
                        editor::SSH => ItemKind::SshKey,
                        _ => ItemKind::Login,
                    },
                    &title,
                )
            });
            item.title = title;
            item.notes = app.get_ed_notes().to_string();
            item.favorite = app.get_ed_favorite();
            if item.kind != ItemKind::SecureNote {
                item.username = app.get_ed_username().trim().to_owned();
                // An authenticator item's account, when none was typed, is the one in its key.
                if item.username.is_empty() && kind == editor::AUTHENTICATOR {
                    item.username = totp::names(&totp).account;
                }
                // A card's PIN is kept where a login keeps its password (an SSH key's private
                // key too, from the editor's own copy below).
                if kind != editor::AUTHENTICATOR && kind != editor::SSH {
                    item.password = password.to_string();
                }
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
            if item.kind == ItemKind::Login {
                item.totp = totp;
            }
            if item.kind == ItemKind::Card {
                card_details.apply(&mut item);
            }
            extras.apply(&mut item);
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

    /// The generator's options on screen, as saved in the settings.
    fn generator_on_screen(&self) -> prefs::Generator {
        let app = self.app();
        let count = |n: i32| u32::try_from(n.clamp(0, 32)).unwrap_or(0);
        prefs::Generator {
            mode: u8::from(app.get_gen_mode() == 1),
            length: u32::try_from(app.get_gen_length().clamp(8, 128)).unwrap_or(20),
            words: u32::try_from(app.get_gen_words().clamp(3, 12)).unwrap_or(6),
            uppercase: app.get_gen_upper(),
            lowercase: app.get_gen_lower(),
            digits: app.get_gen_digits(),
            symbols: app.get_gen_symbols(),
            avoid_ambiguous: app.get_gen_avoid_ambiguous(),
            also_use: app.get_gen_also_use().chars().take(64).collect(),
            never_use: app.get_gen_never_use().chars().take(64).collect(),
            min_uppercase: count(app.get_gen_min_upper()),
            min_lowercase: count(app.get_gen_min_lower()),
            min_digits: count(app.get_gen_min_digits()),
            min_symbols: count(app.get_gen_min_symbols()),
            word_case: u8::try_from(app.get_gen_word_case().clamp(0, 3)).unwrap_or(0),
            separator: u8::try_from(app.get_gen_separator().clamp(0, 3)).unwrap_or(0),
            add_digit: app.get_gen_add_digit(),
        }
    }

    /// Puts saved generator options on screen (at start).
    fn show_generator(&self, options: &prefs::Generator) {
        let app = self.app();
        let int = |n: u32| i32::try_from(n).unwrap_or(0);
        app.set_gen_mode(i32::from(options.mode.min(1)));
        app.set_gen_length(int(options.length.clamp(8, 128)));
        app.set_gen_words(int(options.words.clamp(3, 12)));
        app.set_gen_upper(options.uppercase);
        app.set_gen_lower(options.lowercase);
        app.set_gen_digits(options.digits);
        app.set_gen_symbols(options.symbols);
        app.set_gen_avoid_ambiguous(options.avoid_ambiguous);
        app.set_gen_also_use(options.also_use.as_str().into());
        app.set_gen_never_use(options.never_use.as_str().into());
        app.set_gen_min_upper(int(options.min_uppercase));
        app.set_gen_min_lower(int(options.min_lowercase));
        app.set_gen_min_digits(int(options.min_digits));
        app.set_gen_min_symbols(int(options.min_symbols));
        app.set_gen_word_case(i32::from(options.word_case.min(3)));
        app.set_gen_separator(i32::from(options.separator.min(3)));
        app.set_gen_add_digit(options.add_digit);
        app.set_gen_advanced(
            options.min_uppercase
                + options.min_lowercase
                + options.min_digits
                + options.min_symbols
                > 0
                || !options.also_use.is_empty()
                || !options.never_use.is_empty(),
        );
    }

    fn generate(&self) {
        let app = self.app();
        let chosen = self.generator_on_screen();
        if self.state.borrow().prefs.generator != chosen {
            self.change_prefs(|prefs| prefs.generator = chosen.clone());
        }
        let made = if chosen.mode == 1 {
            let options = PassphraseOptions {
                words: chosen.words as usize,
                case: match chosen.word_case {
                    1 => WordCase::Title,
                    2 => WordCase::Upper,
                    3 => WordCase::Mixed,
                    _ => WordCase::Lower,
                },
                separator: ["-", ".", "_", " "][usize::from(chosen.separator.min(3))].into(),
                include_number: chosen.add_digit,
                ..PassphraseOptions::default()
            };
            generate_passphrase(&options).map(|phrase| (phrase, options.entropy_bits()))
        } else {
            let mut options = PasswordOptions {
                length: chosen.length as usize,
                uppercase: chosen.uppercase,
                lowercase: chosen.lowercase,
                digits: chosen.digits,
                symbols: chosen.symbols,
                avoid_ambiguous: chosen.avoid_ambiguous,
                also_use: chosen.also_use.clone(),
                never_use: chosen.never_use.clone(),
                min_uppercase: chosen.min_uppercase as usize,
                min_lowercase: chosen.min_lowercase as usize,
                min_digits: chosen.min_digits as usize,
                min_symbols: chosen.min_symbols as usize,
                ..PasswordOptions::default()
            };
            // Minimums that need more room than the length: the length grows.
            if options.required() > options.length {
                options.length = options.required().min(128);
                app.set_gen_length(i32::try_from(options.length).unwrap_or(20));
            }
            generate_password(&options).map(|password| (password, options.entropy_bits()))
        };
        match made {
            Ok((password, bits)) => {
                self.set_error(error::NONE, "");
                app.set_gen_password(password.as_str().into());
                app.set_gen_bits(bits.round() as i32);
                let (unit, amount) = view::crack_time(bits);
                app.set_gen_crack_unit(unit);
                app.set_gen_crack_amount(amount);
                app.set_gen_crack_comparison(view::crack_comparison(bits));
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
        self.watch_tick();
        let app = self.app();
        if app.get_screen() != Screen::Vault {
            return;
        }
        if app.get_page() == Page::Item && app.get_d_has_code() {
            self.show_item();
        } else if app.get_page() == Page::None && app.get_place() == Place::Codes {
            self.tick_codes();
        }
    }

    /// Once a second on the codes list: the codes and countdowns of the rows already listed,
    /// changed in place. Only the items that have a code are read, not the whole vault, and
    /// the list keeps its rows (a phone's battery and a scroll position are spared). The list
    /// itself is rebuilt by `refresh_codes`, after any change to the items.
    fn tick_codes(&self) {
        let codes = self.app().get_codes();
        let state = self.state.borrow();
        let Some(vault) = state.vault.as_ref() else {
            return;
        };
        if codes.row_count() != state.code_ids.len() {
            drop(state);
            return self.refresh_codes();
        }
        for (i, id) in state.code_ids.iter().enumerate() {
            let (Some(mut row), Ok(item)) = (codes.row_data(i), vault.get_item(id)) else {
                continue;
            };
            let code = (self.check_for(vault, &item) == 0)
                .then(|| Totp::parse(&item.totp).ok())
                .flatten()
                .map(|totp| (totp.now(), totp.period()));
            let (digits, left, period) = match code {
                Some(((digits, left), period)) => (grouped(&digits), left, period),
                None => (String::new(), 0, 30),
            };
            let left = i32::try_from(left).unwrap_or(0);
            let period = i32::try_from(period).unwrap_or(30);
            if row.code != digits.as_str() || row.left != left || row.period != period {
                row.code = digits.into();
                row.left = left;
                row.period = period;
                codes.set_row_data(i, row);
            }
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
