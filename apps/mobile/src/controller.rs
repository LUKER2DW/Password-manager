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
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const IMPORT_PASSWORD: usize = 8;
    /// Settings → Import and export: the password a protected export is sealed with.
    pub const EXPORT_PASSWORD: usize = 9;
    /// The master password, asked again before an export or a sensitive change (removing the
    /// vault from the phone, stopping sync, removing or adding a device, the backup server).
    pub const EXPORT_MASTER: usize = 10;
    /// The passphrase of an SSH key brought into the editor, used once to open it.
    pub const SSH_PASSPHRASE: usize = 11;
    /// Recovery with the emergency kit: the parts, typed or scanned (any order).
    pub const PART_A: usize = 12;
    pub const PART_B: usize = 13;
    pub const PART_C: usize = 14;
    pub const COUNT: usize = 15;
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
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const IMPORT_PASSWORD: i32 = 26;
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const UPDATE: i32 = 27;
    /// What was pasted or scanned isn't an invite line (`vaultsync:1?…`).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const NOT_INVITE: i32 = 28;
    /// The QR code can't be scanned ("unavailable": no Google Play services, or the detail).
    pub const CAMERA: i32 = 29;
    /// A protected export needs a password of at least 12 characters.
    pub const EXPORT_PASSWORD: i32 = 30;
    /// The export couldn't be made (the detail says why).
    pub const EXPORT: i32 = 31;
    /// Some items are behind the item lock: an export would leave their secrets out.
    pub const EXPORT_LOCKED: i32 = 32;
    /// SSH keys: a public key brought in instead of the private one; a form of key not read
    /// here; a passphrase that doesn't open the key.
    pub const KEY_PUBLIC_ONLY: i32 = 33;
    pub const KEY_UNSUPPORTED: i32 = 34;
    pub const KEY_PASSPHRASE: i32 = 35;
    /// Recovery: a part with a typo; the same part twice; parts of another vault or an older
    /// kit; a vault without recovery parts.
    pub const PART_TYPO: i32 = 36;
    pub const PARTS_SAME: i32 = 37;
    pub const PARTS_WRONG: i32 = 38;
    pub const NO_PARTS: i32 = 39;
    /// Recovery: the picture chosen holds no recovery part (or not the exact pixels any more).
    pub const PART_PICTURE: i32 = 40;
    /// Recovery with two parts didn't finish (the detail says why): nothing changed, the
    /// parts still work and the Secret Key wasn't kept.
    pub const PARTS_KEPT: i32 = 41;
    /// Recovery with two parts: the parts no longer work, but the phone couldn't keep the
    /// Secret Key (the detail says why). It is on screen to be written down.
    pub const KEY_NOT_KEPT: i32 = 42;
    /// The vault key renewed on another device: the Secret Key and master password typed open
    /// none of its copies; the phone couldn't keep the new Secret Key (nothing changed); it
    /// couldn't, and its copy opens only with the new kit now.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const KEY_NOT_TAKEN: i32 = 43;
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const TAKE_NOT_KEPT: i32 = 44;
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const TAKE_ONLY_NEW: i32 = 45;
    /// A protected export's password is below the one-factor floor (CRYPTO.md §3.3.1): it
    /// alone guards the file.
    pub const WEAK_EXPORT: i32 = 46;
    /// Too many failed unlocks in a row: the next try waits (controller/attempts.rs).
    pub const UNLOCK_WAIT: i32 = 47;
}

/// The sheets that ask for a password (app.slint `ask`, `confirming`).
mod sheet {
    /// The sensitive changes the master password confirms (`check_master_then`).
    pub const REMOVE_VAULT: i32 = 1;
    pub const STOP_SYNC: i32 = 2;
    pub const REMOVE_DEVICE: i32 = 3;
    pub const REMOVE_BACKUP: i32 = 4;
    pub const EXPORT_JSON: i32 = 6;
    pub const EXPORT_CSV: i32 = 8;
    pub const IMPORT: i32 = 11;
    pub const MASTER_PASSWORD: i32 = 12;
    pub const ITEM_CHECK: i32 = 13;
    pub const ADD_DEVICE: i32 = 16;
    pub const SSH_PASSPHRASE: i32 = 17;
    /// A newer version of the app on the vault's server: Install, or Later.
    pub const UPDATE: i32 = 18;
    /// The vault key was renewed on another device: its new Secret Key and the master password.
    pub const TAKE_KEY: i32 = 19;
    /// Every use asks, on a phone with no screen lock: the item lock's PIN or password, for
    /// one use (`each_use`).
    pub const USE_CHECK: i32 = 20;
    /// Settings, Security: remove this phone's copy after failed unlocks (what goes, and the
    /// master password).
    pub const REMOVE_AFTER_FAILURES: i32 = 21;
}

/// Where the line of a scanned QR code goes (the screens' `scan-invite` purpose).
pub mod scan {
    /// The start screen's "From your vault server".
    pub const SETUP: i32 = 0;
    /// Settings, Sync: joining the server with an invite.
    pub const JOIN: i32 = 1;
    /// The editor: a one-time code's setup key (an otpauth:// link).
    pub const OTP: i32 = 2;
    /// Recovery: a recovery part from the emergency kit (into the first empty field).
    pub const PART: i32 = 3;
    /// Unlock: the Secret Key from the emergency kit.
    pub const SECRET_KEY: i32 = 4;
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
mod attempts;
mod each_use;
use each_use::{Ask, Use};
mod filling;
mod folders;
mod generated;
mod health;
mod icons;
#[cfg(not(target_arch = "wasm32"))]
mod passkeys;
mod passwords;
mod preview;
mod security;
mod settings;
mod syncing;
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) use syncing::Github;
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
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const UPDATE_READY: i32 = 22;
    /// The phone took a vault key renewed on another device ("1": fingerprint unlock was
    /// turned off with it); one was renewed on another device (Settings, Sync asks for it).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const KEY_TAKEN: i32 = 23;
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const SYNC_KEY_RENEWED: i32 = 24;
    /// A passkey was made for a site or app on the phone (the login's title).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const PASSKEY_SAVED: i32 = 25;
    /// Every use asks, and this phone has no screen lock nor an item lock with a PIN or
    /// password to ask instead: nothing was shown or copied.
    pub const NO_SCREEN_LOCK: i32 = 26;
    /// The phone's check before one use didn't pass or couldn't be asked (what Android said).
    pub const CHECK_FAILED: i32 = 27;
    /// Failed unlocks happened before this one (the argument: since when; `notice-count`: how
    /// many). Its words are `Words.failed-unlocks`.
    pub const FAILED_UNLOCKS: i32 = 28;
    /// This phone's copy of a vault was removed after too many failed unlocks (its name).
    pub const COPY_REMOVED: i32 = 29;
    /// Format v11: an item went to the trash, or came back from it.
    pub const TRASHED: i32 = 30;
    pub const RESTORED: i32 = 31;
    /// Another device's copy was refused (arg: its name, empty when not in the list).
    pub const SYNC_REFUSED: i32 = 32;
    /// Another device's copy couldn't be read (arg: its name, empty when not in the list).
    pub const SYNC_UNREADABLE: i32 = 33;
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

/// One edit of a secret field's input (the system keyboard) put into its buffer. The input
/// held a stand-in for each character of the buffer and now holds `text`, with the cursor at
/// byte `cursor`. The stand-ins missing were deleted where the edit happened, and what isn't a
/// stand-in was typed (or pasted) there: where the first such character is, or, when something
/// was only deleted, where the cursor is now. Returns where the cursor is, in characters.
fn system_edit(buffer: &mut SecretBuffer, text: &str, cursor: usize) -> usize {
    let kept = text.chars().filter(|c| is_stand_in(*c)).count();
    let removed = buffer.char_count().saturating_sub(kept);
    let at = match text.chars().position(SecretBuffer::takes) {
        Some(first) => text.chars().take(first).filter(|c| is_stand_in(*c)).count(),
        None => text
            .char_indices()
            .take_while(|(at, _)| *at < cursor)
            .filter(|(_, c)| is_stand_in(*c))
            .count(),
    };
    buffer.remove(at, removed);
    let typed = Zeroizing::new(
        text.chars()
            .filter(|c| SecretBuffer::takes(*c))
            .collect::<String>(),
    );
    at + buffer.insert_str(at, &typed)
}
/// The list's filter for the items in the trash (format v11).
const TRASH_FILTER: i32 = 7;
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
        ItemKind::Identity => (0x7A, 0x5A, 0x3C),
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
        ItemKind::Identity => 5,
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

/// Notes as the item page shows them: Markdown (bold, italic, code, lists, links). Headings
/// (`# …`), which the renderer leaves out, show as bold lines; text that isn't valid Markdown
/// shows as it is.
fn styled_notes(notes: &str) -> slint::StyledText {
    if notes.is_empty() {
        return slint::StyledText::default();
    }
    let prepared: String = notes
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let heading = trimmed.trim_start_matches('#');
            if trimmed.starts_with('#') && heading.starts_with(' ') && !heading.trim().is_empty() {
                format!("**{}**", heading.trim())
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    slint::StyledText::from_markdown(&prepared)
        .unwrap_or_else(|_| slint::StyledText::from_plain_text(notes))
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
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Whether this phone already opened or wrote a newer revision of the vault `id` than
/// `revision`: the file may be an old copy put in its place ([`Controller::opened`] refuses
/// it). A record of revisions that can't be read is set aside there and starts afresh, so it
/// counts as none here too.
fn older_than_seen(id: &str, revision: u64) -> bool {
    #[cfg(not(target_arch = "wasm32"))]
    let device = DeviceState::load().ok();
    #[cfg(target_arch = "wasm32")]
    let device = Some(DeviceState::load_or_set_aside().0);
    device.is_some_and(|device| {
        matches!(
            device.check_rollback(id, revision),
            RollbackStatus::Older { .. }
        )
    })
}

/// The tests: a job's work and result, waiting as if still on its thread ([`Controller::run`]).
#[cfg(test)]
type HeldJob = Box<dyn FnOnce(&Controller)>;

struct State {
    /// Slow work (password hashing) runs inline: headless tests and screenshots.
    inline: bool,
    /// How many lines of the security log Settings shows (more with "Show older").
    security_log_shown: usize,
    /// How the unlock under way is made, when not as `Opened::by_password` says (a recovery).
    unlock_how: Option<&'static str>,
    /// The phone's copy of the vault file.
    path: PathBuf,
    /// A vault file the person chose, waiting to prove itself before it replaces the copy.
    incoming: Option<Vec<u8>>,
    vault: Option<Vault>,
    secret_key: Option<SecretKey>,
    /// +1 each time a vault opens or locks. A job that borrowed the open vault
    /// ([`Controller::lend_vault`]) gives it back only while this is still what it was when
    /// the job started, so a late result never reopens a vault locked meanwhile.
    session: u64,
    /// A job holds the open vault and its Secret Key for a moment: the vault still counts as
    /// open (leaving the app locks it, and the job's result is then dropped).
    lent: bool,
    /// The tests' stand-in for a job that is still running: its work and result wait here
    /// until [`Controller::finish_held_jobs`].
    #[cfg(test)]
    hold_jobs: bool,
    #[cfg(test)]
    held_jobs: Vec<HeldJob>,
    /// The tests: the keystore refuses to keep a Secret Key ([`Controller::keep_secret_key`]).
    #[cfg(test)]
    refuse_secret_key: bool,
    /// SHA-256 of the vault file as last read or written here.
    file_hash: Option<[u8; 32]>,
    secrets: [SecretBuffer; field::COUNT],
    /// Where each field's cursor is, in characters (`Secrets.carets`).
    carets: [usize; field::COUNT],
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
    /// The card's full number and security code are on screen (asked for with the eye).
    show_card: bool,
    /// A secure note's text is on screen (asked for, when every use asks).
    show_note: bool,
    /// A use of a secret waiting for the phone's check, or the item lock's in its place
    /// (Settings → Ask for the fingerprint or screen lock every time).
    each_use: Option<each_use::Waiting>,
    /// Whether the system can check the person, as last asked (`System::checks_person`:
    /// asked again when the app comes back to the screen).
    person_check: Option<bool>,
    /// One-time codes shown after their check while every use asks: the item, and which code
    /// (its time step, or a counter-based code's counter). Dots again once it isn't the
    /// current one.
    codes_shown: Vec<(ItemId, u64)>,
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
    /// An SSH key brought in that waits for its passphrase (the sheet, `ask(17)`).
    ssh_pending: Option<Zeroizing<String>>,
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
    /// The logins on the health page, in order.
    health_ids: Vec<ItemId>,
    /// Every login the health page lists, before its filter.
    health_all: Vec<(crate::ui::HealthRow, ItemId)>,
    /// The vault's folders on screen, in order.
    folder_ids: Vec<vault_core::FolderId>,
    /// An export made and waiting for the shell to save it (its name and bytes).
    export_pending: Option<(String, Zeroizing<Vec<u8>>)>,
    /// A file to import that waits for its password (asked in the sheet).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    import_pending: Option<Zeroizing<Vec<u8>>>,
    /// The clocks unlock attempts are timed by (the tests put their own in its place), and
    /// when the unlock screen's countdown ends (what shows; each try asks again).
    clock: fn() -> (i64, Option<i64>),
    unlock_until: Option<Instant>,
    /// The new master password the person chose to keep although it is easy to guess, and the
    /// one the breach check passed (or the person went on without it): until it changes
    /// (controller/passwords.rs).
    weak_kept: Option<usize>,
    leaks_cleared: Option<usize>,
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
    /// The id in the file's header, to count a failed try against.
    vault_id: String,
    secret_key: SecretKey,
    typed_key: bool,
    hash: [u8; 32],
    /// Opened with the master password (not the fingerprint).
    by_password: bool,
    /// Two recovery parts brought the Secret Key back: the vault file they were checked
    /// against. They stop working before the vault opens ([`Controller::retire_parts`]).
    used_parts: Option<Vec<u8>>,
}

/// What a recovery with three parts hands back: the vault under its new master password and
/// Secret Key, the file to write, and the fingerprint of the file the parts were checked
/// against.
type Recovered = (Vault, SecretKey, Vec<u8>, [u8; 32]);

/// How retiring the two recovery parts just used went ([`Controller::retire_parts`]).
enum Retired {
    /// Written, and the Secret Key kept on this phone: the file's new fingerprint.
    Done([u8; 32]),
    /// Nothing changed: the parts still work and the Secret Key wasn't kept (why).
    Refused(String),
    /// The parts no longer work but the Secret Key couldn't be kept, nor the file put back
    /// (the file's new fingerprint, and why): the key is shown so it isn't lost.
    KeyNotKept([u8; 32], String),
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
                security_log_shown: 0,
                unlock_how: None,
                prefs: prefs.clone(),
                path,
                incoming: None,
                vault: None,
                secret_key: None,
                session: 0,
                lent: false,
                #[cfg(test)]
                hold_jobs: false,
                #[cfg(test)]
                held_jobs: Vec::new(),
                #[cfg(test)]
                refuse_secret_key: false,
                file_hash: None,
                secrets: std::array::from_fn(|_| SecretBuffer::new()),
                carets: [0; field::COUNT],
                showing: [false; field::COUNT],
                shown: Vec::new(),
                code_ids: Vec::new(),
                selected: None,
                editing: None,
                master_checked: false,
                show_password: false,
                show_card: false,
                show_note: false,
                each_use: None,
                person_check: None,
                codes_shown: Vec::new(),
                confirm_delete: false,
                generated: Zeroizing::new(String::new()),
                copied: None,
                notice_until: None,
                last_touch: Instant::now(),
                sync: syncing::SyncStatus::default(),
                backup_expected: None,
                editor_files: Vec::new(),
                editor_ssh: None,
                ssh_pending: None,
                file_expected: None,
                previous: None,
                bio: settings::BioPending::None,
                leak_lookup: settings::leak_lookup_default,
                leak_for: None,
                leak_batch: settings::leak_batch_default,
                leaked: std::collections::HashSet::new(),
                watch_looked: None,
                health_ids: Vec::new(),
                health_all: Vec::new(),
                folder_ids: Vec::new(),
                export_pending: None,
                import_pending: None,
                clock: attempts::clock_default,
                unlock_until: None,
                weak_kept: None,
                leaks_cleared: None,
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
        app.set_ask_each_use(prefs.ask_each_use);
        app.set_leak_watch(prefs.leak_watch);
        app.set_update_source(i32::from(
            prefs.update_source.min(prefs::UPDATES_FROM_SERVER),
        ));
        app.set_update_checks(prefs.update_checks);
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
        on!(on_start_recovery, |c, mode| c.start_recovery(mode));
        on!(on_cancel_recovery, |c| c.show_entry());
        on!(on_recover, |c| c.recover());
        on!(on_recovered_done, |c| c.recovered_done());
        on!(on_copy_recovered_key, |c| c.copy_recovered_key());
        on!(on_sync_join, |c| c.sync_join());
        on!(on_setup_from_server, |c| c.setup_from_server());
        on!(on_scan_invite, |c, purpose| c.scan_invite(purpose));
        on!(on_sync_use_webdav, |c| c.sync_use_webdav());
        on!(on_sync_now, |c| c.sync_now());
        on!(on_sync_take_key, |c| c.sync_take_key());
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
            let brand = (!digits.is_empty()).then(|| card::detect_brand(&digits));
            c.app()
                .set_ed_card_brand(brand.map_or("", card::Brand::name).into());
            c.app().set_ed_card_mark(brand.map_or(0, view::brand_mark));
        });
        on!(on_close_item, |c| c.close_item());
        // Every field of the item, the secret ones included, shows in the editor: asked first
        // when every use asks.
        on!(on_edit_item, |c| c.use_of_item(Use::Edit));
        on!(on_toggle_favorite, |c| c.toggle_favorite());
        on!(on_toggle_password, |c| {
            if c.state.borrow().show_password {
                c.state.borrow_mut().show_password = false;
                c.show_item();
            } else {
                c.use_of_item(Use::ShowPassword);
            }
        });
        on!(on_show_note, |c| c.use_of_item(Use::ShowNote));
        on!(on_toggle_code, |c| c.toggle_code());
        on!(on_toggle_code_at, |c, index| c.toggle_code_at(index));
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
        on!(on_trash_item, |c| c.trash_item());
        on!(on_restore_item, |c| c.restore_item());
        on!(on_copy_code, |c, index| c.copy_code(index));
        on!(on_move_code, |c, from, to| c.move_code(from, to));
        on!(on_ed_website_changed, |c| c.editor_site_icon());
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
        on!(on_update_source_changed, |c, index| c
            .update_source_changed(index));
        on!(on_update_checks_changed, |c, on| c
            .update_checks_changed(on));
        on!(on_change_password, |c| c.change_password());
        on!(on_use_passphrase, |c, field| c.use_passphrase(field));
        on!(on_keep_new_password, |c| c.keep_new_password());
        on!(on_remove_after_toggled, |c, on| c.remove_after_toggled(on));
        on!(on_health_opened, |c| c.refresh_health());
        on!(on_health_open, |c, index| c.health_open(index));
        on!(on_health_filtered, |c, _which| c.show_health_rows());
        on!(on_folder_edit, |c, index| c.folder_edit(index));
        on!(on_folder_save, |c| c.folder_save());
        on!(on_folder_delete, |c| c.folder_delete());
        on!(on_vault_icon_changed, |c, name, color, background| c
            .vault_icon_changed(&name, color, background));
        on!(on_vault_rename, |c| c.vault_rename());
        on!(on_export_vault, |c, format| c.export_vault(format));
        on!(on_check_master, |c, kind| c.check_master_then(kind));
        on!(on_ssh_passphrase, |c| c.ssh_passphrase());
        on!(on_toggle_card, |c| {
            if c.state.borrow().show_card {
                c.state.borrow_mut().show_card = false;
                c.show_item();
            } else {
                c.use_of_item(Use::ShowCard);
            }
        });
        on!(on_next_code, |c| {
            let selected = c.state.borrow().selected;
            if let Some(id) = selected {
                c.next_code(id);
            }
        });
        on!(on_next_code_at, |c, index| {
            let id = usize::try_from(index)
                .ok()
                .and_then(|index| c.state.borrow().code_ids.get(index).copied());
            if let Some(id) = id {
                c.next_code(id);
            }
        });
        on!(on_edit_code, |c, index| c.edit_code(index));
        on!(on_open_website, |c| {
            let website = c.app().get_d_website();
            c.open_link(&website);
        });
        on!(on_open_link, |c, link| c.open_link(&link));
        on!(on_preview_file, |c, index| c
            .use_of_item(Use::PreviewFile(index)));
        on!(on_ask_save_file, |c, index| c
            .use_of_item(Use::SaveFile(index)));
        on!(on_close_preview, |c| c.close_preview());
        on!(on_ed_totp_edited, |c, text| c.otp_names_into_editor(&text));
        on!(on_scan_otp, |c| c.scan_invite(scan::OTP));
        on!(on_gen_use, |c| c.generator_use());
        on!(on_gen_back, |c| c.generator_back());
        on!(on_gen_new_login, |c| c.generator_new_login());
        on!(on_gen_history_toggled, |c| c.gen_history_toggled());
        on!(on_gen_history_copy, |c, index| c
            .copy_generated_entry(index));
        on!(on_gen_history_delete, |c, index| c
            .delete_generated_entry(index));
        on!(on_gen_history_clear, |c| c.clear_generated());
        on!(on_security_log_show_more, |c| c.security_log_more());
        on!(on_security_log_clear, |c| c.clear_security_log());
        on!(on_import_retry, |c| c.import_retry());
        on!(on_use_checked, |c| c.use_lock_checked());
        on!(on_ask_each_use_changed, |c, on| c.ask_each_use_changed(on));
        on!(on_sheet_opened, |c, kind| c.sheet_opened(kind));
        on!(on_sheet_closed, |c, kind| c.sheet_closed(kind));

        // Secure fields: each key goes straight into its locked buffer.
        let secrets = app.global::<Secrets>();
        let weak = Rc::downgrade(self);
        secrets.on_insert(move |id, text| {
            if let Some(c) = weak.upgrade() {
                c.with_secret_at(id, |buffer, caret| {
                    *caret += buffer.insert_str(*caret, &text);
                });
            }
        });
        let weak = Rc::downgrade(self);
        secrets.on_backspace(move |id| {
            if let Some(c) = weak.upgrade() {
                c.with_secret_at(id, |buffer, caret| {
                    if *caret > 0 {
                        buffer.remove(*caret - 1, 1);
                        *caret -= 1;
                    }
                });
            }
        });
        let weak = Rc::downgrade(self);
        secrets.on_delete(move |id| {
            if let Some(c) = weak.upgrade() {
                c.with_secret_at(id, |buffer, caret| buffer.remove(*caret, 1));
            }
        });
        let weak = Rc::downgrade(self);
        secrets.on_move_caret(move |id, to| {
            if let Some(c) = weak.upgrade() {
                c.with_secret_at(id, |buffer, caret| {
                    *caret = usize::try_from(to).unwrap_or(0).min(buffer.char_count());
                });
            }
        });
        // Offsets in a field's input (stand-ins, bytes) and character counts.
        secrets.on_char_at(|text, byte| {
            let byte = usize::try_from(byte).unwrap_or(0);
            i32::try_from(text.char_indices().take_while(|(at, _)| *at < byte).count())
                .unwrap_or(i32::MAX)
        });
        secrets.on_byte_at(|text, index| {
            let index = usize::try_from(index).unwrap_or(0);
            i32::try_from(
                text.char_indices()
                    .nth(index)
                    .map_or(text.len(), |(at, _)| at),
            )
            .unwrap_or(i32::MAX)
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
        // The system keyboard (Android): each edit of the field's input, with where its cursor
        // is now. The input gets stand-ins back at once, laid out like what came in, so the
        // cursor stays where it is.
        let weak = Rc::downgrade(self);
        secrets.on_typed(move |id, text, cursor| {
            let Some(c) = weak.upgrade() else {
                return SharedString::new();
            };
            let cursor = usize::try_from(cursor).unwrap_or(0);
            c.with_secret_at(id, |buffer, caret| {
                *caret = system_edit(buffer, &text, cursor);
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
                c.with_secret_at(id, |buffer, caret| {
                    if replace {
                        buffer.clear();
                        *caret = 0;
                    }
                    *caret += buffer.insert_str(*caret, &line);
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

    /// Changes a secret field's text as a whole (cleared, generated); the cursor goes to its
    /// end.
    fn with_secret(&self, id: i32, change: impl FnOnce(&mut SecretBuffer)) {
        self.with_secret_at(id, |buffer, caret| {
            change(buffer);
            *caret = buffer.char_count();
        });
    }

    /// Changes a secret field's text where its cursor is (`caret`, in characters, moved by
    /// `change` as needed).
    fn with_secret_at(&self, id: i32, change: impl FnOnce(&mut SecretBuffer, &mut usize)) {
        let Some(index) = usize::try_from(id).ok().filter(|i| *i < field::COUNT) else {
            return;
        };
        {
            let mut state = self.state.borrow_mut();
            state.last_touch = Instant::now();
            let state = &mut *state;
            change(&mut state.secrets[index], &mut state.carets[index]);
            state.carets[index] = state.carets[index].min(state.secrets[index].char_count());
        }
        // A password typed over a shown one is no longer the one on screen.
        if index == field::ITEM_PASSWORD && !self.app().get_ed_password().is_empty() {
            self.show_editor_password(true);
        }
        self.new_password_edited(index);
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
        let mut carets = vec![0i32; 15];
        // The editor's password shows through its own eye (`ed-password`).
        let editor_shown = !self.app().get_ed_password().is_empty();
        let state = self.state.borrow();
        for (slot, buffer) in lengths.iter_mut().zip(&state.secrets) {
            *slot = i32::try_from(buffer.char_count()).unwrap_or(i32::MAX);
        }
        for (slot, caret) in carets.iter_mut().zip(&state.carets) {
            *slot = i32::try_from(*caret).unwrap_or(i32::MAX);
        }
        let chars: Vec<ModelRc<SharedString>> = (0..field::COUNT)
            .map(|index| {
                if state.showing[index] || (index == field::ITEM_PASSWORD && editor_shown) {
                    let chars: Vec<SharedString> = state.secrets[index]
                        .as_str()
                        .chars()
                        .map(|c| SharedString::from(&*c.encode_utf8(&mut [0; 4])))
                        .collect();
                    ModelRc::new(VecModel::from(chars))
                } else {
                    ModelRc::default()
                }
            })
            .collect();
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
        secrets.set_carets(ModelRc::new(VecModel::from(carets)));
        secrets.set_showing(ModelRc::new(VecModel::from(showing)));
        secrets.set_shown(ModelRc::new(VecModel::from(shown)));
        secrets.set_shown_cells(ModelRc::new(VecModel::from(cells)));
        secrets.set_shown_chars(ModelRc::new(VecModel::from(chars)));
    }

    fn clear_secrets(&self) {
        {
            let mut state = self.state.borrow_mut();
            for buffer in &mut state.secrets {
                buffer.clear();
            }
            state.carets = [0; field::COUNT];
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
        done: impl FnOnce(&Controller, R) + Send + 'static,
    ) {
        self.app().set_busy(true);
        #[cfg(test)]
        if self.state.borrow().hold_jobs {
            self.state
                .borrow_mut()
                .held_jobs
                .push(Box::new(move |c: &Controller| {
                    let result = work();
                    c.app().set_busy(false);
                    done(c, result);
                }));
            return;
        }
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

    /// The tests: jobs started from now on wait (as if still running on their thread) until
    /// [`Controller::finish_held_jobs`].
    #[cfg(test)]
    pub(crate) fn hold_jobs(&self) {
        self.state.borrow_mut().hold_jobs = true;
    }

    /// The tests: whether the phone's keystore refuses to keep Secret Keys from now on.
    #[cfg(test)]
    pub(crate) fn refuse_secret_keys(&self, refuse: bool) {
        self.state.borrow_mut().refuse_secret_key = refuse;
    }

    /// The tests: the jobs that waited finish now, in order; later ones run at once again.
    #[cfg(test)]
    pub(crate) fn finish_held_jobs(&self) {
        let held = {
            let mut state = self.state.borrow_mut();
            state.hold_jobs = false;
            std::mem::take(&mut state.held_jobs)
        };
        for job in held {
            job(self);
        }
    }

    /// A new session begins: the vault opened, locked, or the window turned to another vault
    /// file. Work started before it no longer belongs here ([`Controller::run_in_session`],
    /// [`Controller::take_back`]).
    fn new_session(&self) {
        let mut state = self.state.borrow_mut();
        state.session = state.session.wrapping_add(1);
    }

    /// [`Controller::run`] for work done for what is on screen now (the vault open now, or the
    /// unlock screen of this vault file): its result is dropped, unread, when a new session
    /// began before it came back. A password typed before the app was left doesn't open the
    /// vault behind the person's back, and a check passed for a vault since locked opens
    /// nothing in the next one.
    fn run_in_session<R: Send + 'static>(
        &self,
        work: impl FnOnce() -> R + Send + 'static,
        done: impl FnOnce(&Controller, R) + Send + 'static,
    ) {
        let session = self.state.borrow().session;
        self.run(work, move |c, result| {
            if c.state.borrow().session == session {
                done(c, result);
            }
        });
    }

    /// The open vault and its Secret Key, handed to a job (off the UI thread), with the
    /// session they belong to; `None` while locked. Until [`Controller::take_back`] the vault
    /// still counts as open, so leaving the app or the auto-lock locks it all the same.
    fn lend_vault(&self) -> Option<(Vault, SecretKey, u64)> {
        let mut state = self.state.borrow_mut();
        if state.vault.is_none() || state.secret_key.is_none() {
            return None;
        }
        let vault = state.vault.take()?;
        let secret_key = state.secret_key.take()?;
        state.lent = true;
        Some((vault, secret_key, state.session))
    }

    /// A job gives back what [`Controller::lend_vault`] lent it. Only to the session it came
    /// from: when the vault was locked meanwhile (the app was left, the time ran out, Lock),
    /// it stays locked, what the job held is dropped (and wiped) here, and `false` says the
    /// job's result is to be dropped too.
    fn take_back(&self, vault: Vault, secret_key: SecretKey, session: u64) -> bool {
        let mut state = self.state.borrow_mut();
        if state.session != session || !state.lent || state.vault.is_some() {
            return false;
        }
        state.lent = false;
        state.vault = Some(vault);
        state.secret_key = Some(secret_key);
        true
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
        let info = Vault::inspect(&bytes).ok();
        let known = info
            .as_ref()
            .and_then(|info| secret_store::load(&info.id_hex).ok().flatten())
            .is_some();
        app.set_needs_secret_key(!known);
        app.set_screen(Screen::Unlock);
        self.forget_review();
        match &info {
            Some(info) => {
                self.unlock_wait(&info.id_hex);
            }
            None => app.set_unlock_wait(0),
        }
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
        if self.unlock_wait(&info.id_hex) > 0 {
            return self.set_error(error::UNLOCK_WAIT, "");
        }
        let (secret_key, typed_key) = match secret_store::load(&info.id_hex).ok().flatten() {
            Some(key) => (key, false),
            None => match SecretKey::parse(self.secret(field::SECRET_KEY).trim()) {
                Ok(key) => (key, true),
                Err(_) => return self.set_error(error::SECRET_KEY, ""),
            },
        };
        let password = self.secret(field::MASTER);
        let vault_id = info.id_hex;
        self.run_in_session(
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
                    vault_id,
                    secret_key,
                    typed_key,
                    hash: fingerprint(&bytes),
                    by_password: true,
                    used_parts: None,
                }
            },
            |c, opened| c.opened(opened),
        );
    }

    // ---- recovery with the emergency kit ----

    /// "Forgot your master password?" (`mode` 0) or "No Secret Key? Use two recovery parts"
    /// (1), from the unlock screen.
    fn start_recovery(&self, mode: i32) {
        self.clear_secrets();
        self.set_error(error::NONE, "");
        let app = self.app();
        app.set_recover_mode(mode);
        app.set_recovered_key(SharedString::new());
        app.set_screen(Screen::Recover);
    }

    /// The recovery parts typed (or scanned) into `fields`, each a different one.
    fn typed_parts<const N: usize>(
        &self,
        fields: [usize; N],
    ) -> Result<[vault_core::RecoveryPart; N], i32> {
        let mut parts: Vec<vault_core::RecoveryPart> = Vec::with_capacity(N);
        for index in fields {
            let part = vault_core::RecoveryPart::parse(self.secret(index).trim())
                .map_err(|_| error::PART_TYPO)?;
            if parts.iter().any(|other| other.label() == part.label()) {
                return Err(error::PARTS_SAME);
            }
            parts.push(part);
        }
        parts.try_into().map_err(|_| error::PART_TYPO)
    }

    /// Recovery. With two parts the Secret Key comes back (no password hashing) and the
    /// master password opens the vault as usual. With three, a new master password is set
    /// and a new Secret Key made (the old one may be what was lost or seen); the parts used
    /// stop working, fingerprint unlock goes, and the new Secret Key is shown before the
    /// vault opens.
    fn recover(&self) {
        let app = self.app();
        if app.get_busy() {
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
        if !info.has_recovery_parts {
            return self.set_error(error::NO_PARTS, "");
        }
        let wrong_parts = |err: CoreError| match err {
            CoreError::NoMatchingSlot => error::NO_PARTS,
            _ => error::PARTS_WRONG,
        };
        if app.get_recover_mode() == 1 {
            if self.unlock_wait(&info.id_hex) > 0 {
                return self.set_error(error::UNLOCK_WAIT, "");
            }
            let [first, second] = match self.typed_parts([field::PART_A, field::PART_B]) {
                Ok(parts) => parts,
                Err(code) => return self.set_error(code, ""),
            };
            let secret_key = match Vault::recover_secret_key(&bytes, &first, &second) {
                Ok(key) => key,
                Err(err) => return self.set_error(wrong_parts(err), ""),
            };
            let password = self.secret(field::MASTER);
            let vault_id = info.id_hex;
            return self.run_in_session(
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
                        vault_id,
                        secret_key,
                        typed_key: true,
                        hash: fingerprint(&bytes),
                        by_password: true,
                        used_parts: Some(bytes),
                    }
                },
                |c, opened| c.opened(opened),
            );
        }
        let parts = match self.typed_parts([field::PART_A, field::PART_B, field::PART_C]) {
            Ok(parts) => parts,
            Err(code) => return self.set_error(code, ""),
        };
        let password = self.secret(field::NEW);
        if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
            return self.set_error(error::TOO_SHORT, "");
        }
        if *password != *self.secret(field::NEW_AGAIN) {
            return self.set_error(error::MISMATCH, "");
        }
        if !self.review_new_password(passwords::place::RECOVERY) {
            return;
        }
        self.run_in_session(
            move || -> Result<Recovered, (i32, String)> {
                let [a, b, c] = &parts;
                let mut vault =
                    Vault::open(&bytes, Unlock::Parts([a, b, c])).map_err(|err| match err {
                        CoreError::NoMatchingSlot => (error::NO_PARTS, String::new()),
                        CoreError::DecryptionFailed => (error::PARTS_WRONG, String::new()),
                        other => (error::UNREADABLE, other.to_string()),
                    })?;
                let secret_key =
                    SecretKey::generate().map_err(|e| (error::NOT_SAVED, e.to_string()))?;
                let kdf = vault.kdf_params().clone();
                // A keyfile may be what was lost: the new lock is password + Secret Key.
                vault
                    .change_password(&password, &secret_key, None, &kdf)
                    .map_err(|e| (error::NOT_SAVED, e.to_string()))?;
                // Recovery parts work once.
                vault.clear_recovery_parts();
                let written = vault
                    .to_bytes()
                    .map_err(|e| (error::NOT_SAVED, e.to_string()))?;
                Ok((vault, secret_key, written, fingerprint(&bytes)))
            },
            |c, result| c.recovered(result),
        );
    }

    /// A new master password and Secret Key were set: the file is written, the new key kept
    /// in the phone's keystore, and the key shown before the vault opens. Only over the file
    /// the parts were checked against (or as the phone's copy, for a chosen file): one that
    /// changed meanwhile keeps what was written to it, and the parts still work.
    fn recovered(&self, result: Result<Recovered, (i32, String)>) {
        let (vault, secret_key, bytes, read) = match result {
            Ok(done) => done,
            Err((code, detail)) => {
                if code == error::PARTS_WRONG {
                    self.log_failed(security::how::RECOVERY);
                }
                return self.set_error(code, &detail);
            }
        };
        // An older file than one opened here before is refused, as `opened` refuses it, but
        // before anything is written: written over under a new Secret Key that `opened` would
        // then never show, the vault would be lost. The parts still work, on the newest copy.
        if older_than_seen(&vault.id_hex(), vault.revision()) {
            return self.set_error(error::OLDER, "");
        }
        let (path, replaces_copy) = {
            let state = self.state.borrow();
            (state.path.clone(), state.incoming.is_some())
        };
        if !replaces_copy && files::read(&path).ok().map(|now| fingerprint(&now)) != Some(read) {
            return self.set_error(
                error::PARTS_KEPT,
                "the vault file was changed by something else",
            );
        }
        let written = path
            .parent()
            .map_or(Ok(()), files::create_dir_all)
            .map_err(|e| e.to_string())
            .and_then(|()| files::write_atomic(&path, &bytes).map_err(|e| e.to_string()));
        if let Err(detail) = written {
            return self.set_error(error::NOT_SAVED, &detail);
        }
        // What was chosen is the vault now written; nothing waits any more.
        self.state.borrow_mut().incoming = None;
        let id = vault.id_hex();
        // Fingerprint unlock was bound to the old master password.
        self.forget_biometrics(&id);
        let shown = secret_key.to_display_string();
        self.forget_review();
        self.state.borrow_mut().unlock_how = Some(security::how::RECOVERY);
        self.opened(Opened {
            vault: Ok(vault),
            vault_id: id,
            secret_key,
            typed_key: true,
            hash: fingerprint(&bytes),
            by_password: true,
            used_parts: None,
        });
        if self.state.borrow().vault.is_some() {
            let app = self.app();
            app.set_recovered_key(SharedString::from(shown.as_str()));
            app.set_screen(Screen::Recover);
        }
    }

    /// "Open my vault" under the new Secret Key: it leaves the screen.
    fn recovered_done(&self) {
        let app = self.app();
        app.set_recovered_key(SharedString::new());
        self.set_error(error::NONE, "");
        if self.state.borrow().vault.is_some() {
            app.set_screen(Screen::Vault);
        } else {
            self.show_entry();
        }
    }

    fn copy_recovered_key(&self) {
        let key = self.app().get_recovered_key();
        if !key.is_empty() {
            self.copy_secret(&key, notice::COPIED);
        }
    }

    /// A part or the Secret Key scanned from the kit's QR code goes straight into its secure
    /// field (never through the screen's text).
    pub(super) fn kit_code_scanned(&self, purpose: i32, text: &str) {
        let index = if purpose == scan::SECRET_KEY {
            field::SECRET_KEY
        } else {
            let state = self.state.borrow();
            let count = if self.app().get_recover_mode() == 0 {
                3
            } else {
                2
            };
            let empty = [field::PART_A, field::PART_B, field::PART_C]
                .into_iter()
                .take(count)
                .find(|index| state.secrets[*index].char_count() == 0);
            match empty {
                Some(index) => index,
                None => field::PART_A,
            }
        };
        let value = text.trim();
        self.with_secret(i32::try_from(index).unwrap_or(-1), |buffer| {
            buffer.set(value);
        });
        self.set_error(error::NONE, "");
    }

    /// A picture chosen on the recovery screen: the part hidden in it goes into the first
    /// empty field, as a scanned one does. The part never becomes a Slint string.
    pub(super) fn part_picture_picked(&self, bytes: &[u8]) {
        #[cfg(not(target_arch = "wasm32"))]
        match vault_platform::part_picture::read(bytes) {
            Ok(part) => self.kit_code_scanned(scan::PART, &part.to_display_string()),
            Err(err) => self.set_error(error::PART_PICTURE, &format!("{err:#}")),
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = bytes;
            self.set_error(error::PART_PICTURE, "not in a browser");
        }
    }

    fn opened(&self, opened: Opened) {
        let Opened {
            vault,
            vault_id,
            secret_key,
            mut typed_key,
            mut hash,
            by_password,
            used_parts,
        } = opened;
        let mut vault = match vault {
            Ok(vault) => vault,
            Err(CoreError::KeyfileRequired) => return self.set_error(error::KEYFILE, ""),
            Err(err) => {
                self.log_failed(security::how::PASSWORD);
                self.state.borrow_mut().secrets[field::MASTER].clear();
                self.publish_lengths();
                // A wrong master password (or Secret Key): counted, and maybe the last try
                // this phone's copy allowed.
                if matches!(err, CoreError::DecryptionFailed) && self.unlock_failed(&vault_id) {
                    return;
                }
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
        let incoming = self.state.borrow_mut().incoming.take();
        // The Secret Key two recovery parts brought back, when it couldn't be kept here.
        let mut key_not_kept = None;
        if let Some(read) = used_parts {
            // Recovery parts work once: the two just typed stop working before anything is
            // kept or shown (a chosen file becomes the phone's copy with them retired).
            match self.retire_parts(&mut vault, &read, incoming.is_some(), &secret_key) {
                Retired::Done(written) => hash = written,
                Retired::Refused(detail) => {
                    self.state.borrow_mut().incoming = incoming;
                    return self.set_error(error::PARTS_KEPT, &detail);
                }
                Retired::KeyNotKept(written, detail) => {
                    hash = written;
                    key_not_kept = Some(detail);
                }
            }
            // Kept already, or couldn't be.
            typed_key = false;
        } else if let Some(bytes) = incoming {
            // A chosen file proved itself: it becomes the phone's copy (the old one stays as
            // `.bak` next to it).
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
        if typed_key {
            let _ = secret_store::store(&id, &secret_key);
        }
        if by_password {
            self.password_typed(&id);
        }
        let shown = key_not_kept
            .is_some()
            .then(|| secret_key.to_display_string());
        self.new_session();
        {
            let mut state = self.state.borrow_mut();
            state.vault = Some(vault);
            state.secret_key = Some(secret_key);
            state.file_hash = Some(hash);
        }
        {
            let how = self.state.borrow_mut().unlock_how.take();
            let how = how.unwrap_or(if by_password {
                security::how::PASSWORD
            } else {
                security::how::DEVICE
            });
            let state = self.state.borrow();
            if let Some(vault) = state.vault.as_ref() {
                self.log_unlocked(vault, how);
            }
        }
        self.state.borrow_mut().security_log_shown = 0;
        self.enter_vault();
        self.tell_failed_unlocks(&id);
        self.publish_security_log();
        if state_file != StateFile::Read {
            self.notify(notice::STATE_RESET, "");
        }
        if let (Some(detail), Some(shown)) = (key_not_kept, shown) {
            // As after a recovery with three parts: the key on screen, to write down.
            let app = self.app();
            app.set_recovered_key(SharedString::from(shown.as_str()));
            app.set_screen(Screen::Recover);
            self.set_error(error::KEY_NOT_KEPT, &detail);
        }
    }

    /// Two recovery parts and the master password opened `vault`, read from `read`: the
    /// parts stop working, written over the file they were checked against, and only then is
    /// the Secret Key they brought back kept on this phone (a phone that kept it would never
    /// ask for them again, and they would go on working). As `vault recover` does it.
    ///
    /// When the file changed meanwhile (another device's sync) or can't be written, nothing
    /// is written over and nothing kept: the parts still work. When the key can't be kept,
    /// the file is put back as it was, so the parts aren't used up for nothing. `replaces_copy`:
    /// `read` is a chosen file, which becomes the phone's copy (it is written whatever the
    /// copy held).
    fn retire_parts(
        &self,
        vault: &mut Vault,
        read: &[u8],
        replaces_copy: bool,
        secret_key: &SecretKey,
    ) -> Retired {
        let path = self.state.borrow().path.clone();
        // What the phone's copy holds now (nothing yet, on a new phone).
        let before = files::read(&path).ok();
        if !replaces_copy && before.as_deref().map(fingerprint) != Some(fingerprint(read)) {
            return Retired::Refused("the vault file was changed by something else".to_owned());
        }
        vault.clear_recovery_parts();
        let written = match vault.to_bytes() {
            Ok(bytes) => bytes,
            Err(err) => return Retired::Refused(err.to_string()),
        };
        let saved = path
            .parent()
            .map_or(Ok(()), files::create_dir_all)
            .map_err(|e| e.to_string())
            .and_then(|()| files::write_atomic(&path, &written).map_err(|e| e.to_string()));
        if let Err(detail) = saved {
            return Retired::Refused(detail);
        }
        let written_hash = fingerprint(&written);
        let Err(detail) = self.keep_secret_key(&vault.id_hex(), secret_key) else {
            return Retired::Done(written_hash);
        };
        // Back as it was, unless something else wrote it in this moment.
        let put_back = match files::read(&path) {
            Ok(now) if fingerprint(&now) == written_hash => match &before {
                Some(bytes) => files::write_atomic(&path, bytes).map_err(|e| e.to_string()),
                None => {
                    files::remove(&path);
                    Ok(())
                }
            },
            Ok(_) => Err("the vault file was changed by something else".to_owned()),
            Err(err) => Err(err.to_string()),
        };
        match put_back {
            Ok(()) => Retired::Refused(detail),
            Err(back) => Retired::KeyNotKept(written_hash, format!("{detail}; {back}")),
        }
    }

    /// Keeps the Secret Key of the vault `id` in the phone's keystore.
    fn keep_secret_key(&self, id: &str, secret_key: &SecretKey) -> Result<(), String> {
        #[cfg(test)]
        if self.state.borrow().refuse_secret_key {
            return Err("the keystore refused it".to_owned());
        }
        secret_store::store(id, secret_key).map_err(|err| format!("{err:#}"))
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
        self.publish_folders();
        self.refresh_list();
        self.refresh_health();
        self.publish_generated();
        self.fetch_icons();
        self.start_sync();
        self.watch_leaks();
    }

    /// A sync round took another device's item lock (`MergeReport::guard_changed`): what the
    /// replaced lock had opened here closes, as on the desktop. The item lock closes; an item
    /// page or an editor showing an item it guards goes back to the list (an editor on an item
    /// it doesn't guard keeps its typing); a secret copied from the vault leaves the clipboard.
    /// The next look at a locked item asks for the new lock's check.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn after_guard_changed(&self) {
        let copied = self.state.borrow_mut().copied.take();
        if let Some((value, _)) = copied {
            // Only if it is still ours: something copied since stays.
            clipboard::clear_if(&value);
        }
        let guarded = |state: &State, id: Option<ItemId>| match (state.vault.as_ref(), id) {
            (Some(vault), Some(id)) => vault
                .get_item(&id)
                .ok()
                .is_none_or(|item| item.is_locked() || vault.guards(&item)),
            _ => false,
        };
        let (in_editor, on_item) = {
            let mut state = self.state.borrow_mut();
            state.show_password = false;
            state.show_card = false;
            state.show_note = false;
            state.each_use = None;
            state.codes_shown.clear();
            state.master_checked = false;
            if let Some(vault) = state.vault.as_mut() {
                vault.lock_secrets();
            }
            let in_editor = guarded(&state, state.editing);
            let on_item = guarded(&state, state.selected);
            (in_editor, on_item)
        };
        if in_editor {
            {
                let mut state = self.state.borrow_mut();
                state.editing = None;
                state.confirm_delete = false;
                state.secrets[field::ITEM_PASSWORD].clear();
            }
            self.publish_lengths();
            self.clear_editor();
        }
        if in_editor || on_item {
            self.close_item();
        } else {
            self.publish_generated();
        }
        // The item lock asked instead of a screen lock may be another one now.
        self.refresh_each_use();
    }

    /// Items came from another device: the list, and the open item if it is still there.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn after_sync_changes(&self) {
        self.refresh_list();
        // What came may be an item behind the item lock whose password is in the generator's
        // history (copied here, used on another device): the history waits for the lock now,
        // also on a page that is on screen.
        self.publish_generated();
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

    /// Locks: the vault and everything read from it leave memory and the screen. A job that
    /// holds the vault meanwhile ([`Controller::lend_vault`]) can't give it back any more.
    pub fn lock(&self) {
        self.stop_sync();
        self.new_session();
        {
            let mut state = self.state.borrow_mut();
            state.vault = None;
            state.secret_key = None;
            state.lent = false;
            state.shown.clear();
            state.code_ids.clear();
            state.health_ids.clear();
            state.health_all.clear();
            state.selected = None;
            state.editing = None;
            state.master_checked = false;
            state.show_password = false;
            state.show_card = false;
            state.show_note = false;
            state.each_use = None;
            state.codes_shown.clear();
            state.generated = Zeroizing::new(String::new());
            state.leaked.clear();
            state.watch_looked = None;
            state.export_pending = None;
            state.import_pending = None;
            state.ssh_pending = None;
        }
        *self.icons.borrow_mut() = icons::Icons::default();
        let app = self.app();
        app.set_import_name(SharedString::new());
        app.set_choosing_vault(false);
        app.set_confirm_remove_vault(false);
        app.set_import_added(-1);
        app.set_items(ModelRc::default());
        app.set_codes(ModelRc::default());
        app.set_total(0);
        app.set_vault_name(SharedString::new());
        app.set_gen_password(SharedString::new());
        app.set_gen_for_editor(false);
        app.set_notice_code(0);
        app.set_folders(ModelRc::default());
        app.set_folder_filter(-1);
        app.set_health_rows(ModelRc::default());
        app.set_health_problems(0);
        app.set_health_filter(-1);
        app.set_recovered_key(SharedString::new());
        app.set_confirming(0);
        self.forget_generated_rows();
        self.clear_item_page();
        self.clear_editor();
        self.show_entry();
        self.publish_vaults();
        // What key work left on this thread's stack (unlocking, reading items) goes too.
        vault_core::memory::clear_stack();
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

    // ---- the sheet that asks for a password (app.slint `ask`) ----

    /// The secure fields each sheet asks for.
    fn sheet_fields(kind: i32) -> &'static [usize] {
        match kind {
            sheet::EXPORT_JSON..=sheet::EXPORT_CSV => {
                &[field::EXPORT_MASTER, field::EXPORT_PASSWORD]
            }
            sheet::REMOVE_VAULT..=sheet::REMOVE_BACKUP | sheet::ADD_DEVICE => {
                &[field::EXPORT_MASTER]
            }
            sheet::TAKE_KEY => &[field::SECRET_KEY, field::EXPORT_MASTER],
            sheet::IMPORT => &[field::IMPORT_PASSWORD],
            sheet::MASTER_PASSWORD => &[field::CURRENT, field::NEW, field::NEW_AGAIN],
            sheet::ITEM_CHECK | sheet::USE_CHECK => &[field::ITEM_CHECK],
            sheet::SSH_PASSPHRASE => &[field::SSH_PASSPHRASE],
            _ => &[],
        }
    }

    fn clear_fields(&self, fields: &[usize]) {
        {
            let mut state = self.state.borrow_mut();
            for &index in fields {
                state.secrets[index].clear();
                state.showing[index] = false;
            }
        }
        self.publish_lengths();
    }

    /// A sheet opened: nothing from an earlier try stays in its fields or under them.
    fn sheet_opened(&self, kind: i32) {
        self.clear_fields(Self::sheet_fields(kind));
        self.set_error(error::NONE, "");
    }

    /// A sheet closed without its action: its fields are cleared, and a file that waited
    /// for its password is dropped.
    fn sheet_closed(&self, kind: i32) {
        self.clear_fields(Self::sheet_fields(kind));
        if kind == sheet::IMPORT {
            self.state.borrow_mut().import_pending = None;
            self.app().set_import_name(SharedString::new());
        }
        if kind == sheet::SSH_PASSPHRASE {
            self.state.borrow_mut().ssh_pending = None;
        }
        if kind == sheet::UPDATE {
            self.update_put_off();
        }
        if kind == sheet::USE_CHECK {
            self.use_check_dropped();
        }
        self.set_error(error::NONE, "");
    }

    /// The sheet's action is done: it closes (if it is still the one open).
    fn close_sheet(&self, kind: i32) {
        let app = self.app();
        if app.get_confirming() == kind {
            app.set_confirming(0);
            app.global::<Secrets>().set_focused(-1);
        }
    }

    // ---- the master password ----

    /// The change is made (or the vault locked): the sheet's fields are cleared and it closes.
    fn close_password_change(&self) {
        self.forget_review();
        self.clear_fields(Self::sheet_fields(sheet::MASTER_PASSWORD));
        self.set_error(error::NONE, "");
        self.close_sheet(sheet::MASTER_PASSWORD);
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
        if !self.review_new_password(passwords::place::CHANGE) {
            return;
        }
        self.set_error(error::NONE, "");
        let Some((vault, secret_key, session)) = self.lend_vault() else {
            return;
        };
        let (path, expected) = {
            let state = self.state.borrow();
            (state.path.clone(), state.file_hash)
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
            move |c, changed| {
                let revision = changed.vault.revision();
                let id = changed.vault.id_hex();
                // Locked meanwhile (the app was left): it stays locked.
                let back = c.take_back(changed.vault, changed.secret_key, session);
                match changed.outcome {
                    Ok(hash) => {
                        // The file has the new password either way: what follows from it
                        // is done, and the person told.
                        let _ = crate::platform::device::record_revision(&id, revision);
                        if back {
                            c.state.borrow_mut().file_hash = Some(hash);
                            c.close_password_change();
                        }
                        c.forget_review();
                        c.log_event(security::kind::PASSWORD_CHANGED, "", "", "");
                        c.notify(notice::PASSWORD_CHANGED, "");
                        c.biometrics_revoked(&id);
                        if back {
                            c.sync_after_save();
                        }
                    }
                    // Nothing changed, and nothing to say behind the lock screen.
                    Err(_) if !back => {}
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
        // A folder shows its items and those of the folders inside it.
        let folders = self.folder_and_inside(app.get_folder_filter());
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
                // The trash has a filter of its own; archived items and templates are kept
                // for the desktop, out of the phone's lists (format v11).
                let fits = match filter {
                    TRASH_FILTER => item.trashed_at != 0,
                    _ if !item.is_active() => false,
                    1 => item.favorite,
                    2 => item.kind == ItemKind::Login,
                    3 => item.kind == ItemKind::Card,
                    4 => item.kind == ItemKind::SecureNote,
                    5 => item.kind == ItemKind::SshKey,
                    6 => item.passkeys > 0,
                    _ => true,
                };
                let text = format!("{} {} {}", item.title, item.username, item.url).to_lowercase();
                if !fits
                    || folders
                        .as_ref()
                        .is_some_and(|inside| !item.folder.is_some_and(|f| inside.contains(&f)))
                    || !words.iter().all(|word| text.contains(word))
                {
                    continue;
                }
                let detail = [&item.username, &item.card_hint, &item.url]
                    .into_iter()
                    .find(|text| !text.is_empty())
                    .cloned()
                    .unwrap_or_default();
                let (icon, has_icon) = self.picture(&item.url, &item.icon_url);
                let (glyph, glyph_color, glyph_bg) = icons::look_of(&item.icon_url);
                rows.push(ItemRow {
                    brand: view::brand_mark(item.card_brand),
                    glyph,
                    glyph_color,
                    glyph_bg,
                    http: icons::plain_http(&item.url),
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
            state.show_card = false;
            state.show_note = false;
            state.each_use = None;
        }
        self.set_error(error::NONE, "");
        self.show_item();
        self.app().set_page(Page::Item);
    }

    fn show_item(&self) {
        let app = self.app();
        let asks = self.each_use_asks();
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
        let (icon, has_icon) = self.picture(&website, &item.icon_url);
        app.set_d_icon(icon);
        app.set_d_has_icon(has_icon);
        let (glyph, glyph_color, glyph_bg) = icons::look_of(&item.icon_url);
        app.set_d_glyph(glyph);
        app.set_d_glyph_color(glyph_color);
        app.set_d_glyph_bg(glyph_bg);
        app.set_d_http(icons::plain_http(&website));
        // A `*.` rule over a public suffix (or not a plain name) fills nowhere: told here.
        app.set_d_wide(crate::autofill::wildcard_unused(&website));
        let folder = item.folder.and_then(|id| {
            vault
                .folders()
                .iter()
                .find(|folder| folder.id == id)
                .map(|folder| folder.name.clone())
        });
        app.set_d_folder(folder.unwrap_or_default().into());
        app.set_d_created(if item.created_at > 0 {
            view::date(item.created_at).into()
        } else {
            SharedString::new()
        });
        app.set_d_edited(if item.updated_at > item.created_at + 60 {
            view::date(item.updated_at).into()
        } else {
            SharedString::new()
        });
        app.set_d_favorite(item.favorite);
        app.set_d_username(item.username.as_str().into());
        app.set_d_website(website.into());
        app.set_d_check(check);
        // A note's text is the secret of a note: it waits for the check too, and when every
        // use asks, it shows only once asked for ("Show the note").
        let note_asked = open && !item.notes.is_empty() && self.note_waits(item.kind, asks);
        app.set_d_note_waits(note_asked);
        let notes_wait = (!open || note_asked) && item.kind == ItemKind::SecureNote;
        let notes = if notes_wait { "" } else { item.notes.as_str() };
        app.set_d_notes(notes.into());
        app.set_d_notes_styled(styled_notes(notes));
        let details = (item.kind == ItemKind::Card).then(|| CardDetails::from_item(&item));
        let card = match &details {
            Some(details) if open && details.number.len() >= 4 => {
                if state.show_card {
                    card::group(&details.number)
                } else {
                    card::masked(&details.number)
                }
            }
            _ => String::new(),
        };
        app.set_d_card(card.into());
        app.set_d_card_shown(state.show_card);
        app.set_d_brand(details.as_ref().map_or(0, |details| {
            view::brand_mark(card::detect_brand(&card::digits(&details.number)))
        }));
        let code = details
            .as_ref()
            .filter(|_| open)
            .map(|details| details.security_code.clone())
            .unwrap_or_default();
        app.set_d_has_card_code(!code.is_empty());
        app.set_d_card_code(if state.show_card {
            code.as_str().into()
        } else {
            SharedString::new()
        });
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
        let parsed = open.then(|| Totp::parse(&item.totp).ok()).flatten();
        app.set_d_counter_based(parsed.as_ref().is_some_and(Totp::is_counter_based));
        // Every use asks: the code is dots until its eye, and only until it runs out.
        let hide = asks != Ask::Nothing;
        let code = parsed.map(|totp| self.code_now(*id, &totp, hide));
        app.set_d_has_code(code.is_some());
        app.set_d_code_eye(hide);
        match code {
            Some(code) => {
                app.set_d_code(code.text.into());
                app.set_d_code_hidden(code.hidden);
                app.set_d_code_left(i32::try_from(code.left).unwrap_or(0));
                app.set_d_code_period(i32::try_from(code.period).unwrap_or(30));
            }
            None => {
                app.set_d_code(SharedString::new());
                app.set_d_code_hidden(false);
            }
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
        app.set_d_wide(false);
        app.set_d_check(0);
        app.set_d_card_code(SharedString::new());
        app.set_d_has_card_code(false);
        app.set_d_card_shown(false);
        app.set_d_note_waits(false);
        app.set_d_notes_styled(slint::StyledText::default());
        self.close_preview();
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
            let left = state.selected.take();
            state.codes_shown.retain(|(id, _)| Some(*id) != left);
            state.show_password = false;
            state.show_card = false;
            state.show_note = false;
            state.each_use = None;
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
        // The lock closed again: the generator's history waits for it again too.
        self.publish_generated();
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
                // A copy for the check's own thread.
                let key = state.secret_key.as_ref().map(SecretKey::duplicate);
                (state.path.clone(), key)
            };
            let Some(secret_key) = secret_key else {
                return;
            };
            // A check passed for this session only: once locked, it opens nothing.
            return self.run_in_session(
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
        let right = self.open_item_lock(&typed);
        self.item_checked(right);
    }

    /// Opens the item lock with its PIN or password; `false` when it is wrong. Items added
    /// while it was closed are sealed under it, and the vault saved.
    fn open_item_lock(&self, typed: &str) -> bool {
        let right = {
            let mut state = self.state.borrow_mut();
            state
                .vault
                .as_mut()
                .is_some_and(|vault| vault.unlock_secrets(typed).unwrap_or(false))
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
        right
    }

    fn item_checked(&self, right: bool) {
        self.clear_fields(&[field::ITEM_CHECK]);
        if !right {
            return self.set_error(error::WRONG_CHECK, "");
        }
        let shows = self.each_use_asks() != Ask::Nothing;
        let master = self.app().get_d_check() == 1;
        {
            let mut state = self.state.borrow_mut();
            if master {
                state.master_checked = true;
            }
            // "Show the secrets" was asked once, with the item lock's own check: when every
            // use asks, they show now (the password, the card's number, a note) instead of
            // asking the phone again for the same thing. Every later use asks.
            if shows {
                state.show_password = true;
                state.show_card = true;
                state.show_note = true;
            }
        }
        let selected = self.state.borrow().selected;
        if shows && let Some(id) = selected {
            self.mark_code_shown(id);
        }
        self.set_error(error::NONE, "");
        self.close_sheet(sheet::ITEM_CHECK);
        self.show_item();
        // The secrets read now tell which generated passwords logins use: those leave the
        // generator's history.
        self.publish_generated();
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

    /// The item page's copy buttons: a secret (the password, the code, the card's number or
    /// security code) is asked for first when every use asks.
    fn copy(&self, what: i32) {
        match what {
            1 | 2 | 5 | 6 => self.use_of_item(Use::Copy(what)),
            _ => self.copy_now(what),
        }
    }

    fn copy_now(&self, what: i32) {
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
            5 | 6 => {
                let value = self.selected_item().map(|item| {
                    let details = CardDetails::from_item(&item);
                    if what == 5 {
                        card::digits(&details.number)
                    } else {
                        details.security_code
                    }
                });
                if let Some(value) = value.filter(|value| !value.is_empty()) {
                    self.copy_secret(&value, notice::COPIED);
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
        let hide = self.each_use_asks() != Ask::Nothing;
        let (rows, ids) = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            let mut summaries = vault.summaries().unwrap_or_default();
            summaries.retain(|item| item.has_totp && item.is_active());
            // In the order the person gave them (held and dragged), the rest after them by
            // title.
            let order = state
                .prefs
                .code_order
                .get(&vault.id_hex())
                .cloned()
                .unwrap_or_default();
            summaries.sort_by_cached_key(|item| {
                let hex = item.id.to_hex();
                (
                    order.iter().position(|id| *id == hex).unwrap_or(usize::MAX),
                    item.title.to_lowercase(),
                )
            });
            let mut rows = Vec::new();
            let mut ids = Vec::new();
            for summary in &summaries {
                let Ok(item) = vault.get_item(&summary.id) else {
                    continue;
                };
                // Behind the item lock: the row says so instead of showing digits. Every use
                // asking: dots until its eye.
                let code = (self.check_for(vault, &item) == 0)
                    .then(|| Totp::parse(&item.totp).ok())
                    .flatten()
                    .map(|totp| self.code_now(summary.id, &totp, hide));
                let (digits, left, period, hidden) = match code {
                    Some(code) => (code.text, code.left, code.period, code.hidden),
                    None => (String::new(), 0, 30, false),
                };
                let (icon, has_icon) = self.picture(&summary.url, &summary.icon_url);
                let (glyph, glyph_color, glyph_bg) = icons::look_of(&summary.icon_url);
                rows.push(CodeRow {
                    glyph,
                    glyph_color,
                    glyph_bg,
                    counter: Totp::parse(&item.totp).is_ok_and(|t| t.is_counter_based()),
                    icon,
                    has_icon,
                    title: summary.title.as_str().into(),
                    account: summary.username.as_str().into(),
                    code: digits.into(),
                    hidden,
                    eye: hide,
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

    /// A code's card was held and dragged from place `from` to place `to`: the Codes page
    /// keeps that order (on this phone).
    fn move_code(&self, from: i32, to: i32) {
        let (Ok(from), Ok(to)) = (usize::try_from(from), usize::try_from(to)) else {
            return;
        };
        let order = {
            let state = self.state.borrow();
            let Some(vault) = state.vault.as_ref() else {
                return;
            };
            let mut ids: Vec<String> = state.code_ids.iter().map(ItemId::to_hex).collect();
            if from >= ids.len() || to >= ids.len() || from == to {
                return;
            }
            let moved = ids.remove(from);
            ids.insert(to, moved);
            (vault.id_hex(), ids)
        };
        self.change_prefs(move |prefs| {
            prefs.code_order.insert(order.0, order.1);
        });
        self.refresh_codes();
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
        app.set_ed_trashed(false);
        app.set_ed_confirm_delete(false);
        app.set_ed_folder(-1);
        app.set_ed_glyph(SharedString::new());
        app.set_ed_glyph_color(0);
        app.set_ed_glyph_bg(0);
        app.set_ed_counter(false);
        app.set_ed_card_mark(0);
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
            state.carets[field::ITEM_PASSWORD] = state.secrets[field::ITEM_PASSWORD].char_count();
        }
        if let Some(item) = &item {
            app.set_ed_title(item.title.as_str().into());
            app.set_ed_username(item.username.as_str().into());
            app.set_ed_website(item.urls.first().cloned().unwrap_or_default().into());
            app.set_ed_totp(item.totp.as_str().into());
            app.set_ed_notes(item.notes.as_str().into());
            app.set_ed_favorite(item.favorite);
            app.set_ed_trashed(item.trashed_at != 0);
            app.set_ed_folder(self.folder_index(item.folder));
            let (glyph, glyph_color, glyph_bg) = icons::look_of(&item.icon_url);
            app.set_ed_glyph(glyph);
            app.set_ed_glyph_color(glyph_color);
            app.set_ed_glyph_bg(glyph_bg);
            app.set_ed_counter(Totp::parse(&item.totp).is_ok_and(|t| t.is_counter_based()));
            if item.kind == ItemKind::Card {
                let details = CardDetails::from_item(item);
                app.set_ed_card_number(card::group(&details.number).into());
                app.set_ed_card_expiry(details.expiry.as_str().into());
                app.set_ed_card_code(details.security_code.as_str().into());
                if !details.number.is_empty() {
                    let brand = card::detect_brand(&card::digits(&details.number));
                    app.set_ed_card_brand(brand.name().into());
                    app.set_ed_card_mark(view::brand_mark(brand));
                }
            }
        }
        self.editor_files_from(item.as_ref());
        self.publish_lengths();
        self.editor_site_icon();
        app.set_page(Page::Editor);
    }

    /// The site's icon next to the editor's Website field, from what is already known (the
    /// list asks for new sites' icons once the item is saved).
    fn editor_site_icon(&self) {
        let app = self.app();
        let (icon, found) = self.picture(&app.get_ed_website(), "");
        app.set_ed_site_icon(icon);
        app.set_ed_has_site_icon(found);
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
        self.publish_lengths();
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
        // A bare key asked for as counter-based becomes its otpauth://hotp/ link.
        let totp = vault_core::totp::with_kind(
            app.get_ed_totp().trim(),
            kind == editor::AUTHENTICATOR && app.get_ed_counter(),
        );
        // Cards and authenticator items have no website on the phone's editor; what an older
        // one had is kept.
        let website = if kind == editor::LOGIN {
            app.get_ed_website().trim().to_owned()
        } else {
            String::new()
        };
        let folder = self.folder_at(app.get_ed_folder());
        let glyph = app.get_ed_glyph().to_string();
        let look = view::IconLook::new(&glyph, app.get_ed_glyph_color(), app.get_ed_glyph_bg());
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
        // The generator's password going into this item ("Use this password", "New login with
        // it"): from now on it is the item's, shown and copied only as the item allows.
        let from_generator = !password.is_empty() && *password == *self.state.borrow().generated;
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
                // The first website is the one edited here (logins); any others stay.
                match (
                    item.urls.first_mut(),
                    website.is_empty() || kind != editor::LOGIN,
                ) {
                    (Some(_), true) if kind != editor::LOGIN => {}
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
            item.folder = folder;
            // A chosen line icon is kept where a chosen site or picture is; choosing none
            // leaves a site or picture chosen on the desktop as it was.
            if !glyph.is_empty() {
                item.icon_url = look.icon_url();
            } else if item.icon_url.starts_with(icons::GLYPH) {
                item.icon_url.clear();
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
        if from_generator {
            self.forget_generated_result();
        }
        if !self.save() {
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            state.selected = Some(id);
            state.editing = Some(id);
            state.show_password = false;
            state.show_card = false;
            state.show_note = false;
        }
        self.close_editor();
        // A password from the generator that this login now uses leaves its history.
        self.publish_generated();
        self.publish_folders();
        self.notify(notice::SAVED, "");
    }

    /// Puts the item being edited in the trash (format v11): out of every list but the
    /// Trash filter, restorable for 30 days.
    fn trash_item(&self) {
        self.trash_or_restore(true);
    }

    /// Takes the item being edited out of the trash.
    fn restore_item(&self) {
        self.trash_or_restore(false);
    }

    fn trash_or_restore(&self, trash: bool) {
        let done = {
            let mut state = self.state.borrow_mut();
            let state = &mut *state;
            let (Some(vault), Some(id)) = (state.vault.as_mut(), state.editing) else {
                return;
            };
            let title = vault.get_item(&id).map(|item| item.title.clone()).ok();
            let changed = if trash {
                vault.trash_item(&id)
            } else {
                vault.restore_item(&id)
            };
            changed.ok().and(title)
        };
        let Some(title) = done else {
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
        self.notify(
            if trash {
                notice::TRASHED
            } else {
                notice::RESTORED
            },
            &title,
        );
    }

    /// Delete for good (an item in the trash), once the confirmation sheet said yes
    /// (app.slint, `ask(5)`).
    fn delete_item(&self) {
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

    /// The generator's current password is forgotten, on its page and here, and a new one takes
    /// its place: once it went into an item, it is that item's password, shown and copied only
    /// as the item allows, so an item lock closed again leaves nothing of it on the generator's
    /// page, which the item page goes back to (as on the desktop).
    fn forget_generated_result(&self) {
        self.state.borrow_mut().generated = Zeroizing::new(String::new());
        self.app().set_gen_password(SharedString::new());
        self.generate();
    }

    fn copy_generated(&self) {
        let password = self.state.borrow().generated.clone();
        if !password.is_empty() {
            self.copy_secret(&password, notice::COPIED);
            self.record_generated(&password);
        }
    }

    /// "Make a strong one" in the editor, confirmed: the generator opens for it, with the
    /// person's own settings; the editor waits behind it as it was.
    fn editor_generate(&self) {
        let app = self.app();
        app.set_gen_for_editor(true);
        app.set_page(Page::None);
        app.set_place(Place::Generator);
        self.generate();
    }

    /// "Use this password": the generator's password goes into the editor's password field,
    /// shown, and the editor comes back.
    fn generator_use(&self) {
        let password = self.state.borrow().generated.clone();
        if password.is_empty() {
            return;
        }
        self.with_secret(field::ITEM_PASSWORD as i32, |buffer| {
            buffer.set(&password);
        });
        self.record_generated(&password);
        self.show_editor_password(true);
        self.generator_back();
    }

    /// Back from the generator to the editor that asked for it (nothing changed).
    fn generator_back(&self) {
        let app = self.app();
        app.set_gen_for_editor(false);
        app.set_place(Place::Items);
        app.set_page(Page::Editor);
    }

    /// "New login with it": a new login whose password is the generator's.
    fn generator_new_login(&self) {
        let password = self.state.borrow().generated.clone();
        if password.is_empty() {
            return;
        }
        self.open_editor(None);
        self.with_secret(field::ITEM_PASSWORD as i32, |buffer| {
            buffer.set(&password);
        });
        self.record_generated(&password);
        self.show_editor_password(true);
    }

    // ---- codes ----

    /// Next on a counter-based code: its counter moves on (the link in the item changes and
    /// syncs) and the new code shows.
    fn next_code(&self, id: ItemId) {
        let changed = {
            let mut state = self.state.borrow_mut();
            let Some(vault) = state.vault.as_mut() else {
                return;
            };
            let Ok(mut item) = vault.get_item(&id) else {
                return;
            };
            if item.is_locked() {
                return;
            }
            let Some(next) = totp::next_counter(&item.totp) else {
                return;
            };
            item.totp = next;
            item.touch();
            vault.update_item(&id, &item).is_ok()
        };
        if changed && self.save() {
            self.refresh_codes();
            if self.state.borrow().selected == Some(id) {
                self.show_item();
            }
        }
    }

    /// Edit on a swiped code: the login opens in the editor (behind its check, when the item
    /// lock covers it: then its page asks first).
    fn edit_code(&self, index: i32) {
        let id = usize::try_from(index)
            .ok()
            .and_then(|index| self.state.borrow().code_ids.get(index).copied());
        let Some(id) = id else {
            return;
        };
        self.open_item_id(id);
        if self.selected_item().is_some() {
            self.open_editor(Some(id));
        }
    }

    /// A web address handed to the phone's browser: http and https only; a bare host gets
    /// https://.
    fn open_link(&self, link: &str) {
        let link = link.trim();
        if link.is_empty() {
            return;
        }
        let lower = link.to_ascii_lowercase();
        let url = if lower.starts_with("https://") || lower.starts_with("http://") {
            link.to_owned()
        } else if link.contains("://") {
            return;
        } else {
            format!("https://{link}")
        };
        self.system().open_link(&url);
    }

    /// A setup key typed or scanned in the editor: an otpauth:// link brings its service and
    /// account (into empty fields) and its kind (time or counter).
    fn otp_names_into_editor(&self, text: &str) {
        let app = self.app();
        let names = totp::names(text);
        if app.get_ed_title().trim().is_empty() && !names.issuer.is_empty() {
            app.set_ed_title(names.issuer.as_str().into());
        }
        if app.get_ed_username().trim().is_empty() && !names.account.is_empty() {
            app.set_ed_username(names.account.as_str().into());
        }
        if let Ok(parsed) = Totp::parse(text) {
            app.set_ed_counter(parsed.is_counter_based());
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
            let open = state.vault.is_some() || state.lent;
            let idle = open && now.duration_since(state.last_touch) >= state.lock_after;
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
        self.tick_unlock_wait();
        self.watch_tick();
        // Returns at once unless its time has come.
        self.ask_for_update_soon();
        let app = self.app();
        if app.get_screen() != Screen::Vault {
            return;
        }
        self.forget_spent_codes();
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
        let hide = self.each_use_asks() != Ask::Nothing;
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
                .map(|totp| self.code_now(*id, &totp, hide));
            let (digits, left, period, hidden) = match code {
                Some(code) => (code.text, code.left, code.period, code.hidden),
                None => (String::new(), 0, 30, false),
            };
            let left = i32::try_from(left).unwrap_or(0);
            let period = i32::try_from(period).unwrap_or(30);
            if row.code != digits.as_str()
                || row.left != left
                || row.period != period
                || row.hidden != hidden
                || row.eye != hide
            {
                row.code = digits.into();
                row.left = left;
                row.period = period;
                row.hidden = hidden;
                row.eye = hide;
                codes.set_row_data(i, row);
            }
        }
    }

    /// The vault file this window is about.
    pub fn path(&self) -> PathBuf {
        self.state.borrow().path.clone()
    }

    /// Whether a vault is open (for the shell: what to do when the app comes back), also
    /// while a job holds it for a moment.
    pub fn is_unlocked(&self) -> bool {
        let state = self.state.borrow();
        state.vault.is_some() || state.lent
    }
}
