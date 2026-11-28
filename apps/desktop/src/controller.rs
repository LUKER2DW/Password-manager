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
    CustomField, Error as CoreError, FolderId, FormerKey, GuardCheck, ItemData, ItemGuard, ItemId,
    ItemKind, KdfParams, RecoveryCode, RecoveryKey, RecoveryPart, RecoveryParts, SecretKey, Unlock,
    Vault,
    card::{self, CardDetails, CardProblem},
    generator::{self, PassphraseOptions},
    health::HealthReport,
    storage,
    totp::Totp,
};
use vault_import::ExportFormat;
use vault_platform::{
    DeviceState, RollbackStatus, SecretBuffer, StateFile, VersionStatus, clipboard, device, files,
    kit_pdf::{self, KitContents},
    part_picture,
    quick_unlock::{self, DeviceVerifier, QuickUnlockError},
    secret_store::{self, Kept, Loaded},
};
use zeroize::Zeroizing;

use crate::{
    ui::{
        AppWindow, AuthRow, CodeRow, DetailField, EditField, ExportCounts, FolderRow, ItemLock,
        ItemRow, Panel, RecentVault, Screen, Secrets, Theme,
    },
    view,
};
use vault_platform::website_icons::{self as favicon, IconCache};

mod attachments;
mod attempts;
mod browser;
mod drop_box;
mod extension;
mod features;
mod folders;
mod generated;
mod locked_fill;
mod navigation;
mod passwords;
mod protection;
mod renew;
mod syncing;
mod updates;
mod watch;

/// What to draw next to an item.
struct IconVisual {
    image: Image,
    has_image: bool,
    initial: SharedString,
    tint: slint::Color,
    /// A line icon chosen for it (`glyph:` in `icon_url`, `view::IconLook`) and its colours.
    glyph: SharedString,
    glyph_color: i32,
    glyph_bg: i32,
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
    /// Current master password on the "Unlock protection" card.
    pub const KDF_CURRENT: usize = 9;
    /// Current master password on the "Keyfile" card.
    pub const KEYFILE_CURRENT: usize = 10;
    /// Master password asked by a protected item.
    pub const REPROMPT: usize = 11;
    /// New PIN or password for the item lock, and the master password that allows the change.
    pub const GUARD_NEW: usize = 12;
    pub const GUARD_CURRENT: usize = 13;
    /// The master password typed to connect a browser extension.
    pub const PAIRING: usize = 14;
    /// The WebDAV password on the Sync card.
    pub const SYNC_PASSWORD: usize = 15;
    /// Recovery parts: all three on the recovery screen, or two of them on the unlock screen
    /// in place of the Secret Key.
    pub const PART_A: usize = 16;
    pub const PART_B: usize = 17;
    pub const PART_C: usize = 18;
    /// The passphrase of an SSH key brought into the editor, used once to open it.
    pub const SSH_PASSPHRASE: usize = 19;
    /// The master password a Settings dialog asks for before a sensitive change.
    pub const CONFIRM_MASTER: usize = 20;
    pub const COUNT: usize = 21;
    /// Fields whose eye also lays the characters out in boxes, as the kit prints them.
    pub const IN_BOXES: [usize; 4] = [SECRET_KEY, PART_A, PART_B, PART_C];
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
    pub const WORDLIST: i32 = 25;
    pub const LEAK_CHECK: i32 = 26;
    pub const VAULT_NAME: i32 = 27;
    pub const FOLDER_LINK: i32 = 28;
    pub const FOLDER_NAME: i32 = 30;
    pub const KEYFILE_NEEDED: i32 = 32;
    pub const KEYFILE_UNREADABLE: i32 = 33;
    pub const WRONG_WITH_KEYFILE: i32 = 34;
    pub const GUARD_WRONG: i32 = 35;
    pub const GUARD_SECRET: i32 = 36;
    pub const SECRETS_LOCKED: i32 = 37;
    pub const BROWSER_HOST: i32 = 38;
    pub const GUARD_HELLO: i32 = 39;
    pub const LOCKED_FILL_NEEDS_HELLO: i32 = 40;
    pub const TOTP_REQUIRED: i32 = 41;
    pub const BROWSER_PIPE: i32 = 42;
    pub const PARTS_WRONG: i32 = 44;
    pub const PART_TYPO: i32 = 45;
    pub const PARTS_SAME: i32 = 46;
    pub const PART_PICTURE: i32 = 47;
    pub const NO_PARTS: i32 = 48;
    pub const COVER: i32 = 49;
    pub const BACKUP_CHECK: i32 = 50;
    pub const FILE_TOO_LARGE: i32 = 51;
    pub const NOT_A_KEY: i32 = 52;
    /// SSH keys: a public key brought in instead of the private one; a form of key not read
    /// here; a passphrase that doesn't open the key.
    pub const KEY_PUBLIC_ONLY: i32 = 53;
    pub const KEY_UNSUPPORTED: i32 = 54;
    pub const KEY_PASSPHRASE: i32 = 55;
    /// What was typed opened only the newer item lock set on another device: this copy's
    /// own PIN or password is asked next (not a wrong try).
    pub const GUARD_NEWER_OPENED: i32 = 60;
    /// The vault key renewed on another device: the Secret Key and master password typed open
    /// none of its copies; this computer couldn't keep the new Secret Key (nothing changed);
    /// it couldn't, and the file opens only with the new kit now.
    pub const KEY_NOT_TAKEN: i32 = 61;
    pub const KEY_NOT_KEPT: i32 = 62;
    pub const KEY_ONLY_KIT: i32 = 63;
    /// Windows didn't take the start at sign-in (Settings → Appearance), on or off.
    pub const SIGN_IN_START: i32 = 64;
    /// The kit (or a part) was to be saved in a folder a cloud copies away (the detail names
    /// the service); nothing was written.
    pub const KIT_CLOUD: i32 = 65;
    /// A recovery part was to be saved in the folder another part went to; nothing written.
    pub const PARTS_TOGETHER: i32 = 66;
    /// A second request to connect replaced the one shown: its code is a new one.
    pub const PAIRING_REPLACED: i32 = 67;
    /// The browser extension's folder (Settings → Browser extension → Add to a browser)
    /// couldn't be written, or opened in Explorer; the detail says why.
    pub const EXTENSION_FOLDER: i32 = 70;
    pub const EXTENSION_FOLDER_OPEN: i32 = 71;
    /// The folder chosen to take the extension from doesn't read as one (the detail says why).
    pub const EXTENSION_LOCAL: i32 = 72;
    /// A protected export's password is below the one-factor floor (CRYPTO.md §3.3.1): it
    /// alone guards the file.
    pub const WEAK_EXPORT: i32 = 73;
    /// Too many failed unlocks in a row: the next try waits (controller/attempts.rs).
    pub const UNLOCK_WAIT: i32 = 74;
    /// The Secret Key kept on this computer can't be used (CRYPTO.md §2.2.1): the security
    /// chip no longer opens it (cleared, replaced, turned off); two different ones are kept;
    /// it couldn't be read just now (the detail says why). The kit's is asked for.
    pub const SECRET_KEY_CHIP_LOST: i32 = 90;
    pub const SECRET_KEY_CONFLICT: i32 = 91;
    pub const SECRET_KEY_UNREADABLE: i32 = 92;
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
    pub const PARTS_ISSUED: i32 = 8;
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
    pub const HISTORY_CLEARED: i32 = 24;
    pub const OLD_PASSWORD_COPIED: i32 = 25;
    pub const VAULT_SETTINGS_SAVED: i32 = 26;
    pub const WORDLIST_ADDED: i32 = 27;
    pub const LEAKS_CHECKED: i32 = 28;
    pub const BROWSER_OPENED: i32 = 29;
    pub const KDF_CHANGED: i32 = 30;
    pub const KDF_CHANGED_HELLO_OFF: i32 = 31;
    pub const FOLDER_DELETED: i32 = 32;
    pub const WEBSITE_COPIED: i32 = 33;
    pub const LINK_FAILED: i32 = 34;
    pub const KEYFILE_SET: i32 = 35;
    pub const KEYFILE_REMOVED: i32 = 36;
    pub const GUARD_SAVED: i32 = 37;
    pub const GUARD_LOCKED_OUT: i32 = 38;
    pub const SECRETS_LOCKED: i32 = 39;
    pub const BROWSER_FILLED: i32 = 40;
    pub const BROWSER_PAIRED: i32 = 41;
    pub const BROWSER_UNPAIRED: i32 = 42;
    pub const BROWSER_SAVED: i32 = 43;
    pub const GENERATED_CLEARED: i32 = 44;
    pub const LOCKED_FILL_ON: i32 = 45;
    pub const BROWSER_DROPPED: i32 = 46;
    pub const DEVICE_STATE_RESET: i32 = 47;
    pub const DEVICE_STATE_NOT_SAVED: i32 = 48;
    pub const LEAKS_SKIPPED_LOCKED: i32 = 49;
    pub const LEAKS_FOUND_SOME_LOCKED: i32 = 50;
    pub const BROWSER_UPDATED: i32 = 51;
    pub const SYNC_CHANGED: i32 = 52;
    pub const SYNC_CONFLICTS: i32 = 53;
    pub const SYNC_WAITING: i32 = 54;
    pub const SYNC_UNLOCK_CHANGED: i32 = 55;
    pub const SYNC_REFUSED: i32 = 56;
    pub const SYNC_REMOVED: i32 = 57;
    pub const SYNC_JOINED: i32 = 58;
    pub const SYNC_DEVICE_REMOVED: i32 = 59;
    pub const SYNC_MAIN_DOWN: i32 = 62;
    pub const SYNC_MAIN_BACK: i32 = 63;
    pub const SYNC_BACKUP_DOWN: i32 = 64;
    pub const SYNC_BACKUP_BACK: i32 = 65;
    pub const SYNC_BACKUP_JOINED: i32 = 66;
    pub const LEAKS_NEW: i32 = 67;
    pub const BROWSER_PASSKEY_SAVED: i32 = 68;
    pub const BROWSER_PASSKEY_USED: i32 = 69;
    pub const SYNC_ADDRESS_CHANGED: i32 = 70;
    pub const PICTURE_SAVED: i32 = 60;
    pub const PART_READ: i32 = 61;
    /// The item lock was changed on another device; this copy waits for its own lock (and the
    /// new one) to be opened here before its locked items move to it.
    pub const SYNC_LOCK_WAITING: i32 = 80;
    /// This copy took the item lock set on another device: what was open is closed again.
    pub const GUARD_MOVED: i32 = 81;
    /// The vault locked (or another one was chosen) before a changed item lock was saved.
    pub const GUARD_NOT_CHANGED: i32 = 82;
    /// Filling while locked has to be set up once more (the file of an earlier version was
    /// removed).
    pub const LOCKED_FILL_AGAIN: i32 = 83;
    /// Logins saved from the browser while locked wait for the item lock (a login for the
    /// same site and username is locked here).
    pub const BROWSER_DROPPED_WAITING: i32 = 84;
    /// The vault key was renewed here, or one renewed on another device taken ("1": Windows
    /// Hello was turned off with it); one was renewed on another device (Settings → Sync
    /// asks for it); renewed here, but the vault locked before the new kit showed.
    pub const KEY_RENEWED: i32 = 85;
    pub const KEY_TAKEN: i32 = 86;
    pub const SYNC_KEY_RENEWED: i32 = 87;
    pub const KEY_RENEWED_UNSEEN: i32 = 88;
    /// A newer version of the app is out (GitHub's newest release; the argument is its
    /// version).
    pub const UPDATE_OUT: i32 = 89;
    /// The start at sign-in started another program file and now starts this copy (the
    /// argument is that program).
    pub const SIGN_IN_START_MOVED: i32 = 90;
    /// The recovery parts were each saved in a file of their own (the argument: how many).
    pub const PARTS_SAVED: i32 = 91;
    /// Another program changed how the browsers reach the app while the link ran: put back.
    pub const BROWSER_LINK_REPAIRED: i32 = 92;
    /// Another program changed the browser extension's files in the app's folder: put back.
    pub const EXTENSION_PUT_BACK: i32 = 97;
    /// That folder couldn't be checked or put right, twice in a row (the argument says why).
    pub const EXTENSION_NOT_CHECKED: i32 = 98;
    /// A GitHub release's extension wasn't taken (the argument: its version and why).
    pub const EXTENSION_REFUSED: i32 = 99;
    /// The Secret Key the vault opened with couldn't be kept on this computer (the argument
    /// says why): it is asked for at the next unlock.
    pub const SECRET_KEY_NOT_KEPT: i32 = 120;
    /// A newer version of the app opened this vault on this computer before (the argument:
    /// that version): someone may have put back an older one with a known fault.
    pub const OLDER_APP: i32 = 121;
    /// The browser extension asking is older than this app answers (the argument: the oldest
    /// version it answers).
    pub const EXTENSION_OUTDATED: i32 = 122;
    pub const KIT_PDF_PASSWORD_COPIED: i32 = 123;
    /// Failed unlocks happened before this one (the argument: since when; `notice-count`: how
    /// many). Its words are `Messages.failed-unlocks`.
    pub const FAILED_UNLOCKS: i32 = 124;
}

const MIN_MASTER_PASSWORD_CHARS: usize = 12;
/// Index categories at or above this value browse a folder (100 = the first folder).
const FOLDER_CATEGORY: i32 = 100;
const REVEAL_SECONDS: i32 = 15;
const NOTICE_DURATION: Duration = Duration::from_millis(3500);
/// How long one pass of the item lock keeps every locked item open.
const SECRETS_OPEN_FOR: Duration = Duration::from_secs(5 * 60);
const KDF_MEMORY_KIB: u32 = 256 * 1024;
const KDF_TARGET: Duration = Duration::from_millis(1000);

/// What the notification area icon's menu asks for (see `crate::tray`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Open,
    Lock,
    Quit,
}

/// How slow jobs run: on a worker thread (the app) or inline (headless tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runner {
    Thread,
    Inline,
}

struct Session {
    vault: Vault,
    secret_key: SecretKey,
    /// The keyfile the vault was opened with (or found where this device remembers it, after
    /// a Windows Hello unlock); needed to check or change the master password.
    keyfile: Option<vault_core::Keyfile>,
}

/// The dialogs Settings opens (`settings-dialog`, see SettingsPage in ui/pages.slint).
mod dialog {
    pub const NONE: i32 = 0;
    pub const STOP_SYNC: i32 = 5;
    pub const REMOVE_DEVICE: i32 = 6;
    pub const ADD_DEVICE: i32 = 7;
    pub const REMOVE_BACKUP: i32 = 8;
    pub const DISCONNECT: i32 = 9;
    /// The address of the server the vault syncs through, and of the backup server.
    pub const SERVER_ADDRESS: i32 = 12;
    pub const BACKUP_ADDRESS: i32 = 13;
    /// The new Secret Key of a vault key renewed on another device, and the master password.
    pub const TAKE_KEY: i32 = 14;
}

/// Results of background work, sent back to the UI thread.
enum JobResult {
    Created {
        session: Session,
        parts: RecoveryParts,
    },
    Unlocked {
        session: Session,
        typed_secret_key: bool,
        /// Two recovery parts brought back the Secret Key: they are retired once open.
        used_parts: bool,
        /// How long opening took (Argon2id), shown on the Settings page; `None` for Windows
        /// Hello, which skips it.
        seconds: Option<f64>,
    },
    QuickUnlockEnabled {
        session: Session,
    },
    ImportParsed {
        report: vault_import::ImportReport,
    },
    LeaksChecked {
        result: Result<Vec<(ItemId, u64)>, String>,
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
    /// The password slot was rewritten: a new master password, or (with `kdf_seconds`) the
    /// same one at a new Argon2id cost, which took that long to open again.
    PasswordChanged {
        session: Session,
        kdf_seconds: Option<f64>,
    },
    /// Changing the Argon2id cost (or with `keyfile`, the keyfile) failed; the error belongs
    /// on that card.
    KdfFailed {
        code: i32,
        detail: String,
        session: Session,
        /// 1 unlock protection, 2 keyfile, 3 item lock.
        card: i32,
    },
    /// The keyfile was set (`path`) or removed.
    KeyfileChanged {
        session: Session,
        path: Option<PathBuf>,
    },
    /// The check was right: locked items open. `upgraded` when this first pass turned a
    /// format v5 PIN into encryption (the vault must be saved).
    ItemUnlocked {
        session: Session,
        upgraded: bool,
        then: AfterUnlock,
    },
    /// A wrong PIN or password for a guarded item (counted; too many lock the vault).
    ItemRefused {
        session: Session,
    },
    /// The master password was right and the item lock was changed in memory (its key still
    /// open): save it, then set Windows Hello for it up with `hello` (what Windows Hello's new
    /// key gave), or turn it off. `before` puts the vault back when the save fails.
    GuardVerified {
        session: Session,
        hello: Option<Zeroizing<Vec<u8>>>,
        before: Box<vault_core::VaultSnapshot>,
    },
    /// Only the newer item lock set on another device opened (`Vault::guard_waiting`): not a
    /// wrong try; this copy's own lock is still to be opened.
    ItemNewerOpened {
        session: Session,
    },
    KitVerified {
        session: Session,
    },
    /// The master password a Settings dialog asked for was right: its change goes ahead
    /// (`settings_dialog` kinds 5 to 9).
    SettingsConfirmed {
        session: Session,
        kind: i32,
    },
    /// The master password was right: the browser extension whose code was typed (`approved`)
    /// may be connected.
    PairingVerified {
        session: Session,
        approved: vault_browser::pairing::PairingKey,
    },
    /// A job that borrowed the open vault is done; `notice` (0: none) says how it went.
    Returned {
        session: Session,
        notice: i32,
    },
    PartsIssued {
        session: Session,
        parts: RecoveryParts,
    },
    /// The vault key was renewed here (`parts`: the new kit's) or one renewed on another
    /// device taken (`parts` is `None`); `former` opens what this computer sealed before.
    /// `not_kept` says why this computer doesn't hold the new Secret Key, when the file opens
    /// only with it all the same.
    KeyRenewed {
        session: Session,
        parts: Option<RecoveryParts>,
        former: FormerKey,
        not_kept: Option<String>,
    },
    /// A try at the unlock failed (a wrong master password or keyfile, Windows Hello): counted
    /// for vault `vault_id`, even when the window moved on (controller/attempts.rs).
    UnlockFailed {
        code: i32,
        detail: String,
        vault_id: String,
    },
    /// The breach check's answer about a new password (controller/passwords.rs).
    NewPasswordLeaks {
        place: i32,
        found: Result<u64, String>,
    },
    /// `session` is handed back when the job borrowed an open vault.
    Failed {
        code: i32,
        detail: String,
        session: Option<Session>,
    },
}

/// What a background job was started for: the session (`session_epoch`) and the vault file.
/// Its result counts only while both are still the ones open in the window (see
/// `finish_job`).
#[derive(Clone)]
struct JobTicket {
    epoch: u64,
    path: PathBuf,
}

struct State {
    path: PathBuf,
    runner: Runner,
    secrets: Vec<SecretBuffer>,
    session: Option<Session>,
    /// +1 each time the vault is locked or another vault file is chosen. A background job's
    /// result counts only when this is still what it was when the job started (see
    /// `finish_job`).
    session_epoch: u64,
    /// The vault is open: in `session`, or lent to a background job that hands it back.
    /// (`session` alone is `None` while a job holds it, and the vault is not locked then.)
    vault_open: bool,
    /// The vault in memory holds a change its file doesn't: the last save failed.
    unsaved: bool,
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
    /// The editor's files and SSH private key (attachments.rs), never in a Slint string.
    editor_files: Vec<vault_core::Attachment>,
    /// The edited login's passkeys still kept (credential ids, with their rows): one removed
    /// in the editor goes when it is saved.
    editor_passkeys: Vec<(Vec<u8>, crate::ui::PasskeyRow)>,
    editor_ssh: Option<Zeroizing<String>>,
    /// An SSH key brought into the editor that waits for its passphrase.
    ssh_pending: Option<Zeroizing<String>>,
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
    /// Word lists the user added (the bundled EFF list is not in here).
    wordlists: Vec<features::UserWordlist>,
    /// The item whose password history is on screen, and which entries are revealed.
    history_shown: Option<ItemId>,
    history_revealed: Vec<usize>,
    /// Last password health report, the items behind its rows, and leak counts from the last
    /// check (kept only while unlocked).
    health: Option<HealthReport>,
    health_stale: bool,
    /// Counts audits started, so a result that arrives late is recognized and dropped.
    health_generation: u64,
    health_ids: Vec<ItemId>,
    leaks: HashMap<ItemId, u64>,
    /// The newer release Check for updates found (its page on github.com).
    release_page: Option<String>,
    /// The newer version a notice already told of (once per version while the app runs).
    update_told: Option<String>,
    /// The leak watch's check of every login (the tests put a stand-in in its place).
    leak_batch: watch::Batch,
    sync: syncing::SyncStatus,
    /// Import: the place chosen, and which reviewed entries are ticked.
    import_source: Option<vault_import::Source>,
    import_include: Vec<bool>,
    /// Profiles of the chosen browser that have a password store.
    browser_profiles: Vec<vault_import::browser::BrowserProfile>,
    /// Places visited, for back and forward.
    history: navigation::History,
    /// The folder the folder dialog is about (`None` while creating one).
    dialog_folder: Option<FolderId>,
    /// How long the last unlock took on this computer.
    unlock_seconds: Option<f64>,
    /// The item lock's check was passed: every locked item is open, until locked again.
    secrets_open: bool,
    /// Listening for the browser extension (Settings → Browser extension).
    browser_link: Option<browser::BrowserLink>,
    /// The browsers Settings → Browser extension → Add to a browser lists, in its order.
    extension_browsers: Vec<vault_platform::browsers::Browser>,
    /// The last check of the extension's folder failed (the next failure is said).
    extension_check_failed: bool,
    /// The version of the extension in use, which the extension hears; a release's extension
    /// being downloaded.
    extension_version: String,
    extension_fetching: bool,
    /// The connected extension's key (read once per unlock), the app's half of a key
    /// agreement under way, one waiting for the person's answer, and the guard against
    /// replayed requests.
    browser_pairing: Option<vault_browser::pairing::PairingKey>,
    browser_offer: Option<vault_browser::pairing::Offer>,
    browser_pending: Option<vault_browser::pairing::Pending>,
    browser_replay: vault_browser::pairing::Replay,
    /// An extension older than this app answers was told so in the app already (once a run).
    outdated_told: bool,
    /// Generated passwords handed to the extension, until used (see `browser.rs`).
    browser_generated: Vec<(String, vault_browser::service::Kept)>,
    /// The history of generated passwords, once read; the entry shown.
    generated_history: Option<Vec<generated::GeneratedEntry>>,
    /// Generated passwords the extension used while the vault was locked, with that vault's
    /// id: added to its history once it is open again.
    generated_pending: Vec<(String, Zeroizing<String>, String)>,
    /// The password Generate just put in the editor (its SHA-256) and its real entropy: the
    /// strength estimate, which reads random characters as only ~3.3 bits each, shows that
    /// instead while the password is unchanged.
    editor_generated: Option<([u8; 32], f64)>,
    generated_shown: Option<usize>,
    /// Wrong tries at a guarded item since the last right one.
    guard_attempts: u32,
    /// The clocks unlock attempts are timed by (the tests put their own in its place).
    clock: fn() -> device::Clock,
    /// The breach check of a new master password (the tests put a stand-in in its place).
    leak_count: fn(&str) -> Result<u64, String>,
    /// The new password field whose easy password the person chose to keep, and the one whose
    /// password the breach check passed (or the person went on without it): each until that
    /// field changes (controller/passwords.rs).
    weak_kept: Option<usize>,
    leaks_cleared: Option<usize>,
    /// Headless tests: the start at sign-in, kept here instead of in the registry.
    sign_in_start: bool,
}

#[derive(Default)]
struct Timers {
    reveal: Timer,
    clipboard: Timer,
    notice: Timer,
    auto_lock: Timer,
    /// Shows the "locks in …" countdown shortly before the auto-lock.
    lock_warning: Timer,
    /// Ticks that countdown.
    lock_countdown: Timer,
    totp: Timer,
    auth: Timer,
    relock: Timer,
    /// Sync: a round a moment after a save, and one every few minutes.
    sync_soon: Timer,
    sync_every: Timer,
    /// Sync: a round a minute after one where a place didn't answer.
    sync_retry: Timer,
    /// The leak watch: a look every hour whether a day has passed.
    leak_watch: Timer,
    /// Updates: a look at GitHub's releases a moment after the start, then every hour.
    update_first: Timer,
    update_every: Timer,
    /// The browser extension's folder, looked at every few minutes while the link runs.
    extension_check: Timer,
    /// Ticks the unlock screen's countdown after too many failed tries.
    unlock_wait: Timer,
}

pub struct Controller {
    app: slint::Weak<AppWindow>,
    state: RefCell<State>,
    timers: Timers,
    lengths: Rc<VecModel<i32>>,
    /// Where each secret field's cursor is, in characters (`Secrets.carets`).
    carets: Rc<VecModel<i32>>,
    /// The eye on secret fields (`Secrets.showing`, `shown`, `shown-cells`, `shown-chars`),
    /// by field.
    showing: Rc<VecModel<bool>>,
    shown: Rc<VecModel<SharedString>>,
    shown_cells: Rc<VecModel<ModelRc<SharedString>>>,
    shown_chars: Rc<VecModel<ModelRc<SharedString>>>,
    items: Rc<VecModel<ItemRow>>,
    this: RefCell<Weak<Controller>>,
    /// When the auto-lock will lock the vault (while it is open).
    lock_deadline: std::cell::Cell<Option<std::time::Instant>>,
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
        if runner == Runner::Thread
            && let Some(verifier) = verifier.clone()
        {
            std::thread::spawn(move || {
                let available = verifier.is_available();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                        controller.set_quick_available(available);
                    }
                });
            });
        }
        let controller = Rc::new(Self {
            app: app.as_weak(),
            state: RefCell::new(State {
                path,
                runner,
                secrets: (0..field::COUNT).map(|_| SecretBuffer::new()).collect(),
                session: None,
                pending: None,
                session_epoch: 0,
                vault_open: false,
                unsaved: false,
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
                editor_files: Vec::new(),
                editor_passkeys: Vec::new(),
                editor_ssh: None,
                ssh_pending: None,
                pending_import: None,
                settings,
                icons: IconCache::default(),
                icon_images: HashMap::new(),
                fetching_icons: false,
                verifier,
                quick_available,
                wordlists: Vec::new(),
                history_shown: None,
                history_revealed: Vec::new(),
                health: None,
                health_stale: false,
                health_generation: 0,
                health_ids: Vec::new(),
                leaks: HashMap::new(),
                release_page: None,
                update_told: None,
                leak_batch: watch::batch_default,
                sync: syncing::SyncStatus::default(),
                import_source: None,
                import_include: Vec::new(),
                browser_profiles: Vec::new(),
                history: navigation::History::default(),
                dialog_folder: None,
                unlock_seconds: None,
                secrets_open: false,
                browser_link: None,
                extension_browsers: Vec::new(),
                extension_check_failed: false,
                extension_version: extension::VERSION.to_owned(),
                extension_fetching: false,
                browser_pairing: None,
                browser_offer: None,
                browser_pending: None,
                browser_replay: Default::default(),
                outdated_told: false,
                browser_generated: Vec::new(),
                generated_history: None,
                generated_pending: Vec::new(),
                editor_generated: None,
                generated_shown: None,
                guard_attempts: 0,
                clock: device::Clock::read,
                leak_count: vault_platform::leak_check::count,
                weak_kept: None,
                leaks_cleared: None,
                sign_in_start: false,
            }),
            timers: Timers::default(),
            lengths: Rc::new(VecModel::from(vec![0; field::COUNT])),
            carets: Rc::new(VecModel::from(vec![0; field::COUNT])),
            showing: Rc::new(VecModel::from(vec![false; field::COUNT])),
            shown: Rc::new(VecModel::from(vec![SharedString::new(); field::COUNT])),
            shown_cells: Rc::new(VecModel::from(vec![ModelRc::default(); field::COUNT])),
            shown_chars: Rc::new(VecModel::from(vec![ModelRc::default(); field::COUNT])),
            items: Rc::new(VecModel::default()),
            this: RefCell::new(Weak::new()),
            lock_deadline: std::cell::Cell::new(None),
        });
        *controller.this.borrow_mut() = Rc::downgrade(&controller);
        CURRENT.with(|current| *current.borrow_mut() = Rc::downgrade(&controller));
        if controller.state.borrow().settings.browser_extension {
            controller.apply_browser_link(true);
        }

        let secrets = app.global::<Secrets>();
        secrets.set_lengths(ModelRc::from(controller.lengths.clone()));
        secrets.set_carets(ModelRc::from(controller.carets.clone()));
        secrets.set_showing(ModelRc::from(controller.showing.clone()));
        secrets.set_shown(ModelRc::from(controller.shown.clone()));
        secrets.set_shown_cells(ModelRc::from(controller.shown_cells.clone()));
        secrets.set_shown_chars(ModelRc::from(controller.shown_chars.clone()));
        app.set_items(ModelRc::from(controller.items.clone()));
        app.global::<Theme>()
            .set_dark(controller.state.borrow().settings.dark_theme);
        if !controller.state.borrow().settings.backdrop {
            app.global::<Theme>().set_backdrop(0);
        }
        app.set_app_version(env!("CARGO_PKG_VERSION").into());
        // Shown with its switch on the first screen, before any vault is open.
        app.set_update_checks(controller.state.borrow().settings.update_checks);
        let language = controller.state.borrow().settings.language.clone();
        crate::i18n::apply(&language);
        app.set_language(crate::i18n::choice_of(&language));
        controller.wire(app);
        controller.install_shortcuts(app);
        controller.show_extension_browsers();
        controller.show_extension_source();
        controller.load_generator_prefs();
        controller.show_start_screen();
        controller.start_update_checks();
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
                        $body;
                        // Back/forward remember wherever the action led.
                        $c.note_place();
                    }
                });
            }};
        }

        let secrets = app.global::<Secrets>();
        {
            let weak = Rc::downgrade(self);
            secrets.on_toggle_shown(move |field| {
                if let Some(c) = weak.upgrade()
                    && let Ok(index) = usize::try_from(field)
                    && index < field::COUNT
                {
                    let on = !c.showing.row_data(index).unwrap_or(false);
                    c.showing.set_row_data(index, on);
                    c.refresh_shown(index);
                }
            });
        }
        {
            let weak = Rc::downgrade(self);
            secrets.on_insert(move |field, text| {
                if let Some(c) = weak.upgrade() {
                    c.edit_secret_at(field, |buffer, caret| {
                        *caret += buffer.insert_str(*caret, &text);
                    });
                }
            });
        }
        {
            let weak = Rc::downgrade(self);
            secrets.on_backspace(move |field| {
                if let Some(c) = weak.upgrade() {
                    c.edit_secret_at(field, |buffer, caret| {
                        if *caret > 0 {
                            buffer.remove(*caret - 1, 1);
                            *caret -= 1;
                        }
                    });
                }
            });
        }
        {
            let weak = Rc::downgrade(self);
            secrets.on_delete(move |field| {
                if let Some(c) = weak.upgrade() {
                    c.edit_secret_at(field, |buffer, caret| buffer.remove(*caret, 1));
                }
            });
        }
        {
            let weak = Rc::downgrade(self);
            secrets.on_move_caret(move |field, to| {
                if let Some(c) = weak.upgrade() {
                    c.edit_secret_at(field, |buffer, caret| {
                        *caret = usize::try_from(to).unwrap_or(0).min(buffer.char_count());
                    });
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
        {
            let weak = Rc::downgrade(self);
            secrets.on_paste(move |field, replace| {
                if let Some(c) = weak.upgrade()
                    && let Some(text) = clipboard::paste_text()
                {
                    c.edit_secret_at(field, |buffer, caret| {
                        if replace {
                            buffer.clear();
                            *caret = 0;
                        }
                        *caret += buffer.insert_str(*caret, &text);
                    });
                }
            });
        }

        on!(on_create_vault, |c| c.create_vault());
        {
            let review = app.global::<crate::ui::NewPassword>();
            let weak = Rc::downgrade(self);
            review.on_use_passphrase(move |field| {
                if let Some(c) = weak.upgrade() {
                    c.touch_activity();
                    c.use_passphrase(field);
                }
            });
            let weak = Rc::downgrade(self);
            review.on_keep(move || {
                if let Some(c) = weak.upgrade() {
                    c.touch_activity();
                    c.keep_reviewed_password();
                    c.note_place();
                }
            });
        }
        on!(on_suggest_passphrase, |c| c.suggest_passphrase());
        on!(on_use_suggestion, |c| c.use_suggestion());
        on!(on_finish_onboarding, |c| c.finish_onboarding());
        on!(on_gen_reveal_history, |c, index| c.reveal_generated(index));
        on!(on_gen_copy_history, |c, index| c
            .copy_generated_entry(index));
        on!(on_gen_clear_history, |c| c.clear_generated_history());
        on!(on_finish_onboarding_import, |c| {
            c.finish_onboarding();
            c.open_transfer();
        });
        on!(on_unlock, |c| c.unlock());
        on!(on_quick_unlock, |c| c.quick_unlock());
        on!(on_quick_unlock_toggled, |c, on| c.set_quick_unlock(on));
        on!(on_show_recovery, |c| c.show_recovery());
        on!(on_check_parts, |c| c.check_parts());
        on!(on_ssh_generate, |c| c.ssh_generate());
        on!(on_ssh_load, |c| c.ssh_load());
        on!(on_ssh_paste, |c| c.ssh_paste());
        on!(on_ssh_open, |c| c.ssh_open());
        on!(on_file_add, |c| c.file_add());
        on!(on_file_remove, |c, index| c.file_remove(index));
        on!(on_passkey_remove, |c, index| c.passkey_remove(index));
        on!(on_file_save, |c, index| c.file_save(index));
        on!(on_new_parts_now, |c| c.new_parts_now());
        on!(on_choose_part_picture, |c| c.choose_part_picture());
        on!(on_back_to_unlock, |c| c.show_screen(Screen::Unlock));
        on!(on_recover, |c| c.recover());

        on!(on_search, |c, _text| c.refresh_list());
        on!(on_select_category, |c, category| c
            .select_category(category));
        on!(on_select, |c, index| c.select(index));
        on!(on_new_item, |c| c.open_editor(None));
        // The `on!` macro counts the click as activity, which restarts the auto-lock.
        on!(on_stay_unlocked, |c| c.stop_lock_warning());
        on!(on_open_generator, |c| c.open_generator());
        on!(on_open_settings, |c| c.open_settings());
        on!(on_open_kit, |c| c.open_kit());
        on!(on_print_kit, |c| c.print_kit());
        on!(on_save_kit, |c| c.save_kit());
        on!(on_save_parts_apart, |c| c.save_parts_apart());
        on!(on_open_transfer, |c| c.open_transfer());
        on!(on_import_choose, |c| c.import_choose());
        on!(on_import_open, |c| c.parse_import());
        on!(on_import_confirm, |c| c.import_confirm());
        on!(on_import_cancel, |c| c.import_cancel());
        on!(on_import_wipe, |c| c.import_wipe());
        on!(on_export_backup, |c| c.export_backup());
        on!(on_export_ask, |c| c.ask_export());
        on!(on_export_cancel, |c| c.cancel_export());
        on!(on_export_plain, |c| c.verify_then(KitAction::Export));
        on!(on_lock, |c| c.lock());

        on!(on_edit_item, |c| {
            let selected = c.state.borrow().selected;
            if let Some(id) = selected {
                c.open_editor(Some(id));
            }
        });
        on!(on_toggle_favorite, |c| c.toggle_favorite());
        on!(on_new_folder, |c| c.new_folder());
        on!(on_edit_folder, |c, index| c.edit_folder(index));
        on!(on_ask_delete_folder, |c, index| c.ask_delete_folder(index));
        on!(on_move_folder, |c, from, to| c.move_folder(from, to));
        on!(on_folder_dialog_save, |c| c.save_folder_dialog());
        on!(on_folder_dialog_fetch, |c| c.fetch_folder_preview());
        on!(on_folder_dialog_delete, |c| c.delete_folder_dialog());
        on!(on_folder_dialog_cancel, |c| c.close_folder_dialog());
        on!(on_go_back, |c| c.go(false));
        on!(on_go_forward, |c| c.go(true));
        on!(on_reveal_field, |c, index| c.reveal_field(index));
        on!(on_open_url, |c, index| c.open_url(index));
        on!(on_copy_url, |c, index| c.copy_url(index));
        on!(on_change_kdf, |c| c.change_kdf());
        on!(on_choose_keyfile, |c| c.choose_keyfile());
        on!(on_keyfile_action, |c, what| c.keyfile_action(what));
        on!(on_unlock_item, |c| c.unlock_secrets(AfterUnlock::Show));
        on!(on_unlock_item_hello, |c| c.unlock_secrets_hello());
        on!(on_pairing_decided, |c, allow| c.pairing_decided(allow));
        on!(on_forget_pairing, |c| c.forget_pairing());
        on!(on_sync_choose, |c| c.sync_choose());
        on!(on_sync_now, |c| c.sync_round());
        on!(on_sync_stop, |c| c.sync_stop());
        on!(on_sync_join_server, |c| c.sync_join_server());
        on!(on_sync_use_webdav, |c| c.sync_use_webdav());
        on!(on_sync_add_device, |c| c.sync_add_device());
        on!(on_sync_join_backup, |c| c.sync_join_backup());
        on!(on_sync_remove_backup, |c| c.sync_remove_backup());
        on!(on_sync_change_address, |c, backup| c
            .sync_change_address(backup));
        on!(on_window_drag, |c| c.window_drag());
        on!(on_window_resize, |c, direction| c.window_resize(direction));
        on!(on_window_minimize, |c| c.window_minimize());
        on!(on_window_toggle_maximized, |c| c.window_toggle_maximized());
        on!(on_window_close, |c| c.window_close());
        on!(on_sync_hide_invite, |c| c.sync_hide_invite());
        on!(on_sync_remove, |c, index| c.sync_remove_device(index));
        on!(on_lock_secrets, |c| {
            c.lock_secrets();
            c.notify(notice::SECRETS_LOCKED, "");
        });
        on!(on_save_guard, |c| c.save_guard());
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
        on!(on_card_number_edited, |c, text| c.card_number_edited(&text));
        on!(on_show_history, |c| c.show_history());
        on!(on_hide_history, |c| c.hide_history());
        on!(on_reveal_history, |c, index| c.reveal_history(index));
        on!(on_copy_history, |c, index| c.copy_history(index));
        on!(on_clear_history, |c| c.clear_history());
        on!(on_open_health, |c| c.open_health());
        on!(on_health_filter_changed, |c, _filter| c.show_health());
        on!(on_check_leaks, |c| c.check_leaks());
        on!(on_check_updates, |c| c.check_updates());
        on!(on_add_extension, |c, index| c.add_extension(index));
        on!(on_open_extension_folder, |c| c.open_extension_folder());
        on!(on_choose_extension_folder, |c| c.choose_extension_folder());
        on!(on_use_extension_release, |c| c.use_extension_release());
        on!(on_open_release, |c| c.open_release());
        on!(on_health_open, |c, index| c.health_open(index));
        on!(on_add_wordlist, |c| c.add_wordlist());
        on!(on_remove_wordlist, |c| c.remove_wordlist());
        on!(on_vault_settings_changed, |c| c.vault_settings_changed());
        on!(on_pick_source, |c, index| c.pick_source(index));
        on!(on_open_browser, |c| c.open_browser());
        on!(on_import_direct, |c| c.import_direct());
        on!(on_import_toggle, |c, index, on| c.import_toggle(index, on));
        on!(on_import_select_all, |c, on| c.import_select_all(on));
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
        on!(on_first_update_checks, |c, on| c.first_update_checks(on));
        on!(on_start_at_sign_in_changed, |c, on| c
            .set_start_at_sign_in(on));
        on!(on_ed_url_changed, |c| c.editor_site_icon());
        on!(on_open_settings_dialog, |c, kind| c
            .open_settings_dialog(kind));
        on!(on_close_settings_dialog, |c| c.close_settings_dialog());
        on!(on_confirm_settings, |c, kind| c.confirm_settings(kind));
        on!(on_appearance_changed, |c, dark| c.set_appearance(dark));
        on!(on_language_changed, |c, choice| c.set_language(choice));
        on!(on_change_password, |c| c.change_password());
        on!(on_show_kit, |c| c.verify_then(KitAction::Show));
        on!(on_copy_kit_pdf_password, |c| c.copy_kit_pdf_password());
        on!(on_hide_kit, |c| {
            let app = c.app();
            hide_kit_keys(&app);
            clear_kit_parts(&app);
        });
        on!(on_new_parts, |c| c.verify_then(KitAction::NewParts));
        on!(on_renew_key, |c| c.verify_then(KitAction::RenewKey));
        on!(on_sync_take_key, |c| c.take_new_key());
        on!(on_save_part_picture, |c| c.save_part_picture());
    }

    /// Changes a secret field's text as a whole (set, cleared, generated); the cursor goes to
    /// its end.
    fn edit_secret(&self, field: i32, edit: impl FnOnce(&mut SecretBuffer)) {
        self.edit_secret_at(field, |buffer, caret| {
            edit(buffer);
            *caret = buffer.char_count();
        });
    }

    /// Changes a secret field's text where its cursor is (`caret`, in characters, moved by
    /// `edit` as needed).
    fn edit_secret_at(&self, field: i32, edit: impl FnOnce(&mut SecretBuffer, &mut usize)) {
        let Some(index) = usize::try_from(field).ok().filter(|&i| i < field::COUNT) else {
            return;
        };
        let (length, caret) = {
            let mut state = self.state.borrow_mut();
            let mut caret = usize::try_from(self.carets.row_data(index).unwrap_or(0)).unwrap_or(0);
            edit(&mut state.secrets[index], &mut caret);
            let length = state.secrets[index].char_count();
            (length, caret.min(length))
        };
        self.lengths
            .set_row_data(index, i32::try_from(length).unwrap_or(i32::MAX));
        self.carets
            .set_row_data(index, i32::try_from(caret).unwrap_or(i32::MAX));
        if index == field::ITEM_PASSWORD {
            self.update_editor_strength();
        }
        self.new_password_edited(index);
        // A shown password in the editor must follow the buffer.
        if index == field::ITEM_PASSWORD && !self.app().get_editor_password_shown().is_empty() {
            let text = SharedString::from(self.state.borrow().secrets[index].as_str());
            self.app().set_editor_password_shown(text);
        }
        self.refresh_shown(index);
        self.set_error(error::NONE, "");
        self.touch_activity();
    }

    /// Empties a field and hides it again: a field opened later starts hidden.
    fn clear_secret(&self, index: usize) {
        self.new_password_edited(index);
        self.state.borrow_mut().secrets[index].clear();
        self.lengths.set_row_data(index, 0);
        self.carets.set_row_data(index, 0);
        self.showing.set_row_data(index, false);
        self.refresh_shown(index);
    }

    /// Every field hidden again and its shown text dropped (the screen changed).
    fn clear_all_secrets(&self) {
        for index in 0..field::COUNT {
            self.showing.set_row_data(index, false);
            self.clear_secret(index);
        }
    }

    /// What a field's eye shows: its text (and boxes) while asked, nothing otherwise.
    fn refresh_shown(&self, index: usize) {
        let on = self.showing.row_data(index).unwrap_or(false);
        let text = if on {
            Zeroizing::new(self.state.borrow().secrets[index].as_str().to_owned())
        } else {
            Zeroizing::new(String::new())
        };
        if self
            .shown
            .row_data(index)
            .is_some_and(|old| old != text.as_str())
        {
            self.shown.set_row_data(index, text.as_str().into());
        }
        let cells: Vec<SharedString> = if on && field::IN_BOXES.contains(&index) {
            view::key_cells(&text, 4, 7)
                .iter()
                .map(|cell| cell.as_str().into())
                .collect()
        } else {
            Vec::new()
        };
        self.shown_cells
            .set_row_data(index, ModelRc::new(VecModel::from(cells)));
        let chars: Vec<SharedString> = text
            .chars()
            .map(|c| SharedString::from(&*c.encode_utf8(&mut [0; 4])))
            .collect();
        self.shown_chars
            .set_row_data(index, ModelRc::new(VecModel::from(chars)));
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
                // Whether a Secret Key is kept, without opening it: the chip is asked only
                // at the unlock, which says so if it no longer opens it.
                let known = secret_store::kept(&info.id_hex).ok().flatten().is_some();
                app.set_quick_unlock_on(
                    self.state.borrow().quick_available && quick_unlock::is_enrolled(&info.id_hex),
                );
                app.set_needs_keyfile(info.needs_keyfile);
                app.set_keyfile_path(SharedString::from(
                    vault_platform::keyfile::remembered_path(&info.id_hex)
                        .filter(|_| info.needs_keyfile)
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                ));
                app.set_needs_secret_key(!known);
                app.set_can_use_parts(info.has_recovery_parts);
                app.set_use_parts(false);
                self.show_screen(Screen::Unlock);
                self.unlock_wait(&info.id_hex);
                app.set_vault_id(SharedString::from(info.id_hex));
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
        self.forget_review();
        self.app().set_screen(screen);
    }

    fn set_error(&self, code: i32, detail: &str) {
        let app = self.app();
        app.set_error_code(code);
        app.set_error_detail(SharedString::from(detail));
        // Set again by `change_kdf` / `keyfile_action` when the error is their own.
        app.set_kdf_failed(false);
        app.set_keyfile_failed(false);
        app.set_guard_failed(false);
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
            CoreError::SecretsLocked => (error::SECRETS_LOCKED, String::new()),
            CoreError::FileChanged => (error::CHANGED_OUTSIDE, String::new()),
            CoreError::WeakPassword => (error::WEAK_EXPORT, String::new()),
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
        let ticket = self.job_ticket();
        match runner {
            Runner::Inline => self.finish_job(job(), &ticket),
            Runner::Thread => {
                std::thread::spawn(move || {
                    let result = job();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                            controller.finish_job(result, &ticket);
                        }
                    });
                });
            }
        }
    }

    /// The session and vault file a job starting now belongs to.
    fn job_ticket(&self) -> JobTicket {
        let state = self.state.borrow();
        JobTicket {
            epoch: state.session_epoch,
            path: state.path.clone(),
        }
    }

    /// Runs a background job's result on the UI thread, if it still belongs here: the vault
    /// it was started for (`ticket`) must still be the one in the window, in the same
    /// session. A result that comes back after the vault was locked (by hand, the timer, the
    /// system) or another vault file was chosen is dropped with the vault it holds, its keys
    /// wiped. Put back, it would open the vault again behind a lock screen (where the browser
    /// extension would find it open), or open one vault under another one's file, whose next
    /// save would write the first vault's contents over the second.
    fn finish_job(&self, result: JobResult, ticket: &JobTicket) {
        let app = self.app();
        app.set_busy(false);
        app.set_quick_waiting(false);
        let current = {
            let state = self.state.borrow();
            ticket.epoch == state.session_epoch && same_path(&ticket.path, &state.path)
        };
        if !current {
            self.drop_job_result(result);
            return;
        }
        match result {
            JobResult::Created { session, parts } => {
                self.forget_review();
                self.clear_secret(field::MASTER);
                self.clear_secret(field::CONFIRM);
                self.state.borrow_mut().suggestion = None;
                app.set_suggestion(SharedString::new());
                app.set_vault_id(SharedString::from(session.vault.id_hex()));
                show_kit_keys(&app, &session.vault, &session.secret_key);
                show_kit_parts(&app, &parts);
                app.set_recovered(false);
                app.set_kit_saved(false);
                self.clear_secret(field::GUARD_NEW);
                app.set_onboarding_step(3);
                self.state.borrow_mut().pending = Some(session);
            }
            JobResult::Recovered { session } => {
                self.forget_review();
                app.set_quick_unlock_on(false);
                self.clear_secret(field::MASTER);
                self.clear_secret(field::CONFIRM);
                self.clear_secret(field::RECOVERY_KEY);
                for part in [field::PART_A, field::PART_B, field::PART_C] {
                    self.clear_secret(part);
                }
                show_kit_keys(&app, &session.vault, &session.secret_key);
                clear_kit_parts(&app);
                app.set_recovered(true);
                app.set_kit_saved(false);
                app.set_onboarding_step(3);
                self.state.borrow_mut().pending = Some(session);
                self.show_screen(Screen::Onboarding);
            }
            JobResult::Unlocked {
                session,
                typed_secret_key,
                used_parts,
                seconds,
            } => {
                if seconds.is_some() {
                    self.state.borrow_mut().unlock_seconds = seconds;
                }
                let id = session.vault.id_hex();
                let revision = session.vault.revision();
                // A damaged record of the newest revisions is set aside, never written over,
                // and the person is told that older copies aren't caught until then.
                let (mut device_state, state_file) = DeviceState::load_or_set_aside();
                if let RollbackStatus::Older {
                    revision,
                    highest_seen,
                } = device_state.check_rollback(&id, revision)
                {
                    self.set_error(error::ROLLBACK, &format!("{revision} < {highest_seen}"));
                    return;
                }
                device_state.record_revision(&id, revision);
                // A newer version of the apps opened this vault here before: this one may be
                // an old copy put back with a fault fixed since. It opens all the same (the
                // person must reach their vault), and says so once the vault is shown.
                let older = match device_state.note_version(&id, env!("CARGO_PKG_VERSION")) {
                    VersionStatus::Older { highest, .. } => Some(highest),
                    VersionStatus::Ok => None,
                };
                if state_file != StateFile::Unreadable
                    && let Err(err) = device_state.save()
                {
                    self.notify_long(notice::DEVICE_STATE_NOT_SAVED, &err.to_string());
                }
                if state_file != StateFile::Read {
                    self.notify_long(notice::DEVICE_STATE_RESET, "");
                }
                if typed_secret_key {
                    // Kept by `enter_vault`, off the UI thread (the chip may make its key).
                    app.set_needs_secret_key(false);
                }
                // An extension asked to connect while the vault was locked: the master
                // password just typed (not Windows Hello) already answers its dialog.
                let pairing_by_password = seconds.is_some();
                self.clear_secret(field::MASTER);
                self.clear_secret(field::SECRET_KEY);
                self.clear_secret(field::PART_A);
                self.clear_secret(field::PART_B);
                app.set_use_parts(false);
                self.enter_vault(session);
                if used_parts {
                    self.retire_used_parts();
                }
                if let Some(highest) = older {
                    self.notify_long(notice::OLDER_APP, &highest);
                }
                self.offer_pending_pairing(!pairing_by_password);
            }
            JobResult::KdfFailed {
                code,
                detail,
                session,
                card,
            } => {
                self.state.borrow_mut().session = Some(session);
                self.set_error(code, &detail);
                app.set_kdf_failed(card == 1);
                app.set_keyfile_failed(card == 2);
                app.set_guard_failed(card == 3);
            }
            JobResult::KeyfileChanged { session, path } => {
                self.clear_secret(field::KEYFILE_CURRENT);
                app.set_settings_dialog(dialog::NONE);
                // Like a password change, the rewritten lock revokes the device unlock.
                let id = session.vault.id_hex();
                let had_quick_unlock = quick_unlock::is_enrolled(&id);
                self.state.borrow_mut().session = Some(session);
                self.remember_file();
                if had_quick_unlock {
                    self.turn_off_quick_unlock(&id);
                }
                self.show_vault_settings();
                match path {
                    Some(path) => self.notify_long(
                        notice::KEYFILE_SET,
                        &path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    ),
                    None => self.notify_long(notice::KEYFILE_REMOVED, ""),
                }
            }
            JobResult::ItemUnlocked {
                session,
                upgraded,
                then,
            } => {
                self.clear_secret(field::REPROMPT);
                {
                    let mut state = self.state.borrow_mut();
                    state.session = Some(session);
                    state.secrets_open = true;
                    state.guard_attempts = 0;
                    state.summaries_stale = true;
                }
                self.set_error(error::NONE, "");
                self.start_relock();
                // New items added while the item lock was closed are sealed now.
                let sealed = self
                    .state
                    .borrow_mut()
                    .session
                    .as_mut()
                    .and_then(|s| s.vault.seal_pending().ok())
                    .unwrap_or(0);
                if (upgraded || sealed > 0) && !self.save_vault() {
                    return;
                }
                // Logins the browser saved while locked for a login behind this lock.
                self.open_drop_box();
                match then {
                    AfterUnlock::Show => self.secrets_changed(),
                    AfterUnlock::SaveItem => {
                        self.sync_guard_state();
                        self.save_item();
                    }
                }
                // Last: the round may take a newer item lock, which closes this one again.
                self.sync_after_unlocking_items();
            }
            JobResult::ItemRefused { session } => {
                self.state.borrow_mut().session = Some(session);
                self.item_refused();
            }
            JobResult::GuardVerified {
                session,
                hello,
                before,
            } => {
                self.state.borrow_mut().session = Some(session);
                self.apply_guard(hello, *before);
            }
            JobResult::ItemNewerOpened { session } => {
                self.state.borrow_mut().session = Some(session);
                self.newer_lock_opened();
            }
            JobResult::PasswordChanged {
                session,
                kdf_seconds,
            } => {
                self.forget_review();
                for index in [
                    field::CURRENT,
                    field::NEW,
                    field::NEW_AGAIN,
                    field::KDF_CURRENT,
                ] {
                    self.clear_secret(index);
                }
                app.set_settings_dialog(dialog::NONE);
                // The device unlock is bound to the old password slot and no longer opens the
                // vault; remove it so the switch shows the truth.
                let id = session.vault.id_hex();
                let had_quick_unlock = quick_unlock::is_enrolled(&id);
                self.state.borrow_mut().session = Some(session);
                self.remember_file();
                if had_quick_unlock {
                    self.turn_off_quick_unlock(&id);
                }
                if let Some(seconds) = kdf_seconds {
                    self.state.borrow_mut().unlock_seconds = Some(seconds);
                    self.show_vault_settings();
                    let shown = format!("{seconds:.1}");
                    if had_quick_unlock {
                        self.notify(notice::KDF_CHANGED_HELLO_OFF, &shown);
                    } else {
                        self.notify(notice::KDF_CHANGED, &shown);
                    }
                } else if had_quick_unlock {
                    self.notify(notice::PASSWORD_CHANGED_HELLO_OFF, "");
                } else {
                    self.notify(notice::PASSWORD_CHANGED, "");
                }
            }
            JobResult::ImportParsed { report } => self.import_parsed(report),
            JobResult::LeaksChecked { result } => self.finish_leak_check(result),
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
            JobResult::PairingVerified { session, approved } => {
                self.state.borrow_mut().session = Some(session);
                self.finish_pairing(&approved);
            }
            JobResult::SettingsConfirmed { session, kind } => {
                self.state.borrow_mut().session = Some(session);
                self.clear_secret(field::CONFIRM_MASTER);
                self.settings_confirmed(kind);
            }
            JobResult::Returned { session, notice } => {
                self.state.borrow_mut().session = Some(session);
                if notice != 0 {
                    self.notify(notice, "");
                }
            }
            JobResult::KitVerified { session } => {
                self.clear_secret(field::CURRENT);
                show_kit_keys(&app, &session.vault, &session.secret_key);
                clear_kit_parts(&app);
                self.state.borrow_mut().session = Some(session);
                self.refresh_kit_lock();
            }
            JobResult::KeyRenewed {
                session,
                parts,
                former,
                not_kept,
            } => self.key_renewed(session, parts, former, not_kept),
            JobResult::PartsIssued { session, parts } => {
                self.clear_secret(field::CURRENT);
                show_kit_keys(&app, &session.vault, &session.secret_key);
                show_kit_parts(&app, &parts);
                app.set_vault_recovery(2);
                self.state.borrow_mut().session = Some(session);
                self.refresh_kit_lock();
                self.remember_file();
                self.notify(notice::PARTS_ISSUED, "");
            }
            JobResult::UnlockFailed {
                code,
                detail,
                vault_id,
            } => {
                self.unlock_failed(&vault_id);
                self.set_error(code, &detail);
            }
            JobResult::NewPasswordLeaks { place, found } => self.new_password_leaks(place, found),
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

    /// A job's result that no longer belongs here (see `finish_job`): dropped, keys and all.
    /// What the job already did outside the vault is undone where it would mislead.
    fn drop_job_result(&self, result: JobResult) {
        if let JobResult::UnlockFailed { vault_id, .. } = &result {
            // A failure counts wherever the window went meanwhile.
            device::unlock_attempts::failed(vault_id, self.clock());
            return;
        }
        if let JobResult::KeyRenewed {
            session, former, ..
        } = result
        {
            return self.key_renewed_unseen(session, former);
        }
        if let JobResult::GuardVerified { session, hello, .. } = result {
            // The item lock was changed only in the memory that goes now: it stays as it is
            // on disk. Windows Hello's key for it was made anew by then, so the copy of the
            // lock's key it wrapped before (and filling while locked, made with it) no longer
            // opens: forgotten, rather than failing at its next use.
            let id = session.vault.id_hex();
            if hello.is_some() {
                quick_unlock::item_lock_forget(&id);
                locked_fill::remove_index(&id);
            }
            self.notify_long(notice::GUARD_NOT_CHANGED, "");
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

    /// Onboarding's main button. On the first step it checks the master password and moves
    /// on to the item lock; on the second it creates the vault with that lock.
    fn create_vault(&self) {
        let Some(password) = self.new_password_from(field::MASTER, field::CONFIRM) else {
            return;
        };
        let app = self.app();
        if app.get_onboarding_step() == 1 {
            if !self.review_new_password(passwords::place::ONBOARDING) {
                return;
            }
            // The suggested start: a PIN on every item, and Windows Hello where it exists.
            self.set_error(error::NONE, "");
            self.clear_secret(field::GUARD_NEW);
            app.set_guard_all(true);
            app.set_guard_hello(app.get_quick_unlock_available());
            app.set_onboarding_step(2);
            return;
        }
        let lock = match app.get_onboarding_guard() {
            0 => Some(GuardCheck::Pin),
            1 => Some(GuardCheck::Password),
            2 => Some(GuardCheck::Master),
            _ => None,
        };
        let guard_secret = Zeroizing::new(
            self.state.borrow().secrets[field::GUARD_NEW]
                .as_str()
                .to_owned(),
        );
        if let Some(check) = lock
            && ItemGuard::check_secret(check, &guard_secret).is_err()
        {
            self.set_error(error::GUARD_SECRET, "");
            return;
        }
        if lock == Some(GuardCheck::Password)
            && !self.review_new_password(passwords::place::LOCK_ONBOARDING)
        {
            return;
        }
        let guard_all = app.get_guard_all();
        let want_hello = app.get_guard_hello() && app.get_quick_unlock_available();
        let verifier = self.state.borrow().verifier.clone();
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
                let parts = RecoveryParts::generate().map_err(|e| (error::OTHER, e.to_string()))?;
                let mut vault = Vault::create(&password, &secret_key, None, kdf)
                    .map_err(|e| (error::OTHER, e.to_string()))?;
                vault
                    .set_recovery_parts(&parts, &secret_key)
                    .map_err(|e| (error::OTHER, e.to_string()))?;
                if let Some(check) = lock {
                    let secret = (check != GuardCheck::Master).then(|| guard_secret.as_str());
                    vault
                        .set_item_guard(guard_all, check, secret, Some(&password))
                        .map_err(|e| (error::GUARD_SECRET, e.to_string()))?;
                    if want_hello
                        && vault.item_guard().encrypts()
                        && let Some(verifier) = &verifier
                    {
                        let key_id = quick_unlock::item_lock_key_id(&vault.id_hex());
                        if let Ok(device) = verifier.enroll(&key_id) {
                            let _ = quick_unlock::item_lock_enroll(&vault, &device);
                        }
                    }
                    vault.lock_secrets();
                }
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
                    session: Session {
                        vault,
                        secret_key,
                        keyfile: None,
                    },
                    parts,
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
        hide_kit_keys(&app);
        clear_kit_parts(&app);
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
        self.app().set_can_use_parts(info.has_recovery_parts);
        if self.unlock_wait(&info.id_hex) > 0 {
            self.set_error(error::UNLOCK_WAIT, "");
            return;
        }
        let used_parts = self.app().get_use_parts();
        let (secret_key, typed) = match secret_store::load_checked(&info.id_hex) {
            Ok(Loaded::Key(key)) => (key, false),
            // None kept that opens here: the kit's Secret Key, typed or brought back by two
            // recovery parts. Why the kept one can't be used is said when nothing was typed.
            kept => {
                let why = match &kept {
                    Ok(Loaded::ChipLost) => Some((error::SECRET_KEY_CHIP_LOST, String::new())),
                    Ok(Loaded::Conflict) => Some((error::SECRET_KEY_CONFLICT, String::new())),
                    Err(err) => Some((error::SECRET_KEY_UNREADABLE, format!("{err:#}"))),
                    Ok(_) => None,
                };
                if used_parts {
                    match self.secret_key_from_parts(&bytes, info.has_recovery_parts) {
                        Ok(key) => (key, true),
                        Err(code) => {
                            self.set_error(code, "");
                            return;
                        }
                    }
                } else {
                    let nothing_typed = self.state.borrow().secrets[field::SECRET_KEY].is_empty();
                    let parsed =
                        SecretKey::parse(self.state.borrow().secrets[field::SECRET_KEY].as_str());
                    match (parsed, why) {
                        (Ok(key), _) => (key, true),
                        (Err(_), Some((code, detail))) if nothing_typed => {
                            self.app().set_needs_secret_key(true);
                            self.set_error(code, &detail);
                            return;
                        }
                        (Err(err), _) => {
                            self.app().set_needs_secret_key(true);
                            let (code, detail) = self.core_error(&err);
                            self.set_error(code, &detail);
                            return;
                        }
                    }
                }
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
        let keyfile = if info.needs_keyfile {
            match self.keyfile_for_unlock() {
                Ok(found) => Some(found),
                Err((code, detail)) => {
                    self.set_error(code, &detail);
                    return;
                }
            }
        } else {
            None
        };
        let vault_id = info.id_hex.clone();
        self.run_job(move || {
            let started = std::time::Instant::now();
            let unlock = match &keyfile {
                Some((keyfile, _)) => Unlock::PasswordAndKeyfile {
                    password: &password,
                    secret_key: &secret_key,
                    keyfile,
                },
                None => Unlock::Password {
                    password: &password,
                    secret_key: &secret_key,
                },
            };
            match Vault::open(&bytes, unlock) {
                Ok(vault) => {
                    let seconds = started.elapsed().as_secs_f64();
                    let _ = quick_unlock::record_password_unlock(&vault);
                    if let Some((_, path)) = &keyfile {
                        // It worked: this device remembers where the file is.
                        let _ = vault_platform::keyfile::remember_path(&vault.id_hex(), Some(path));
                    }
                    JobResult::Unlocked {
                        session: Session {
                            vault,
                            secret_key,
                            keyfile: keyfile.map(|(key, _)| key),
                        },
                        typed_secret_key: typed,
                        used_parts,
                        seconds: Some(seconds),
                    }
                }
                Err(CoreError::DecryptionFailed) => JobResult::UnlockFailed {
                    code: if keyfile.is_some() {
                        error::WRONG_WITH_KEYFILE
                    } else {
                        error::WRONG_PASSWORD
                    },
                    detail: String::new(),
                    vault_id,
                },
                Err(other) => JobResult::Failed {
                    code: error::OTHER,
                    detail: other.to_string(),
                    session: None,
                },
            }
        });
    }

    /// The recovery screen: with three parts, or with the Recovery Key of an older kit when
    /// the vault still has one.
    fn show_recovery(&self) {
        let path = self.state.borrow().path.clone();
        let older_key = storage::read(&path)
            .ok()
            .and_then(|bytes| Vault::inspect(&bytes).ok())
            .is_some_and(|info| info.has_recovery_key);
        self.app().set_recover_with_parts(!older_key);
        self.app().set_recover_step(1);
        self.show_screen(Screen::Recover);
    }

    /// Recovery, first step: the three parts are tried on the vault file (quick: no password
    /// hashing) before the new master password is asked for.
    fn check_parts(&self) {
        let parts = match self.typed_parts([field::PART_A, field::PART_B, field::PART_C]) {
            Ok(parts) => parts,
            Err(code) => return self.set_error(code, ""),
        };
        let path = self.state.borrow().path.clone();
        let bytes = match storage::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => return self.set_error(error::FILE, &err.to_string()),
        };
        let [a, b, c] = &parts;
        match Vault::open(&bytes, Unlock::Parts([a, b, c])) {
            Ok(_) => {
                self.set_error(error::NONE, "");
                self.app().set_recover_step(2);
            }
            Err(CoreError::NoMatchingSlot) => self.set_error(error::NO_PARTS, ""),
            Err(CoreError::DecryptionFailed) => self.set_error(error::PARTS_WRONG, ""),
            Err(other) => self.set_error(error::OTHER, &other.to_string()),
        }
    }

    /// Two parts just brought back the Secret Key and the vault is open: they stop working,
    /// and a new kit is offered.
    fn retire_used_parts(&self) {
        let had_parts = {
            let mut state = self.state.borrow_mut();
            let Some(session) = state.session.as_mut() else {
                return;
            };
            let had = session.vault.has_recovery_parts();
            session.vault.clear_recovery_parts();
            had
        };
        if had_parts && self.save_vault() {
            let app = self.app();
            app.set_vault_recovery(0);
            app.set_parts_used(true);
        }
    }

    /// New recovery parts without asking for the master password again: right after a
    /// recovery (the vault waiting on the kit screen) or right after unlocking with parts.
    fn new_parts_now(&self) {
        let app = self.app();
        if app.get_screen() == Screen::Onboarding {
            let made = {
                let mut state = self.state.borrow_mut();
                let path = state.path.clone();
                let Some(Session {
                    vault, secret_key, ..
                }) = state.pending.as_mut()
                else {
                    return;
                };
                (|| -> vault_core::Result<RecoveryParts> {
                    let parts = RecoveryParts::generate()?;
                    vault.set_recovery_parts(&parts, secret_key)?;
                    storage::write_atomic(&path, &vault.to_bytes()?)?;
                    let _ = device::record_revision(&vault.id_hex(), vault.revision());
                    Ok(parts)
                })()
            };
            match made {
                Ok(parts) => {
                    show_kit_parts(&app, &parts);
                    // A new kit, a new password for its files.
                    if let Some(session) = self.state.borrow().pending.as_ref() {
                        show_kit_keys(&app, &session.vault, &session.secret_key);
                    }
                    app.set_kit_saved(false);
                }
                Err(err) => self.set_error(error::FILE, &err.to_string()),
            }
            return;
        }
        let made = {
            let mut state = self.state.borrow_mut();
            let Some(session) = state.session.as_mut() else {
                return;
            };
            let secret_key = &session.secret_key;
            RecoveryParts::generate().and_then(|parts| {
                session
                    .vault
                    .set_recovery_parts(&parts, secret_key)
                    .map(|()| parts)
            })
        };
        match made {
            Ok(parts) if self.save_vault() => {
                if let Some(session) = self.state.borrow().session.as_ref() {
                    show_kit_keys(&app, &session.vault, &session.secret_key);
                }
                self.refresh_kit_lock();
                show_kit_parts(&app, &parts);
                app.set_vault_recovery(2);
                app.set_panel(Panel::Kit);
                self.note_place();
                self.notify(notice::PARTS_ISSUED, "");
            }
            Ok(_) => {}
            Err(err) => self.set_error(error::OTHER, &err.to_string()),
        }
    }

    /// The recovery parts typed into `fields`, each a different one. `Err` is the error code
    /// for the screen.
    fn typed_parts<const N: usize>(&self, fields: [usize; N]) -> Result<[RecoveryPart; N], i32> {
        let state = self.state.borrow();
        let mut parts = Vec::with_capacity(N);
        for index in fields {
            let part =
                RecoveryPart::parse(state.secrets[index].as_str()).map_err(|_| error::PART_TYPO)?;
            if parts
                .iter()
                .any(|other: &RecoveryPart| other.label() == part.label())
            {
                return Err(error::PARTS_SAME);
            }
            parts.push(part);
        }
        parts.try_into().map_err(|_| error::OTHER)
    }

    /// The Secret Key from the two parts typed on the unlock screen (quick: no password
    /// hashing). The master password is still checked when the vault opens with it.
    fn secret_key_from_parts(&self, bytes: &[u8], has_parts: bool) -> Result<SecretKey, i32> {
        if !has_parts {
            return Err(error::NO_PARTS);
        }
        let [first, second] = self.typed_parts([field::PART_A, field::PART_B])?;
        Vault::recover_secret_key(bytes, &first, &second).map_err(|err| match err {
            CoreError::NoMatchingSlot => error::NO_PARTS,
            CoreError::DecryptionFailed => error::PARTS_WRONG,
            _ => error::OTHER,
        })
    }

    fn recover(&self) {
        enum With {
            Parts([RecoveryPart; 3]),
            Key(RecoveryKey),
        }
        let with = if self.app().get_recover_with_parts() {
            match self.typed_parts([field::PART_A, field::PART_B, field::PART_C]) {
                Ok(parts) => With::Parts(parts),
                Err(code) => {
                    self.set_error(code, "");
                    return;
                }
            }
        } else {
            match RecoveryKey::parse(self.state.borrow().secrets[field::RECOVERY_KEY].as_str()) {
                Ok(key) => With::Key(key),
                Err(_) => {
                    self.set_error(error::RECOVERY_KEY, "");
                    return;
                }
            }
        };
        let Some(password) = self.new_password_from(field::MASTER, field::CONFIRM) else {
            return;
        };
        if !self.review_new_password(passwords::place::RECOVERY) {
            return;
        }
        let path = self.state.borrow().path.clone();
        self.run_job(move || {
            let result = (|| -> Result<JobResult, (i32, String)> {
                let bytes = storage::read(&path).map_err(|e| (error::FILE, e.to_string()))?;
                let (unlock, wrong) = match &with {
                    With::Parts([a, b, c]) => (Unlock::Parts([a, b, c]), error::PARTS_WRONG),
                    With::Key(key) => (Unlock::Recovery(key), error::RECOVERY_KEY),
                };
                let mut vault = Vault::open(&bytes, unlock).map_err(|e| match e {
                    CoreError::DecryptionFailed => (wrong, String::new()),
                    CoreError::NoMatchingSlot if wrong == error::PARTS_WRONG => {
                        (error::NO_PARTS, String::new())
                    }
                    CoreError::NoMatchingSlot => (error::RECOVERY_KEY, String::new()),
                    other => (error::OTHER, other.to_string()),
                })?;
                // The old Secret Key may be lost or exposed: always issue a new one. The
                // recovery parts keep working and bring back the new one.
                let secret_key =
                    SecretKey::generate().map_err(|e| (error::OTHER, e.to_string()))?;
                let kdf = vault.kdf_params().clone();
                // The keyfile may be what was lost: the new lock is password + Secret Key.
                vault
                    .change_password(&password, &secret_key, None, &kdf)
                    .map_err(|e| (error::OTHER, e.to_string()))?;
                // Recovery parts work once: the ones just typed stop working (new ones are
                // offered with the new kit).
                if matches!(with, With::Parts(_)) {
                    vault.clear_recovery_parts();
                }
                let _ = vault_platform::keyfile::remember_path(&vault.id_hex(), None);
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
                    session: Session {
                        vault,
                        secret_key,
                        keyfile: None,
                    },
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
        if self.unlock_wait(&id) > 0 {
            self.set_error(error::UNLOCK_WAIT, "");
            return;
        }
        let secret_key = match secret_store::load_checked(&id) {
            Ok(Loaded::Key(key)) => key,
            kept => {
                app.set_needs_secret_key(true);
                match kept {
                    Ok(Loaded::ChipLost) => self.set_error(error::SECRET_KEY_CHIP_LOST, ""),
                    Ok(Loaded::Conflict) => self.set_error(error::SECRET_KEY_CONFLICT, ""),
                    Err(err) => self.set_error(error::SECRET_KEY_UNREADABLE, &format!("{err:#}")),
                    Ok(_) => {}
                }
                return;
            }
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
                    // Windows Hello said no (or its chip is locked after wrong PINs): a failed
                    // try, counted like a wrong master password.
                    return JobResult::UnlockFailed {
                        code: error::HELLO_FAILED,
                        detail,
                        vault_id: id,
                    };
                }
            };
            match Vault::open_with_device(&bytes, &secret, &sealed) {
                Ok(vault) if quick_unlock::password_is_recent(&vault) => {
                    // Windows Hello holds the vault key itself; the keyfile is only needed
                    // later, to check or change the master password.
                    let keyfile = vault
                        .needs_keyfile()
                        .then(|| vault_platform::keyfile::remembered_path(&vault.id_hex()))
                        .flatten()
                        .and_then(|path| vault_platform::keyfile::read(&path).ok());
                    JobResult::Unlocked {
                        session: Session {
                            vault,
                            secret_key,
                            keyfile,
                        },
                        typed_secret_key: false,
                        used_parts: false,
                        seconds: None,
                    }
                }
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
            state.vault_open = true;
            state.unsaved = false;
            state.summaries_stale = true;
            state.file_hash = None;
            state.selected = None;
            state.editing = None;
            state.health = None;
            state.leaks.clear();
            state.secrets_open = false;
        }
        app.set_leaks_checked(false);
        app.set_search_text(SharedString::new());
        app.set_category(0);
        app.set_panel(Panel::Detail);
        self.remember_file();
        self.show_vault_name();
        if let Ok(mut device_state) = DeviceState::load() {
            device_state.remember_vault(&self.state.borrow().path);
            let _ = device_state.save();
        }
        self.load_icon_cache();
        self.refresh_list();
        self.show_detail();
        self.show_screen(Screen::Vault);
        self.reset_history();
        self.restart_auto_lock();
        self.start_icon_fetch();
        self.refresh_health();
        self.refresh_locked_fill();
        self.record_pending_generated();
        self.open_drop_box();
        self.start_sync();
        self.start_leak_watch();
        self.keep_secret_key();
        let id = self.app().get_vault_id().to_string();
        self.tell_failed_unlocks(&id);
    }

    /// Keeps the Secret Key the vault just opened with on this computer, in the strongest form
    /// it can (`secret_store::settle`): under the security chip, checked, whether it was typed
    /// from the kit or kept the older way; Settings → Security then says how. Off the UI thread:
    /// the chip makes its key the first time.
    fn keep_secret_key(&self) {
        let app = self.app();
        app.set_secret_key_kept(0);
        // A second copy for the thread, still under the key shield (never the printed text).
        let copy = {
            let state = self.state.borrow();
            state
                .session
                .as_ref()
                .map(|session| (session.vault.id_hex(), session.secret_key.duplicate()))
        };
        let Some((id, key)) = copy else {
            return;
        };
        let ticket = self.job_ticket();
        let settle = move || secret_store::settle(&id, &key).map_err(|err| format!("{err:#}"));
        let runner = self.state.borrow().runner;
        match runner {
            Runner::Inline => self.secret_key_kept(settle(), &ticket),
            Runner::Thread => {
                std::thread::spawn(move || {
                    let kept = settle();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
                            controller.secret_key_kept(kept, &ticket);
                        }
                    });
                });
            }
        }
    }

    fn secret_key_kept(&self, kept: Result<Kept, String>, ticket: &JobTicket) {
        let current = {
            let state = self.state.borrow();
            state.vault_open
                && ticket.epoch == state.session_epoch
                && same_path(&ticket.path, &state.path)
        };
        if !current {
            return;
        }
        let app = self.app();
        match kept {
            Ok(Kept::Chip) => app.set_secret_key_kept(1),
            Ok(Kept::System) => app.set_secret_key_kept(2),
            Err(detail) => self.notify_long(notice::SECRET_KEY_NOT_KEPT, &detail),
        }
    }

    /// The headless test's stand-in for a slow item check: the open vault is taken by a
    /// "job", the vault is locked meanwhile, and the job then comes back with it.
    #[cfg(test)]
    pub(crate) fn lock_while_a_job_holds_the_vault(&self) {
        let ticket = self.job_ticket();
        let session = self
            .state
            .borrow_mut()
            .session
            .take()
            .expect("an open vault");
        self.lock();
        self.finish_job(
            JobResult::ItemUnlocked {
                session,
                upgraded: false,
                then: AfterUnlock::Show,
            },
            &ticket,
        );
    }

    /// The same with the notification area's "Lock now", asked while the job holds the
    /// vault; `while_held` sees the tray's status meanwhile (locked?).
    #[cfg(test)]
    pub(crate) fn tray_lock_while_a_job_holds_the_vault(&self, while_held: impl FnOnce(bool)) {
        let ticket = self.job_ticket();
        let session = self
            .state
            .borrow_mut()
            .session
            .take()
            .expect("an open vault");
        while_held(Self::tray_status().expect("installed").0);
        Self::tray_action(TrayAction::Lock);
        self.finish_job(
            JobResult::ItemUnlocked {
                session,
                upgraded: false,
                then: AfterUnlock::Show,
            },
            &ticket,
        );
    }

    /// An unlock of the open vault's file (its session, as the job would hand it back) that
    /// finishes only after the person chose `other` meanwhile, from the lock screen.
    #[cfg(test)]
    pub(crate) fn unlock_finishes_after_switching_to(&self, other: PathBuf) {
        let session = self
            .state
            .borrow_mut()
            .session
            .take()
            .expect("an open vault");
        self.lock();
        // The unlock starts on this vault's lock screen...
        let ticket = self.job_ticket();
        // ...and while it runs, another vault is chosen.
        self.switch_vault(other);
        self.finish_job(
            JobResult::Unlocked {
                session,
                typed_secret_key: false,
                used_parts: false,
                seconds: Some(0.1),
            },
            &ticket,
        );
    }

    /// The generator's current result as Rust holds it (for the headless test).
    #[cfg(test)]
    pub(crate) fn generated_result(&self) -> Option<String> {
        self.state
            .borrow()
            .generated
            .as_ref()
            .map(|value| value.as_str().to_owned())
    }

    /// How many items wait to be sealed under the item lock (for the headless test).
    #[cfg(test)]
    pub(crate) fn pending_seal(&self) -> Option<usize> {
        self.state
            .borrow()
            .session
            .as_ref()
            .and_then(|s| s.vault.pending_seal().ok())
    }

    /// What the notification area icon's menu shows: whether the vault is locked, its name,
    /// the minutes left before the auto-lock, and whether the app is dark.
    ///
    /// Open while a background job holds the vault (a Windows Hello prompt for a locked item,
    /// say): it comes back open, so "Lock now" must stay there to stop that.
    pub fn tray_status() -> Option<(bool, String, i32, bool)> {
        let controller = CURRENT.with(|c| c.borrow().upgrade())?;
        let state = controller.state.borrow();
        let name = state.session.as_ref().map_or_else(
            || controller.app().get_vault_name().to_string(),
            |s| s.vault.settings().name.clone(),
        );
        Some((
            !state.vault_open,
            name,
            controller.minutes_left().max(1),
            controller.app().global::<Theme>().get_dark(),
        ))
    }

    /// Windows locked the session, switched user, is signing out or suspending: the vault
    /// locks (Settings → Security, on by default). Also while a job holds it, as the tray's
    /// Lock does.
    pub fn windows_session_ended() {
        if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
            let lock = {
                let state = controller.state.borrow();
                state.settings.lock_with_windows && state.vault_open
            };
            if lock {
                controller.lock();
            }
        }
    }

    /// The start at sign-in pointed at `before` and now starts this copy: a moved or newer
    /// copy of the app, or another program put there, so the person is told which.
    pub fn sign_in_start_moved(before: &str) {
        if let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) {
            controller.notify(notice::SIGN_IN_START_MOVED, before);
        }
    }

    /// What the notification area icon's menu asks for.
    pub fn tray_action(action: TrayAction) {
        let Some(controller) = CURRENT.with(|c| c.borrow().upgrade()) else {
            return;
        };
        match action {
            TrayAction::Open => controller.show_from_tray(),
            TrayAction::Lock => {
                // Also while a job holds the vault: its result is then dropped (`finish_job`).
                if controller.state.borrow().vault_open {
                    controller.lock();
                }
            }
            TrayAction::Quit => {
                let _ = slint::quit_event_loop();
            }
        }
    }

    /// The window's close button. Returns whether the app keeps running in the notification
    /// area (the window is then hidden); otherwise it quits.
    pub fn close_to_tray(&self, tray: bool) -> bool {
        if !(tray && self.state.borrow().settings.close_to_tray) {
            return false;
        }
        // Nothing to draw while hidden: the per-second timers stop, and a password shown
        // on screen is hidden again.
        self.timers.totp.stop();
        self.timers.auth.stop();
        self.conceal();
        true
    }

    /// Whether a start at sign-in waits in the notification area (Settings → Appearance).
    pub fn starts_in_tray(&self) -> bool {
        self.state.borrow().settings.start_in_tray
    }

    /// Whether Windows starts the app at sign-in. Windows keeps that (`autostart.rs`), so an
    /// entry turned off in Task Manager shows as off; headless tests keep it in memory.
    fn starts_at_sign_in(&self) -> bool {
        let state = self.state.borrow();
        if state.runner == Runner::Inline {
            state.sign_in_start
        } else {
            vault_platform::autostart::is_on()
        }
    }

    /// Settings → Appearance → "Open when I sign in to Windows". The check then shows what
    /// Windows will do, also when it refused.
    fn set_start_at_sign_in(&self, on: bool) {
        let done = if self.state.borrow().runner == Runner::Inline {
            self.state.borrow_mut().sign_in_start = on;
            Ok(())
        } else {
            std::env::current_exe()
                .map_err(anyhow::Error::from)
                .and_then(|exe| vault_platform::autostart::set(&exe, on))
        };
        match done {
            Ok(()) => self.set_error(error::NONE, ""),
            Err(err) => self.set_error(error::SIGN_IN_START, &err.to_string()),
        }
        self.app().set_start_at_sign_in(self.starts_at_sign_in());
    }

    /// Shows the window again, as it was.
    fn show_from_tray(&self) {
        let app = self.app();
        let _ = app.show();
        if self.state.borrow().session.is_some() {
            match app.get_panel() {
                Panel::Detail => self.show_detail(),
                Panel::Authenticator => self.open_authenticator(),
                _ => {}
            }
        }
        self.bring_to_front();
    }

    fn lock(&self) {
        self.stop_sync();
        self.app().set_settings_dialog(dialog::NONE);
        self.app().set_export_asking(false);
        self.stop_lock_warning();
        self.lock_deadline.set(None);
        for timer in [
            &self.timers.reveal,
            &self.timers.auto_lock,
            &self.timers.totp,
            &self.timers.auth,
            &self.timers.relock,
            &self.timers.leak_watch,
        ] {
            timer.stop();
        }
        // A secret copied a moment ago leaves the clipboard with the vault (only if it is
        // still what the clipboard holds: anything copied since is left alone).
        self.timers.clipboard.stop();
        let copied = self.state.borrow_mut().copied.take();
        if let Some(value) = copied {
            clipboard::clear_if(&value);
        }
        self.state.borrow_mut().editor_generated = None;
        {
            // The lock screen asks for the keyfile again when the vault uses one.
            let keyfile = self.state.borrow().session.as_ref().map(|s| {
                let id = s.vault.id_hex();
                (
                    s.vault.needs_keyfile(),
                    vault_platform::keyfile::remembered_path(&id),
                )
            });
            if let Some((needed, path)) = keyfile {
                let app = self.app();
                app.set_needs_keyfile(needed);
                app.set_keyfile_path(SharedString::from(
                    path.filter(|_| needed)
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                ));
            }
        }
        {
            let mut state = self.state.borrow_mut();
            // A job still holding the open vault won't hand it back (`finish_job`).
            state.session_epoch = state.session_epoch.wrapping_add(1);
            state.vault_open = false;
            state.unsaved = false;
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
            state.health = None;
            state.health_ids.clear();
            state.leaks.clear();
            state.history_shown = None;
            state.history_revealed.clear();
            state.import_include.clear();
            state.history = navigation::History::default();
            state.dialog_folder = None;
            state.browser_pairing = None;
            state.browser_offer = None;
            state.browser_pending = None;
            state.browser_generated.clear();
            state.generated_history = None;
            state.generated_shown = None;
            state.secrets_open = false;
            state.guard_attempts = 0;
        }
        self.clear_all_secrets();
        self.sync_guard_state();
        {
            let app = self.app();
            app.set_detail_history(ModelRc::default());
            app.set_detail_history_shown(false);
            app.set_health_rows(ModelRc::default());
            app.set_import_rows(ModelRc::default());
            app.set_leaks_checked(false);
            app.set_vault_name(SharedString::new());
            app.set_folder_dialog(-1);
            app.set_pairing_code(SharedString::new());
            app.set_can_go_back(false);
            app.set_can_go_forward(false);
        }
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
        hide_kit_keys(&app);
        clear_kit_parts(&app);
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
        // What key work left on this thread's stack (unlocking, reading items) goes too.
        vault_core::memory::clear_stack();
    }

    fn touch_activity(&self) {
        if self.state.borrow().session.is_some() {
            self.restart_auto_lock();
        }
    }

    fn restart_auto_lock(&self) {
        let total = u64::from(self.state.borrow().settings.auto_lock_minutes.max(1)) * 60;
        self.stop_lock_warning();
        let weak = self.weak();
        self.timers.auto_lock.start(
            TimerMode::SingleShot,
            Duration::from_secs(total),
            move || {
                if let Some(controller) = weak.upgrade() {
                    controller.lock();
                }
            },
        );
        // The last minute (half of a one-minute wait) is counted down in the corner.
        let lead = view::lock_warning_lead(total);
        let deadline = std::time::Instant::now() + Duration::from_secs(total);
        self.lock_deadline.set(Some(deadline));
        let weak = self.weak();
        self.timers.lock_warning.start(
            TimerMode::SingleShot,
            Duration::from_secs(total - lead),
            move || {
                if let Some(controller) = weak.upgrade() {
                    controller.start_lock_countdown(deadline);
                }
            },
        );
    }

    fn start_lock_countdown(&self, deadline: std::time::Instant) {
        let tick = {
            let weak = self.weak();
            move || {
                if let Some(controller) = weak.upgrade() {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    let seconds = i32::try_from(left.as_secs().saturating_add(1)).unwrap_or(1);
                    controller.app().set_lock_warning_seconds(seconds);
                }
            }
        };
        tick();
        self.timers
            .lock_countdown
            .start(TimerMode::Repeated, Duration::from_millis(500), tick);
    }

    /// Whole minutes (rounded up) before the auto-lock; 0 when locked.
    fn minutes_left(&self) -> i32 {
        let left = self.lock_deadline.get().map_or(Duration::ZERO, |deadline| {
            deadline.saturating_duration_since(std::time::Instant::now())
        });
        i32::try_from(left.as_secs().div_ceil(60)).unwrap_or(0)
    }

    fn stop_lock_warning(&self) {
        self.timers.lock_warning.stop();
        self.timers.lock_countdown.stop();
        self.app().set_lock_warning_seconds(0);
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
        let folders: Vec<(FolderId, String, String, u8, String)> = self
            .state
            .borrow()
            .session
            .as_ref()
            .map(|s| {
                s.vault
                    .folders()
                    .iter()
                    .map(|f| {
                        (
                            f.id,
                            f.name.clone(),
                            f.icon.clone(),
                            f.color,
                            f.icon_url.clone(),
                        )
                    })
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
                Some((id, name, icon, color, link)) => {
                    browsing = Some((*id, name.clone()));
                    app.set_folder_icon(SharedString::from(icon.as_str()));
                    app.set_folder_color(i32::from(*color));
                    let picture = self.folder_picture(link);
                    app.set_folder_has_image(picture.is_some());
                    app.set_folder_image(picture.unwrap_or_default());
                }
                None => {
                    category = 0;
                    app.set_category(0);
                }
            }
        }
        let folder_rows: Vec<FolderRow> = folders
            .iter()
            .map(|(id, name, icon, color, link)| {
                let picture = self.folder_picture(link);
                FolderRow {
                    has_image: picture.is_some(),
                    image: picture.unwrap_or_default(),
                    icon: SharedString::from(icon.as_str()),
                    color: i32::from(*color),
                    name: SharedString::from(name.as_str()),
                    count: i32::try_from(
                        summaries.iter().filter(|s| s.folder == Some(*id)).count(),
                    )
                    .unwrap_or(0),
                }
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
                let visual = self.icon_for(s.kind, &s.url, &s.icon_url, &s.title);
                ItemRow {
                    title: SharedString::from(s.title.as_str()),
                    subtitle: SharedString::from(view::subtitle(s)),
                    kind: view::kind_to_int(s.kind),
                    favorite: s.favorite,
                    icon: visual.image,
                    has_icon: visual.has_image,
                    initial: visual.initial,
                    tint: visual.tint,
                    brand: view::brand_mark(s.card_brand),
                    glyph: visual.glyph,
                    glyph_color: visual.glyph_color,
                    glyph_bg: visual.glyph_bg,
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
        let stale = std::mem::take(&mut self.state.borrow_mut().health_stale);
        if stale {
            self.refresh_health();
        }
    }

    fn select_category(&self, category: i32) {
        let app = self.app();
        app.set_category(category);
        if matches!(
            app.get_panel(),
            Panel::Generator
                | Panel::Settings
                | Panel::Kit
                | Panel::Health
                | Panel::Transfer
                | Panel::Authenticator
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

    /// The selected item, for showing or copying its secrets and for changing it. `None` while
    /// a guarded item still waits for its check, so nothing reaches the secrets by another
    /// route (the right-click menu, a shortcut).
    fn selected_item(&self) -> Option<(ItemId, ItemData)> {
        let (id, item) = self.selected_item_raw()?;
        (!self.item_locked(&item)).then_some((id, item))
    }

    fn selected_item_raw(&self) -> Option<(ItemId, ItemData)> {
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
        app.set_detail_locked(false);
        let Some((id, item)) = self.selected_item_raw() else {
            app.set_has_selection(false);
            self.state.borrow_mut().totp = None;
            self.state.borrow_mut().codes_shown = None;
            app.set_detail_codes(ModelRc::default());
            return;
        };
        // Guarded and not opened yet: the page shows who the account is (title, username,
        // website, plain fields, notes) and nothing secret leaves Rust.
        let locked = self.item_locked(&item);
        app.set_detail_locked(locked);
        self.sync_guard_state();
        app.set_detail_guarded_open(
            !locked
                && self
                    .state
                    .borrow()
                    .session
                    .as_ref()
                    .is_some_and(|s| s.vault.guards(&item)),
        );
        app.set_detail_check(
            self.state
                .borrow()
                .session
                .as_ref()
                .map_or(0, |s| protection::check_code(s.vault.item_guard().check)),
        );
        if locked {
            self.clear_secret(field::REPROMPT);
        }
        app.set_has_selection(true);
        app.set_detail_title(SharedString::from(item.title.as_str()));
        app.set_detail_kind(view::kind_to_int(item.kind));
        self.apply_detail_icon(&item);
        app.set_detail_favorite(item.favorite);
        app.set_detail_username(SharedString::from(item.username.as_str()));
        app.set_detail_has_password(!locked && !item.password.is_empty());
        // A secure note's text is its secret.
        let notes_hidden = locked && item.kind == ItemKind::SecureNote;
        app.set_detail_notes(SharedString::from(if notes_hidden {
            ""
        } else {
            item.notes.as_str()
        }));
        let urls: Vec<SharedString> = item
            .urls
            .iter()
            .map(|u| SharedString::from(u.as_str()))
            .collect();
        app.set_detail_urls(ModelRc::from(Rc::new(VecModel::from(urls))));
        let fields: Vec<DetailField> = view::detail_fields(&item, view::now_month_year())
            .into_iter()
            .filter(|f| !locked || !f.hideable)
            .map(|f| DetailField {
                label: SharedString::from(f.label),
                value: SharedString::from(f.value),
                sensitive: f.sensitive,
                index: i32::try_from(f.index).unwrap_or(-1),
                warning: f.warning,
                icon: SharedString::from(f.icon),
                hideable: f.hideable,
            })
            .collect();
        app.set_detail_fields(ModelRc::from(Rc::new(VecModel::from(fields))));
        app.set_detail_folder(SharedString::from(
            item.folder
                .and_then(|folder| self.folder_name(&folder))
                .unwrap_or_default(),
        ));
        let codes = if locked { 0 } else { item.recovery_codes.len() };
        app.set_detail_codes_total(i32::try_from(codes).unwrap_or(0));
        self.show_detail_files(&item, locked);
        app.set_detail_codes_left(i32::try_from(item.recovery_codes_left()).unwrap_or(0));
        if !locked && self.state.borrow().codes_shown == Some(id) {
            self.fill_codes(&item);
        } else {
            self.state.borrow_mut().codes_shown = None;
            app.set_detail_codes(ModelRc::default());
        }

        if locked {
            app.set_detail_history_count(0);
        } else {
            self.show_password_details(id, &item);
        }
        let totp = (!locked && !item.totp.is_empty())
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
        self.conceal();
        let app = self.app();
        app.set_revealed_password(SharedString::from(item.password.as_str()));
        self.start_reveal_countdown();
    }

    /// Shows one hidden extra field (a hidden custom field, a card's number or security code),
    /// or hides it again when it is the one on screen. Only one secret is visible at a time.
    fn reveal_field(&self, index: i32) {
        let app = self.app();
        if app.get_revealed_field() == index {
            self.conceal();
            return;
        }
        let Some((_, item)) = self.selected_item() else {
            return;
        };
        let Some(field) = usize::try_from(index)
            .ok()
            .and_then(|i| item.custom_fields.get(i))
        else {
            return;
        };
        let shown = if item.kind == ItemKind::Card && field.name.eq_ignore_ascii_case(card::NUMBER)
        {
            card::group(&card::digits(&field.value))
        } else {
            field.value.clone()
        };
        self.conceal();
        app.set_revealed_field(index);
        app.set_revealed_field_value(SharedString::from(shown.as_str()));
        self.start_reveal_countdown();
    }

    fn start_reveal_countdown(&self) {
        let app = self.app();
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
        app.set_revealed_field(-1);
        app.set_revealed_field_value(SharedString::new());
        app.set_reveal_left(0);
    }

    /// Opens one of the selected item's websites in the default browser.
    fn open_url(&self, index: i32) {
        let Some((_, item)) = self.selected_item_raw() else {
            return;
        };
        let Some(url) = usize::try_from(index).ok().and_then(|i| item.urls.get(i)) else {
            return;
        };
        if let Err(err) = files::open_web_link(url) {
            self.notify_long(notice::LINK_FAILED, &format!("{url} ({err:#})"));
        }
    }

    fn copy_url(&self, index: i32) {
        let Some((_, item)) = self.selected_item_raw() else {
            return;
        };
        if let Some(url) = usize::try_from(index).ok().and_then(|i| item.urls.get(i)) {
            self.copy(Zeroizing::new(url.clone()), false, notice::WEBSITE_COPIED);
        }
    }

    fn copy_from_selected(&self, what: CopyWhat) {
        let Some((_, item)) = self.selected_item_raw() else {
            return;
        };
        // What a locked item still shows can be copied; its secrets cannot.
        let visible = match what {
            CopyWhat::Username => true,
            CopyWhat::Field(index) => view::detail_fields(&item, view::now_month_year())
                .iter()
                .any(|f| i32::try_from(f.index) == Ok(index) && !f.hideable),
            _ => false,
        };
        if !visible && self.item_locked(&item) {
            return;
        }
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
            self.state.borrow_mut().unsaved = true;
            self.set_error(error::CHANGED_OUTSIDE, "");
            self.notify_long(notice::NOT_SAVED, "");
            return false;
        }
        let result = {
            let mut state = self.state.borrow_mut();
            state.summaries_stale = true;
            let path = state.path.clone();
            // Compared again right before the rename: a save by someone else while this one
            // was being written is noticed too (a file that is gone is written again).
            let expected = state.file_hash.filter(|_| path.exists());
            match state.session.as_mut() {
                Some(session) => session.vault.to_bytes().and_then(|bytes| {
                    match expected {
                        Some(read) => storage::write_atomic_if_unchanged(&path, &read, &bytes)?,
                        None => storage::write_atomic(&path, &bytes)?,
                    }
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
                {
                    let mut state = self.state.borrow_mut();
                    state.file_hash = Some(hash);
                    state.unsaved = false;
                }
                let _ = device::record_revision(&id, revision);
                // Keep the index's count of problems current (cheap: no network).
                self.state.borrow_mut().health_stale = true;
                self.refresh_locked_fill();
                if self.app().get_error_code() == error::CHANGED_OUTSIDE {
                    self.set_error(error::NONE, "");
                }
                self.sync_after_save();
                true
            }
            Err(err) => {
                self.state.borrow_mut().unsaved = true;
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
        !file_unchanged(&path, expected)
    }

    fn toggle_favorite(&self) {
        let Some((id, mut item)) = self.selected_item_raw() else {
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
    ///
    /// Whatever a background job still does for the vault shown before (an unlock, a
    /// Windows Hello prompt) is dropped when it comes back: it belongs to the other file.
    pub fn switch_vault(&self, path: PathBuf) {
        let open = {
            let state = self.state.borrow();
            state.vault_open || state.session.is_some()
        };
        if open {
            self.lock();
        }
        self.clear_all_secrets();
        {
            let mut state = self.state.borrow_mut();
            state.session_epoch = state.session_epoch.wrapping_add(1);
            state.path = path;
            state.pending = None;
            state.suggestion = None;
        }
        let app = self.app();
        app.set_choosing_vault(false);
        app.set_suggestion(SharedString::new());
        hide_kit_keys(&app);
        clear_kit_parts(&app);
        app.set_recovered(false);
        self.show_start_screen();
    }

    /// Whether another vault may be chosen now: not while a job works for the one shown (its
    /// result would be dropped anyway, see `switch_vault`, but the person would not know why).
    fn may_switch_vault(&self) -> bool {
        !self.app().get_busy()
    }

    fn pick_vault(&self, index: i32) {
        if !self.may_switch_vault() {
            return;
        }
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
        if self.state.borrow().runner == Runner::Inline || !self.may_switch_vault() {
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
        if self.state.borrow().runner == Runner::Inline || !self.may_switch_vault() {
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
        self.fill_authenticator();
        let app = self.app();
        app.set_auth_search(SharedString::new());
        app.set_panel(Panel::Authenticator);
        self.set_error(error::NONE, "");
        self.clear_secret(field::REPROMPT);
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

    /// Every item with a one-time code. Locked items are listed too, without their secret:
    /// the page shows them masked until the item lock's check is passed.
    fn fill_authenticator(&self) {
        let (guard_all, open) = {
            let state = self.state.borrow();
            (
                state
                    .session
                    .as_ref()
                    .is_some_and(|s| s.vault.item_guard().all_items),
                state.secrets_open,
            )
        };
        let listed: Vec<(ItemId, bool)> = self
            .state
            .borrow()
            .summaries
            .iter()
            .filter(|s| s.has_totp)
            .map(|s| (s.id, guard_all || s.reprompt))
            .collect();
        let mut entries = Vec::with_capacity(listed.len());
        for (id, guarded) in listed {
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
            let totp = if guarded && !open {
                None
            } else {
                // A broken secret is reported on the item page; here it is simply left out.
                match Totp::parse(&item.totp) {
                    Ok(totp) => Some(totp),
                    Err(_) => continue,
                }
            };
            let url = item.urls.first().map(String::as_str).unwrap_or_default();
            let visual = self.icon_for(item.kind, url, &item.icon_url, &item.title);
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
                guarded,
                visual,
            });
        }
        entries.sort_by_key(|e| e.title.to_lowercase());
        let app = self.app();
        app.set_auth_locked(entries.iter().any(|e| e.totp.is_none()));
        app.set_auth_guarded_open(entries.iter().any(|e| e.guarded && e.totp.is_some()));
        self.state.borrow_mut().auth = entries;
        self.sync_guard_state();
    }

    /// Mirrors the item lock's state for the pages that depend on it.
    fn sync_guard_state(&self) {
        let app = self.app();
        let state = self.state.borrow();
        let guard = state.session.as_ref().map(|s| s.vault.item_guard());
        app.set_secrets_open(state.secrets_open);
        app.set_guard_encrypts(guard.is_some_and(|g| g.encrypts()));
        app.set_guard_hello_on(
            state.quick_available
                && guard.is_some_and(|g| g.encrypts())
                && state
                    .session
                    .as_ref()
                    .is_some_and(|s| quick_unlock::item_lock_enrolled(&s.vault.id_hex())),
        );
        app.set_guard_current_all(guard.is_some_and(|g| g.all_items));
        app.set_detail_check(guard.map_or(0, |g| protection::check_code(g.check)));
        // A newer item lock from another device that waits here, and what opens it.
        let waiting = state
            .session
            .as_ref()
            .and_then(|s| s.vault.guard_waiting_check());
        app.global::<ItemLock>()
            .set_waiting(waiting.map_or(0, protection::waiting_code));
    }

    /// The item lock opened or closed: redraw what shows secrets.
    fn secrets_changed(&self) {
        self.conceal();
        // The item lock was opened here: the locked-fill index gets every password now.
        self.refresh_locked_fill();
        self.refresh_list();
        match self.app().get_panel() {
            Panel::Authenticator => {
                self.fill_authenticator();
                self.tick_auth();
            }
            Panel::Generator => self.fill_generated_history(),
            Panel::Kit => self.refresh_kit_lock(),
            _ => self.show_detail(),
        }
    }

    /// The kit page's keys and PDF password wait for the item lock while one is in use and
    /// closed: its check (PIN, password, master password or Windows Hello) shows them.
    fn refresh_kit_lock(&self) {
        let locked = self.item_lock_closed();
        self.app().set_kit_keys_locked(locked);
    }

    /// Copies the kit's PDF password (the clipboard clears itself and keeps it out of
    /// history): on the kit page once the item lock is open, as showing it.
    fn copy_kit_pdf_password(&self) {
        let app = self.app();
        let password = app.get_kit_pdf_password();
        let gated = app.get_screen() != Screen::Onboarding && self.item_lock_closed();
        if password.is_empty() || gated {
            return;
        }
        self.copy(
            Zeroizing::new(password.to_string()),
            true,
            notice::KIT_PDF_PASSWORD_COPIED,
        );
    }

    /// Closes every locked item again (the Lock button, or the time is up).
    ///
    /// The generator's result goes too: it may be the password a locked login was just given,
    /// and it would stay readable (and copyable) on the generator page after its item closed.
    fn lock_secrets(&self) {
        self.timers.relock.stop();
        {
            let mut state = self.state.borrow_mut();
            state.secrets_open = false;
            state.summaries_stale = true;
            if let Some(session) = state.session.as_mut() {
                session.vault.lock_secrets();
            }
        }
        self.forget_generated_result();
        self.clear_secret(field::REPROMPT);
        self.secrets_changed();
    }

    /// One pass of the item lock keeps it open this long (the relock timer, from now).
    fn start_relock(&self) {
        let weak = self.weak();
        self.timers
            .relock
            .start(TimerMode::SingleShot, SECRETS_OPEN_FOR, move || {
                if let Some(controller) = weak.upgrade() {
                    controller.relock_secrets();
                }
            });
    }

    /// The open time is up. An item being edited keeps its secrets until it is saved or
    /// closed, so nothing typed is lost.
    fn relock_secrets(&self) {
        if self.app().get_panel() == Panel::Editor {
            let weak = self.weak();
            self.timers
                .relock
                .start(TimerMode::SingleShot, Duration::from_secs(30), move || {
                    if let Some(controller) = weak.upgrade() {
                        controller.relock_secrets();
                    }
                });
            return;
        }
        if self.state.borrow().session.is_some() {
            self.lock_secrets();
        }
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
                let (code, left, period) = match &e.totp {
                    Some(totp) => {
                        let (code, left) = totp.now();
                        (view::group_code(&code), left, totp.period())
                    }
                    None => (String::new(), 0, 30),
                };
                AuthRow {
                    title: SharedString::from(e.title.as_str()),
                    subtitle: SharedString::from(e.subtitle.as_str()),
                    code: SharedString::from(code),
                    locked: e.totp.is_none(),
                    left: i32::try_from(left).unwrap_or(0),
                    period: i32::try_from(period).unwrap_or(30),
                    kind: view::kind_to_int(ItemKind::Login),
                    icon: e.visual.image.clone(),
                    has_icon: e.visual.has_image,
                    initial: e.visual.initial.clone(),
                    tint: e.visual.tint,
                    glyph: e.visual.glyph.clone(),
                    glyph_color: e.visual.glyph_color,
                    glyph_bg: e.visual.glyph_bg,
                }
            })
            .collect();
        drop(state);
        // Once a second only the countdowns move (and every 30 s the codes): with the same
        // rows listed, those are changed in place. A new model would make the list build
        // every row again, icons included, each second.
        let current = app.get_auth_rows();
        let same_rows = current.row_count() == rows.len()
            && rows.iter().enumerate().all(|(i, row)| {
                current.row_data(i).is_some_and(|old| {
                    old.title == row.title
                        && old.subtitle == row.subtitle
                        && old.has_icon == row.has_icon
                        && old.initial == row.initial
                        && old.tint == row.tint
                })
            });
        if !same_rows {
            app.set_auth_rows(ModelRc::from(Rc::new(VecModel::from(rows))));
            return;
        }
        for (i, row) in rows.into_iter().enumerate() {
            let moved = current.row_data(i).is_some_and(|old| {
                old.code != row.code
                    || old.left != row.left
                    || old.period != row.period
                    || old.locked != row.locked
            });
            if moved {
                current.set_row_data(i, row);
            }
        }
    }

    fn auth_copy(&self, index: i32) {
        let visible = self.visible_auth();
        let code = usize::try_from(index)
            .ok()
            .and_then(|i| visible.get(i))
            .and_then(|&i| {
                let state = self.state.borrow();
                state.auth[i].totp.as_ref().map(|totp| totp.now().0)
            });
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
        if let Some(id) = id {
            let item = self
                .state
                .borrow()
                .session
                .as_ref()
                .and_then(|s| s.vault.get_item(&id).ok());
            if item.is_some_and(|item| self.item_locked(&item)) {
                return; // its check first
            }
        }
        self.clear_secret(field::REPROMPT);
        self.sync_guard_state();
        let item = id.and_then(|id| {
            self.state
                .borrow()
                .session
                .as_ref()?
                .vault
                .get_item(&id)
                .ok()
        });
        let new = item.is_none();
        let item = item.unwrap_or_else(|| ItemData::new(vault_core::ItemKind::Login, ""));
        // A new item starts as the kind of the list (or page) it was asked for from.
        app.set_ed_kind(if new {
            view::new_item_kind(app.get_category(), app.get_panel() == Panel::Authenticator)
        } else {
            view::editor_kind(&item)
        });
        app.set_ed_title(SharedString::from(item.title.as_str()));
        app.set_ed_username(SharedString::from(item.username.as_str()));
        app.set_ed_url(SharedString::from(
            item.urls.first().map(String::as_str).unwrap_or_default(),
        ));
        // A line icon chosen for it (`glyph:`), else a site or picture chosen as its icon.
        let look = view::IconLook::of_icon_url(&item.icon_url).unwrap_or_default();
        app.set_ed_glyph(look.name.as_str().into());
        app.set_ed_glyph_color(look.color);
        app.set_ed_glyph_bg(look.background);
        app.set_ed_icon_url(if look.name.is_empty() {
            SharedString::from(item.icon_url.as_str())
        } else {
            SharedString::new()
        });
        app.set_ed_totp(SharedString::from(item.totp.as_str()));
        app.set_ed_notes(SharedString::from(item.notes.as_str()));
        app.set_ed_favorite(item.favorite);
        app.set_ed_reprompt(item.reprompt);
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
        // Extra fields; a card's own details and an SSH key's public half have their own boxes.
        let is_card = item.kind == ItemKind::Card;
        let is_ssh = item.kind == ItemKind::SshKey;
        self.state.borrow_mut().edit_fields = item
            .custom_fields
            .iter()
            .filter(|f| {
                (!is_card
                    || !card::RESERVED
                        .iter()
                        .any(|r| f.name.eq_ignore_ascii_case(r)))
                    && (!is_ssh
                        || (f.name != vault_core::ssh::PUBLIC_KEY_FIELD
                            && f.name != vault_core::ssh::FINGERPRINT_FIELD
                            && f.name != vault_core::ssh::KEY_TYPE_FIELD))
            })
            .cloned()
            .collect();
        self.show_edit_fields();
        self.editor_files_from(&item);
        let details = CardDetails::from_item(&item);
        app.set_ed_card_number(SharedString::from(card::group(&details.number)));
        app.set_ed_card_expiry(SharedString::from(
            card::parse_expiry(&details.expiry).map_or(details.expiry.clone(), card::format_expiry),
        ));
        app.set_ed_card_code(SharedString::from(details.security_code.as_str()));
        self.card_number_edited(&details.number);
        app.set_editor_password_shown(SharedString::new());
        self.edit_secret(field::ITEM_PASSWORD as i32, |buffer| {
            buffer.set(&item.password);
        });
        self.state.borrow_mut().editing = Some(id);
        app.set_ed_gen_open(false);
        app.set_editor_is_new(id.is_none());
        app.set_editing_item(true);
        self.editor_site_icon();
        app.set_panel(Panel::Editor);
        self.set_error(error::NONE, "");
    }

    /// The site's icon next to the editor's Website field and in its automatic preview, from
    /// what is already known (a new site's icon is asked for once the item is saved).
    fn editor_site_icon(&self) {
        let app = self.app();
        let url = app.get_ed_url();
        let visual = self.icon_for(ItemKind::Login, &url, "", "");
        app.set_ed_site_icon(visual.image);
        app.set_ed_has_site_icon(visual.has_image);
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
        self.clear_editor_files();
        app.set_editing_item(false);
        app.set_panel(Panel::Detail);
        self.show_detail();
    }

    fn save_item(&self) {
        let app = self.app();
        let totp = app.get_ed_totp().trim().to_owned();
        let mut title = app.get_ed_title().trim().to_owned();
        // An authenticator item named by nobody takes the service in its setup key, else its
        // website's name.
        if title.is_empty() && app.get_ed_kind() == view::EDITOR_AUTHENTICATOR {
            title = view::authenticator_title(&totp, &app.get_ed_url());
        }
        if title.is_empty() {
            self.set_error(
                if app.get_ed_kind() == view::EDITOR_AUTHENTICATOR && totp.is_empty() {
                    error::TOTP_REQUIRED
                } else {
                    error::TITLE_REQUIRED
                },
                "",
            );
            return;
        }
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
        let kind = view::editor_kind_to_kind(app.get_ed_kind());
        if app.get_ed_kind() == view::EDITOR_AUTHENTICATOR && totp.is_empty() {
            self.set_error(error::TOTP_REQUIRED, "");
            return;
        }
        let mut item = existing.unwrap_or_else(|| ItemData::new(kind, &title));
        item.kind = kind;
        item.title = title;
        item.username = app.get_ed_username().to_string();
        if item.username.trim().is_empty() && app.get_ed_kind() == view::EDITOR_AUTHENTICATOR {
            item.username = vault_core::totp::names(&totp).account;
        }
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
        let glyph = app.get_ed_glyph();
        item.icon_url = if glyph.is_empty() {
            view::icon_site(&app.get_ed_icon_url())
        } else {
            view::IconLook::new(&glyph, app.get_ed_glyph_color(), app.get_ed_glyph_bg()).icon_url()
        };
        item.notes = app.get_ed_notes().to_string();
        item.favorite = app.get_ed_favorite();
        item.reprompt = app.get_ed_reprompt();
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
        self.editor_files_into(&mut item);
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

        // A changed item the item lock covers (or one read while locked) needs its PIN or
        // password first, typed in the editor. A new item doesn't: it is sealed the next time
        // the item lock opens (`Vault::add_item`).
        let was_locked = item.is_locked();
        item.sealed = None;
        let needs_unlock = editing.is_some()
            && (was_locked
                || self
                    .state
                    .borrow()
                    .session
                    .as_ref()
                    .is_some_and(|s| s.vault.needs_unlock_to_store(&item)));
        if needs_unlock {
            if self.state.borrow().secrets[field::REPROMPT].is_empty() {
                self.set_error(error::SECRETS_LOCKED, "");
            } else {
                self.unlock_secrets(AfterUnlock::SaveItem);
            }
            return;
        }

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
        // The generator's result typed or pasted in by hand is now this item's password.
        let generated = self
            .state
            .borrow()
            .generated
            .as_ref()
            .is_some_and(|value| !item.password.is_empty() && value.as_str() == item.password);
        if result.is_ok() && generated {
            self.forget_generated_result();
        }
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
            let bits = f64::from(self.app().get_gen_bits());
            self.state.borrow_mut().editor_generated = Some((file_hash(password.as_bytes()), bits));
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

    fn regenerate(&self) {
        if let Some(value) = self.generate() {
            self.app()
                .set_gen_result(SharedString::from(value.as_str()));
            self.state.borrow_mut().generated = Some(value);
        }
    }

    /// The generator's current result is forgotten, on the page and in Rust (a new one is made
    /// the next time the generator opens): once it went into an item, it is that item's
    /// password, shown and copied only as the item allows.
    pub(crate) fn forget_generated_result(&self) {
        self.state.borrow_mut().generated = None;
        self.app().set_gen_result(SharedString::new());
    }

    fn open_generator(&self) {
        let app = self.app();
        app.set_panel(Panel::Generator);
        self.set_error(error::NONE, "");
        if app.get_gen_result().is_empty() {
            self.regenerate();
        }
        self.state.borrow_mut().generated_shown = None;
        self.fill_generated_history();
    }

    fn copy_generated(&self) {
        let value = self.state.borrow().generated.clone();
        if let Some(value) = value {
            self.record_generated(&value, "");
            self.copy(value, true, notice::GENERATED_COPIED);
        }
    }

    fn use_generated(&self) {
        let value = self.state.borrow().generated.clone();
        let editing = self.state.borrow().editing.is_some();
        if let (Some(value), true) = (value, editing) {
            self.record_generated(&value, "");
            self.edit_secret(field::ITEM_PASSWORD as i32, |buffer| {
                buffer.set(&value);
            });
            // Handed to the editor: no longer the generator's to show.
            self.forget_generated_result();
            let app = self.app();
            app.set_editor_password_shown(SharedString::from(value.as_str()));
            app.set_panel(Panel::Editor);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------------------------------

    /// A Settings dialog opens: nothing left from before (an error, what was typed).
    fn open_settings_dialog(&self, kind: i32) {
        self.set_error(error::NONE, "");
        let app = self.app();
        app.set_kdf_failed(false);
        app.set_keyfile_failed(false);
        app.set_guard_failed(false);
        app.set_sync_setup_error(SharedString::new());
        self.clear_settings_secrets();
        if kind == dialog::SERVER_ADDRESS || kind == dialog::BACKUP_ADDRESS {
            self.fill_server_address(kind == dialog::BACKUP_ADDRESS);
        }
        app.set_settings_dialog(kind);
    }

    /// A Settings dialog was closed without its change: what was typed in it is forgotten.
    fn close_settings_dialog(&self) {
        self.clear_settings_secrets();
        self.set_error(error::NONE, "");
        self.app().set_settings_dialog(dialog::NONE);
    }

    fn clear_settings_secrets(&self) {
        for index in [
            field::CURRENT,
            field::NEW,
            field::NEW_AGAIN,
            field::KDF_CURRENT,
            field::KEYFILE_CURRENT,
            field::GUARD_NEW,
            field::GUARD_CURRENT,
            field::CONFIRM_MASTER,
        ] {
            self.clear_secret(index);
        }
    }

    /// A Settings dialog's action (kinds 5 to 9). Removing the backup server only asks; the
    /// others go ahead once the master password typed in the dialog opens the vault file.
    fn confirm_settings(&self, kind: i32) {
        if kind == dialog::REMOVE_BACKUP {
            return self.settings_confirmed(kind);
        }
        let typed = Zeroizing::new(
            self.state.borrow().secrets[field::CONFIRM_MASTER]
                .as_str()
                .to_owned(),
        );
        if typed.is_empty() {
            return self.set_error(error::WRONG_CURRENT, "");
        }
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let path = self.state.borrow().path.clone();
        self.run_job(move || match verify_current(&path, &typed, &session) {
            Ok(()) => JobResult::SettingsConfirmed { session, kind },
            Err((code, detail)) => JobResult::Failed {
                code,
                detail,
                session: Some(session),
            },
        });
    }

    fn settings_confirmed(&self, kind: i32) {
        let app = self.app();
        app.set_settings_dialog(dialog::NONE);
        match kind {
            dialog::STOP_SYNC => self.sync_stop(),
            dialog::REMOVE_DEVICE => self.sync_remove_device(app.get_sync_removing()),
            // The invite shows in a dialog of its own once the server made it.
            dialog::ADD_DEVICE => self.sync_add_device(),
            dialog::REMOVE_BACKUP => self.sync_remove_backup(),
            dialog::DISCONNECT => self.forget_pairing(),
            _ => {}
        }
    }

    fn open_settings(&self) {
        let app = self.app();
        let settings = self.state.borrow().settings.clone();
        app.set_auto_lock_minutes(settings.auto_lock_minutes as i32);
        app.set_lock_with_windows(settings.lock_with_windows);
        app.set_clipboard_seconds(settings.clipboard_clear_seconds as i32);
        app.set_website_icons(settings.website_icons);
        app.set_leak_watch(settings.leak_watch);
        app.set_update_checks(settings.update_checks);
        app.set_close_to_tray(settings.close_to_tray);
        app.set_start_in_tray(settings.start_in_tray);
        app.set_start_at_sign_in(self.starts_at_sign_in());
        app.set_browser_locked_fill(settings.browser_locked_fill);
        app.set_browser_extension(settings.browser_extension);
        app.set_browser_saves(settings.browser_saves);
        app.set_browser_passkeys(settings.browser_passkeys);
        app.set_browser_warnings(settings.browser_warnings);
        app.set_browser_fill_notices(settings.browser_fill_notices);
        app.set_browser_always_asks(settings.browser_always_asks);
        app.set_browser_ask_way(self.browser_ask_way());
        app.set_backdrop_on(settings.backdrop);
        app.set_settings_dialog(dialog::NONE);
        app.set_browser_paired(self.browser_is_paired());
        app.set_extension_steps(false);
        self.show_extension_browsers();
        self.show_extension_source();
        self.show_vault_settings();
        hide_kit_keys(&app);
        clear_kit_parts(&app);
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
        self.show_sources();
        app.set_panel(Panel::Transfer);
        self.set_error(error::NONE, "");
    }

    fn import_choose(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests: they call start_import directly
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Import from another password manager")
            .add_filter("Password exports", self.source_extensions())
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
        app.set_import_plaintext(!format.needs_password());
        self.set_error(error::NONE, "");
        self.state.borrow_mut().pending_import = Some(PendingImport {
            path,
            bytes,
            format,
            report: None,
        });
        if format.needs_password() {
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
            let parsed = vault_import::import(&bytes, format, &password, None);
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
            Ok(_) => {
                if !self.show_review(&report) {
                    return;
                }
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
        let target = self.import_target();
        let include = std::mem::take(&mut self.state.borrow_mut().import_include);
        let outcome = self
            .state
            .borrow_mut()
            .session
            .as_mut()
            .map(|s| report.add_selected(&mut s.vault, &include, &target));
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

    /// Overwrites and deletes the unencrypted export that was just imported: the very file that
    /// was read (another one put at that path meanwhile is left alone).
    fn import_wipe(&self) {
        let read = self
            .state
            .borrow()
            .pending_import
            .as_ref()
            .map(|p| (p.path.clone(), p.bytes.clone()));
        if let Some((path, bytes)) = read {
            match files::wipe_if_same(&path, &bytes) {
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
        let name = format!("vault-backup-{}.vault", view::date(view::now_unix()));
        let Some(target) = rfd::FileDialog::new()
            .set_title("Save a backup copy of the vault")
            .set_file_name(&name)
            .add_filter("Vault", &["vault"])
            .save_file()
        else {
            return;
        };
        self.save_confirmed_backup(&target);
    }

    /// Writes the copy, reads it back, and calls it done only when it is the vault file byte
    /// for byte and opens with this vault's key (every byte authenticated, no password asked
    /// again). A copy that fails is deleted.
    ///
    /// The file copied must be the one this window last read or wrote, at the revision open
    /// here: a vault file replaced meanwhile (by an older copy of this same vault, still
    /// authentic) is not saved as "the backup of the vault as it is now".
    pub(crate) fn save_confirmed_backup(&self, target: &std::path::Path) {
        self.set_error(error::NONE, "");
        let source = self.state.borrow().path.clone();
        let bytes = match storage::read(&source) {
            Ok(bytes) => bytes,
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
                return;
            }
        };
        if self.state.borrow().file_hash != Some(file_hash(&bytes)) {
            self.set_error(error::CHANGED_OUTSIDE, "");
            return;
        }
        // Everything knowable from the bytes is checked before the target is touched: a copy
        // refused after writing would be deleted, and with it a good backup it replaced, or
        // the vault file itself.
        if same_path(target, &source) {
            self.set_error(error::FILE, "that is the vault file itself");
            return;
        }
        let fit = (|| -> Result<(), String> {
            let state = self.state.borrow();
            let session = state.session.as_ref().ok_or("the vault is locked")?;
            let revision = session
                .vault
                .check_copy(&bytes)
                .map_err(|e| e.to_string())?;
            if revision != session.vault.revision() {
                return Err("the vault file is not the revision open here".into());
            }
            Ok(())
        })();
        if let Err(detail) = fit {
            self.set_error(error::OTHER, &detail);
            return;
        }
        if let Err(err) = storage::write_atomic(target, &bytes) {
            let (code, detail) = self.core_error(&err);
            self.set_error(code, &detail);
            return;
        }
        let checked = (|| -> Result<(), String> {
            let back = storage::read(target).map_err(|e| e.to_string())?;
            if storage::fingerprint(&back) != storage::fingerprint(&bytes) {
                return Err("the copy read back differs from the vault file".into());
            }
            Ok(())
        })();
        match checked {
            Ok(()) => self.notify_long(
                notice::BACKUP_SAVED,
                &backup_summary(target, bytes.len(), view::now_unix()),
            ),
            Err(detail) => {
                let _ = std::fs::remove_file(target);
                self.set_error(error::BACKUP_CHECK, &detail);
            }
        }
    }

    /// The format chosen on the page (app.slint `export-format`; 0 is the encrypted backup).
    fn export_format(&self) -> ExportFormat {
        match self.app().get_export_format() {
            3 => ExportFormat::Sealed,
            2 => ExportFormat::Csv,
            _ => ExportFormat::Json,
        }
    }

    /// "Export…": the dialog, with what this vault's file leaves out and what anyone who gets
    /// it reads. Locked items can't be counted (nor exported): that is said there, and counted
    /// when the master password opens them (`export_verified`).
    fn ask_export(&self) {
        let counted = match self.state.borrow().session.as_ref() {
            Some(session) => vault_import::export_report(&session.vault, self.export_format()),
            None => return,
        };
        self.forget_export_secrets();
        let app = self.app();
        app.set_export_recounted(false);
        match counted {
            Ok(report) => {
                app.set_export_counts(export_counts(&report));
                self.set_error(error::NONE, "");
            }
            Err(err) => {
                app.set_export_counts(ExportCounts::default());
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
            }
        }
        app.set_export_asking(true);
    }

    fn cancel_export(&self) {
        self.app().set_export_asking(false);
        self.forget_export_secrets();
        self.set_error(error::NONE, "");
    }

    /// What the export dialog asks for: nothing typed for an earlier try stays.
    fn forget_export_secrets(&self) {
        for secret in [field::CURRENT, field::NEW, field::NEW_AGAIN] {
            self.clear_secret(secret);
        }
    }

    /// The session back from an export's check. The master password opened the item lock for
    /// the export only: it closes again, unless it was open before.
    fn put_back(&self, mut session: Session) {
        if !self.state.borrow().secrets_open {
            session.vault.lock_secrets();
        }
        self.state.borrow_mut().session = Some(session);
    }

    /// After the master password check: writes the export to a file the user picks. What the
    /// file holds must be what the dialog showed: anything else (the master password opened
    /// locked items, a sync changed the vault) is shown first and confirmed again, and with
    /// no dialog there is no export.
    fn export_verified(&self, session: Session) {
        let app = self.app();
        if !app.get_export_asking() {
            self.put_back(session);
            self.forget_export_secrets();
            return;
        }
        let format = self.export_format();
        let csv = format == ExportFormat::Csv;
        // The export protected by a password chosen for the file.
        let protected = format == ExportFormat::Sealed;
        let counted = vault_import::export_report(&session.vault, format)
            .map(|report| export_counts(&report));
        if counted.as_ref().ok() != Some(&app.get_export_counts()) {
            self.put_back(session);
            match counted {
                Ok(counts) => {
                    app.set_export_counts(counts);
                    app.set_export_recounted(true);
                }
                Err(err) => {
                    self.clear_secret(field::CURRENT);
                    let (code, detail) = self.core_error(&err);
                    self.set_error(code, &detail);
                }
            }
            return;
        }
        self.clear_secret(field::CURRENT);
        let file_password =
            Zeroizing::new(self.state.borrow().secrets[field::NEW].as_str().to_owned());
        if protected && let Some(code) = self.export_password_problem() {
            self.put_back(session);
            self.set_error(code, "");
            return;
        }
        // What the export dialog asked is checked: it closes, and the file is made.
        self.app().set_export_asking(false);
        let sealed = session
            .vault
            .summaries()
            .is_ok_and(|all| all.iter().any(|s| s.locked));
        let text: Result<Zeroizing<Vec<u8>>, CoreError> = if sealed {
            Err(CoreError::SecretsLocked)
        } else if protected {
            vault_import::export_sealed(&session.vault, &file_password).map(Zeroizing::new)
        } else if csv {
            vault_import::export_csv(&session.vault).map(|t| Zeroizing::new(t.as_bytes().to_vec()))
        } else {
            vault_import::export_json(&session.vault).map(|t| Zeroizing::new(t.as_bytes().to_vec()))
        };
        self.clear_secret(field::NEW);
        self.clear_secret(field::NEW_AGAIN);
        let (runner, vault_path) = {
            let state = self.state.borrow();
            (state.runner, state.path.clone())
        };
        self.put_back(session);
        let text = match text {
            Ok(text) => text,
            Err(err) => {
                let (code, detail) = self.core_error(&err);
                self.set_error(code, &detail);
                return;
            }
        };
        let extension = if protected {
            "vaultx"
        } else if csv {
            "csv"
        } else {
            "json"
        };
        let target = match runner {
            // Headless tests: next to the test vault.
            Runner::Inline => Some(vault_path.with_extension(format!("export.{extension}"))),
            Runner::Thread => rfd::FileDialog::new()
                .set_title(if protected {
                    "Export protected by a password"
                } else {
                    "Export without encryption"
                })
                .set_file_name(format!("vault-export.{extension}"))
                .add_filter(
                    if protected {
                        "Protected export"
                    } else if csv {
                        "CSV"
                    } else {
                        "JSON"
                    },
                    &[extension],
                )
                .save_file(),
        };
        let Some(target) = target else { return };
        match std::fs::write(&target, text.as_slice()) {
            Ok(()) => self.notify(notice::EXPORTED, &target.display().to_string()),
            Err(err) => self.set_error(error::FILE, &err.to_string()),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Emergency kit page, printing and PDF
    // -----------------------------------------------------------------------------------------

    fn open_kit(&self) {
        let app = self.app();
        hide_kit_keys(&app);
        clear_kit_parts(&app);
        self.clear_secret(field::CURRENT);
        app.set_panel(Panel::Kit);
        self.refresh_kit_lock();
        self.set_error(error::NONE, "");
    }

    /// The kit currently on screen as a PDF, with a file name. `None` until the keys are shown.
    /// Protected by the kit's PDF password (CRYPTO.md §3.10), which the PDF viewer asks for.
    /// `print`: the kit to print, with the recovery parts' pages, in a temporary file wiped
    /// when the vault locks (a kit of empty boxes, holding no key, is not protected).
    /// Otherwise the kit to keep in a file: the Secret Key's page only (the three parts
    /// together open the vault without the master password).
    fn kit_pdf(&self, print: bool) -> Option<anyhow::Result<(String, Zeroizing<Vec<u8>>)>> {
        let app = self.app();
        let secret_key = app.get_kit_secret_key();
        let pdf_password = app.get_kit_pdf_password();
        if secret_key.is_empty() || pdf_password.is_empty() {
            return None;
        }
        let parts = [
            app.get_kit_part_a(),
            app.get_kit_part_b(),
            app.get_kit_part_c(),
        ];
        let vault_id = app.get_vault_id();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let kit = KitContents {
            secret_key: &secret_key,
            parts: (print && !parts[0].is_empty())
                .then(|| [parts[0].as_str(), parts[1].as_str(), parts[2].as_str()]),
            vault_id: &vault_id,
            created_at,
            filled: app.get_kit_filled(),
            part_c_elsewhere: app.get_kit_part_c_pictured() && app.get_kit_leave_c_out(),
        };
        let bytes = if print && !kit.filled {
            Ok(kit_pdf::render(&kit))
        } else {
            kit_pdf::render_protected(&kit, &pdf_password)
        };
        let short_id: String = vault_id.chars().take(8).collect();
        Some(bytes.map(|bytes| (format!("emergency-kit-{short_id}.pdf"), bytes)))
    }

    /// The kit as it would print (`true`) or be saved (tests).
    #[cfg(test)]
    pub(crate) fn kit_pdf_for_test(&self, print: bool) -> Option<Zeroizing<Vec<u8>>> {
        self.kit_pdf(print).map(|made| made.unwrap().1)
    }

    /// Writes the kit to the print folder (wiped when the vault locks) and opens it in the PDF
    /// viewer, where it can be printed.
    fn print_kit(&self) {
        let (name, bytes) = match self.kit_pdf(true) {
            None => return,
            Some(Ok(made)) => made,
            Some(Err(err)) => {
                self.set_error(error::FILE, &format!("{err:#}"));
                return;
            }
        };
        let protected = if self.app().get_kit_filled() { "1" } else { "" };
        match files::write_for_printing(&name, &bytes) {
            Ok(path) => {
                // Headless tests stop at writing the file.
                if self.state.borrow().runner == Runner::Thread
                    && let Err(err) = files::open_with_default_app(&path)
                {
                    self.set_error(error::OTHER, &err.to_string());
                    return;
                }
                self.notify(notice::KIT_OPENED, protected);
            }
            Err(err) => self.set_error(error::FILE, &err.to_string()),
        }
    }

    /// Emergency kit → Save as PDF: the Secret Key's page only (the parts go on paper, or each
    /// to a file of its own: `save_parts_apart`), never in a folder a cloud copies away.
    fn save_kit(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests
        }
        let (name, bytes) = match self.kit_pdf(false) {
            None => return,
            Some(Ok(made)) => made,
            Some(Err(err)) => {
                self.set_error(error::FILE, &format!("{err:#}"));
                return;
            }
        };
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save emergency kit")
            .set_file_name(&name)
            .add_filter("PDF", &["pdf"])
            .save_file()
        else {
            return;
        };
        if let Some(cloud) = files::cloud_folder(&path) {
            self.set_error(error::KIT_CLOUD, cloud);
            return;
        }
        match write_kit_file(&path, &bytes, &self.app().get_kit_pdf_password()) {
            Ok(()) => self.notify(notice::KIT_SAVED, &path.display().to_string()),
            Err(err) => self.set_error(error::FILE, &format!("{err:#}")),
        }
    }

    /// Emergency kit → Save each part apart: one PDF per recovery part, each in a folder of its
    /// own (a USB drive, another computer…), never one a cloud copies away. Part C kept in its
    /// picture is left out when the paper kit leaves it out. Stops at the first cancel.
    fn save_parts_apart(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests
        }
        let app = self.app();
        let parts = [
            app.get_kit_part_a(),
            app.get_kit_part_b(),
            app.get_kit_part_c(),
        ];
        let pdf_password = app.get_kit_pdf_password();
        if parts[0].is_empty() || pdf_password.is_empty() {
            return;
        }
        let leave_c_out = app.get_kit_part_c_pictured() && app.get_kit_leave_c_out();
        let vault_id = app.get_vault_id();
        let short_id: String = vault_id.chars().take(8).collect();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut used: Vec<(char, std::path::PathBuf)> = Vec::new();
        for (label, part) in vault_core::PartLabel::ALL.into_iter().zip(parts.iter()) {
            if leave_c_out && label == vault_core::PartLabel::C {
                continue;
            }
            let letter = label.letter();
            let Some(path) = rfd::FileDialog::new()
                .set_title(format!(
                    "Save recovery part {letter}: a place of its own, apart from the others"
                ))
                .set_file_name(format!("recovery-part-{letter}-{short_id}.pdf"))
                .add_filter("PDF", &["pdf"])
                .save_file()
            else {
                break;
            };
            if let Some(cloud) = files::cloud_folder(&path) {
                self.set_error(error::KIT_CLOUD, cloud);
                return;
            }
            let folder = path.parent().map(std::path::Path::to_path_buf);
            if let Some((other, _)) = used
                .iter()
                .find(|(_, earlier)| Some(earlier) == folder.as_ref())
            {
                self.set_error(error::PARTS_TOGETHER, &other.to_string());
                return;
            }
            let written = kit_pdf::render_part_protected(
                label,
                part,
                &vault_id,
                created_at,
                app.get_kit_filled(),
                &pdf_password,
            )
            .and_then(|bytes| write_kit_file(&path, &bytes, &pdf_password));
            if let Err(err) = written {
                self.set_error(error::FILE, &format!("{err:#}"));
                return;
            }
            used.push((letter, folder.unwrap_or_default()));
        }
        if !used.is_empty() {
            self.set_error(error::NONE, "");
            self.notify(notice::PARTS_SAVED, &used.len().to_string());
        }
    }

    /// Emergency kit → hide part C in a picture of the person's own: chosen, saved as a PNG
    /// with the part in its pixels, and read back before it is called done.
    fn save_part_picture(&self) {
        let app = self.app();
        let Ok(part) = RecoveryPart::parse(&app.get_kit_part_c()) else {
            return;
        };
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests
        }
        let Some(cover_path) = rfd::FileDialog::new()
            .set_title("Choose a picture to hide part C in")
            .add_filter("Pictures", &["png", "jpg", "jpeg", "webp", "bmp", "gif"])
            .pick_file()
        else {
            return;
        };
        let picture = match std::fs::read(&cover_path)
            .map_err(anyhow::Error::from)
            .and_then(|cover| part_picture::make(&part, Some(&cover)))
        {
            Ok(picture) => picture,
            Err(err) => {
                self.set_error(error::COVER, &format!("{err:#}"));
                return;
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let name = part_picture::suggested_name(
            cover_path.file_name().and_then(|name| name.to_str()),
            now,
        );
        let mut dialog = rfd::FileDialog::new()
            .set_title("Save the picture")
            .set_file_name(&name)
            .add_filter("PNG", &["png"]);
        if let Some(folder) = cover_path.parent() {
            dialog = dialog.set_directory(folder);
        }
        let Some(target) = dialog.save_file() else {
            return;
        };
        self.write_part_picture(&target, &picture, &part);
    }

    /// Writes the picture, then reads the file back: done only when it gives the part again.
    fn write_part_picture(&self, target: &std::path::Path, picture: &[u8], part: &RecoveryPart) {
        let checked = std::fs::write(target, picture)
            .map_err(anyhow::Error::from)
            .and_then(|()| part_picture::read(&std::fs::read(target)?))
            .and_then(|back| {
                if &back == part {
                    Ok(())
                } else {
                    anyhow::bail!("the saved file gives back another part")
                }
            });
        match checked {
            Ok(()) => {
                // From now on the printed kit leaves part C out (kit page's switch).
                self.app().set_kit_part_c_pictured(true);
                self.notify(notice::PICTURE_SAVED, &target.display().to_string());
            }
            Err(err) => {
                let _ = std::fs::remove_file(target);
                self.set_error(error::COVER, &format!("{err:#}"));
            }
        }
    }

    /// Recovery screen or unlock screen → read a part from the picture that holds it.
    fn choose_part_picture(&self) {
        if self.state.borrow().runner == Runner::Inline {
            return; // no dialogs in headless tests
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Choose the picture that holds a recovery part")
            .add_filter("PNG", &["png"])
            .pick_file()
        {
            self.read_part_picture(&path);
        }
    }

    /// Puts the part a picture holds into the right field: its own on the recovery screen,
    /// the first empty one on the unlock screen. The field shows only its length.
    fn read_part_picture(&self, path: &std::path::Path) {
        let part = match std::fs::read(path)
            .map_err(anyhow::Error::from)
            .and_then(|file| part_picture::read(&file))
        {
            Ok(part) => part,
            Err(err) => {
                self.set_error(error::PART_PICTURE, &format!("{err:#}"));
                return;
            }
        };
        let index = if self.app().get_screen() == Screen::Recover {
            match part.label() {
                vault_core::PartLabel::A => field::PART_A,
                vault_core::PartLabel::B => field::PART_B,
                vault_core::PartLabel::C => field::PART_C,
            }
        } else if self.state.borrow().secrets[field::PART_A].char_count() == 0 {
            field::PART_A
        } else {
            field::PART_B
        };
        let text = part.to_display_string();
        self.edit_secret(index as i32, |buffer| {
            buffer.set(&text);
        });
        self.set_error(error::NONE, "");
        self.notify(notice::PART_READ, &part.label().letter().to_string());
    }

    fn set_appearance(&self, dark: bool) {
        self.app().global::<Theme>().set_dark(dark);
        self.save_settings();
    }

    /// Settings → Appearance → Language: every screen changes at once.
    fn set_language(&self, choice: i32) {
        let language = crate::i18n::setting_of(choice);
        crate::i18n::apply(&language);
        self.state.borrow_mut().settings.language = language;
        self.save_settings();
    }

    fn save_settings(&self) {
        let app = self.app();
        let settings = device::Settings {
            auto_lock_minutes: u32::try_from(app.get_auto_lock_minutes().clamp(1, 60)).unwrap_or(5),
            lock_with_windows: app.get_lock_with_windows(),
            clipboard_clear_seconds: u32::try_from(app.get_clipboard_seconds().clamp(5, 120))
                .unwrap_or(20),
            dark_theme: app.global::<Theme>().get_dark(),
            website_icons: app.get_website_icons(),
            leak_watch: app.get_leak_watch(),
            update_checks: app.get_update_checks(),
            browser_extension: app.get_browser_extension(),
            close_to_tray: app.get_close_to_tray(),
            start_in_tray: app.get_start_in_tray(),
            browser_locked_fill: app.get_browser_locked_fill(),
            generator: self.state.borrow().settings.generator.clone(),
            language: self.state.borrow().settings.language.clone(),
            browser_saves: app.get_browser_saves(),
            browser_passkeys: app.get_browser_passkeys(),
            browser_warnings: app.get_browser_warnings(),
            browser_fill_notices: app.get_browser_fill_notices(),
            browser_always_asks: app.get_browser_always_asks(),
            backdrop: app.get_backdrop_on(),
        };
        app.global::<Theme>()
            .set_backdrop(i32::from(settings.backdrop));
        let mut device_state = DeviceState::load().unwrap_or_default();
        device_state.settings = settings.clone();
        if let Err(err) = device_state.save() {
            self.set_error(error::FILE, &err.to_string());
        }
        let icons_were_on = self.state.borrow().settings.website_icons;
        let watch_was_on = self.state.borrow().settings.leak_watch;
        let update_checks_were_on = self.state.borrow().settings.update_checks;
        let browser_was_on = self.state.borrow().settings.browser_extension;
        let locked_fill_was_on = self.state.borrow().settings.browser_locked_fill;
        self.state.borrow_mut().settings = settings.clone();
        if browser_was_on != settings.browser_extension {
            self.apply_browser_link(settings.browser_extension);
            // Turned on: the drop box for saving while locked is made now.
            if settings.browser_extension {
                self.open_drop_box();
            }
        }
        if locked_fill_was_on != settings.browser_locked_fill
            || browser_was_on != settings.browser_extension
        {
            if settings.browser_locked_fill && settings.browser_extension {
                self.enable_locked_fill();
            } else {
                self.refresh_locked_fill();
            }
        }
        self.restart_auto_lock();
        if !watch_was_on && settings.leak_watch {
            self.watch_leaks();
        }
        if !update_checks_were_on && settings.update_checks {
            self.update_checks_turned_on();
        }
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
    // Website icons (opt-in; see vault_platform::website_icons for the privacy model)
    // -----------------------------------------------------------------------------------------

    /// What to draw for an item: its website's icon when there is one to show (any kind: a
    /// card's is its bank's site), else its initial on a colour. An `icon_url` chosen in an
    /// earlier version wins over `url` and is shown even when website icons are off, since
    /// the user asked for that icon.
    fn icon_for(&self, kind: ItemKind, url: &str, icon_url: &str, title: &str) -> IconVisual {
        // A line icon chosen for it (`glyph:name`, here or on the phone) isn't a site or a
        // picture to fetch: it is drawn, in its colours.
        let look = view::IconLook::of_icon_url(icon_url);
        let chosen = !icon_url.trim().is_empty() && look.is_none();
        let key = if chosen {
            favicon::IconSource::parse(icon_url).map(|source| source.key())
        } else {
            favicon::host_of(url).map(|host| favicon::cache_key(&host))
        };
        let (r, g, b) = view::tint(kind, key.as_deref().unwrap_or(title));
        let mut visual = IconVisual {
            image: Image::default(),
            has_image: false,
            initial: SharedString::from(view::initial(title)),
            tint: slint::Color::from_rgb_u8(r, g, b),
            glyph: SharedString::new(),
            glyph_color: 0,
            glyph_bg: 0,
        };
        if let Some(look) = look {
            visual.glyph = look.name.as_str().into();
            visual.glyph_color = look.color;
            visual.glyph_bg = look.background;
            return visual;
        }
        let wanted = chosen || self.state.borrow().settings.website_icons;
        if let Some(image) = key
            .filter(|_| wanted)
            .and_then(|key| self.cached_icon(&key))
        {
            visual.image = image;
            visual.has_image = true;
        }
        visual
    }

    /// A downloaded icon from the encrypted cache, as an image (built once per key).
    fn cached_icon(&self, key: &str) -> Option<Image> {
        let mut state = self.state.borrow_mut();
        if let Some(image) = state.icon_images.get(key) {
            return Some(image.clone());
        }
        let pixels = state.icons.get(key)?.to_vec();
        let image = Image::from_rgba8(SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
            &pixels,
            favicon::ICON_SIZE,
            favicon::ICON_SIZE,
        ));
        state.icon_images.insert(key.to_owned(), image.clone());
        Some(image)
    }

    fn apply_detail_icon(&self, item: &ItemData) {
        let url = item.urls.first().map(String::as_str).unwrap_or_default();
        let visual = self.icon_for(item.kind, url, &item.icon_url, &item.title);
        let app = self.app();
        app.set_detail_icon(visual.image);
        app.set_detail_has_icon(visual.has_image);
        app.set_detail_initial(visual.initial);
        app.set_detail_tint(visual.tint);
        app.set_detail_glyph(visual.glyph);
        app.set_detail_glyph_color(visual.glyph_color);
        app.set_detail_glyph_bg(visual.glyph_bg);
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
            if state.fetching_icons || state.session.is_none() {
                return;
            }
            let all_sites = state.settings.website_icons;
            let mut seen = std::collections::BTreeSet::new();
            // Every item's website when website icons are on; the icons chosen per item and
            // per folder always (the user asked for those).
            let folder_links: Vec<String> = state
                .session
                .as_ref()
                .map(|s| {
                    s.vault
                        .folders()
                        .iter()
                        .map(|f| f.icon_url.clone())
                        .collect()
                })
                .unwrap_or_default();
            let hosts: Vec<(String, favicon::IconSource)> = state
                .summaries
                .iter()
                .filter_map(|s| {
                    if !s.icon_url.trim().is_empty() {
                        favicon::IconSource::parse(&s.icon_url)
                    } else if all_sites {
                        favicon::host_of(&s.url).map(favicon::IconSource::Site)
                    } else {
                        None
                    }
                })
                .chain(
                    folder_links
                        .iter()
                        .filter_map(|link| favicon::IconSource::parse(link)),
                )
                .filter_map(|source| {
                    let key = source.key();
                    (state.icons.needs_fetch(&key) && seen.insert(key.clone()))
                        .then_some((key, source))
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
                for (key, source) in hosts {
                    let icon = source.fetch();
                    self.icon_fetched(key, icon);
                }
                self.icons_done();
            }
            Runner::Thread => {
                std::thread::spawn(move || {
                    for (key, source) in hosts {
                        let icon = source.fetch();
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

    fn icon_fetched(&self, key: String, icon: favicon::Fetched) {
        if self.state.borrow().session.is_none() {
            return; // locked meanwhile: drop the result
        }
        let found = icon.shows();
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
        if !self.review_new_password(passwords::place::CHANGE) {
            return;
        }
        let current = Zeroizing::new(
            self.state.borrow().secrets[field::CURRENT]
                .as_str()
                .to_owned(),
        );
        let Some(session) = self.state.borrow_mut().session.take() else {
            return;
        };
        let (path, expected) = {
            let state = self.state.borrow();
            (state.path.clone(), state.file_hash)
        };
        self.run_job(move || {
            let mut session = session;
            if let Err(failure) = verify_current(&path, &current, &session) {
                return JobResult::Failed {
                    code: failure.0,
                    detail: failure.1,
                    session: Some(session),
                };
            }
            if !file_unchanged(&path, expected) {
                return JobResult::Failed {
                    code: error::CHANGED_OUTSIDE,
                    detail: String::new(),
                    session: Some(session),
                };
            }
            let kdf = session.vault.kdf_params().clone();
            // With the secrets open, the item lock's reset copy of its key follows the new
            // master password.
            let was_open = session.vault.secrets_open();
            let _ = session.vault.unlock_secrets_with_master(&current);
            let secret_key = &session.secret_key;
            let keyfile = session.keyfile.as_ref();
            // A failed write leaves the vault as it is on disk (the old password).
            let outcome = session.vault.change_unlock(|vault| {
                let changed = vault.change_password(&new_password, secret_key, keyfile, &kdf);
                if !was_open {
                    vault.lock_secrets();
                }
                changed?;
                let bytes = vault.to_bytes()?;
                storage::write_atomic(&path, &bytes)
            });
            match outcome {
                Ok(()) => {
                    let _ =
                        device::record_revision(&session.vault.id_hex(), session.vault.revision());
                    JobResult::PasswordChanged {
                        session,
                        kdf_seconds: None,
                    }
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
        if matches!(action, KitAction::Export)
            && self.export_format() == ExportFormat::Sealed
            && let Some(code) = self.export_password_problem()
        {
            self.set_error(code, "");
            return;
        }
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
        let (path, expected) = {
            let state = self.state.borrow();
            (state.path.clone(), state.file_hash)
        };
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
                KitAction::RenewKey => renew::renew(&path, expected, &current, session),
                KitAction::Export => {
                    // The master password just typed also opens locked secrets for the
                    // export, when the item lock kept a copy of its key for it.
                    let _ = session.vault.unlock_secrets_with_master(&current);
                    JobResult::ExportVerified { session }
                }
                KitAction::NewParts => {
                    if !file_unchanged(&path, expected) {
                        return JobResult::Failed {
                            code: error::CHANGED_OUTSIDE,
                            detail: String::new(),
                            session: Some(session),
                        };
                    }
                    // A failed write keeps the parts (or Recovery Key) the file still has.
                    let secret_key = &session.secret_key;
                    let outcome = session.vault.change_unlock(|vault| {
                        let parts = RecoveryParts::generate()?;
                        vault.set_recovery_parts(&parts, secret_key)?;
                        let bytes = vault.to_bytes()?;
                        storage::write_atomic(&path, &bytes)?;
                        Ok(parts)
                    });
                    match outcome {
                        Ok(parts) => {
                            let _ = device::record_revision(
                                &session.vault.id_hex(),
                                session.vault.revision(),
                            );
                            JobResult::PartsIssued { session, parts }
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

/// Where a confirmed backup went, how big it is and when: `path (24 KB, 2026-11-21 14:03 UTC)`.
fn backup_summary(path: &std::path::Path, len: usize, unix: i64) -> String {
    let size = if len < 1024 * 1024 {
        format!("{} KB", len.div_ceil(1024))
    } else {
        format!("{:.1} MB", len as f64 / (1024.0 * 1024.0))
    };
    let minutes = unix.rem_euclid(86_400) / 60;
    format!(
        "{} ({size}, {} {:02}:{:02} UTC)",
        path.display(),
        view::date(unix),
        minutes / 60,
        minutes % 60
    )
}

/// Shows the kit's Secret Key and the password of its saved files (CRYPTO.md §3.10), as
/// text the kit page and the onboarding's kit step draw; [`hide_kit_keys`] clears both.
fn show_kit_keys(app: &AppWindow, vault: &vault_core::Vault, secret_key: &SecretKey) {
    app.set_kit_secret_key(SharedString::from(secret_key.to_display_string().as_str()));
    app.set_kit_pdf_password(SharedString::from(
        vault.kit_pdf_password(secret_key).as_str(),
    ));
}

fn hide_kit_keys(app: &AppWindow) {
    app.set_kit_secret_key(SharedString::new());
    app.set_kit_pdf_password(SharedString::new());
}

/// Writes a protected kit file, then reads it back: done only when it opens with the
/// password the kit page shows. A file that doesn't is removed.
fn write_kit_file(path: &std::path::Path, bytes: &[u8], pdf_password: &str) -> anyhow::Result<()> {
    std::fs::write(path, bytes)?;
    let opens = std::fs::read(path)
        .map(Zeroizing::new)
        .is_ok_and(|back| kit_pdf::open_protected(&back, pdf_password).is_some());
    if !opens {
        let _ = std::fs::remove_file(path);
        anyhow::bail!("the saved file doesn't open with the PDF password");
    }
    Ok(())
}

/// Shows the three parts of a kit just issued (the only time they can be shown).
fn show_kit_parts(app: &AppWindow, parts: &RecoveryParts) {
    app.set_kit_part_c_pictured(false);
    app.set_kit_leave_c_out(true);
    let text = |label| SharedString::from(parts.part(label).to_display_string().as_str());
    app.set_kit_part_a(text(vault_core::PartLabel::A));
    app.set_kit_part_b(text(vault_core::PartLabel::B));
    app.set_kit_part_c(text(vault_core::PartLabel::C));
}

fn clear_kit_parts(app: &AppWindow) {
    app.set_kit_part_c_pictured(false);
    app.set_kit_part_a(SharedString::new());
    app.set_kit_part_b(SharedString::new());
    app.set_kit_part_c(SharedString::new());
}

#[derive(Debug, Clone, Copy)]
enum CopyWhat {
    Username,
    Password,
    Totp,
    Field(i32),
    RecoveryCode(i32),
}

/// What follows a passed item lock check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterUnlock {
    /// Show the secrets where they were asked for.
    Show,
    /// Save the item in the editor, which needed the lock open.
    SaveItem,
}

#[derive(Debug, Clone, Copy)]
enum KitAction {
    Show,
    /// A new kit: new recovery parts, the old ones (or the Recovery Key) stop working.
    NewParts,
    /// A new vault key, Secret Key and kit (CRYPTO.md §3.8): older copies of the file, the old
    /// kit and the old Secret Key stop opening it.
    RenewKey,
    /// Unencrypted export (the file is chosen after the password check).
    Export,
}

/// One code on the Authenticator page.
struct AuthEntry {
    id: ItemId,
    title: String,
    subtitle: String,
    /// `None` while the item's secrets are locked.
    totp: Option<Totp>,
    /// The item lock covers this item.
    guarded: bool,
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

/// An export's counts for the dialog (numbers only: no title goes to the window).
fn export_counts(report: &vault_import::ExportReport) -> ExportCounts {
    let count = |n: usize| i32::try_from(n).unwrap_or(i32::MAX);
    let (out, clear) = (&report.left_out, &report.in_clear);
    ExportCounts {
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
    }
}

fn file_hash(bytes: &[u8]) -> [u8; 32] {
    storage::fingerprint(bytes)
}

/// Whether the vault file still holds what this window last read or wrote (`expected`).
/// Background jobs that write the file themselves check it too, so no path overwrites
/// someone else's save (AGENTS.md §4.1, rule 7).
fn file_unchanged(path: &std::path::Path, expected: Option<[u8; 32]>) -> bool {
    match (expected, std::fs::read(path)) {
        (Some(expected), Ok(bytes)) => file_hash(&bytes) == expected,
        // Deleted or unreadable, or never read: writing it again is the safe move.
        _ => true,
    }
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
    let unlock = match &session.keyfile {
        Some(keyfile) => Unlock::PasswordAndKeyfile {
            password,
            secret_key: &session.secret_key,
            keyfile,
        },
        None => Unlock::Password {
            password,
            secret_key: &session.secret_key,
        },
    };
    Vault::open(&bytes, unlock).map(drop).map_err(|e| match e {
        CoreError::DecryptionFailed => (error::WRONG_CURRENT, String::new()),
        // Opened with Windows Hello and the keyfile isn't where this device remembers it.
        CoreError::KeyfileRequired => (error::KEYFILE_NEEDED, String::new()),
        other => (error::OTHER, other.to_string()),
    })
}
