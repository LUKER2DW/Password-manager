//! Per-device state: rollback protection and local preferences (`<app dir>/state.json`).
//! Nothing secret is stored here.

use std::{collections::BTreeMap, fs};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use vault_core::{
    attempts::UnlockAttempts,
    storage,
    sync::{DeviceId, SeenRevisions},
};

use crate::paths;

pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 5;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DeviceState {
    #[serde(default)]
    vaults: BTreeMap<String, VaultState>,
    #[serde(default)]
    pub settings: Settings,
    /// Vault files opened on this device, most recent first (paths only).
    #[serde(default)]
    recent_vaults: Vec<String>,
    /// This device's id for sync (hex), made the first time a vault is synced here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

/// How many vault files the device remembers.
pub const MAX_RECENT_VAULTS: usize = 8;

#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultState {
    highest_revision: u64,
    /// Where the vault's keyfile was last found (a location, never the key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keyfile_path: Option<String>,
    /// Sync: the folder chosen for this vault on this device (written by earlier versions;
    /// read as `sync_to` = a folder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync_folder: Option<String>,
    /// Sync: where this vault syncs on this device, if anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync_to: Option<SyncTo>,
    /// Sync: a backup place, synced too, through which the vault keeps syncing while the
    /// main one can't be reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync_backup: Option<SyncTo>,
    /// Sync: the vault revision whose copy was last put on the backup place.
    #[serde(default)]
    sync_published_backup: u64,
    /// Sync: the copies already seen from each other device (rollback and fork checks).
    #[serde(default, skip_serializing_if = "is_empty_seen")]
    sync_seen: SeenRevisions,
    /// Sync: when the last round finished (Unix seconds), and the revision last published.
    #[serde(default)]
    sync_at: i64,
    #[serde(default)]
    sync_published: u64,
    /// Sync: this device's id for this vault when it isn't the device's own id: it joined the
    /// vault again as a new device (after it was removed, or coming from another place).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    /// Sync: the id a join under way uses, kept until it succeeds so that a join tried again
    /// goes on with the key it already has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    joining_id: Option<String>,
    /// Sync: the ids this device synced this vault as before. They are this device's own old
    /// entries in the vault's device list, taken out at the next round.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retired_ids: Vec<String>,
    /// What opened this vault before this device renewed its key or took one renewed
    /// elsewhere (`VaultInfo::unlock_id`, hex): a copy that still carries one of these, and
    /// that this device can't open, was written before by a device yet to take the new key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retired_unlocks: Vec<String>,
    /// The newest version of the apps (the desktop app, the `vault` command: released together,
    /// at one version) that opened this vault on this device, `x.y.z`. Never lowered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    highest_version: Option<String>,
    /// The failed unlocks of this vault here since its last right one (a count and when:
    /// nothing secret), so that a restart doesn't clear the wait they impose.
    #[serde(default, skip_serializing_if = "UnlockAttempts::is_clear")]
    unlock_attempts: UnlockAttempts,
    /// The icon chosen for this vault on this computer (a line icon's name, as a folder's);
    /// none shows the vault name's initial. Not in the vault: each device picks its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    icon: Option<String>,
    /// The title bar's alerts marked as read, by kind: how many there were then, and when.
    /// Only counts (how many weak passwords, a sync that failed), never which items.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    alerts_read: BTreeMap<String, AlertRead>,
}

/// An alert marked as read: how many there were, and when (Unix seconds).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRead {
    pub count: u32,
    pub at: i64,
}

/// How long an alert marked as read stays out of sight while it isn't dealt with.
pub const ALERT_QUIET_SECONDS: i64 = 7 * 24 * 60 * 60;

impl AlertRead {
    /// Whether an alert of `count` is shown at `now`, when this one was its last reading: there
    /// are more of it than were read, or a week has passed.
    pub fn shows(read: Option<Self>, count: u32, now: i64) -> bool {
        count > 0
            && match read {
                None => true,
                Some(read) => {
                    count > read.count || now.saturating_sub(read.at) >= ALERT_QUIET_SECONDS
                }
            }
    }
}

/// How many of a vault's earlier ids on this device are remembered.
const MAX_RETIRED_IDS: usize = 4;

fn is_empty_seen(seen: &SeenRevisions) -> bool {
    *seen == SeenRevisions::default()
}

/// Where a vault syncs. Nothing secret: the WebDAV password and the server key are in the
/// OS credential store (`secret_store`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SyncTo {
    /// A folder another program keeps the same everywhere.
    Folder { path: std::path::PathBuf },
    /// Our own `vault-server`, at this address.
    Server { url: String },
    /// A WebDAV collection (Nextcloud, a NAS), with this user name.
    Webdav { url: String, user: String },
}

impl SyncTo {
    /// What to show the person: the folder or the address.
    /// What to show for it: the folder, or the address without a certificate pin (a long hex
    /// string that means nothing to read and is kept for the connection only).
    pub fn describe(&self) -> String {
        match self {
            Self::Folder { path } => path.display().to_string(),
            Self::Server { url } | Self::Webdav { url, .. } => {
                let (address, pinned) = crate::sync::split_pin(url);
                if pinned.is_some() {
                    format!("{address} (pinned certificate)")
                } else {
                    address.to_owned()
                }
            }
        }
    }
}

/// What this device keeps about syncing one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPlace {
    pub to: SyncTo,
    /// A second place synced too (a backup server), if any.
    pub backup: Option<SyncTo>,
    pub seen: SeenRevisions,
    /// Unix seconds of the last finished round; 0 = never.
    pub at: i64,
    /// The vault revision whose copy was last put in the folder.
    pub published: u64,
    /// The same, for the backup place.
    pub published_backup: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Lock after this many minutes without interaction.
    pub auto_lock_minutes: u32,
    /// Lock when Windows locks the session, switches user, signs out, sleeps or hibernates.
    /// On by default.
    pub lock_with_windows: bool,
    /// Seconds before a copied secret is cleared from the clipboard.
    pub clipboard_clear_seconds: u32,
    /// Desktop app appearance; dark is the default.
    pub dark_theme: bool,
    /// Download website icons (contacts each saved site once). Off by default for privacy.
    pub website_icons: bool,
    /// Let the browser extension ask this app for logins. Off by default.
    pub browser_extension: bool,
    /// Answer as the SSH agent (`ssh_agent.rs`): programs sign with the vault's SSH keys, each
    /// signature approved in the app. Off by default.
    pub ssh_agent: bool,
    /// Closing the window keeps the app running in the notification area. On by default.
    pub close_to_tray: bool,
    /// Started by Windows at sign-in, the app waits in the notification area instead of
    /// opening its window. On by default. (Whether Windows starts it is kept by Windows: see
    /// `autostart.rs`.)
    pub start_in_tray: bool,
    /// The browser extension can fill logins while the vault is locked, with Windows Hello
    /// for each one. On by default; it needs the item lock's Windows Hello.
    pub browser_locked_fill: bool,
    /// The generator's last options.
    pub generator: GeneratorPrefs,
    /// The app's language (`pt_BR`); empty follows the system.
    pub language: String,
    /// The leak watch: every login's password checked once a day while the vault is open (it
    /// uses the network on its own, so it is off until turned on).
    pub leak_watch: bool,
    /// The browser extension may save logins typed into pages (new ones, changed passwords,
    /// and those saved while the vault is locked). On by default.
    pub browser_saves: bool,
    /// The browser extension may make and use the vault's passkeys. On by default; off, the
    /// browser's own passkeys are used.
    pub browser_passkeys: bool,
    /// The browser extension warns when the password of a login is pasted or sent on a page
    /// that isn't that login's site, and when a page only looks like a site of the vault (the
    /// app compares, from the vault's own sites). On by default.
    pub browser_warnings: bool,
    /// A notice in the app for every login the extension fills. On by default.
    pub browser_fill_notices: bool,
    /// Every password, one-time code or passkey the browser extension uses asks for Windows
    /// Hello or the item lock's PIN or password first, in that very request, not only the
    /// logins behind the item lock. On by default.
    pub browser_always_asks: bool,
    /// The extension's window lists every login of the vault, not only the open site's (S18:
    /// a stolen pairing then learns every login's name and site). Off by default.
    pub browser_whole_vault: bool,
    /// The drawn texture behind the open vault. On by default.
    pub backdrop: bool,
    /// Look for a newer version on GitHub by itself, every hour while the app runs (one
    /// anonymous request; nothing about the vault). On by default, so a fix reaches every
    /// computer soon after it is released.
    pub update_checks: bool,
    /// A newer version found is downloaded, checked against the release's signed manifest and
    /// put in this program's place by itself (`self_update`); the person then chooses when to
    /// restart. On by default. Off, it is only told, with a button that does the same.
    pub update_install: bool,
    /// The open vault's index (categories and folders, on the left) is hidden.
    pub sidebar_hidden: bool,
    /// The unlock screen offers to type the master password on a secure desktop of its own
    /// (`secure_desktop.rs`): other programs' keyboard hooks and screen capture don't reach
    /// it. Off by default: screen readers and on-screen keyboards don't either.
    pub secure_desktop: bool,
    /// What the browser extension may do on particular sites (Settings → Browser extension,
    /// and the extension's window for the site in front). Kept on this device only, in this
    /// file: the vault's format has no place for them yet. Not secret, but it names the sites
    /// given a rule.
    pub site_rules: Vec<SiteRule>,
    /// The first unlock of each vault after the app starts takes the master password; Windows
    /// Hello opens it only after that. Off by default.
    pub master_at_start: bool,
    /// Hiding the window in the notification area locks the vault too. Off by default.
    pub lock_on_tray: bool,
    /// A password or hidden field shown on screen hides again when another window takes the
    /// focus. On by default.
    pub conceal_on_blur: bool,
    /// Windows Hello opens the vault for this many days before the master password is asked
    /// once (1 to `quick_unlock::MAX_PASSWORD_INTERVAL_DAYS`).
    pub hello_master_days: u32,
    /// The settings Password health's review was told to stop suggesting (its codes).
    pub review_ignored: Vec<u8>,
    /// The shortcut from any program that opens the vault's search (0 off, then
    /// `hotkeys::Combo::QUICK` from 1; Ctrl+Shift+Space by default), and the one that locks it
    /// (0 off, the default, then `hotkeys::Combo::LOCK`).
    pub quick_hotkey: u8,
    pub lock_hotkey: u8,
    /// The `vault` command may ask the open app for secrets (`vault run`, `vault inject`,
    /// `vault git-credential`), each use approved in the app. Off by default.
    pub cli_link: bool,
}

/// What the browser extension may do on one site: the host and every host under it
/// (`example.com` covers `www.example.com` and `shop.example.com`). Every rule is off by
/// default; a site with none of them on is not kept.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteRule {
    /// The host, lowercase, without `www.` (`example.com`, `intranet.example:8443`).
    pub host: String,
    /// Never offer to save a login typed there, nor to update its password.
    pub never_save: bool,
    /// Never show the card under its fields (the extension's window still lists its logins).
    pub no_card: bool,
    /// Never fill there: no login, one-time code or card is typed into its pages.
    pub never_fill: bool,
    /// The vault's passkeys are not offered there; the browser's own handle the site.
    pub no_passkeys: bool,
    /// Hosts of other sites whose frames in this site's pages may get a card (a payment
    /// provider's fields embedded in a shop's checkout). Empty: only the site's own fields.
    pub card_frames: Vec<String>,
}

impl SiteRule {
    /// Whether nothing is set: the rule is dropped rather than kept.
    pub fn is_empty(&self) -> bool {
        !(self.never_save || self.no_card || self.never_fill || self.no_passkeys)
            && self.card_frames.is_empty()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            lock_with_windows: true,
            clipboard_clear_seconds: 20,
            dark_theme: true,
            website_icons: false,
            browser_extension: false,
            ssh_agent: false,
            close_to_tray: true,
            start_in_tray: true,
            browser_locked_fill: true,
            generator: GeneratorPrefs::default(),
            language: String::new(),
            leak_watch: false,
            browser_saves: true,
            browser_passkeys: true,
            browser_warnings: true,
            browser_fill_notices: true,
            browser_always_asks: true,
            browser_whole_vault: false,
            backdrop: true,
            update_checks: true,
            update_install: true,
            sidebar_hidden: false,
            secure_desktop: false,
            site_rules: Vec::new(),
            master_at_start: false,
            lock_on_tray: false,
            conceal_on_blur: true,
            hello_master_days: 14,
            review_ignored: Vec::new(),
            quick_hotkey: 1,
            lock_hotkey: 0,
            cli_link: false,
        }
    }
}

/// How the generator was last set up on this device. Not secret: no generated value is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneratorPrefs {
    /// 0 random characters, 1 words.
    pub mode: u8,
    pub length: u32,
    pub words: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub extended_ascii: bool,
    pub avoid_ambiguous: bool,
    pub also_use: String,
    pub never_use: String,
    /// 0 lower, 1 UPPER, 2 Title, 3 mixed.
    pub word_case: u8,
    pub add_digit: bool,
    pub separator: String,
    /// File name in the word list folder; empty = the bundled EFF list.
    pub wordlist: String,
    /// At least this many of each kind (Advanced options; 0 = just one, as always).
    pub min_lowercase: u32,
    pub min_uppercase: u32,
    pub min_digits: u32,
    pub min_symbols: u32,
    /// The editor's username generator: 0 two words, 1 the person's email with a tag after a
    /// `+`, 2 a random name at the person's own domain.
    pub username_kind: u8,
    /// The email address tagged (kind 1) and the domain (kind 2), as typed here.
    pub username_email: String,
    pub username_domain: String,
    /// Two words: four digits after them.
    pub username_number: bool,
}

impl Default for GeneratorPrefs {
    fn default() -> Self {
        Self {
            mode: 0,
            length: 24,
            words: 6,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            extended_ascii: false,
            avoid_ambiguous: false,
            also_use: String::new(),
            never_use: String::new(),
            word_case: 0,
            add_digit: false,
            separator: "-".into(),
            wordlist: String::new(),
            min_lowercase: 0,
            min_uppercase: 0,
            min_digits: 0,
            min_symbols: 0,
            username_kind: 0,
            username_email: String::new(),
            username_domain: String::new(),
            username_number: true,
        }
    }
}

/// What [`DeviceState::load_or_set_aside`] found in the state file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFile {
    /// Read as it was, or there was none yet.
    Read,
    /// It couldn't be read: moved to `state.json.unreadable` (kept), and a fresh state started.
    SetAside,
    /// It couldn't be read nor moved: a fresh state in memory only. Don't save it, or it
    /// would replace the file.
    Unreadable,
}

/// Outcome of comparing an opened vault with what this device has seen before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackStatus {
    Ok,
    /// The file is older than a revision this device already saw: it may have been replaced
    /// with an old copy.
    Older {
        revision: u64,
        highest_seen: u64,
    },
}

/// What [`DeviceState::note_version`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionStatus {
    Ok,
    /// A newer version of the apps opened this vault on this device before: the one running
    /// may be an old copy put back in place of the newest, with a fault fixed since. The vault
    /// still opens; the person is told.
    Older {
        running: String,
        highest: String,
    },
}

impl DeviceState {
    /// Notes that version `running` of the apps (`x.y.z`, the program's own) opened vault
    /// `vault_id`, and says whether a newer one did before. The version kept only ever goes
    /// up: an older one leaves it as it is, and one that isn't `x.y.z` is not kept.
    pub fn note_version(&mut self, vault_id: &str, running: &str) -> VersionStatus {
        let Some(now) = vault_sync_wire::parse_version(running) else {
            return VersionStatus::Ok;
        };
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        match entry.highest_version.as_deref() {
            Some(highest)
                if vault_sync_wire::parse_version(highest).is_some_and(|seen| seen > now) =>
            {
                VersionStatus::Older {
                    running: running.to_owned(),
                    highest: highest.to_owned(),
                }
            }
            _ => {
                entry.highest_version = Some(running.to_owned());
                VersionStatus::Ok
            }
        }
    }

    /// Vault files opened on this device, most recent first.
    pub fn recent_vaults(&self) -> Vec<std::path::PathBuf> {
        self.recent_vaults
            .iter()
            .map(std::path::PathBuf::from)
            .collect()
    }

    /// Puts path first in the recent list (moving it if it was already there).
    pub fn remember_vault(&mut self, path: &std::path::Path) {
        let path = path.to_string_lossy().into_owned();
        self.recent_vaults
            .retain(|p| !p.eq_ignore_ascii_case(&path));
        self.recent_vaults.insert(0, path);
        self.recent_vaults.truncate(MAX_RECENT_VAULTS);
    }

    /// Removes path from the recent list (the file itself is untouched).
    pub fn forget_vault(&mut self, path: &std::path::Path) {
        let path = path.to_string_lossy();
        self.recent_vaults
            .retain(|p| !p.eq_ignore_ascii_case(&path));
    }

    pub fn load() -> Result<Self> {
        let path = paths::app_dir()?.join("state.json");
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Like [`DeviceState::load`], for the apps: a state file that can't be read is never
    /// written over (it holds the highest revision seen of every vault) and never locks the
    /// person out. It is moved to `state.json.unreadable`, kept, and a fresh state starts;
    /// [`StateFile`] says which happened, so the app can tell the person that older copies
    /// of their vaults aren't caught until they are opened again here.
    pub fn load_or_set_aside() -> (Self, StateFile) {
        match paths::app_dir() {
            Ok(dir) => Self::load_or_set_aside_at(&dir.join("state.json")),
            Err(_) => (Self::default(), StateFile::Unreadable),
        }
    }

    fn load_or_set_aside_at(path: &std::path::Path) -> (Self, StateFile) {
        match fs::read(path) {
            Ok(bytes) => {
                if let Ok(state) = serde_json::from_slice(&bytes) {
                    return (state, StateFile::Read);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return (Self::default(), StateFile::Read);
            }
            Err(_) => {}
        }
        if fs::rename(path, path.with_file_name("state.json.unreadable")).is_ok() {
            (Self::default(), StateFile::SetAside)
        } else {
            // Still there (held by another program, say): left alone, and not saved over.
            (Self::default(), StateFile::Unreadable)
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = paths::app_dir()?.join("state.json");
        fs::create_dir_all(path.parent().expect("state path has a parent"))?;
        storage::write_atomic(&path, &serde_json::to_vec_pretty(self)?).map_err(|e| anyhow!(e))
    }

    pub fn check_rollback(&self, vault_id: &str, revision: u64) -> RollbackStatus {
        let highest_seen = self.vaults.get(vault_id).map_or(0, |v| v.highest_revision);
        if revision < highest_seen {
            RollbackStatus::Older {
                revision,
                highest_seen,
            }
        } else {
            RollbackStatus::Ok
        }
    }

    /// Remembers that this device stopped using what `unlock_id` names for vault `vault_id`:
    /// it renewed the vault key, or took one renewed on another device. The last few are kept.
    pub fn retire_unlock(&mut self, vault_id: &str, unlock_id: &[u8; 16]) {
        const KEEP: usize = 16;
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        let id = hex(unlock_id);
        if !entry.retired_unlocks.contains(&id) {
            entry.retired_unlocks.push(id);
        }
        let extra = entry.retired_unlocks.len().saturating_sub(KEEP);
        entry.retired_unlocks.drain(..extra);
    }

    /// Whether this device retired what `unlock_id` names for vault `vault_id`
    /// ([`DeviceState::retire_unlock`]).
    pub fn unlock_retired(&self, vault_id: &str, unlock_id: &[u8; 16]) -> bool {
        let id = hex(unlock_id);
        self.vaults
            .get(vault_id)
            .is_some_and(|entry| entry.retired_unlocks.contains(&id))
    }

    pub fn record_revision(&mut self, vault_id: &str, revision: u64) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        entry.highest_revision = entry.highest_revision.max(revision);
    }

    /// The failed unlocks of vault `vault_id` on this device since its last right one.
    pub fn unlock_attempts(&self, vault_id: &str) -> UnlockAttempts {
        self.vaults
            .get(vault_id)
            .map(|v| v.unlock_attempts)
            .unwrap_or_default()
    }

    /// One more failed unlock of vault `vault_id`, at `clock`; returns the count as it is now.
    pub fn record_failed_unlock(&mut self, vault_id: &str, clock: Clock) -> UnlockAttempts {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        entry
            .unlock_attempts
            .record_failure(clock.now, clock.uptime);
        entry.unlock_attempts
    }

    /// Seconds before the next unlock of vault `vault_id` may be tried (0: now), and whether
    /// the state changed (a clock set back starts the wait again from now): save it then.
    pub fn unlock_wait(&mut self, vault_id: &str, clock: Clock) -> (i64, bool) {
        let Some(entry) = self.vaults.get_mut(vault_id) else {
            return (0, false);
        };
        let changed = entry.unlock_attempts.settle_clock(clock.now);
        (
            entry.unlock_attempts.wait_left(clock.now, clock.uptime),
            changed,
        )
    }

    /// A right unlock of vault `vault_id`: the failures before it are forgotten, and returned
    /// to be told once.
    pub fn take_unlock_attempts(&mut self, vault_id: &str) -> UnlockAttempts {
        self.vaults
            .get_mut(vault_id)
            .map(|v| std::mem::take(&mut v.unlock_attempts))
            .unwrap_or_default()
    }

    /// The alerts of vault `vault_id` marked as read here, by kind.
    pub fn alerts_read(&self, vault_id: &str) -> BTreeMap<String, AlertRead> {
        self.vaults
            .get(vault_id)
            .map(|v| v.alerts_read.clone())
            .unwrap_or_default()
    }

    /// Marks the alerts `counts` (kind, how many now) of vault `vault_id` read at `now`.
    pub fn mark_alerts_read(&mut self, vault_id: &str, counts: &[(&str, u32)], now: i64) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        for (kind, count) in counts {
            if *count > 0 {
                entry.alerts_read.insert(
                    (*kind).to_owned(),
                    AlertRead {
                        count: *count,
                        at: now,
                    },
                );
            }
        }
    }

    /// Follows the alerts of vault `vault_id` down as they are dealt with: a kind now at fewer
    /// than were read keeps the lower count (so one more shows at once), and one at none is
    /// forgotten. Returns whether anything changed (save it then).
    pub fn settle_alerts(&mut self, vault_id: &str, counts: &[(&str, u32)]) -> bool {
        let Some(entry) = self.vaults.get_mut(vault_id) else {
            return false;
        };
        let mut changed = false;
        for (kind, count) in counts {
            let Some(read) = entry.alerts_read.get_mut(*kind) else {
                continue;
            };
            if *count == 0 {
                entry.alerts_read.remove(*kind);
                changed = true;
            } else if *count < read.count {
                read.count = *count;
                changed = true;
            }
        }
        changed
    }

    /// The icon chosen for vault `vault_id` on this device ("" for its initial).
    pub fn vault_icon(&self, vault_id: &str) -> String {
        self.vaults
            .get(vault_id)
            .and_then(|v| v.icon.clone())
            .unwrap_or_default()
    }

    /// Chooses the icon of vault `vault_id` on this device ("" for its initial). Only a line
    /// icon's name is kept: letters, digits and dashes, short.
    pub fn set_vault_icon(&mut self, vault_id: &str, icon: &str) {
        let fits = icon.len() <= 32
            && icon
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        let icon = (fits && !icon.is_empty()).then(|| icon.to_owned());
        if icon.is_none() && !self.vaults.contains_key(vault_id) {
            return;
        }
        self.vaults.entry(vault_id.to_owned()).or_default().icon = icon;
    }

    /// Where this device last found the vault's keyfile.
    pub fn keyfile_path(&self, vault_id: &str) -> Option<std::path::PathBuf> {
        self.vaults
            .get(vault_id)?
            .keyfile_path
            .as_deref()
            .map(std::path::PathBuf::from)
    }

    pub fn set_keyfile_path(&mut self, vault_id: &str, path: Option<&std::path::Path>) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        entry.keyfile_path = path.map(|p| p.to_string_lossy().into_owned());
    }

    /// Whether this device already has a sync id.
    pub fn has_device_id(&self) -> bool {
        self.device_id
            .as_deref()
            .and_then(DeviceId::from_hex)
            .is_some()
    }

    /// This device's sync id, made (and kept, once saved) the first time it is asked for.
    pub fn device_id(&mut self) -> vault_core::Result<DeviceId> {
        if let Some(id) = self.device_id.as_deref().and_then(DeviceId::from_hex) {
            return Ok(id);
        }
        let id = DeviceId::generate()?;
        self.device_id = Some(id.to_hex());
        Ok(id)
    }

    /// This device's sync id for vault `vault_id`: its own id for that vault when it joined it
    /// again as a new device, else the device's id ([`DeviceState::device_id`]).
    pub fn device_id_for(&mut self, vault_id: &str) -> vault_core::Result<DeviceId> {
        let own = self
            .vaults
            .get(vault_id)
            .and_then(|v| v.device_id.as_deref())
            .and_then(DeviceId::from_hex);
        match own {
            Some(id) => Ok(id),
            None => self.device_id(),
        }
    }

    /// The id a join of vault `vault_id` enrolls when this device isn't already enrolled
    /// there: a new one, made once and kept until a join succeeds. Save before joining.
    pub fn joining_id_for(&mut self, vault_id: &str) -> vault_core::Result<DeviceId> {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        if let Some(id) = entry.joining_id.as_deref().and_then(DeviceId::from_hex) {
            return Ok(id);
        }
        let id = DeviceId::generate()?;
        entry.joining_id = Some(id.to_hex());
        Ok(id)
    }

    /// Vault `vault_id` syncs as `id` on this device from now on (a join succeeded with it).
    /// Returns the id it synced as before when that was another one: forget its keys. That
    /// id is retired: it leaves the vault's device list at the next round
    /// ([`DeviceState::retired_ids`]).
    pub fn adopt_device_id(
        &mut self,
        vault_id: &str,
        id: DeviceId,
    ) -> vault_core::Result<Option<DeviceId>> {
        let before = self.device_id_for(vault_id)?;
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        entry.joining_id = None;
        if before == id {
            return Ok(None);
        }
        entry.device_id = Some(id.to_hex());
        let (old, new) = (before.to_hex(), id.to_hex());
        entry.retired_ids.retain(|r| *r != old && *r != new);
        entry.retired_ids.push(old);
        let excess = entry.retired_ids.len().saturating_sub(MAX_RETIRED_IDS);
        entry.retired_ids.drain(..excess);
        Ok(Some(before))
    }

    /// The ids this device synced vault `vault_id` as before (see
    /// [`DeviceState::adopt_device_id`]).
    pub fn retired_ids(&self, vault_id: &str) -> Vec<DeviceId> {
        self.vaults.get(vault_id).map_or_else(Vec::new, |v| {
            v.retired_ids
                .iter()
                .filter_map(|id| DeviceId::from_hex(id))
                .collect()
        })
    }

    /// This device was removed from vault `vault_id` on another device: it stops syncing it,
    /// and takes a new id for it, so that it can join again as a new device (removing a device
    /// doesn't bar it for good). Returns the id it was removed as, to forget its keys.
    pub fn removed_from(&mut self, vault_id: &str) -> vault_core::Result<DeviceId> {
        let removed = self.device_id_for(vault_id)?;
        let fresh = DeviceId::generate()?;
        self.adopt_device_id(vault_id, fresh)?;
        self.set_sync_to(vault_id, None);
        Ok(removed)
    }

    /// Where and how vault `vault_id` syncs on this device; `None` when it doesn't.
    pub fn sync_place(&self, vault_id: &str) -> Option<SyncPlace> {
        let state = self.vaults.get(vault_id)?;
        let to = state.sync_to.clone().or_else(|| {
            state.sync_folder.as_deref().map(|path| SyncTo::Folder {
                path: std::path::PathBuf::from(path),
            })
        })?;
        Some(SyncPlace {
            to,
            backup: state.sync_backup.clone(),
            seen: state.sync_seen.clone(),
            at: state.sync_at,
            published: state.sync_published,
            published_backup: state.sync_published_backup,
        })
    }

    /// Starts syncing vault `vault_id` through `folder`, or (with `None`) stops.
    pub fn set_sync_folder(&mut self, vault_id: &str, folder: Option<&std::path::Path>) {
        self.set_sync_to(
            vault_id,
            folder.map(|path| SyncTo::Folder {
                path: path.to_owned(),
            }),
        );
    }

    /// Starts syncing vault `vault_id` through `to`, or (with `None`) stops. Stopping forgets
    /// what was seen: syncing again later starts afresh. Moving to another place keeps it, so
    /// an older copy put back is still refused there.
    pub fn set_sync_to(&mut self, vault_id: &str, to: Option<SyncTo>) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        entry.sync_folder = None;
        let stopped = to.is_none();
        if entry.sync_to != to {
            entry.sync_published = 0;
        }
        entry.sync_to = to;
        if stopped {
            entry.sync_seen = SeenRevisions::default();
            entry.sync_at = 0;
            entry.sync_published = 0;
            entry.sync_backup = None;
            entry.sync_published_backup = 0;
        }
    }

    /// Adds (or with `None` removes) a backup place for vault `vault_id`: synced every round
    /// too, so the vault keeps syncing while the main place can't be reached.
    pub fn set_sync_backup(&mut self, vault_id: &str, backup: Option<SyncTo>) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        if entry.sync_backup != backup {
            entry.sync_published_backup = 0;
        }
        entry.sync_backup = backup;
    }

    /// Records that `revision`'s copy is on the place in `role`.
    pub fn record_published(&mut self, vault_id: &str, role: crate::sync::Role, revision: u64) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        let published = match role {
            crate::sync::Role::Main => &mut entry.sync_published,
            crate::sync::Role::Backup => &mut entry.sync_published_backup,
        };
        *published = (*published).max(revision);
    }

    /// Records a finished round.
    pub fn record_sync(&mut self, vault_id: &str, seen: &SeenRevisions, at: i64, published: u64) {
        let entry = self.vaults.entry(vault_id.to_owned()).or_default();
        entry.sync_seen = seen.clone();
        entry.sync_at = at;
        entry.sync_published = entry.sync_published.max(published);
    }
}

/// Loads, records and saves in one step.
pub fn record_revision(vault_id: &str, revision: u64) -> Result<()> {
    let mut state = DeviceState::load()?;
    state.record_revision(vault_id, revision);
    state.save()
}

/// The two clocks unlock attempts are timed by (`vault_core::attempts`): the wall clock, and
/// the device's time since it started, which nobody sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// Unix seconds.
    pub now: i64,
    /// Seconds since the device started, where the system tells it (Windows, Android).
    pub uptime: Option<i64>,
}

impl Clock {
    /// Both clocks as they read now.
    pub fn read() -> Self {
        Self {
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
            uptime: uptime_seconds(),
        }
    }
}

/// Seconds since the device started, sleep included; no one can set it. `None` where the
/// system doesn't say.
pub fn uptime_seconds() -> Option<i64> {
    #[cfg(windows)]
    {
        // SAFETY: GetTickCount64 takes nothing and only returns a number.
        #[allow(unsafe_code)]
        let millis = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
        i64::try_from(millis / 1000).ok()
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `time` is a valid timespec this call writes into; CLOCK_BOOTTIME (time since
        // the device started, suspend included) exists on every kernel Android supports.
        #[allow(unsafe_code)]
        let read = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) };
        (read == 0).then(|| i64::from(time.tv_sec))
    }
    #[cfg(not(any(windows, target_os = "android", target_os = "linux")))]
    {
        None
    }
}

/// Unlock attempts through the state file, for the apps: each call reads it, changes it and
/// writes it back (unless it can't be read: nothing is written over it then).
pub mod unlock_attempts {
    use vault_core::attempts::UnlockAttempts;

    use super::{Clock, DeviceState, StateFile};

    fn with_state<T>(change: impl FnOnce(&mut DeviceState) -> (T, bool)) -> T {
        let (mut state, file) = DeviceState::load_or_set_aside();
        let (out, changed) = change(&mut state);
        if changed && file != StateFile::Unreadable {
            let _ = state.save();
        }
        out
    }

    /// One more failed unlock of vault `vault_id`; returns the count as it is now.
    pub fn failed(vault_id: &str, clock: Clock) -> UnlockAttempts {
        with_state(|state| (state.record_failed_unlock(vault_id, clock), true))
    }

    /// Seconds before the next unlock of vault `vault_id` may be tried (0: now).
    pub fn wait(vault_id: &str, clock: Clock) -> i64 {
        with_state(|state| state.unlock_wait(vault_id, clock))
    }

    /// A right unlock of vault `vault_id`: returns the failures since the last one (to be told
    /// once), forgotten from now on.
    pub fn succeeded(vault_id: &str) -> UnlockAttempts {
        with_state(|state| {
            let taken = state.take_unlock_attempts(vault_id);
            (taken, !taken.is_clear())
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreadable_state_file_is_set_aside_not_written_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert_eq!(DeviceState::load_or_set_aside_at(&path).1, StateFile::Read);

        let mut state = DeviceState::default();
        state.record_revision("v", 7);
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        let (read, file) = DeviceState::load_or_set_aside_at(&path);
        assert_eq!(file, StateFile::Read);
        assert_eq!(
            read.check_rollback("v", 6),
            RollbackStatus::Older {
                revision: 6,
                highest_seen: 7
            }
        );

        fs::write(&path, b"{ damaged").unwrap();
        let (fresh, file) = DeviceState::load_or_set_aside_at(&path);
        assert_eq!(file, StateFile::SetAside);
        assert_eq!(fresh.check_rollback("v", 0), RollbackStatus::Ok);
        assert!(!path.exists());
        assert_eq!(
            fs::read(dir.path().join("state.json.unreadable")).unwrap(),
            b"{ damaged"
        );
    }

    #[test]
    fn the_newest_version_that_opened_a_vault_is_kept_and_never_lowered() {
        let mut state = DeviceState::default();
        assert_eq!(state.note_version("v1", "0.4.7"), VersionStatus::Ok);
        assert_eq!(state.note_version("v1", "0.4.10"), VersionStatus::Ok);
        // An older one is told of, every time, and leaves the newest as it was.
        for _ in 0..2 {
            assert_eq!(
                state.note_version("v1", "0.4.9"),
                VersionStatus::Older {
                    running: "0.4.9".into(),
                    highest: "0.4.10".into()
                }
            );
        }
        assert_eq!(state.note_version("v1", "0.4.10"), VersionStatus::Ok);
        // Each vault on its own; a version that isn't x.y.z is neither told of nor kept.
        assert_eq!(state.note_version("v2", "0.4.1"), VersionStatus::Ok);
        assert_eq!(state.note_version("v1", "dev"), VersionStatus::Ok);
        assert!(matches!(
            state.note_version("v1", "0.4.8"),
            VersionStatus::Older { .. }
        ));
        // Kept in the state file; files written before it load without it.
        let bytes = serde_json::to_vec(&state).unwrap();
        let mut again: DeviceState = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(
            again.note_version("v1", "0.4.9"),
            VersionStatus::Older { .. }
        ));
        let old: DeviceState =
            serde_json::from_str(r#"{"vaults":{"v1":{"highest_revision":3}}}"#).unwrap();
        assert_eq!(old.vaults["v1"].highest_version, None);
    }

    #[test]
    fn rollback_detection() {
        let mut state = DeviceState::default();
        assert_eq!(state.check_rollback("v", 1), RollbackStatus::Ok);
        state.record_revision("v", 5);
        state.record_revision("v", 3); // never goes down
        assert_eq!(state.check_rollback("v", 5), RollbackStatus::Ok);
        assert_eq!(
            state.check_rollback("v", 4),
            RollbackStatus::Older {
                revision: 4,
                highest_seen: 5
            }
        );
        assert_eq!(state.check_rollback("other", 0), RollbackStatus::Ok);
    }

    #[test]
    fn alerts_read_come_back_after_a_week_or_when_there_are_more() {
        let mut state = DeviceState::default();
        let now = 1_800_000_000;
        assert!(AlertRead::shows(None, 2, now), "never read");
        assert!(!AlertRead::shows(None, 0, now), "nothing to tell");
        state.mark_alerts_read("aa", &[("weak", 2), ("leaked", 0)], now);
        let read = state.alerts_read("aa");
        assert_eq!(read.len(), 1, "only what there was");
        let weak = read.get("weak").copied();
        assert!(!AlertRead::shows(weak, 2, now + 60), "read");
        assert!(
            AlertRead::shows(weak, 3, now + 60),
            "a new one shows at once"
        );
        assert!(
            AlertRead::shows(weak, 2, now + ALERT_QUIET_SECONDS),
            "back after a week, not dealt with"
        );
        // One dealt with: the count follows it down, so the next new one shows at once.
        assert!(state.settle_alerts("aa", &[("weak", 1)]));
        let weak = state.alerts_read("aa").get("weak").copied();
        assert_eq!(weak.map(|w| w.count), Some(1));
        assert!(AlertRead::shows(weak, 2, now + 60));
        // All dealt with: forgotten.
        assert!(state.settle_alerts("aa", &[("weak", 0)]));
        assert!(state.alerts_read("aa").is_empty());
        assert!(!state.settle_alerts("aa", &[("weak", 0)]));
    }

    #[test]
    fn a_vault_icon_is_kept_per_vault() {
        let mut state = DeviceState::default();
        assert_eq!(state.vault_icon("aa"), "");
        state.set_vault_icon("aa", "briefcase");
        assert_eq!(state.vault_icon("aa"), "briefcase");
        assert_eq!(
            state.vault_icon("bb"),
            "",
            "another vault keeps its initial"
        );
        state.set_vault_icon("aa", "../not an icon");
        assert_eq!(state.vault_icon("aa"), "", "only a line icon's name");
        state.set_vault_icon("cc", "");
        assert!(!state.vaults.contains_key("cc"), "nothing kept for nothing");
        let json = serde_json::to_string(&state).unwrap();
        assert!(
            !json.contains("\"icon\""),
            "no icon written when there is none"
        );
        state.set_vault_icon("aa", "home");
        let back: DeviceState =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        assert_eq!(back.vault_icon("aa"), "home");
    }

    #[test]
    fn recent_vaults_most_recent_first() {
        let mut state = DeviceState::default();
        for i in 0..10 {
            state.remember_vault(std::path::Path::new(&format!("C:/v{i}.vault")));
        }
        state.remember_vault(std::path::Path::new("C:/V5.vault")); // same file, other case
        let recent = state.recent_vaults();
        assert_eq!(recent.len(), MAX_RECENT_VAULTS);
        assert_eq!(recent[0], std::path::PathBuf::from("C:/V5.vault"));
        assert_eq!(
            recent
                .iter()
                .filter(|p| p.to_string_lossy().to_lowercase() == "c:/v5.vault")
                .count(),
            1
        );
        state.forget_vault(std::path::Path::new("c:/v5.vault"));
        assert!(
            !state
                .recent_vaults()
                .iter()
                .any(|p| p.ends_with("V5.vault"))
        );
    }

    #[test]
    fn failed_unlocks_are_kept_per_vault_until_a_right_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = DeviceState::default();
        let at = |now| Clock {
            now,
            uptime: Some(now - 1_000),
        };
        for i in 0..5 {
            assert_eq!(state.unlock_wait("v", at(2_000 + i)), (0, false));
            state.record_failed_unlock("v", at(2_000 + i));
        }
        assert_eq!(state.unlock_wait("v", at(2_004)), (30, false));
        assert_eq!(state.unlock_wait("other", at(2_004)), (0, false));
        // Written and read back, as by an app started again.
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        let (mut read, _) = DeviceState::load_or_set_aside_at(&path);
        assert_eq!(read.unlock_attempts("v").failed, 5);
        assert_eq!(read.unlock_wait("v", at(2_014)), (20, false));
        // A clock set back: the wait starts again, and that is to be saved.
        let back = Clock {
            now: 1_000,
            uptime: None,
        };
        assert_eq!(read.unlock_wait("v", back), (30, true));
        let taken = read.take_unlock_attempts("v");
        assert_eq!((taken.failed, taken.first_at), (5, 1_000));
        assert!(read.unlock_attempts("v").is_clear());
        assert!(read.take_unlock_attempts("v").is_clear());
        let json = String::from_utf8(serde_json::to_vec(&read).unwrap()).unwrap();
        assert!(!json.contains("unlock_attempts"), "nothing kept once clear");
        assert!(uptime_seconds().is_none_or(|up| up > 0));
    }

    #[test]
    fn old_state_files_still_load() {
        let json = r#"{"vaults": {"abc": {"highest_revision": 7}}}"#;
        let state: DeviceState = serde_json::from_str(json).unwrap();
        assert_eq!(state.settings, Settings::default());
        // A settings block written before `dark_theme` existed still loads, with the default.
        let partial = r#"{"settings": {"auto_lock_minutes": 9, "clipboard_clear_seconds": 30}}"#;
        let older: DeviceState = serde_json::from_str(partial).unwrap();
        assert_eq!(older.settings.auto_lock_minutes, 9);
        assert!(older.settings.dark_theme);
        assert_eq!(
            state.check_rollback("abc", 6),
            RollbackStatus::Older {
                revision: 6,
                highest_seen: 7
            }
        );
    }
}
