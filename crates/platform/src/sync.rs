//! Sync targets (spec: SYNC.md §5) and one sync round, shared by the CLI and the desktop app.
//!
//! A target holds one sealed copy of the vault per device and nothing else. This device
//! writes only its own copy and reads the others; [`vault_core::Vault::merge`] decides what
//! they change here. Targets: a folder (here), our own server ([`server`]) and WebDAV
//! ([`webdav`]).

#[cfg(test)]
mod hostile;
mod http;
pub mod server;
pub mod webdav;

use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use vault_core::{
    FormerKey, Keyfile, SecretKey, Unlock, Vault,
    sync::{DeviceId, MergeReport, SeenRevisions},
};

pub use http::{check_address, check_webdav_address, pin_text, split_pin, with_pin};
pub use server::ServerTarget;
pub use webdav::WebDavTarget;

use crate::{SyncPlace, SyncTo, secret_store};

/// Copies bigger than this are not read: a vault is kilobytes to a few MB (pictures stay in
/// each device's cache), and a target is not trusted to hand over something sane.
pub const MAX_COPY_BYTES: u64 = 64 * 1024 * 1024;

/// How long a temporary file in a sync folder must have been left alone to be taken for what an
/// interrupted write left behind: far longer than writing a copy takes, on any share.
const LEFTOVER_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Where copies are kept. Every call may be slow (a network share, a cloud drive fetching a
/// file on demand): run them off the UI thread.
pub trait Target: Send + Sync {
    /// The devices that have a copy there, each with a tag that changes when its copy does
    /// (`None`: unknown, always read it).
    fn list(&self) -> Result<Vec<Listed>>;
    fn get(&self, device: DeviceId) -> Result<Vec<u8>>;
    /// Replaces this device's own copy, whole: readers never see half of it.
    fn put(&self, own: DeviceId, bytes: &[u8]) -> Result<()>;
    /// Deletes a device's copy (a device removed from the vault).
    fn remove(&self, device: DeviceId) -> Result<()>;
    /// Waits up to `seconds` for a change after `after` (a counter the target hands out) and
    /// returns where the counter stands. `None`: this target can't tell, look again later.
    fn wait(&self, _after: u64, _seconds: u64) -> Option<Result<u64>> {
        None
    }
}

/// One copy found on a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub device: DeviceId,
    pub tag: Option<String>,
}

/// The tags of the copies already folded in, so an unchanged copy isn't read again. Kept in
/// memory only: the first round after an unlock reads everything.
pub type Tags = HashMap<DeviceId, String>;

/// A folder another program keeps the same on every computer (OneDrive, Google Drive for
/// desktop, Dropbox, Syncthing, a network share): `<folder>/<vault id>/devices/<device>.vault`.
#[derive(Debug, Clone)]
pub struct FolderTarget {
    devices: PathBuf,
}

impl FolderTarget {
    /// The target for vault `vault_id` (hex) under `folder`, the one the person chose.
    pub fn new(folder: &Path, vault_id: &str) -> Result<Self> {
        if vault_id.len() != 32 || !vault_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("not a vault id");
        }
        Ok(Self {
            devices: folder.join(vault_id).join("devices"),
        })
    }

    fn path(&self, device: DeviceId) -> PathBuf {
        self.devices.join(format!("{}.vault", device.to_hex()))
    }

    /// A fresh name next to the copies for `own`'s next copy while it is written:
    /// `.<device>.<32 random hex>.vault.tmp`, which `list` and the watch ignore. Random, so
    /// another program writing in the shared folder can't have a file or a link waiting under
    /// it.
    fn temp_path(&self, own: DeviceId) -> Result<PathBuf> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|err| anyhow::anyhow!("no randomness: {err}"))?;
        let tag: String = random.iter().map(|b| format!("{b:02x}")).collect();
        Ok(self
            .devices
            .join(format!(".{}.{tag}.vault.tmp", own.to_hex())))
    }

    /// Whether `name` is one `device`'s copy is written under before it is renamed into place:
    /// [`FolderTarget::temp_path`]'s, or the fixed one of older versions.
    fn is_temp_name(name: &str, device: DeviceId) -> bool {
        let Some(rest) = name.strip_prefix(&format!(".{}.", device.to_hex())) else {
            return false;
        };
        rest == "vault.tmp"
            || rest.strip_suffix(".vault.tmp").is_some_and(|random| {
                random.len() == 32 && random.bytes().all(|b| b.is_ascii_hexdigit())
            })
    }

    /// Deletes what writes of `device`'s copy left behind when they were cut short (the app
    /// killed, the power gone): each is a sealed copy, or part of one, that everyone with access
    /// to the folder could read for good, also after the master password was changed. Only
    /// files and links under its temporary names (a link itself, never what it points at) that
    /// were last written `age` ago or more, so one being written is left alone. Best effort:
    /// what can't be deleted is tried again after the next copy.
    fn clear_leftovers(&self, device: DeviceId, age: Duration) {
        let Ok(entries) = fs::read_dir(&self.devices) else {
            return;
        };
        let now = SystemTime::now();
        for entry in entries.flatten() {
            let name = entry.file_name();
            if !name
                .to_str()
                .is_some_and(|name| Self::is_temp_name(name, device))
            {
                continue;
            }
            // Of the entry itself: a link is not followed.
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let left_alone = meta
                .modified()
                .ok()
                .and_then(|at| now.duration_since(at).ok())
                .is_some_and(|since| since >= age);
            if left_alone && !meta.is_dir() {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    /// The folders the copies go in, made if they aren't there yet. Links are refused before
    /// they are made (nothing is made inside one) and after (one put there meanwhile).
    fn make_folders(&self) -> Result<()> {
        self.refuse_links()?;
        fs::create_dir_all(&self.devices).context("creating the sync folder")?;
        self.refuse_links()
    }

    /// Refuses to write when the vault's folder or its `devices` folder is a link: someone
    /// else writing in the shared folder could otherwise have this device's copy written, or a
    /// copy removed, in a folder of their choosing. The folder the person chose may be a link;
    /// these two are made here and never are.
    fn refuse_links(&self) -> Result<()> {
        for dir in self.devices.ancestors().take(2) {
            if fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_symlink()) {
                bail!(
                    "{} is a link, not a folder: this device writes its copy only in a real folder",
                    dir.display()
                );
            }
        }
        Ok(())
    }

    /// Writes `bytes` under `temp`, which must not exist yet, and renames it over `own`'s
    /// copy. Whatever is already under `temp` (a file, a link, a folder) makes it fail and is
    /// left as it is: the file is created new, never opened, so nothing is written through a
    /// link or into someone else's file. When writing or the rename fails, only the file made
    /// here is removed (removing a link removes the link, never what it points at).
    fn put_through(&self, temp: &Path, own: DeviceId, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp)
            .context("writing to the sync folder")?;
        let written = file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| {
                drop(file);
                fs::rename(temp, self.path(own))
            });
        if let Err(err) = written {
            let _ = fs::remove_file(temp);
            return Err(err).context("writing to the sync folder");
        }
        Ok(())
    }
}

impl Target for FolderTarget {
    fn list(&self) -> Result<Vec<Listed>> {
        let entries = match fs::read_dir(&self.devices) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err).context("reading the sync folder"),
        };
        let mut devices = Vec::new();
        for entry in entries {
            let entry = entry.context("reading the sync folder")?;
            // Only `<32 hex>.vault`: a cloud drive's "conflicted copy", a temporary file or
            // anything else someone put there is not a device's copy.
            let name = entry.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".vault")) else {
                continue;
            };
            if let Some(device) = DeviceId::from_hex(stem)
                && let Ok(meta) = entry.metadata()
                && meta.is_file()
            {
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_nanos());
                devices.push(Listed {
                    device,
                    tag: Some(format!("{}-{modified}", meta.len())),
                });
            }
        }
        devices.sort_by_key(|l| l.device);
        Ok(devices)
    }

    fn get(&self, device: DeviceId) -> Result<Vec<u8>> {
        let path = self.path(device);
        let file = fs::File::open(&path).with_context(|| format!("reading {}", path.display()))?;
        let mut bytes = Vec::new();
        file.take(MAX_COPY_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_COPY_BYTES {
            bail!("{} is too big to be a vault", path.display());
        }
        Ok(bytes)
    }

    fn put(&self, own: DeviceId, bytes: &[u8]) -> Result<()> {
        self.make_folders()?;
        // Written beside it under a fresh name `list` ignores, then renamed over it.
        self.put_through(&self.temp_path(own)?, own, bytes)?;
        self.clear_leftovers(own, LEFTOVER_AGE);
        Ok(())
    }

    fn remove(&self, device: DeviceId) -> Result<()> {
        self.refuse_links()?;
        match fs::remove_file(self.path(device)) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err.into()),
            _ => {}
        }
        // It writes no copy here again, so nothing else would clear these.
        self.clear_leftovers(device, Duration::ZERO);
        Ok(())
    }
}

/// Watches the folder target of vault `vault_id` under `folder` until `stop` is set, and calls
/// `changed` (on this thread) when another device's copy appears, changes or goes: a second
/// after the last such event, so a copy written in pieces counts once. This device's own
/// copy and temporary files are ignored. Returns at once if the folder can't be watched
/// (some network shares, or a link where the vault's folder should be, which is neither
/// watched nor written through): the regular rounds still run.
pub fn watch_folder(
    folder: &Path,
    vault_id: &str,
    own: DeviceId,
    stop: &std::sync::atomic::AtomicBool,
    changed: impl Fn(),
) {
    use std::sync::atomic::Ordering;

    use notify::{RecursiveMode, Watcher};

    let Ok(target) = FolderTarget::new(folder, vault_id) else {
        return;
    };
    if target.make_folders().is_err() {
        return;
    }
    let own_name = format!("{}.vault", own.to_hex());
    let (sender, events) = std::sync::mpsc::channel();
    let Ok(mut watcher) = notify::recommended_watcher(sender) else {
        return;
    };
    if watcher
        .watch(&target.devices, RecursiveMode::NonRecursive)
        .is_err()
    {
        return;
    }
    let concerns = |event: &notify::Event| {
        event.paths.iter().any(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".vault").map(|stem| (n, stem)))
                .is_some_and(|(name, stem)| name != own_name && DeviceId::from_hex(stem).is_some())
        })
    };
    let mut pending = false;
    while !stop.load(Ordering::Relaxed) {
        match events.recv_timeout(Duration::from_secs(1)) {
            Ok(Ok(event)) => pending |= concerns(&event),
            Ok(Err(_)) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if pending && !stop.load(Ordering::Relaxed) {
                    pending = false;
                    changed();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// The other devices' copies, read in one go (off the UI thread), and what couldn't be read.
#[derive(Debug, Default)]
pub struct Fetched {
    pub copies: Vec<(DeviceId, Vec<u8>)>,
    pub unreadable: Vec<(DeviceId, String)>,
    /// The tags of the copies read or known, to pass as `known` next time once merged.
    pub tags: Tags,
    /// Copies left unread because their tag was known.
    pub unchanged: usize,
}

/// The most other devices' copies one round attempts to read, and the most bytes they may hold
/// together: a target that lists thousands of copies, or huge ones, can't make this device
/// download and hold them all (a vault syncs a few devices of a few MB).
pub const MAX_COPIES_READ: usize = 64;
pub const MAX_ROUND_BYTES: usize = 256 * 1024 * 1024;

/// Attempts to read every copy but this device's own whose tag isn't in `known` (pass an empty
/// map to read them all). An unreachable target is an error; one copy that can't be read is
/// listed and the others are still tried. Once [`MAX_COPIES_READ`] attempts or
/// [`MAX_ROUND_BYTES`] are reached, one remaining copy is listed as unreadable and no other
/// is read; copies listed after it that are known and unchanged are still counted as such, so
/// their tags aren't forgotten for the next round.
pub fn fetch(target: &dyn Target, own: DeviceId, known: &Tags) -> Result<Fetched> {
    let mut fetched = Fetched::default();
    let mut bytes_read = 0usize;
    let mut copies_attempted = 0usize;
    let mut overflowed = false;
    for listed in target.list()? {
        if listed.device == own {
            continue;
        }
        if let Some(tag) = &listed.tag
            && known.get(&listed.device) == Some(tag)
        {
            fetched.unchanged += 1;
            fetched.tags.insert(listed.device, tag.clone());
            continue;
        }
        if overflowed {
            continue;
        }
        if copies_attempted >= MAX_COPIES_READ || bytes_read >= MAX_ROUND_BYTES {
            fetched.unreadable.push((
                listed.device,
                "too many copies to read in one round".to_owned(),
            ));
            overflowed = true;
            continue;
        }
        copies_attempted += 1;
        match target.get(listed.device) {
            Ok(bytes) => {
                bytes_read = bytes_read.saturating_add(bytes.len());
                if let Some(tag) = listed.tag {
                    fetched.tags.insert(listed.device, tag);
                }
                fetched.copies.push((listed.device, bytes));
            }
            Err(err) => fetched.unreadable.push((listed.device, format!("{err:#}"))),
        }
    }
    Ok(fetched)
}

/// Which of a vault's sync places.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Where the vault syncs.
    Main,
    /// A second place (a backup server) synced every round too: the vault keeps syncing
    /// through it while the main place can't be reached, and the main place catches up as
    /// soon as it answers again.
    Backup,
}

impl Role {
    /// Added to the names its credentials are kept under; the main place's keep the names
    /// they always had.
    fn suffix(self) -> &'static str {
        match self {
            Role::Main => "",
            Role::Backup => ":backup",
        }
    }
}

/// The name `device`'s key for the server in `role` is kept under (the `device` of
/// `secret_store::*_sync_key`).
pub fn sync_key_name(device: DeviceId, role: Role) -> String {
    format!("{}{}", device.to_hex(), role.suffix())
}

/// The name the WebDAV password for the place in `role` is kept under (the `vault_id` of
/// `secret_store::*_webdav_password`).
pub fn webdav_password_name(vault_id: &str, role: Role) -> String {
    format!("{vault_id}{}", role.suffix())
}

/// The target for vault `vault_id` synced by `device` through `to`, with what it needs from
/// the OS credential store.
pub fn open_target(vault_id: &str, device: DeviceId, to: &SyncTo) -> Result<Box<dyn Target>> {
    open_target_as(vault_id, device, to, Role::Main)
}

/// [`open_target`] for the place in `role`.
pub fn open_target_as(
    vault_id: &str,
    device: DeviceId,
    to: &SyncTo,
    role: Role,
) -> Result<Box<dyn Target>> {
    Ok(match to {
        SyncTo::Folder { path } => Box::new(FolderTarget::new(path, vault_id)?),
        SyncTo::Server { url } => {
            let seed = secret_store::load_sync_key(vault_id, &sync_key_name(device, role))?
                .context("this device has no key for the sync server: join it again")?;
            Box::new(ServerTarget::new(
                url,
                vault_id,
                device,
                vault_sync_wire::DeviceKey::from_seed(&seed),
            )?)
        }
        SyncTo::Webdav { url, user } => {
            // An address the password may not go to (one kept before plain http:// was
            // limited to this computer) is refused before the password leaves the store.
            let url = check_webdav_address(url)?;
            let password =
                secret_store::load_webdav_password(&webdav_password_name(vault_id, role))?
                    .context("the WebDAV password isn't saved on this device: set it again")?;
            Box::new(WebDavTarget::new(&url, vault_id, user, &password)?)
        }
    })
}

/// The tags of the copies already merged, per place.
#[derive(Debug, Default, Clone)]
pub struct KnownTags {
    pub main: Tags,
    pub backup: Tags,
}

/// One round's reading from every place the vault syncs through.
#[derive(Debug)]
pub struct Reading {
    pub main: Result<Fetched, String>,
    /// `None` when there is no backup place.
    pub backup: Option<Result<Fetched, String>>,
}

impl Reading {
    /// At least one place answered: the round goes on with what it read.
    pub fn reached(&self) -> bool {
        self.main.is_ok() || matches!(self.backup, Some(Ok(_)))
    }

    /// Why the main place couldn't be read, when it couldn't.
    pub fn main_down(&self) -> Option<&str> {
        self.main.as_ref().err().map(String::as_str)
    }

    /// Why the backup place couldn't be read, when there is one and it couldn't.
    pub fn backup_down(&self) -> Option<&str> {
        match &self.backup {
            Some(Err(why)) => Some(why),
            _ => None,
        }
    }

    /// The tags to pass as `known` next round, once what was read is merged: a place that
    /// didn't answer keeps what was known of it.
    pub fn tags(&self, before: &KnownTags) -> KnownTags {
        KnownTags {
            main: self
                .main
                .as_ref()
                .map_or_else(|_| before.main.clone(), |f| f.tags.clone()),
            backup: match &self.backup {
                Some(Ok(fetched)) => fetched.tags.clone(),
                _ => before.backup.clone(),
            },
        }
    }

    /// The places that answered, by role.
    fn answered(&self) -> impl Iterator<Item = (Role, &Fetched)> {
        let main = self.main.as_ref().ok().map(|f| (Role::Main, f));
        let backup = match &self.backup {
            Some(Ok(fetched)) => Some((Role::Backup, fetched)),
            _ => None,
        };
        main.into_iter().chain(backup)
    }
}

/// Reads every other device's copy from the main place and the backup place, if any, at the
/// same time (off the UI thread). A place that can't be reached is reported in the result;
/// the round goes on with the other.
pub fn read_all(vault_id: &str, device: DeviceId, place: &SyncPlace, known: &KnownTags) -> Reading {
    let read = |to: &SyncTo, role: Role, known: &Tags| {
        open_target_as(vault_id, device, to, role)
            .and_then(|target| fetch(&*target, device, known))
            .map_err(|err| format!("{err:#}"))
    };
    std::thread::scope(|scope| {
        let backup = place
            .backup
            .as_ref()
            .map(|to| scope.spawn(|| read(to, Role::Backup, &known.backup)));
        let main = read(&place.to, Role::Main, &known.main);
        Reading {
            main,
            backup: backup.map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err("reading the backup place failed".to_owned()))
            }),
        }
    })
}

/// Folds what a round read into `vault`. With one place this is [`merge_all`]. With a backup
/// place, each other device's newest copy is taken from whichever place has it; a copy older
/// than one already merged from that device is left out without a warning, since a place
/// that was down holds older copies until it catches up (it is never merged either way).
pub fn merge_reading(vault: &mut Vault, reading: &Reading, seen: &mut SeenRevisions) -> Round {
    if reading.backup.is_none() {
        return match &reading.main {
            Ok(fetched) => merge_all(vault, fetched, seen),
            Err(_) => Round::default(),
        };
    }
    let mut chosen: Vec<(DeviceId, &[u8], Option<u64>)> = Vec::new();
    for (_, fetched) in reading.answered() {
        for (device, bytes) in &fetched.copies {
            let revision = vault.check_copy(bytes).ok();
            if let (Some(revision), Some(known)) = (revision, seen.revision(device))
                && revision < known
            {
                continue;
            }
            match chosen.iter_mut().find(|(id, _, _)| id == device) {
                None => chosen.push((*device, bytes, revision)),
                Some(slot) if revision > slot.2 => *slot = (*device, bytes, revision),
                Some(_) => {}
            }
        }
    }
    let fetched = Fetched {
        copies: chosen
            .into_iter()
            .map(|(device, bytes, _)| (device, bytes.to_vec()))
            .collect(),
        ..Fetched::default()
    };
    merge_all(vault, &fetched, seen)
}

/// The places this device's copy goes to after a round: those that answered and don't have
/// `revision` yet (all that answered when the round `changed` the vault).
pub fn to_publish(place: &SyncPlace, reading: &Reading, revision: u64, changed: bool) -> Vec<Role> {
    let mut roles = Vec::new();
    if reading.main.is_ok() && (changed || revision > place.published) {
        roles.push(Role::Main);
    }
    if matches!(reading.backup, Some(Ok(_))) && (changed || revision > place.published_backup) {
        roles.push(Role::Backup);
    }
    roles
}

/// What each place answered when this device's copy was put there.
pub type Published = Vec<(Role, Result<(), String>)>;

/// Puts this device's copy on each place in `roles` (off the UI thread); what each answered.
pub fn publish_all(
    vault_id: &str,
    device: DeviceId,
    place: &SyncPlace,
    bytes: &[u8],
    roles: &[Role],
) -> Published {
    roles
        .iter()
        .filter_map(|role| {
            let to = match role {
                Role::Main => &place.to,
                Role::Backup => place.backup.as_ref()?,
            };
            let put = open_target_as(vault_id, device, to, *role)
                .and_then(|target| target.put(device, bytes))
                .map_err(|err| format!("{err:#}"));
            Some((*role, put))
        })
        .collect()
}

/// What folding the fetched copies did.
#[derive(Debug, Default)]
pub struct Round {
    pub reports: Vec<MergeReport>,
    /// Copies refused (a replay, a fork, another vault, a removed device…), with why.
    pub refused: Vec<(DeviceId, vault_core::Error)>,
    /// This device was removed from the vault on another device: stop syncing.
    pub removed_here: bool,
}

impl Round {
    /// Whether the vault changed and must be saved (and then published).
    pub fn changed(&self) -> bool {
        self.reports.iter().any(MergeReport::changed)
    }

    pub fn conflicts(&self) -> usize {
        self.reports.iter().map(|r| r.conflicts.len()).sum()
    }

    pub fn waiting_for_lock(&self) -> usize {
        self.reports.iter().map(|r| r.waiting_for_lock).sum()
    }

    pub fn unlock_changed(&self) -> bool {
        self.reports.iter().any(|r| r.unlock_changed)
    }
}

/// A copy a round couldn't use (SYNC.md §8): whose, when this device found it, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyProblem {
    pub device: DeviceId,
    /// Read, but refused (a replay, a fork, another vault…); otherwise it couldn't be read.
    pub refused: bool,
    pub why: String,
    /// When it was first found like this (Unix seconds).
    pub at: i64,
}

/// What the rounds couldn't use, one entry per device, kept for as long as that device's
/// copy stays unusable: a refused copy whose tag doesn't change isn't read again, and still
/// counts. Copies that wait for the item lock or are under another vault key are said apart
/// (`Round::waiting_for_lock`, [`key_mismatch`]) and left out.
#[derive(Debug, Default, Clone)]
pub struct CopyProblems {
    list: Vec<CopyProblem>,
}

impl CopyProblems {
    /// Takes in one round. Returns the problems that are new (not found like this before), to
    /// tell the person once; a device whose copy was used, or read and not refused, is
    /// dropped from the list.
    pub fn note(&mut self, reading: &Reading, round: &Round, now: i64) -> Vec<CopyProblem> {
        let merged: Vec<DeviceId> = round.reports.iter().map(|r| r.writer).collect();
        let mut found: Vec<(DeviceId, bool, String)> = Vec::new();
        for (device, err) in &round.refused {
            if matches!(
                err,
                vault_core::Error::SecretsLocked | vault_core::Error::DecryptionFailed
            ) || merged.contains(device)
            {
                continue;
            }
            if !found.iter().any(|(d, _, _)| d == device) {
                found.push((*device, true, err.to_string()));
            }
        }
        let mut read_fine: Vec<DeviceId> = merged.clone();
        for (_, fetched) in reading.answered() {
            for (device, why) in &fetched.unreadable {
                if !merged.contains(device) && !found.iter().any(|(d, _, _)| d == device) {
                    found.push((*device, false, why.clone()));
                }
            }
            read_fine.extend(fetched.copies.iter().map(|(device, _)| *device));
        }
        // A copy read again and neither refused nor unreadable is fine now.
        self.list.retain(|p| {
            !read_fine.contains(&p.device) || found.iter().any(|(d, _, _)| *d == p.device)
        });
        let mut new = Vec::new();
        for (device, refused, why) in found {
            match self.list.iter_mut().find(|p| p.device == device) {
                Some(p) if p.refused == refused && p.why == why => {}
                Some(p) => {
                    *p = CopyProblem {
                        device,
                        refused,
                        why,
                        at: now,
                    };
                    new.push(p.clone());
                }
                None => {
                    let p = CopyProblem {
                        device,
                        refused,
                        why,
                        at: now,
                    };
                    new.push(p.clone());
                    self.list.push(p);
                }
            }
        }
        new
    }

    /// The problem with `device`'s copy, if there is one.
    pub fn of(&self, device: DeviceId) -> Option<&CopyProblem> {
        self.list.iter().find(|p| p.device == device)
    }

    pub fn all(&self) -> &[CopyProblem] {
        &self.list
    }

    pub fn clear(&mut self) {
        self.list.clear();
    }
}

/// The copies a round couldn't open with the vault key held here (`DecryptionFailed`), told
/// apart by their public header (`VaultInfo::unlock_id`, see `DeviceState::retire_unlock`).
#[derive(Debug, Default)]
pub struct KeyMismatch {
    /// Written before this device renewed the vault key or took a renewed one: each waits for
    /// its device to take the new key (nothing to do here).
    pub behind: Vec<DeviceId>,
    /// Sealed under a key this device doesn't hold: the vault key may have been renewed on
    /// that device. The master password and the new Secret Key open them
    /// ([`take_renewed_key`]).
    pub renewed: Vec<(DeviceId, Vec<u8>)>,
}

impl KeyMismatch {
    pub fn is_empty(&self) -> bool {
        self.behind.is_empty() && self.renewed.is_empty()
    }
}

/// Sorts the copies of `round` refused because the vault key held here doesn't open them.
pub fn key_mismatch(
    vault_id: &str,
    reading: &Reading,
    round: &Round,
    state: &crate::DeviceState,
) -> KeyMismatch {
    let copies: Vec<&(DeviceId, Vec<u8>)> = reading
        .answered()
        .flat_map(|(_, fetched)| fetched.copies.iter())
        .collect();
    key_mismatch_in(vault_id, copies, round, state)
}

/// [`key_mismatch`] for a round merged from `copies` (one place's [`Fetched::copies`]).
pub fn key_mismatch_in<'a>(
    vault_id: &str,
    copies: impl IntoIterator<Item = &'a (DeviceId, Vec<u8>)>,
    round: &Round,
    state: &crate::DeviceState,
) -> KeyMismatch {
    let copies: Vec<&(DeviceId, Vec<u8>)> = copies.into_iter().collect();
    let mut mismatch = KeyMismatch::default();
    for (device, err) in &round.refused {
        if !matches!(err, vault_core::Error::DecryptionFailed) {
            continue;
        }
        let Some(bytes) = copies
            .iter()
            .find(|(d, _)| d == device)
            .map(|(_, bytes)| bytes)
        else {
            continue;
        };
        let Ok(info) = Vault::inspect(bytes) else {
            continue;
        };
        if info.id_hex != vault_id {
            continue;
        }
        if state.unlock_retired(vault_id, &info.unlock_id) {
            mismatch.behind.push(*device);
        } else if !mismatch.renewed.iter().any(|(d, _)| d == device) {
            mismatch.renewed.push((*device, bytes.clone()));
        }
    }
    mismatch
}

/// Takes the vault key another device renewed into `vault` (`Vault::adopt_key`): the first of
/// `copies` that the master password and the new Secret Key (with the keyfile, when the vault
/// needs one) open gives it, and what opened `vault` before is remembered as retired in
/// `state`. `Ok(None)`: the copy opened but shares this key already. Fails with
/// `DecryptionFailed` when none opens (a wrong Secret Key or password); nothing changes then.
/// The caller saves the vault, keeps `secret_key` on the device and seals again what it
/// sealed with the former key.
pub fn take_renewed_key(
    vault: &mut Vault,
    copies: &[(DeviceId, Vec<u8>)],
    password: &str,
    secret_key: &SecretKey,
    keyfile: Option<&Keyfile>,
    state: &mut crate::DeviceState,
) -> vault_core::Result<Option<FormerKey>> {
    let before = vault.unlock_id();
    let mut why = vault_core::Error::DecryptionFailed;
    for (_, bytes) in copies {
        let unlock = match keyfile {
            Some(keyfile) => Unlock::PasswordAndKeyfile {
                password,
                secret_key,
                keyfile,
            },
            None => Unlock::Password {
                password,
                secret_key,
            },
        };
        match Vault::open(bytes, unlock) {
            Ok(renewed) => {
                let former = vault.adopt_key(&renewed)?;
                if former.is_some() {
                    state.retire_unlock(&vault.id_hex(), &before);
                }
                return Ok(former);
            }
            Err(vault_core::Error::KeyfileRequired) => why = vault_core::Error::KeyfileRequired,
            Err(_) => {}
        }
    }
    Err(why)
}

/// Folds every fetched copy into `vault`. Runs where the vault is (the UI thread), and is
/// quick: no file or network access. A copy is taken only from the device it is listed under
/// (`Vault::merge_from`): a place that hands one device's copy over as another's gets it
/// refused, so what is said of each device is its own.
pub fn merge_all(vault: &mut Vault, fetched: &Fetched, seen: &mut SeenRevisions) -> Round {
    let mut round = Round::default();
    for (device, bytes) in &fetched.copies {
        match vault.merge_from(*device, bytes, seen) {
            Ok(report) => round.reports.push(report),
            Err(vault_core::Error::RemovedHere) => round.removed_here = true,
            Err(err) => round.refused.push((*device, err)),
        }
    }
    round
}

/// Makes sure this vault writes as `device` and lists it among the devices that sync it.
/// Returns whether that changed the vault (save it).
pub fn join(vault: &mut Vault, device: DeviceId, name: &str) -> vault_core::Result<bool> {
    let mut changed = vault.device() != device;
    vault.set_device(device);
    if !vault.sync_devices().iter().any(|d| d.id == device) {
        vault.add_sync_device(vault_core::sync::SyncDevice {
            id: device,
            name: name.to_owned(),
            signing_key: None,
            added_at: unix_now(),
        })?;
        changed = true;
    }
    Ok(changed)
}

/// Takes the ids this device synced the vault as before out of its device list: they are
/// this device's own old entries (it joined again as a new device). Returns whether that
/// changed the vault (save it).
pub fn retire(vault: &mut Vault, retired: &[DeviceId]) -> bool {
    let own = vault.device();
    let mut changed = false;
    for id in retired {
        if *id != own && vault.sync_devices().iter().any(|d| d.id == *id) {
            changed |= vault.remove_sync_device(id).is_ok();
        }
    }
    changed
}

/// Joins vault `vault_id` on the server at `address` with a one-time `invite`, off the UI
/// thread. When this device is already enrolled there as one of `resume` (a join tried again
/// after the rest of a setup failed, or the same server joined once more) it goes on with
/// that key, since an invite works only once. Otherwise it enrolls as `fresh`: a device that
/// was removed from the vault, or that synced it through another place, comes back as a new
/// device instead of as the one the vault remembers. The key is kept in the credential
/// store. Returns the target and the id it is enrolled as.
pub fn join_server(
    address: &str,
    vault_id: &str,
    resume: &[DeviceId],
    fresh: DeviceId,
    name: &str,
    invite: &str,
    role: Role,
) -> Result<(ServerTarget, DeviceId)> {
    for device in resume.iter().chain([&fresh]) {
        if let Ok(Some(seed)) = secret_store::load_sync_key(vault_id, &sync_key_name(*device, role))
            && let Ok(server) = ServerTarget::new(
                address,
                vault_id,
                *device,
                vault_sync_wire::DeviceKey::from_seed(&seed),
            )
            && server.enrolled().is_ok()
        {
            return Ok((server, *device));
        }
    }
    let server = ServerTarget::join(address, vault_id, fresh, name, invite)?;
    secret_store::store_sync_key(vault_id, &sync_key_name(fresh, role), &server.key_seed())?;
    Ok((server, fresh))
}

/// Forgets what this device kept to sync vault `vault_id` as `device`: its keys for the main
/// and the backup server.
pub fn forget_keys(vault_id: &str, device: DeviceId) {
    for role in [Role::Main, Role::Backup] {
        let _ = secret_store::forget_sync_key(vault_id, &sync_key_name(device, role));
    }
}

/// A name for this device in the vault's device list: the computer's name.
pub fn device_name() -> String {
    let name = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default();
    let name: String = name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(vault_core::sync::SyncDevice::MAX_NAME_CHARS)
        .collect();
    if name.is_empty() {
        "This computer".into()
    } else {
        name
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    struct CountingTarget {
        listed: usize,
        fail_all: bool,
        gets: std::sync::atomic::AtomicUsize,
    }

    impl CountingTarget {
        fn new(listed: usize, fail_all: bool) -> Self {
            Self {
                listed,
                fail_all,
                gets: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn gets(&self) -> usize {
            self.gets.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Target for CountingTarget {
        fn list(&self) -> Result<Vec<Listed>> {
            Ok((1..=self.listed)
                .map(|n| Listed {
                    device: device(u8::try_from(n).unwrap()),
                    tag: None,
                })
                .collect())
        }

        fn get(&self, _device: DeviceId) -> Result<Vec<u8>> {
            let attempt = self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_all || attempt % 2 == 1 {
                anyhow::bail!("unreadable copy");
            }
            Ok(vec![u8::try_from(attempt).unwrap()])
        }

        fn put(&self, _own: DeviceId, _bytes: &[u8]) -> Result<()> {
            unreachable!("the fetch tests do not write copies")
        }

        fn remove(&self, _device: DeviceId) -> Result<()> {
            unreachable!("the fetch tests do not remove copies")
        }
    }

    #[test]
    fn failed_reads_count_toward_the_round_limit() {
        let target = CountingTarget::new(MAX_COPIES_READ + 10, true);
        let fetched = fetch(&target, device(0), &Tags::new()).unwrap();

        assert_eq!(target.gets(), MAX_COPIES_READ);
        assert!(fetched.copies.is_empty());
        assert_eq!(fetched.unreadable.len(), MAX_COPIES_READ + 1);
        assert_eq!(
            fetched.unreadable.last().unwrap().1,
            "too many copies to read in one round"
        );
    }

    #[test]
    fn known_copies_listed_after_the_limit_keep_their_tags() {
        struct Tagged(CountingTarget);
        impl Target for Tagged {
            fn list(&self) -> Result<Vec<Listed>> {
                let mut listed = self.0.list()?;
                // The last one is known and unchanged.
                listed.last_mut().unwrap().tag = Some("kept".to_owned());
                Ok(listed)
            }
            fn get(&self, device: DeviceId) -> Result<Vec<u8>> {
                self.0.get(device)
            }
            fn put(&self, own: DeviceId, bytes: &[u8]) -> Result<()> {
                self.0.put(own, bytes)
            }
            fn remove(&self, device: DeviceId) -> Result<()> {
                self.0.remove(device)
            }
        }
        let listed = MAX_COPIES_READ + 10;
        let last = device(u8::try_from(listed).unwrap());
        let target = Tagged(CountingTarget::new(listed, true));
        let mut known = Tags::new();
        known.insert(last, "kept".to_owned());
        let fetched = fetch(&target, device(0), &known).unwrap();

        assert_eq!(target.0.gets(), MAX_COPIES_READ);
        assert_eq!(fetched.unreadable.len(), MAX_COPIES_READ + 1);
        assert_eq!(fetched.unchanged, 1);
        assert_eq!(fetched.tags.get(&last).map(String::as_str), Some("kept"));
    }

    #[test]
    fn successful_and_failed_reads_share_the_round_limit() {
        let target = CountingTarget::new(MAX_COPIES_READ + 10, false);
        let fetched = fetch(&target, device(0), &Tags::new()).unwrap();

        assert_eq!(target.gets(), MAX_COPIES_READ);
        assert_eq!(fetched.copies.len(), MAX_COPIES_READ.div_ceil(2));
        assert_eq!(fetched.unreadable.len(), MAX_COPIES_READ / 2 + 1);
    }

    #[test]
    fn a_folder_holds_one_copy_per_device_and_ignores_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let target = FolderTarget::new(dir.path(), id).unwrap();
        assert!(target.list().unwrap().is_empty(), "nothing there yet");
        let devices_of = |target: &FolderTarget| -> Vec<DeviceId> {
            target
                .list()
                .unwrap()
                .into_iter()
                .map(|l| l.device)
                .collect()
        };
        target.put(device(1), b"one").unwrap();
        target.put(device(2), b"two").unwrap();
        target.put(device(1), b"one, newer").unwrap();
        let devices = dir.path().join(id).join("devices");
        // What cloud drives and people leave next to the copies.
        fs::write(devices.join("conflicted copy.vault"), b"x").unwrap();
        fs::write(
            devices.join(format!("{} (1).vault", device(3).to_hex())),
            b"x",
        )
        .unwrap();
        fs::create_dir(devices.join(format!("{}.vault", device(4).to_hex()))).unwrap();
        assert_eq!(devices_of(&target), [device(1), device(2)]);
        assert_eq!(target.get(device(1)).unwrap(), b"one, newer");
        let fetched = fetch(&target, device(1), &Tags::new()).unwrap();
        assert_eq!(fetched.copies, [(device(2), b"two".to_vec())]);
        // Known and unchanged: not read again.
        let again = fetch(&target, device(1), &fetched.tags).unwrap();
        assert!(again.copies.is_empty());
        assert_eq!(again.unchanged, 1);
        target.remove(device(2)).unwrap();
        target.remove(device(2)).unwrap();
        assert_eq!(devices_of(&target), [device(1)]);
        assert!(FolderTarget::new(dir.path(), "../escape").is_err());
    }

    #[test]
    fn a_folder_watch_hears_other_devices_only() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        let dir = tempfile::tempdir().unwrap();
        let id = "c".repeat(32);
        let target = FolderTarget::new(dir.path(), &id).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let heard = Arc::new(AtomicUsize::new(0));
        let watching = {
            let (folder, id, stop, heard) = (
                dir.path().to_owned(),
                id.clone(),
                stop.clone(),
                heard.clone(),
            );
            std::thread::spawn(move || {
                watch_folder(&folder, &id, device(1), &stop, || {
                    heard.fetch_add(1, Ordering::SeqCst);
                });
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(300));
        target.put(device(1), b"own copy").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1800));
        assert_eq!(heard.load(Ordering::SeqCst), 0, "this device's own copy");
        target.put(device(2), b"another device").unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while heard.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < until {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(heard.load(Ordering::SeqCst), 1, "one change, heard once");
        stop.store(true, Ordering::SeqCst);
        watching.join().unwrap();
    }

    /// Makes `link` a symbolic link to the file `target`, where this computer allows it.
    #[cfg(unix)]
    fn link_file(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn link_file(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }

    /// Makes `link` point at the folder `target`: a symbolic link, or on Windows without the
    /// right to make one, a junction.
    #[cfg(unix)]
    fn link_dir(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn link_dir(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
            || std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .is_ok_and(|out| out.status.success())
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The name a copy used to be written under before it was renamed into place.
    fn old_temp_name(device: DeviceId) -> String {
        format!(".{}.vault.tmp", device.to_hex())
    }

    #[test]
    fn a_file_or_link_at_the_old_temporary_name_is_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let id = "d".repeat(32);
        let target = FolderTarget::new(dir.path(), &id).unwrap();
        let devices = dir.path().join(&id).join("devices");
        fs::create_dir_all(&devices).unwrap();
        // Another writer in the shared folder leaves, under the names this device used to
        // write through: a hard link to a file of theirs elsewhere, a file, and (where links
        // can be made) a symbolic link to that file.
        let theirs = outside.path().join("theirs.txt");
        fs::write(&theirs, b"a file outside the sync folder").unwrap();
        fs::hard_link(&theirs, devices.join(old_temp_name(device(1)))).unwrap();
        fs::write(devices.join(old_temp_name(device(2))), b"left here").unwrap();
        let linked = link_file(&theirs, &devices.join(old_temp_name(device(3))));
        if !linked {
            eprintln!("no symbolic links on this computer: that case is skipped");
        }

        for n in 1..=3 {
            target.put(device(n), b"sealed copy").unwrap();
            target.put(device(n), b"sealed copy, newer").unwrap();
        }
        assert_eq!(
            fs::read(&theirs).unwrap(),
            b"a file outside the sync folder"
        );
        assert_eq!(
            fs::read(devices.join(old_temp_name(device(1)))).unwrap(),
            b"a file outside the sync folder"
        );
        assert_eq!(
            fs::read(devices.join(old_temp_name(device(2)))).unwrap(),
            b"left here"
        );
        if linked {
            assert_eq!(
                fs::read_link(devices.join(old_temp_name(device(3)))).unwrap(),
                theirs
            );
        }
        for n in 1..=3 {
            assert_eq!(target.get(device(n)).unwrap(), b"sealed copy, newer");
        }
        // The copies, and what was left there: nothing of this device's writing remains.
        let mut expected: Vec<String> = (1..=3)
            .map(|n| format!("{}.vault", device(n).to_hex()))
            .chain([old_temp_name(device(1)), old_temp_name(device(2))])
            .chain(linked.then(|| old_temp_name(device(3))))
            .collect();
        expected.sort();
        assert_eq!(names(&devices), expected);
        assert_eq!(names(outside.path()), ["theirs.txt"]);
    }

    #[test]
    fn a_taken_temporary_name_fails_without_touching_anything() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let id = "e".repeat(32);
        let target = FolderTarget::new(dir.path(), &id).unwrap();
        target.put(device(1), b"old copy").unwrap();
        target.put(device(2), b"a neighbour's copy").unwrap();
        let devices = dir.path().join(&id).join("devices");

        // A file under the name picked.
        let taken = devices.join("taken.vault.tmp");
        fs::write(&taken, b"someone else's").unwrap();
        assert!(target.put_through(&taken, device(1), b"new copy").is_err());
        assert_eq!(fs::read(&taken).unwrap(), b"someone else's", "kept");
        // A folder under it.
        let folder = devices.join("folder.vault.tmp");
        fs::create_dir(&folder).unwrap();
        fs::write(folder.join("inside"), b"inside").unwrap();
        assert!(target.put_through(&folder, device(1), b"new copy").is_err());
        assert_eq!(fs::read(folder.join("inside")).unwrap(), b"inside");
        // A link to a file that isn't there yet: not followed, so nothing is made there.
        let missing = outside.path().join("made-through-the-link");
        let dangling = devices.join("dangling.vault.tmp");
        if link_file(&missing, &dangling) {
            assert!(
                target
                    .put_through(&dangling, device(1), b"new copy")
                    .is_err()
            );
            assert!(fs::symlink_metadata(&dangling).is_ok(), "the link is kept");
        } else {
            eprintln!("no symbolic links on this computer: that case is skipped");
        }
        assert!(!missing.exists());

        assert_eq!(target.get(device(1)).unwrap(), b"old copy");
        assert_eq!(target.get(device(2)).unwrap(), b"a neighbour's copy");
        assert!(names(outside.path()).is_empty());
    }

    #[test]
    fn a_copy_that_cant_be_put_in_place_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let id = "f".repeat(32);
        let target = FolderTarget::new(dir.path(), &id).unwrap();
        let devices = dir.path().join(&id).join("devices");
        // A folder where this device's copy goes: the rename fails.
        let in_the_way = target.path(device(1));
        fs::create_dir_all(&in_the_way).unwrap();
        fs::write(in_the_way.join("inside"), b"inside").unwrap();
        assert!(target.put(device(1), b"copy").is_err());
        assert_eq!(fs::read(in_the_way.join("inside")).unwrap(), b"inside");
        assert_eq!(names(&devices), [format!("{}.vault", device(1).to_hex())]);
    }

    #[test]
    fn temporary_names_are_fresh_and_never_listed() {
        let dir = tempfile::tempdir().unwrap();
        let target = FolderTarget::new(dir.path(), &"a".repeat(32)).unwrap();
        let one = target.temp_path(device(1)).unwrap();
        let two = target.temp_path(device(1)).unwrap();
        assert_ne!(one, two);
        for temp in [&one, &two] {
            let name = temp.file_name().unwrap().to_str().unwrap();
            assert!(
                name.starts_with(&format!(".{}.", device(1).to_hex())),
                "{name}"
            );
            assert!(name.ends_with(".vault.tmp"), "{name}");
            assert_ne!(name, old_temp_name(device(1)));
            assert_eq!(temp.parent(), Some(target.devices.as_path()));
        }
        fs::create_dir_all(&target.devices).unwrap();
        fs::write(&one, b"half a copy").unwrap();
        assert!(target.list().unwrap().is_empty());
    }

    #[test]
    fn a_linked_vault_or_devices_folder_is_not_written_through() {
        for linked in ["vault", "devices"] {
            let dir = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            let id = "b".repeat(32);
            let vault_dir = dir.path().join(&id);
            let link = if linked == "vault" {
                vault_dir.clone()
            } else {
                fs::create_dir(&vault_dir).unwrap();
                vault_dir.join("devices")
            };
            if !link_dir(outside.path(), &link) {
                eprintln!("no links to folders on this computer: skipped");
                return;
            }
            // A copy of theirs under the name a removed device's copy would have.
            let theirs = outside.path().join(format!("{}.vault", device(2).to_hex()));
            fs::write(&theirs, b"theirs").unwrap();
            let target = FolderTarget::new(dir.path(), &id).unwrap();
            let refused = format!("{:#}", target.put(device(1), b"copy").unwrap_err());
            assert!(refused.contains("link"), "{refused}");
            assert!(target.remove(device(2)).is_err());
            assert_eq!(fs::read(&theirs).unwrap(), b"theirs");
            assert_eq!(
                names(outside.path()),
                [format!("{}.vault", device(2).to_hex())],
                "nothing made there ({linked})"
            );
        }
    }

    #[test]
    fn a_watch_makes_nothing_inside_a_link() {
        for linked in ["vault", "devices"] {
            let dir = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            let id = "9".repeat(32);
            let vault_dir = dir.path().join(&id);
            let link = if linked == "vault" {
                vault_dir.clone()
            } else {
                fs::create_dir(&vault_dir).unwrap();
                vault_dir.join("devices")
            };
            if !link_dir(outside.path(), &link) {
                eprintln!("no links to folders on this computer: skipped");
                return;
            }
            // Told to stop already, so the watch only makes its folders and returns.
            let stop = std::sync::atomic::AtomicBool::new(true);
            watch_folder(dir.path(), &id, device(1), &stop, || {
                panic!("nothing is heard through a link");
            });
            assert!(
                names(outside.path()).is_empty(),
                "nothing made there ({linked})"
            );
            let target = FolderTarget::new(dir.path(), &id).unwrap();
            assert!(target.make_folders().is_err(), "{linked}");
        }
        // Real folders are made and watched.
        let dir = tempfile::tempdir().unwrap();
        let id = "8".repeat(32);
        let stop = std::sync::atomic::AtomicBool::new(true);
        watch_folder(dir.path(), &id, device(1), &stop, || {});
        assert!(dir.path().join(&id).join("devices").is_dir());
    }

    /// Makes `path` look last written `ago`.
    fn age(path: &Path, ago: Duration) {
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - ago)
            .unwrap();
    }

    #[test]
    fn what_an_interrupted_write_left_behind_is_cleared_later() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = FolderTarget::new(dir.path(), &"7".repeat(32)).unwrap();
        target.put(device(1), b"first copy").unwrap();
        let devices = &target.devices;
        let (day, hour) = (Duration::from_secs(86_400), Duration::from_secs(3_600));
        let left = |name: &str, ago: Duration| {
            let path = devices.join(name);
            fs::write(&path, b"part of a sealed copy").unwrap();
            age(&path, ago);
            path
        };
        let fresh_name = |n: u8| {
            let path = target.temp_path(device(n)).unwrap();
            path.file_name().unwrap().to_str().unwrap().to_owned()
        };
        // This device's, from days ago: an interrupted write's, and an older version's.
        let old = left(&fresh_name(1), 3 * day);
        let older = left(&old_temp_name(device(1)), 3 * day);
        // Being written now (or an hour ago, on a slow share), another device's, and names
        // this app doesn't write under.
        let other = left(&fresh_name(2), 3 * day);
        let own = device(1).to_hex();
        let kept = [
            left(&fresh_name(1), hour),
            other.clone(),
            left(&format!(".{own}.notes.vault.tmp"), 3 * day),
            left(&format!(".{own}.vault.tmp.txt"), 3 * day),
            left(&format!("{own}.vault.tmp"), 3 * day),
            left("notes.txt", 3 * day),
        ];
        // A folder under such a name is no leftover.
        let folder = devices.join(fresh_name(1));
        fs::create_dir(&folder).unwrap();

        target.put(device(1), b"second copy").unwrap();
        assert!(!old.exists(), "an interrupted write's");
        assert!(!older.exists(), "an older version's");
        for path in &kept {
            assert!(path.exists(), "{}", path.display());
        }
        assert!(folder.is_dir());
        assert_eq!(target.get(device(1)).unwrap(), b"second copy");

        // A device removed from the vault writes nothing here again: its leftovers go with its
        // copy, however recent, and a link under such a name goes alone.
        let theirs = outside.path().join("theirs.txt");
        fs::write(&theirs, b"theirs").unwrap();
        target.put(device(2), b"another device's copy").unwrap();
        let recent = left(&fresh_name(2), Duration::from_secs(5));
        let link = devices.join(old_temp_name(device(2)));
        let linked = link_file(&theirs, &link);
        if linked {
            // A link's own time is when it was made.
            std::thread::sleep(Duration::from_millis(50));
        }
        target.remove(device(2)).unwrap();
        assert!(!recent.exists() && !other.exists());
        if linked {
            assert!(fs::symlink_metadata(&link).is_err(), "the link is gone");
        }
        assert_eq!(fs::read(&theirs).unwrap(), b"theirs");
        assert_eq!(target.get(device(1)).unwrap(), b"second copy");
    }

    #[test]
    fn a_webdav_place_on_plain_http_is_refused_before_its_password_is_read() {
        for url in [
            "http://100.101.102.103:8080/dav",
            "http://[fd7a:115c:a1e0::1]:8080/dav",
        ] {
            let to = SyncTo::Webdav {
                url: url.into(),
                user: "dav-tester".into(),
            };
            let refused = open_target(&"e".repeat(32), device(1), &to)
                .err()
                .expect("refused");
            let refused = format!("{refused:#}");
            assert!(refused.contains("https://"), "{url}: {refused}");
        }
    }

    #[test]
    fn a_copy_too_big_to_be_a_vault_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let target = FolderTarget::new(dir.path(), &"a".repeat(32)).unwrap();
        target.put(device(1), b"small").unwrap();
        let file = fs::File::create(target.path(device(2))).unwrap();
        file.set_len(MAX_COPY_BYTES + 1).unwrap();
        let fetched = fetch(&target, device(9), &Tags::new()).unwrap();
        assert_eq!(fetched.copies.len(), 1);
        assert_eq!(fetched.unreadable.len(), 1);
    }

    /// A device on the old key can't read a copy sealed under a renewed one: the round says
    /// so, the new Secret Key and the master password take the new key, and the device that
    /// renewed knows the other's old copy for what it is.
    #[test]
    fn a_renewed_vault_key_is_told_apart_and_taken() {
        use vault_core::{ItemData, KdfParams};
        const PASSWORD: &str = "test master password";
        let secret_key = SecretKey::generate().unwrap();
        let mut first =
            Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
        first
            .add_item(&ItemData::login(
                "Shared",
                "me",
                "test-pw",
                "shared.example",
            ))
            .unwrap();
        let bytes = first.to_bytes().unwrap();
        let open = |bytes: &[u8]| {
            let mut vault = Vault::open(
                bytes,
                vault_core::Unlock::Password {
                    password: PASSWORD,
                    secret_key: &secret_key,
                },
            )
            .unwrap();
            vault.set_device(DeviceId::generate().unwrap());
            vault
        };
        let (mut a, mut b) = (open(&bytes), open(&bytes));
        let (a_id, b_id) = (a.device(), b.device());
        let vault_id = a.id_hex();
        let reading_of = |device: DeviceId, copy: Vec<u8>| Reading {
            main: Ok(Fetched {
                copies: vec![(device, copy)],
                ..Fetched::default()
            }),
            backup: None,
        };
        let b_old_copy = b.to_bytes().unwrap();

        // A renews, remembering what opened it before.
        let mut state_a = crate::DeviceState::default();
        let before = a.unlock_id();
        let renewed = a.renew_key(PASSWORD, &secret_key, None).unwrap();
        state_a.retire_unlock(&vault_id, &before);
        let a_copy = a.to_bytes().unwrap();

        // B can't read it, and doesn't know that header: maybe renewed there.
        let mut state_b = crate::DeviceState::default();
        let reading = reading_of(a_id, a_copy.clone());
        let round = merge_reading(&mut b, &reading, &mut SeenRevisions::new());
        let mismatch = key_mismatch(&vault_id, &reading, &round, &state_b);
        assert!(mismatch.behind.is_empty());
        assert_eq!(mismatch.renewed.len(), 1);
        // A wrong Secret Key takes nothing; the new one does.
        let wrong = SecretKey::generate().unwrap();
        assert!(matches!(
            take_renewed_key(
                &mut b,
                &mismatch.renewed,
                PASSWORD,
                &wrong,
                None,
                &mut state_b
            ),
            Err(vault_core::Error::DecryptionFailed)
        ));
        let b_before = b.unlock_id();
        let former = take_renewed_key(
            &mut b,
            &mismatch.renewed,
            PASSWORD,
            &renewed.secret_key,
            None,
            &mut state_b,
        )
        .unwrap();
        assert!(former.is_some());
        assert!(state_b.unlock_retired(&vault_id, &b_before));
        let round = merge_reading(&mut b, &reading, &mut SeenRevisions::new());
        assert!(round.refused.is_empty(), "{:?}", round.refused);

        // A, which renewed, sees B's copy from before as waiting for B, not as news.
        let reading = reading_of(b_id, b_old_copy);
        let round = merge_reading(&mut a, &reading, &mut SeenRevisions::new());
        let mismatch = key_mismatch(&vault_id, &reading, &round, &state_a);
        assert_eq!(mismatch.behind, [b_id]);
        assert!(mismatch.renewed.is_empty());
    }

    #[test]
    fn a_copy_that_cant_be_used_is_named_once_and_kept_until_it_can() {
        let (a, b) = (device(1), device(2));
        let fetched = |copies: Vec<DeviceId>, unreadable: Vec<DeviceId>| Reading {
            main: Ok(Fetched {
                copies: copies.into_iter().map(|d| (d, Vec::new())).collect(),
                unreadable: unreadable
                    .into_iter()
                    .map(|d| (d, "the server said 500".to_owned()))
                    .collect(),
                ..Fetched::default()
            }),
            backup: None,
        };
        let refused = |device| Round {
            refused: vec![(device, vault_core::Error::SyncRollback)],
            ..Round::default()
        };
        let mut problems = CopyProblems::default();
        // A refused, B unreadable: both new.
        let new = problems.note(&fetched(vec![a], vec![b]), &refused(a), 100);
        assert_eq!(new.len(), 2);
        assert!(problems.of(a).unwrap().refused);
        assert!(!problems.of(b).unwrap().refused);
        assert_eq!(problems.of(b).unwrap().at, 100);
        // The same again: nothing new to tell, the first time kept. A's copy is unchanged
        // (not read again) and still counts.
        let new = problems.note(&fetched(vec![], vec![b]), &Round::default(), 200);
        assert!(new.is_empty());
        assert_eq!(problems.of(b).unwrap().at, 100);
        assert!(problems.of(a).is_some());
        // Waiting for the item lock, or under another key, is said apart.
        let locked = Round {
            refused: vec![
                (a, vault_core::Error::SecretsLocked),
                (b, vault_core::Error::DecryptionFailed),
            ],
            ..Round::default()
        };
        let new = problems.note(&fetched(vec![a, b], vec![]), &locked, 300);
        assert!(new.is_empty());
        assert!(problems.all().is_empty());
        // Merged: gone.
        problems.note(&fetched(vec![], vec![b]), &Round::default(), 400);
        let merged = Round {
            reports: vec![MergeReport {
                writer: b,
                ..MergeReport::default()
            }],
            ..Round::default()
        };
        problems.note(&fetched(vec![b], vec![]), &merged, 500);
        assert!(problems.of(b).is_none());
    }
}
