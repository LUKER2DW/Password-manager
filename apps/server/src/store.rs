//! What the server keeps, as plain files under one data folder:
//!
//! ```text
//! <data>/store.lock                          locked while the files below are changed
//! <data>/admin-invites.json                  invites made with `vault-server invite`
//! <data>/vaults/<vault>/enrolled.json        the devices allowed in, with their public keys
//! <data>/vaults/<vault>/invites.json         invites made by an enrolled device, or for this
//!                                            vault with `vault-server invite --vault`
//! <data>/vaults/<vault>/generation           a new value whenever a copy is written or removed
//! <data>/vaults/<vault>/copies/<device>.vault  each device's sealed copy
//! <data>/app/android.apk, android.json        the phone app's update (`publish-app`)
//! ```
//!
//! Invites are stored as digests only, with who made them: a device's invites end with its
//! place in the vault. Every file is written beside its place and renamed
//! over it, so a crash never leaves half a file; on Unix only the server's user may read them
//! (files 0600, folders 0700). Every change (the devices, the invites, the copies) is made
//! under one lock, so two at once never lose each other's change (a device removed coming
//! back, an invite used twice). The lock is a file lock on `store.lock` as well as one in
//! memory: the admin commands (`vault-server remove`, `invite`) run as processes of their own
//! beside a serving server, and stand in the same line.
//!
//! A change a device asked for checks again, under the lock and just before it is made, that
//! the device is still enrolled with the key that signed the request. A device taken out while
//! its request was under way (an upload still arriving) changes nothing after it: the removal
//! is wholly before the change (refused) or wholly after it (which undoes it). All calls are
//! blocking: the server runs them off its async threads.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vault_sync_wire::{self as wire, AppRelease, Copy};

/// The most devices one vault may enroll.
pub const MAX_DEVICES: usize = 32;
/// The most invites waiting to be used, per vault and for the admin.
pub const MAX_INVITES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub device: String,
    /// Ed25519 public key (hex).
    pub key: String,
    pub name: String,
    pub added_at: i64,
    #[serde(default)]
    pub seen_at: i64,
}

impl Device {
    pub fn public_key(&self) -> Option<[u8; 32]> {
        wire::unhex(&self.key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredInvite {
    digest: String,
    expires_at: i64,
    /// Who made it: a device's id, or [`ADMIN`]. Older versions didn't note it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    by: Option<String>,
}

/// [`StoredInvite::by`] of an invite made with `vault-server invite` (a device's is its id, 32
/// hex characters).
const ADMIN: &str = "admin";

impl StoredInvite {
    /// Whether who made it may still let someone into `scope` (a vault where `devices` are
    /// enrolled, or with `None` the admin's, good for a new vault): the admin always, a device
    /// while it is enrolled itself. A device taken out leaves no way back in, however it asked
    /// for one before. A vault's invite that doesn't say who made it, stored by an older
    /// version, may be such a device's: it isn't taken, and a new one is made.
    fn stands(&self, scope: Option<&str>, devices: &[Device]) -> bool {
        match (scope, self.by.as_deref()) {
            (None, _) | (Some(_), Some(ADMIN)) => true,
            (Some(_), Some(by)) => devices.iter().any(|d| d.device == by),
            (Some(_), None) => false,
        }
    }
}

/// A change a device asked for, refused because the device was taken out of the vault after
/// its request was let in (the key that signed it is no longer enrolled). The answer is the one
/// a new request from it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revoked;

#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
    /// Held while a file is read, changed and written back, with the file lock.
    lock: Arc<Mutex<()>>,
}

/// While held, nothing else changes the store's files: no other request of this server (the
/// lock in memory), and no admin command run beside it (the lock on `store.lock`, which the
/// operating system lets go of when the file is closed, even if the process dies).
struct Changing<'a> {
    _file: fs::File,
    _here: MutexGuard<'a, ()>,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        create_private_dir(&root.join("vaults"))
            .with_context(|| format!("creating the data folder {}", root.display()))?;
        Ok(Self {
            root: root.to_owned(),
            lock: Arc::default(),
        })
    }

    /// One change at a time, in this process and among all processes using this data folder.
    /// A panic while the lock in memory was held left nothing half written (every write is
    /// whole), so it is taken again.
    fn changing(&self) -> Result<Changing<'_>> {
        let here = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let path = self.root.join("store.lock");
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.lock()
            .with_context(|| format!("locking {}", path.display()))?;
        Ok(Changing {
            _file: file,
            _here: here,
        })
    }

    /// Whether `signer`, the device a request was let in as, is still enrolled in `vault` with
    /// the key that signed it. A change it asked for checks this again under the lock, and an
    /// answer once it has been put together: a device taken out meanwhile (or enrolled again
    /// with another key) gets nothing more.
    pub fn still_enrolled(&self, vault: &str, signer: &Device) -> Result<bool> {
        Ok(self
            .device(vault, &signer.device)?
            .is_some_and(|d| d.key == signer.key))
    }

    fn generation_path(&self, vault: &str) -> Result<PathBuf> {
        Ok(self.vault_dir(vault)?.join("generation"))
    }

    /// Where the copies of `vault` stand: a new value whenever one is written or removed, by
    /// this process or another (`vault-server remove`). A listing kept in memory is good only
    /// while this stays the same. Empty before the first change.
    pub fn generation(&self, vault: &str) -> Result<String> {
        match fs::read_to_string(self.generation_path(vault)?) {
            Ok(text) => Ok(text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(err) => Err(err.into()),
        }
    }

    /// The copies of `vault` with the generation read before them. A change made while they
    /// are read writes its new generation only once it is made, so the listing is never kept
    /// as newer than it is: at worst it is read again.
    pub fn listing(&self, vault: &str) -> Result<(String, Vec<Copy>)> {
        let generation = self.generation(vault)?;
        Ok((generation, self.copies(vault)?))
    }

    /// Notes, under the lock, that a copy of `vault` was just written or removed.
    fn moved(&self, _changing: &Changing<'_>, vault: &str) -> Result<()> {
        write_atomic(&self.generation_path(vault)?, wire::new_nonce().as_bytes())
    }

    fn vault_dir(&self, vault: &str) -> Result<PathBuf> {
        if !wire::is_id(vault) {
            bail!("not a vault id");
        }
        Ok(self.root.join("vaults").join(vault))
    }

    fn copy_path(&self, vault: &str, device: &str) -> Result<PathBuf> {
        if !wire::is_id(device) {
            bail!("not a device id");
        }
        Ok(self
            .vault_dir(vault)?
            .join("copies")
            .join(format!("{device}.vault")))
    }

    /// Every vault with at least one enrolled device.
    pub fn vaults(&self) -> Result<Vec<String>> {
        let mut vaults = Vec::new();
        for entry in fs::read_dir(self.root.join("vaults"))? {
            let name = entry?.file_name();
            if let Some(name) = name.to_str().filter(|n| wire::is_id(n)) {
                vaults.push(name.to_owned());
            }
        }
        vaults.sort();
        Ok(vaults)
    }

    pub fn devices(&self, vault: &str) -> Result<Vec<Device>> {
        read_json(&self.vault_dir(vault)?.join("enrolled.json"))
    }

    pub fn device(&self, vault: &str, device: &str) -> Result<Option<Device>> {
        Ok(self
            .devices(vault)?
            .into_iter()
            .find(|d| d.device == device))
    }

    fn write_devices(&self, vault: &str, devices: &[Device]) -> Result<()> {
        let dir = self.vault_dir(vault)?;
        create_private_dir(&dir)?;
        write_json(&dir.join("enrolled.json"), devices)
    }

    /// Adds a device. One already enrolled isn't enrolled again: a device that lost its key
    /// joins as a new device (with a new id), so an invite can't take over another device's
    /// place.
    pub fn enroll(&self, vault: &str, device: Device) -> Result<()> {
        let _changing = self.changing()?;
        let mut devices = self.devices(vault)?;
        if devices.iter().any(|d| d.device == device.device) {
            bail!("already enrolled");
        }
        if devices.len() >= MAX_DEVICES {
            bail!("too many devices");
        }
        devices.push(device);
        self.write_devices(vault, &devices)
    }

    /// Enrolls `device` with the invite `invite`, both or neither (see [`Store::enroll`]),
    /// under one hold of the lock. An invite made for this vault always counts. An admin
    /// invite good for any vault only starts a vault (one with no device yet): one that leaked
    /// can't put a stranger's device into a vault in use. A device joins such a vault with an
    /// invite from a device already in, or from `vault-server invite --vault`. `Ok(Err(why))`
    /// for a refusal, which leaves the invite as it was.
    ///
    /// The invite is checked first. Whoever has no good one gets [`Refusal::Invite`] whatever
    /// the vault holds: they learn neither that a device id is enrolled nor that the vault is
    /// full. The other answers are for someone the admin or a device of the vault gave an
    /// invite to.
    pub fn enroll_with_invite(
        &self,
        vault: &str,
        invite: &str,
        device: Device,
        now: i64,
    ) -> Result<std::result::Result<(), Refusal>> {
        let changing = self.changing()?;
        let mut devices = self.devices(vault)?;
        let digest = wire::invite_digest(invite);
        let scope = if self.use_invite(&changing, Some(vault), &devices, &digest, now, false)? {
            Some(vault)
        } else if self.use_invite(&changing, None, &[], &digest, now, false)? {
            if !devices.is_empty() {
                return Ok(Err(Refusal::NewVaultOnly));
            }
            None
        } else {
            return Ok(Err(Refusal::Invite));
        };
        if devices.iter().any(|d| d.device == device.device) {
            return Ok(Err(Refusal::AlreadyEnrolled));
        }
        if devices.len() >= MAX_DEVICES {
            return Ok(Err(Refusal::TooManyDevices));
        }
        // Found a moment ago under the same hold of the lock, so it is there to take.
        if !self.use_invite(&changing, scope, &devices, &digest, now, true)? {
            return Ok(Err(Refusal::Invite));
        }
        devices.push(device);
        self.write_devices(vault, &devices)?;
        Ok(Ok(()))
    }

    /// Notes when a device was last heard from. Only a device still enrolled: one removed
    /// meanwhile, by a request or by `vault-server remove`, isn't written back.
    pub fn touch(&self, vault: &str, device: &str, at: i64) -> Result<()> {
        let _changing = self.changing()?;
        let mut devices = self.devices(vault)?;
        if let Some(entry) = devices.iter_mut().find(|d| d.device == device) {
            entry.seen_at = at;
            self.write_devices(vault, &devices)?;
        }
        Ok(())
    }

    /// Takes a device out of the vault: its key, the invites it made and its copy. Returns
    /// whether it was there. This is the admin's removal (`vault-server remove`); a device's
    /// goes through [`Store::remove_for`].
    pub fn remove(&self, vault: &str, device: &str) -> Result<bool> {
        let changing = self.changing()?;
        self.remove_locked(&changing, vault, device)
    }

    /// [`Store::remove`] asked for by `signer`, made only if `signer` is still enrolled with
    /// the key that signed the request: a device taken out while its request was under way
    /// takes no one else out.
    pub fn remove_for(
        &self,
        vault: &str,
        signer: &Device,
        device: &str,
    ) -> Result<std::result::Result<bool, Revoked>> {
        let changing = self.changing()?;
        if !self.still_enrolled(vault, signer)? {
            return Ok(Err(Revoked));
        }
        self.remove_locked(&changing, vault, device).map(Ok)
    }

    /// The steps in the order that matters if they are cut short (the disk full, the process
    /// killed): the key first, then the invites. Each is made again by the next try, also when
    /// an earlier one got as far as having nothing left to take out: the generation moves every
    /// time, so a listing kept from before never outlives a removal tried again.
    fn remove_locked(&self, changing: &Changing<'_>, vault: &str, device: &str) -> Result<bool> {
        let copy = self.copy_path(vault, device)?;
        // Nothing is made for a vault that isn't here (a mistyped id).
        if !self.vault_dir(vault)?.is_dir() {
            return Ok(false);
        }
        let mut devices = self.devices(vault)?;
        let before = devices.len();
        devices.retain(|d| d.device != device);
        let was_enrolled = devices.len() != before;
        if was_enrolled {
            self.write_devices(vault, &devices)?;
        }
        self.drop_fallen_invites(changing, vault, &devices)?;
        // Before the copy goes, so that a removal cut short right after it is noticed too; and
        // after, since a listing read in between has the new generation and the old copy.
        self.moved(changing, vault)?;
        let had_copy = match fs::remove_file(copy) {
            Ok(()) => true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => return Err(err.into()),
        };
        self.moved(changing, vault)?;
        Ok(was_enrolled || had_copy)
    }

    pub fn copies(&self, vault: &str) -> Result<Vec<Copy>> {
        read_copies(self.copy_files(vault)?)
    }

    /// Each device that has a copy here, with its file.
    fn copy_files(&self, vault: &str) -> Result<Vec<(String, PathBuf)>> {
        let dir = self.vault_dir(vault)?.join("copies");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if let Some(device) = name
                .to_str()
                .and_then(|n| n.strip_suffix(".vault"))
                .filter(|d| wire::is_id(d))
            {
                files.push((device.to_owned(), entry.path()));
            }
        }
        files.sort();
        Ok(files)
    }

    pub fn get(&self, vault: &str, device: &str) -> Result<Option<Vec<u8>>> {
        match fs::read(self.copy_path(vault, device)?) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Puts `device`'s copy in place, whoever is enrolled. The API writes a device's copy
    /// through [`Store::put_for`].
    pub fn put(&self, vault: &str, device: &str, bytes: &[u8]) -> Result<()> {
        let staged = Staged::write(&self.copy_path(vault, device)?, bytes)?;
        let changing = self.changing()?;
        staged.commit()?;
        self.moved(&changing, vault)
    }

    /// Puts `signer`'s copy in place, if `signer` is still enrolled with the key that signed
    /// the request (else `Err(Revoked)`, and nothing changes). With `expected` (the tag of
    /// `If-Match`), only over the copy with that tag: `Ok(false)` when another one is there.
    ///
    /// The copy is written and synced beside its place before the lock is taken, so a large
    /// one holds up no one while it reaches the disk; the checks and the rename are made under
    /// the lock. A removal is then wholly before (the copy is refused and deleted) or wholly
    /// after (it takes the copy out with the device).
    pub fn put_for(
        &self,
        vault: &str,
        signer: &Device,
        bytes: &[u8],
        expected: Option<&str>,
    ) -> Result<std::result::Result<bool, Revoked>> {
        let staged = Staged::write(&self.copy_path(vault, &signer.device)?, bytes)?;
        let changing = self.changing()?;
        if !self.still_enrolled(vault, signer)? {
            return Ok(Err(Revoked));
        }
        if let Some(expected) = expected {
            let current = self.get(vault, &signer.device)?.map(|b| wire::tag(&b));
            if current.as_deref() != Some(expected) {
                return Ok(Ok(false));
            }
        }
        staged.commit()?;
        self.moved(&changing, vault)?;
        Ok(Ok(true))
    }

    /// Puts an update of the phone app here: its package (an APK, as built) and its version.
    /// The phones fetch it with their device key; Android installs it only if it is signed
    /// like the app already on the phone.
    pub fn publish_app(&self, package: &[u8], version: &str) -> Result<AppRelease> {
        if wire::parse_version(version).is_none() {
            bail!("a version is three numbers, like 0.2.0");
        }
        if package.len() > wire::MAX_APP_BYTES {
            bail!("that package is too large");
        }
        if !package.starts_with(b"PK\x03\x04") {
            bail!("that isn't an APK (an APK is a zip file)");
        }
        let release = AppRelease {
            version: version.trim().to_owned(),
            sha256: Sha256::digest(package)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            size: package.len() as u64,
        };
        let dir = self.root.join("app");
        create_private_dir(&dir)?;
        write_atomic(&dir.join("android.apk"), package)?;
        write_atomic(
            &dir.join("android.json"),
            &serde_json::to_vec_pretty(&release)?,
        )?;
        Ok(release)
    }

    /// The phone app's update, when one was published.
    pub fn app_release(&self) -> Result<Option<AppRelease>> {
        match fs::read(self.root.join("app").join("android.json")) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// The phone app's update package, when one was published.
    pub fn app_package(&self) -> Result<Option<Vec<u8>>> {
        match fs::read(self.root.join("app").join("android.apk")) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Stores a new invite for `vault` (or, with `None`, an admin invite good for any vault).
    /// This is the admin's (`vault-server invite`); a device's goes through
    /// [`Store::add_invite_for`].
    pub fn add_invite(
        &self,
        vault: Option<&str>,
        invite: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<()> {
        let changing = self.changing()?;
        if !self.add_invite_locked(&changing, vault, ADMIN, invite, expires_at, now)? {
            bail!("too many invites waiting");
        }
        Ok(())
    }

    /// Stores an invite `signer` asked for, for `vault`, if `signer` is still enrolled with the
    /// key that signed the request: a device taken out while its request was under way leaves
    /// no way in behind. It is good only while `signer` stays in (see [`Store::remove`]).
    /// `Ok(false)` when too many invites wait already.
    pub fn add_invite_for(
        &self,
        vault: &str,
        signer: &Device,
        invite: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<std::result::Result<bool, Revoked>> {
        let changing = self.changing()?;
        if !self.still_enrolled(vault, signer)? {
            return Ok(Err(Revoked));
        }
        self.add_invite_locked(
            &changing,
            Some(vault),
            &signer.device,
            invite,
            expires_at,
            now,
        )
        .map(Ok)
    }

    /// Adds the invite `by` made (a device's id, or [`ADMIN`]) unless [`MAX_INVITES`] wait
    /// already (`false`).
    fn add_invite_locked(
        &self,
        _changing: &Changing<'_>,
        vault: Option<&str>,
        by: &str,
        invite: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool> {
        let devices = match vault {
            Some(vault) => self.devices(vault)?,
            None => Vec::new(),
        };
        let path = self.invites_path(vault)?;
        let mut invites: Vec<StoredInvite> = read_json(&path)?;
        invites.retain(|i| i.expires_at > now && i.stands(vault, &devices));
        if invites.len() >= MAX_INVITES {
            return Ok(false);
        }
        invites.push(StoredInvite {
            digest: wire::hex(&wire::invite_digest(invite)),
            expires_at,
            by: Some(by.to_owned()),
        });
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        write_json(&path, &invites)?;
        Ok(true)
    }

    /// Uses up an invite for `vault`: one made for it, or an admin invite. Returns whether
    /// there was one.
    pub fn take_invite(&self, vault: &str, invite: &str, now: i64) -> Result<bool> {
        let changing = self.changing()?;
        let devices = self.devices(vault)?;
        let digest = wire::invite_digest(invite);
        Ok(
            self.use_invite(&changing, Some(vault), &devices, &digest, now, true)?
                || self.use_invite(&changing, None, &[], &digest, now, true)?,
        )
    }

    /// Whether the invite with `digest` waits among `scope`'s (a vault's, where `devices` are
    /// enrolled, or with `None` the admin's); with `take`, uses it up. Expired ones, and those
    /// of devices no longer in, are dropped on the way.
    fn use_invite(
        &self,
        _changing: &Changing<'_>,
        scope: Option<&str>,
        devices: &[Device],
        digest: &[u8; 32],
        now: i64,
        take: bool,
    ) -> Result<bool> {
        let path = self.invites_path(scope)?;
        let mut invites: Vec<StoredInvite> = read_json(&path)?;
        let before = invites.len();
        invites.retain(|i| i.expires_at > now && i.stands(scope, devices));
        let found = invites.iter().position(|i| {
            wire::unhex::<32>(&i.digest).is_some_and(|d| wire::same_digest(&d, digest))
        });
        if take && let Some(index) = found {
            invites.remove(index);
        }
        if invites.len() != before {
            write_json(&path, &invites)?;
        }
        Ok(found.is_some())
    }

    /// Drops the invites of `vault` whose maker isn't among its `devices` (any more).
    fn drop_fallen_invites(
        &self,
        _changing: &Changing<'_>,
        vault: &str,
        devices: &[Device],
    ) -> Result<()> {
        let path = self.invites_path(Some(vault))?;
        let mut invites: Vec<StoredInvite> = read_json(&path)?;
        let before = invites.len();
        invites.retain(|i| i.stands(Some(vault), devices));
        if invites.len() != before {
            write_json(&path, &invites)?;
        }
        Ok(())
    }

    fn invites_path(&self, vault: Option<&str>) -> Result<PathBuf> {
        Ok(match vault {
            Some(vault) => self.vault_dir(vault)?.join("invites.json"),
            None => self.root.join("admin-invites.json"),
        })
    }
}

/// Reads the copies in `files`. One that is gone by now (a listing takes no lock, and an admin
/// command may take a device out meanwhile) is left out, as if it had been gone before.
fn read_copies(files: Vec<(String, PathBuf)>) -> Result<Vec<Copy>> {
    let mut copies = Vec::with_capacity(files.len());
    for (device, path) in files {
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
        copies.push(Copy {
            device,
            tag: wire::tag(&bytes),
            size: bytes.len() as u64,
        });
    }
    Ok(copies)
}

fn read_json<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T> {
    match fs::read(path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    write_atomic(path, &serde_json::to_vec_pretty(value)?)
}

/// Why an enrollment was refused (the API's answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The invite is wrong, used or expired.
    Invite,
    TooManyDevices,
    /// That device id is enrolled already.
    AlreadyEnrolled,
    /// An admin invite good for any vault, offered to a vault that has devices already: it
    /// only starts a new vault.
    NewVaultOnly,
}

/// A folder only the server's user may open (0700 on Unix), with its parents.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    Staged::write(path, bytes)?.commit()
}

/// A file written whole and synced beside its place, not in it yet: [`Staged::commit`] renames
/// it over its place, and dropping it first deletes it.
struct Staged {
    temp: PathBuf,
    path: PathBuf,
    committed: bool,
}

impl Staged {
    fn write(path: &Path, bytes: &[u8]) -> Result<Self> {
        let dir = path.parent().context("no parent folder")?;
        create_private_dir(dir)?;
        let name = path.file_name().context("no file name")?.to_string_lossy();
        let staged = Self {
            temp: dir.join(format!(".{name}.{}.tmp", wire::new_nonce())),
            path: path.to_owned(),
            committed: false,
        };
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        (|| -> std::io::Result<()> {
            let mut file = options.open(&staged.temp)?;
            file.write_all(bytes)?;
            file.sync_all()
        })()
        .with_context(|| format!("writing {}", path.display()))?;
        Ok(staged)
    }

    fn commit(mut self) -> Result<()> {
        fs::rename(&self.temp, &self.path)
            .with_context(|| format!("writing {}", self.path.display()))?;
        self.committed = true;
        // The rename itself reaches the disk too (on Unix a folder is synced like a file).
        #[cfg(unix)]
        if let Some(dir) = self.path.parent() {
            fs::File::open(dir)
                .and_then(|dir| dir.sync_all())
                .with_context(|| format!("writing {}", self.path.display()))?;
        }
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.temp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(c: char) -> String {
        c.to_string().repeat(32)
    }

    #[test]
    fn devices_copies_and_invites() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (vault, phone) = (id('a'), id('b'));
        assert!(store.devices(&vault).unwrap().is_empty());
        store
            .enroll(
                &vault,
                Device {
                    device: phone.clone(),
                    key: "00".repeat(32),
                    name: "Phone".into(),
                    added_at: 1,
                    seen_at: 0,
                },
            )
            .unwrap();
        assert_eq!(store.vaults().unwrap(), std::slice::from_ref(&vault));
        store.put(&vault, &phone, b"sealed").unwrap();
        store.put(&vault, &phone, b"sealed, newer").unwrap();
        assert_eq!(
            store.get(&vault, &phone).unwrap().unwrap(),
            b"sealed, newer"
        );
        assert_eq!(store.copies(&vault).unwrap().len(), 1);
        assert!(store.put(&vault, "../x", b"").is_err());
        assert!(store.get("..", &phone).is_err());

        store.add_invite(Some(&vault), &id('c'), 100, 0).unwrap();
        assert!(
            !store.take_invite(&vault, &id('c'), 100).unwrap(),
            "expired"
        );
        store.add_invite(Some(&vault), &id('c'), 100, 0).unwrap();
        assert!(
            !store.take_invite(&id('f'), &id('c'), 50).unwrap(),
            "another vault's"
        );
        assert!(store.take_invite(&vault, &id('c'), 50).unwrap());
        assert!(
            !store.take_invite(&vault, &id('c'), 50).unwrap(),
            "used once"
        );
        store.add_invite(None, &id('d'), 100, 0).unwrap();
        assert!(
            store.take_invite(&id('e'), &id('d'), 50).unwrap(),
            "admin invite"
        );

        // An enrolled device isn't enrolled again (a new key would take over its place).
        let again = Device {
            device: phone.clone(),
            key: "11".repeat(32),
            name: "Thief".into(),
            added_at: 2,
            seen_at: 0,
        };
        assert!(store.enroll(&vault, again.clone()).is_err());
        store.add_invite(Some(&vault), &id('9'), 100, 0).unwrap();
        assert_eq!(
            store
                .enroll_with_invite(&vault, &id('9'), again, 50)
                .unwrap(),
            Err(Refusal::AlreadyEnrolled)
        );
        assert_eq!(store.devices(&vault).unwrap()[0].key, "00".repeat(32));
        assert!(
            store.take_invite(&vault, &id('9'), 50).unwrap(),
            "a refused enrollment leaves the invite"
        );

        // An admin invite only starts a vault: one in use takes the invites made for it.
        store.add_invite(None, &id('7'), 100, 0).unwrap();
        let newcomer = Device {
            device: id('8'),
            key: "22".repeat(32),
            name: "New".into(),
            added_at: 3,
            seen_at: 0,
        };
        assert_eq!(
            store
                .enroll_with_invite(&vault, &id('7'), newcomer.clone(), 50)
                .unwrap(),
            Err(Refusal::NewVaultOnly)
        );
        assert_eq!(store.devices(&vault).unwrap().len(), 1);
        assert_eq!(
            store
                .enroll_with_invite(&id('6'), &id('7'), newcomer, 50)
                .unwrap(),
            Ok(()),
            "the refusal left it for a new vault"
        );

        assert!(store.remove(&vault, &phone).unwrap());
        assert!(store.devices(&vault).unwrap().is_empty());
        assert!(store.get(&vault, &phone).unwrap().is_none());
        assert!(!store.remove(&vault, &phone).unwrap());
    }

    fn device(c: char, key: &str) -> Device {
        Device {
            device: id(c),
            key: key.repeat(32),
            name: format!("Device {c}"),
            added_at: 1,
            seen_at: 0,
        }
    }

    /// What is in the vault's copies folder, temporary files included.
    fn files_in_copies(dir: &Path, vault: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir.join("vaults").join(vault).join("copies"))
            .map(|entries| {
                entries
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// PM-11: a device taken out while its upload was arriving doesn't bring its copy back,
    /// and the copy written ahead of the check leaves nothing behind.
    #[test]
    fn a_removed_devices_change_is_refused_where_it_is_made() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let vault = id('a');
        let (phone, pc) = (device('b', "00"), device('c', "11"));
        store.enroll(&vault, phone.clone()).unwrap();
        store.enroll(&vault, pc.clone()).unwrap();
        assert_eq!(
            store.put_for(&vault, &phone, b"phone copy", None).unwrap(),
            Ok(true)
        );
        assert_eq!(
            store.put_for(&vault, &pc, b"pc copy", None).unwrap(),
            Ok(true)
        );

        // The admin takes the phone out (`vault-server remove`); its request was let in
        // before that and reaches the store after.
        assert!(store.remove(&vault, &phone.device).unwrap());
        assert_eq!(
            store
                .put_for(&vault, &phone, b"phone copy, late", None)
                .unwrap(),
            Err(Revoked)
        );
        assert!(store.get(&vault, &phone.device).unwrap().is_none());
        assert_eq!(
            files_in_copies(dir.path(), &vault),
            [format!("{}.vault", pc.device)],
            "no copy and no temporary file left"
        );
        // Nor does it take anyone else out, or leave an invite behind.
        assert_eq!(
            store.remove_for(&vault, &phone, &pc.device).unwrap(),
            Err(Revoked)
        );
        assert_eq!(store.devices(&vault).unwrap(), std::slice::from_ref(&pc));
        assert_eq!(
            store
                .add_invite_for(&vault, &phone, &id('9'), 100, 0)
                .unwrap(),
            Err(Revoked)
        );
        assert!(!store.take_invite(&vault, &id('9'), 50).unwrap());
        // Nor does it note that it was seen.
        store.touch(&vault, &phone.device, 99).unwrap();
        assert_eq!(store.devices(&vault).unwrap(), std::slice::from_ref(&pc));

        // Enrolled again with another key, the old key's request is still refused.
        let again = Device {
            key: "22".repeat(32),
            ..phone.clone()
        };
        store.enroll(&vault, again.clone()).unwrap();
        assert_eq!(
            store.put_for(&vault, &phone, b"old key", None).unwrap(),
            Err(Revoked)
        );
        assert_eq!(
            store.put_for(&vault, &again, b"new key", None).unwrap(),
            Ok(true)
        );
        // A device still in: its own changes go through, and `If-Match` still holds.
        assert_eq!(
            store
                .put_for(&vault, &pc, b"pc copy, newer", Some("not the tag"))
                .unwrap(),
            Ok(false)
        );
        assert_eq!(store.get(&vault, &pc.device).unwrap().unwrap(), b"pc copy");
        let tag = wire::tag(b"pc copy");
        assert_eq!(
            store
                .put_for(&vault, &pc, b"pc copy, newer", Some(&tag))
                .unwrap(),
            Ok(true)
        );
        assert_eq!(
            store.add_invite_for(&vault, &pc, &id('8'), 100, 0).unwrap(),
            Ok(true)
        );
        assert_eq!(
            store.remove_for(&vault, &pc, &again.device).unwrap(),
            Ok(true)
        );
        assert_eq!(store.devices(&vault).unwrap(), [pc]);
    }

    /// PM-11: a device taken out leaves no way back in, whenever it made its invites. The
    /// admin's and the other devices' stay.
    #[test]
    fn a_removed_devices_invites_go_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let vault = id('a');
        let (phone, pc) = (device('b', "00"), device('c', "11"));
        let enroll_all = || {
            for device in [&phone, &pc] {
                let _ = store.enroll(&vault, device.clone());
            }
        };
        let invite = |by: &Device, c: char| {
            let added = store.add_invite_for(&vault, by, &id(c), 100, 0).unwrap();
            assert_eq!(added, Ok(true));
        };
        let join = |c: char| {
            let newcomer = Device {
                device: id('f'),
                ..device('d', "44")
            };
            let outcome = store.enroll_with_invite(&vault, &id(c), newcomer, 50);
            let outcome = outcome.unwrap();
            if outcome.is_ok() {
                store.remove(&vault, &id('f')).unwrap();
            }
            outcome
        };
        enroll_all();
        invite(&phone, '1');
        invite(&phone, '2');
        invite(&phone, '3');
        invite(&pc, '4');
        store.add_invite(Some(&vault), &id('5'), 100, 0).unwrap();
        assert_eq!(join('1'), Ok(()), "good while the phone is in");

        // Taken out by the admin, an invite the phone made before isn't good any more.
        assert!(store.remove(&vault, &phone.device).unwrap());
        assert_eq!(join('2'), Err(Refusal::Invite));
        assert!(!store.take_invite(&vault, &id('2'), 50).unwrap());
        // Nor is it once the same device is in again: it makes a new one.
        enroll_all();
        assert_eq!(join('3'), Err(Refusal::Invite));
        // Taken out by the computer: the same.
        invite(&phone, '6');
        assert_eq!(
            store.remove_for(&vault, &pc, &phone.device).unwrap(),
            Ok(true)
        );
        assert_eq!(join('6'), Err(Refusal::Invite));
        // The others' invites stand.
        assert_eq!(join('4'), Ok(()));
        assert_eq!(join('5'), Ok(()));
        assert!(store.devices(&vault).unwrap() == [pc]);
    }

    /// Also if the removal was cut short after the key was taken out, before the invites were:
    /// an invite counts only while its maker is enrolled.
    #[test]
    fn an_invite_whose_maker_is_not_enrolled_is_not_taken() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let vault = id('a');
        let (phone, pc) = (device('b', "00"), device('c', "11"));
        store.enroll(&vault, phone.clone()).unwrap();
        store.enroll(&vault, pc.clone()).unwrap();
        assert_eq!(
            store
                .add_invite_for(&vault, &phone, &id('1'), 100, 0)
                .unwrap(),
            Ok(true)
        );
        store.write_devices(&vault, &[pc]).unwrap();
        let newcomer = device('d', "44");
        assert_eq!(
            store
                .enroll_with_invite(&vault, &id('1'), newcomer, 50)
                .unwrap(),
            Err(Refusal::Invite)
        );
    }

    /// An older version's invites don't say who made them. A vault's may be a device's that was
    /// taken out since: not taken. The admin's (for any new vault) were always the admin's.
    #[test]
    fn a_vaults_invite_of_unknown_maker_is_not_taken() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let vault = id('a');
        let first = device('b', "00");
        store.enroll(&vault, first.clone()).unwrap();
        let older = |c: char| {
            let digest = wire::hex(&wire::invite_digest(&id(c)));
            format!(r#"[{{"digest":"{digest}","expires_at":100}}]"#)
        };
        let path = dir.path().join("vaults").join(&vault).join("invites.json");
        fs::write(&path, older('1')).unwrap();
        assert_eq!(
            store
                .enroll_with_invite(&vault, &id('1'), device('c', "11"), 50)
                .unwrap(),
            Err(Refusal::Invite)
        );
        // It takes no room either, and one made now is taken.
        fs::write(&path, older('1')).unwrap();
        assert_eq!(
            store
                .add_invite_for(&vault, &first, &id('2'), 100, 0)
                .unwrap(),
            Ok(true)
        );
        assert_eq!(
            read_json::<Vec<StoredInvite>>(&path).unwrap().len(),
            1,
            "the older one is dropped"
        );
        assert_eq!(
            store
                .enroll_with_invite(&vault, &id('2'), device('c', "11"), 50)
                .unwrap(),
            Ok(())
        );
        fs::write(dir.path().join("admin-invites.json"), older('3')).unwrap();
        assert_eq!(
            store
                .enroll_with_invite(&id('e'), &id('3'), device('d', "22"), 50)
                .unwrap(),
            Ok(())
        );
    }

    /// N-06: a removal that was cut short after the copy was deleted and before the generation
    /// moved is made good by trying again, though it then finds nothing left to take out.
    #[test]
    fn a_removal_tried_again_always_moves_the_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let vault = id('a');
        let phone = device('b', "00");
        store.enroll(&vault, phone.clone()).unwrap();
        store
            .put_for(&vault, &phone, b"phone", None)
            .unwrap()
            .unwrap();
        let (kept_at, listed) = store.listing(&vault).unwrap();
        assert_eq!(listed.len(), 1);
        // As left by a removal killed right after it deleted the copy.
        store.write_devices(&vault, &[]).unwrap();
        fs::remove_file(store.copy_path(&vault, &phone.device).unwrap()).unwrap();
        assert_eq!(store.generation(&vault).unwrap(), kept_at);

        assert!(!store.remove(&vault, &phone.device).unwrap());
        assert_ne!(store.generation(&vault).unwrap(), kept_at);

        // A vault that isn't here stays that way.
        assert!(!store.remove(&id('f'), &phone.device).unwrap());
        assert_eq!(store.vaults().unwrap(), [vault]);
    }

    /// N-06: the generation that can't be written (a full disk, say) fails the removal before
    /// the copy is deleted: it never goes without the listing noticing.
    #[test]
    fn a_removal_that_cant_move_the_generation_keeps_the_copy_listed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let vault = id('a');
        let phone = device('b', "00");
        store.enroll(&vault, phone.clone()).unwrap();
        store
            .put_for(&vault, &phone, b"phone", None)
            .unwrap()
            .unwrap();
        // Something in the way of the file: it can't be replaced.
        let generation = store.generation_path(&vault).unwrap();
        fs::remove_file(&generation).unwrap();
        fs::create_dir(&generation).unwrap();
        fs::write(generation.join("inside"), b"").unwrap();
        assert!(store.remove(&vault, &phone.device).is_err());
        assert_eq!(store.devices(&vault).unwrap(), [], "its key is out");
        assert_eq!(store.copies(&vault).unwrap().len(), 1);
        // Out of the way again: the next try finishes it.
        fs::remove_dir_all(&generation).unwrap();
        assert!(store.remove(&vault, &phone.device).unwrap());
        assert!(store.copies(&vault).unwrap().is_empty());
    }

    /// A copy deleted between the folder's listing and its reading (an admin removal beside a
    /// device's request) is left out; the listing is not an error.
    #[test]
    fn a_copy_gone_while_the_listing_is_read_is_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let vault = id('a');
        let (phone, pc) = (id('b'), id('c'));
        store.put(&vault, &phone, b"phone").unwrap();
        store.put(&vault, &pc, b"pc").unwrap();
        let files = store.copy_files(&vault).unwrap();
        assert_eq!(files.len(), 2);
        let admin = Store::open(dir.path()).unwrap();
        assert!(admin.remove(&vault, &phone).unwrap());
        let listed = read_copies(files).unwrap();
        assert_eq!(
            listed,
            [Copy {
                device: pc,
                tag: wire::tag(b"pc"),
                size: 2
            }]
        );
        // Another kind of failure is still one.
        let unreadable = dir.path().join("a folder");
        fs::create_dir(&unreadable).unwrap();
        assert!(read_copies(vec![(phone, unreadable)]).is_err());
    }

    /// N-06: every change to the copies, by this process or by an admin command beside it
    /// (another `Store` on the same folder), moves the generation a listing is kept at.
    #[test]
    fn the_generation_moves_with_every_change_to_the_copies() {
        let dir = tempfile::tempdir().unwrap();
        let serving = Store::open(dir.path()).unwrap();
        let admin = Store::open(dir.path()).unwrap();
        let vault = id('a');
        let (phone, pc) = (device('b', "00"), device('c', "11"));
        serving.enroll(&vault, phone.clone()).unwrap();
        serving.enroll(&vault, pc.clone()).unwrap();
        assert_eq!(serving.generation(&vault).unwrap(), "");

        serving
            .put_for(&vault, &phone, b"phone", None)
            .unwrap()
            .unwrap();
        let one = serving.generation(&vault).unwrap();
        assert!(!one.is_empty());
        serving.put_for(&vault, &pc, b"pc", None).unwrap().unwrap();
        let (two, listed) = serving.listing(&vault).unwrap();
        assert_ne!(one, two);
        assert_eq!(listed.len(), 2);

        // The admin's removal, in "another process": the serving store sees it moved.
        assert!(admin.remove(&vault, &phone.device).unwrap());
        let three = serving.generation(&vault).unwrap();
        assert_ne!(two, three);
        let (at, listed) = serving.listing(&vault).unwrap();
        assert_eq!(at, three);
        assert_eq!(listed.len(), 1);
        assert_eq!(serving.device(&vault, &phone.device).unwrap(), None);

        // A refused change moves nothing.
        assert_eq!(
            serving.put_for(&vault, &phone, b"late", None).unwrap(),
            Err(Revoked)
        );
        assert_eq!(serving.generation(&vault).unwrap(), three);
    }

    /// The admin commands run as processes of their own: while one store changes the files,
    /// another on the same folder waits for it.
    #[test]
    fn two_stores_on_one_folder_change_it_one_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let serving = Store::open(dir.path()).unwrap();
        let admin = Store::open(dir.path()).unwrap();
        let vault = id('a');
        let held = serving.changing().unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        let waiting = std::thread::spawn(move || {
            admin.enroll(&vault, device('b', "00")).unwrap();
            done.send(()).unwrap();
        });
        assert!(
            finished
                .recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "the other store changed the files while this one held them"
        );
        drop(held);
        finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the other store went on once they were let go");
        waiting.join().unwrap();
        assert_eq!(serving.devices(&id('a')).unwrap().len(), 1);
    }

    /// Without a good invite the answer is always the same: whether a device id is enrolled
    /// or the vault is full is told only to someone holding one.
    #[test]
    fn an_enrollment_without_a_good_invite_learns_nothing_of_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let vault = id('a');
        let first = device('b', "00");
        store.enroll(&vault, first.clone()).unwrap();
        // The same id as an enrolled device, with no invite or a wrong one.
        let same_id = Device {
            key: "33".repeat(32),
            ..first.clone()
        };
        assert_eq!(
            store
                .enroll_with_invite(&vault, &id('9'), same_id.clone(), 50)
                .unwrap(),
            Err(Refusal::Invite)
        );
        // A full vault.
        for n in 1..MAX_DEVICES {
            store
                .enroll(
                    &vault,
                    Device {
                        device: format!("{n:032}"),
                        ..device('c', "44")
                    },
                )
                .unwrap();
        }
        assert_eq!(
            store
                .enroll_with_invite(&vault, &id('9'), device('d', "55"), 50)
                .unwrap(),
            Err(Refusal::Invite)
        );
        // An expired invite: the same answer, and it is not left to be tried again.
        store.add_invite(Some(&vault), &id('8'), 40, 0).unwrap();
        assert_eq!(
            store
                .enroll_with_invite(&vault, &id('8'), device('d', "55"), 50)
                .unwrap(),
            Err(Refusal::Invite)
        );
        // With a good one, the reason, and the invite stays for another try.
        store.add_invite(Some(&vault), &id('7'), 100, 0).unwrap();
        assert_eq!(
            store
                .enroll_with_invite(&vault, &id('7'), same_id, 50)
                .unwrap(),
            Err(Refusal::AlreadyEnrolled)
        );
        assert_eq!(
            store
                .enroll_with_invite(&vault, &id('7'), device('d', "55"), 50)
                .unwrap(),
            Err(Refusal::TooManyDevices)
        );
        assert!(store.take_invite(&vault, &id('7'), 50).unwrap());
    }
}
