//! What the server keeps, as plain files under one data folder:
//!
//! ```text
//! <data>/admin-invites.json                  invites made with `vault-server invite`
//! <data>/vaults/<vault>/enrolled.json        the devices allowed in, with their public keys
//! <data>/vaults/<vault>/invites.json         invites made by an enrolled device
//! <data>/vaults/<vault>/copies/<device>.vault  each device's sealed copy
//! <data>/app/android.apk, android.json        the phone app's update (`publish-app`)
//! ```
//!
//! Invites are stored as digests only. Every file is written beside its place and renamed
//! over it, so a crash never leaves half a file. All calls are blocking: the server runs them
//! off its async threads.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
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
}

#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root.join("vaults"))
            .with_context(|| format!("creating the data folder {}", root.display()))?;
        Ok(Self {
            root: root.to_owned(),
        })
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
        fs::create_dir_all(&dir)?;
        write_json(&dir.join("enrolled.json"), devices)
    }

    /// Adds (or, enrolled again with a new key, replaces) a device.
    pub fn enroll(&self, vault: &str, device: Device) -> Result<()> {
        let mut devices = self.devices(vault)?;
        devices.retain(|d| d.device != device.device);
        if devices.len() >= MAX_DEVICES {
            bail!("too many devices");
        }
        devices.push(device);
        self.write_devices(vault, &devices)
    }

    /// Notes when a device was last heard from.
    pub fn touch(&self, vault: &str, device: &str, at: i64) -> Result<()> {
        let mut devices = self.devices(vault)?;
        if let Some(entry) = devices.iter_mut().find(|d| d.device == device) {
            entry.seen_at = at;
            self.write_devices(vault, &devices)?;
        }
        Ok(())
    }

    /// Takes a device out of the vault: its key and its copy. Returns whether it was there.
    pub fn remove(&self, vault: &str, device: &str) -> Result<bool> {
        let mut devices = self.devices(vault)?;
        let before = devices.len();
        devices.retain(|d| d.device != device);
        let was_enrolled = devices.len() != before;
        if was_enrolled {
            self.write_devices(vault, &devices)?;
        }
        let had_copy = match fs::remove_file(self.copy_path(vault, device)?) {
            Ok(()) => true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => return Err(err.into()),
        };
        Ok(was_enrolled || had_copy)
    }

    pub fn copies(&self, vault: &str) -> Result<Vec<Copy>> {
        let dir = self.vault_dir(vault)?.join("copies");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut copies = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(device) = name
                .to_str()
                .and_then(|n| n.strip_suffix(".vault"))
                .filter(|d| wire::is_id(d))
            else {
                continue;
            };
            let bytes = fs::read(entry.path())?;
            copies.push(Copy {
                device: device.to_owned(),
                tag: wire::tag(&bytes),
                size: bytes.len() as u64,
            });
        }
        copies.sort_by(|a, b| a.device.cmp(&b.device));
        Ok(copies)
    }

    pub fn get(&self, vault: &str, device: &str) -> Result<Option<Vec<u8>>> {
        match fs::read(self.copy_path(vault, device)?) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub fn put(&self, vault: &str, device: &str, bytes: &[u8]) -> Result<()> {
        let path = self.copy_path(vault, device)?;
        write_atomic(&path, bytes)
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
    pub fn add_invite(
        &self,
        vault: Option<&str>,
        invite: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<()> {
        let path = self.invites_path(vault)?;
        let mut invites: Vec<StoredInvite> = read_json(&path)?;
        invites.retain(|i| i.expires_at > now);
        if invites.len() >= MAX_INVITES {
            bail!("too many invites waiting");
        }
        invites.push(StoredInvite {
            digest: wire::hex(&wire::invite_digest(invite)),
            expires_at,
        });
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_json(&path, &invites)
    }

    /// Uses up an invite for `vault`: one made for it, or an admin invite. Returns whether
    /// there was one.
    pub fn take_invite(&self, vault: &str, invite: &str, now: i64) -> Result<bool> {
        let digest = wire::invite_digest(invite);
        for scope in [Some(vault), None] {
            let path = self.invites_path(scope)?;
            let mut invites: Vec<StoredInvite> = read_json(&path)?;
            let before = invites.len();
            invites.retain(|i| i.expires_at > now);
            let found = invites.iter().position(|i| {
                wire::unhex::<32>(&i.digest).is_some_and(|d| wire::same_digest(&d, &digest))
            });
            if let Some(index) = found {
                invites.remove(index);
            }
            if found.is_some() || invites.len() != before {
                write_json(&path, &invites)?;
            }
            if found.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn invites_path(&self, vault: Option<&str>) -> Result<PathBuf> {
        Ok(match vault {
            Some(vault) => self.vault_dir(vault)?.join("invites.json"),
            None => self.root.join("admin-invites.json"),
        })
    }
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

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("no parent folder")?;
    fs::create_dir_all(dir)?;
    let name = path.file_name().context("no file name")?.to_string_lossy();
    let temp = dir.join(format!(".{name}.{}.tmp", wire::new_nonce()));
    let written = (|| -> Result<()> {
        let mut file = fs::File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written.with_context(|| format!("writing {}", path.display()))
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

        assert!(store.remove(&vault, &phone).unwrap());
        assert!(store.devices(&vault).unwrap().is_empty());
        assert!(store.get(&vault, &phone).unwrap().is_none());
        assert!(!store.remove(&vault, &phone).unwrap());
    }
}
