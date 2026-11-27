//! Copies of the vault as a hostile sync place could hand them over (THREAT_MODEL A2, SYNC.md
//! §4.1): a copy under another device's name is refused, this copy stays exactly as it was,
//! and the same copy under its own name still goes in.

use vault_core::{
    Error, ItemData, ItemId, KdfParams, SecretKey, Unlock, Vault, VaultSettings,
    sync::{DeviceId, MergeReport, SeenRevisions, SyncDevice},
};

const PASSWORD: &str = "test master password";

/// One device: its copy of the vault and what it has seen from the others.
struct Device {
    vault: Vault,
    seen: SeenRevisions,
}

impl Device {
    fn copy(&mut self) -> Vec<u8> {
        self.vault.to_bytes().unwrap()
    }

    fn id(&self) -> DeviceId {
        self.vault.device()
    }

    /// The copy as a place lists it: under `listed`'s name.
    fn take_from(&mut self, listed: DeviceId, copy: &[u8]) -> vault_core::Result<MergeReport> {
        self.vault.merge_from(listed, copy, &mut self.seen)
    }

    /// Everything a merge could change here, as the person would see it, and what was seen.
    fn state(&self) -> State {
        let mut items: Vec<(ItemId, ItemData)> = self
            .vault
            .item_ids()
            .map(|id| (id, self.vault.get_item(&id).unwrap()))
            .collect();
        items.sort_by_key(|(id, _)| *id);
        State {
            items,
            folders: self
                .vault
                .folders()
                .iter()
                .map(|f| (f.id.to_hex(), f.name.clone()))
                .collect(),
            devices: self.vault.sync_devices().to_vec(),
            settings: self.vault.settings().clone(),
            revision: self.vault.revision(),
            unlock_id: self.vault.unlock_id(),
            guard_waiting: self.vault.guard_waiting(),
            seen: self.seen.clone(),
        }
    }
}

#[derive(Debug, PartialEq)]
struct State {
    items: Vec<(ItemId, ItemData)>,
    folders: Vec<(String, String)>,
    devices: Vec<SyncDevice>,
    settings: VaultSettings,
    revision: u64,
    unlock_id: [u8; 16],
    guard_waiting: bool,
    seen: SeenRevisions,
}

/// Two devices of one vault, each listed in it, with two logins both have; the second has
/// written a copy with one more item and a folder, which the first hasn't seen yet.
fn two_devices() -> (Device, Device, Vec<u8>, SecretKey) {
    let secret_key = SecretKey::generate().unwrap();
    let mut first =
        Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    for title in ["Shared", "Also shared"] {
        first
            .add_item(&ItemData::login(
                title,
                "me",
                "first-password",
                "https://shared.example",
            ))
            .unwrap();
    }
    let bytes = first.to_bytes().unwrap();
    let device = |n: u8| {
        let mut vault = open(&bytes, &secret_key).unwrap();
        let id = DeviceId::from_bytes([n; 16]);
        vault.set_device(id);
        vault
            .add_sync_device(SyncDevice {
                id,
                name: format!("Device {n}"),
                signing_key: None,
                added_at: 1,
            })
            .unwrap();
        Device {
            vault,
            seen: SeenRevisions::new(),
        }
    };
    let (a, mut b) = (device(1), device(2));
    b.vault
        .add_item(&ItemData::login(
            "From B",
            "b",
            "b-password",
            "https://b.example",
        ))
        .unwrap();
    b.vault.add_folder("B's folder").unwrap();
    let copy = b.copy();
    (a, b, copy, secret_key)
}

fn open(bytes: &[u8], secret_key: &SecretKey) -> vault_core::Result<Vault> {
    Vault::open(
        bytes,
        Unlock::Password {
            password: PASSWORD,
            secret_key,
        },
    )
}

/// The honest copy still goes in after whatever was refused before it.
fn honest_copy_still_merges(a: &mut Device, from: DeviceId, copy: &[u8]) {
    let report = a.take_from(from, copy).unwrap();
    assert_eq!(report.added, 1, "{report:?}");
    assert_eq!(report.writer, from);
    let titles: Vec<String> = a
        .vault
        .summaries()
        .unwrap()
        .into_iter()
        .map(|s| s.title.clone())
        .collect();
    assert!(titles.iter().any(|t| t == "From B"), "{titles:?}");
}

#[test]
fn a_copy_under_another_devices_name_is_refused() {
    let (mut a, b, copy, _) = two_devices();
    let before = a.state();
    let stranger = DeviceId::from_bytes([9; 16]);
    for listed in [stranger, a.id()] {
        assert!(
            matches!(a.take_from(listed, &copy), Err(Error::WrongWriter)),
            "{listed:?}"
        );
    }
    assert_eq!(a.state(), before);
    let own = a.copy();
    let before_own = a.state();
    assert!(matches!(a.take_from(b.id(), &own), Err(Error::WrongWriter)));
    assert_eq!(a.state(), before_own);
    // Under its own name, this device's copy changes nothing.
    assert!(!a.take_from(a.id(), &own).unwrap().changed());
    honest_copy_still_merges(&mut a, b.id(), &copy);
}
