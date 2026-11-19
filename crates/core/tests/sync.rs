//! Merging copies of one vault written by different devices (spec: SYNC.md §4, §9).

use proptest::prelude::*;
use vault_core::{
    Error, GuardCheck, ItemData, ItemId, KdfParams, SecretKey, Unlock, Vault,
    sync::{DeviceId, SeenRevisions, SyncDevice},
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

    fn take(&mut self, copy: &[u8]) -> vault_core::sync::MergeReport {
        self.try_take(copy).unwrap()
    }

    fn try_take(&mut self, copy: &[u8]) -> vault_core::Result<vault_core::sync::MergeReport> {
        self.vault.merge(copy, &mut self.seen)
    }
}

/// `n` devices holding the same vault, each with its own device id. The first item is a
/// login every device has.
fn devices(n: usize) -> (Vec<Device>, ItemId, SecretKey) {
    let secret_key = SecretKey::generate().unwrap();
    let mut first =
        Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    let shared = first
        .add_item(&ItemData::login(
            "Shared",
            "me",
            "first-password",
            "https://shared.example",
        ))
        .unwrap();
    let bytes = first.to_bytes().unwrap();
    let devices = (0..n)
        .map(|_| {
            let mut vault = open(&bytes, &secret_key, PASSWORD).unwrap();
            vault.set_device(DeviceId::generate().unwrap());
            Device {
                vault,
                seen: SeenRevisions::new(),
            }
        })
        .collect();
    (devices, shared, secret_key)
}

fn open(bytes: &[u8], secret_key: &SecretKey, password: &str) -> vault_core::Result<Vault> {
    Vault::open(
        bytes,
        Unlock::Password {
            password,
            secret_key,
        },
    )
}

fn now() -> i64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    i64::try_from(since.as_secs()).unwrap()
}

fn set_password(vault: &mut Vault, id: &ItemId, password: &str) {
    let mut item = vault.get_item(id).unwrap();
    item.password = password.into();
    item.touch();
    vault.update_item(id, &item).unwrap();
}

/// Each device takes every other device's copy, twice round, as a sync target would serve
/// them.
fn exchange(devices: &mut [Device]) {
    for _ in 0..2 {
        let copies: Vec<Vec<u8>> = devices.iter_mut().map(Device::copy).collect();
        for (i, device) in devices.iter_mut().enumerate() {
            for (j, copy) in copies.iter().enumerate() {
                if i != j {
                    device.take(copy);
                }
            }
        }
    }
}

/// What a person would compare: every item's visible content, by id.
fn contents(vault: &Vault) -> Vec<(ItemId, String, String, Vec<String>)> {
    let mut items: Vec<_> = vault
        .item_ids()
        .map(|id| {
            let item = vault.get_item(&id).unwrap();
            let history = item
                .password_history
                .iter()
                .map(|h| h.password.clone())
                .collect();
            (id, item.title.clone(), item.password.clone(), history)
        })
        .collect();
    items.sort_by_key(|item| item.0);
    items
}

#[test]
fn an_item_added_on_one_device_reaches_the_other() {
    let (mut d, shared, _) = devices(2);
    let added = d[1]
        .vault
        .add_item(&ItemData::login("Phone", "p", "pw", "https://p.example"))
        .unwrap();
    let copy = d[1].copy();
    let report = d[0].take(&copy);
    assert_eq!((report.added, report.updated, report.removed), (1, 0, 0));
    assert!(report.changed());
    assert_eq!(d[0].vault.get_item(&added).unwrap().title, "Phone");
    assert_eq!(
        d[0].vault.get_item(&shared).unwrap().password,
        "first-password"
    );
    // Taking the same copy again changes nothing.
    let again = d[0].take(&copy);
    assert!(!again.changed());
}

#[test]
fn edits_on_both_devices_keep_both_passwords_and_converge() {
    let (mut d, shared, _) = devices(2);
    set_password(&mut d[0].vault, &shared, "desktop-password");
    set_password(&mut d[1].vault, &shared, "phone-password");
    let (a, b) = (d[0].copy(), d[1].copy());
    let report = d[0].take(&b);
    assert_eq!(report.conflicts, [shared]);
    d[1].take(&a);
    let one = contents(&d[0].vault);
    assert_eq!(
        one,
        contents(&d[1].vault),
        "both devices reach the same items"
    );
    let item = d[0].vault.get_item(&shared).unwrap();
    let history: Vec<&str> = item
        .password_history
        .iter()
        .map(|h| h.password.as_str())
        .collect();
    // The newer password wins; the other one and the original are in the history.
    let other = if item.password == "desktop-password" {
        "phone-password"
    } else {
        assert_eq!(item.password, "phone-password");
        "desktop-password"
    };
    assert!(history.contains(&other) && history.contains(&"first-password"));
    // A second round finds nothing new.
    let (a, b) = (d[0].copy(), d[1].copy());
    assert!(!d[0].take(&b).changed());
    assert!(!d[1].take(&a).changed());
}

#[test]
fn a_deletion_spreads_but_never_removes_a_later_edit() {
    let (mut d, shared, _) = devices(2);
    let other = d[0]
        .vault
        .add_item(&ItemData::login("Other", "o", "pw", "https://o.example"))
        .unwrap();
    exchange(&mut d);
    assert_eq!(d[1].vault.item_ids().count(), 2);

    // Deleted on the desktop, untouched on the phone: deleted on both.
    d[0].vault.remove_item(&other).unwrap();
    let copy = d[0].copy();
    let report = d[1].take(&copy);
    assert_eq!(report.removed, 1);
    assert!(d[1].vault.get_item(&other).is_err());
    // The phone's older copy, which still has it, doesn't bring it back.
    let phone = d[1].copy();
    d[0].take(&phone);
    assert!(d[0].vault.get_item(&other).is_err());

    // Deleted on the desktop, edited later on the phone: the edit is kept everywhere.
    d[0].vault.remove_item(&shared).unwrap();
    let mut item = d[1].vault.get_item(&shared).unwrap();
    item.notes = "edited after the deletion".into();
    item.updated_at = now() + 60;
    d[1].vault.update_item(&shared, &item).unwrap();
    exchange(&mut d);
    for device in &d {
        assert_eq!(
            device.vault.get_item(&shared).unwrap().notes,
            "edited after the deletion"
        );
    }
}

#[test]
fn a_replayed_or_forked_copy_is_refused() {
    let (mut d, _, secret_key) = devices(2);
    let old = d[1].copy();
    d[1].vault
        .add_item(&ItemData::login("New", "n", "pw", "https://n.example"))
        .unwrap();
    let newer = d[1].copy();
    d[0].take(&newer);
    // The older copy, served again by the target: refused, nothing changes.
    let before = contents(&d[0].vault);
    assert!(matches!(d[0].try_take(&old), Err(Error::SyncRollback)));
    assert_eq!(contents(&d[0].vault), before);

    // Two different copies with the same revision from one device.
    let mut twin = open(&newer, &secret_key, PASSWORD).unwrap();
    twin.add_item(&ItemData::login("Twin", "t", "pw", "https://t.example"))
        .unwrap();
    let forked = twin.to_bytes().unwrap();
    let honest = d[1].copy();
    d[0].take(&honest);
    assert!(matches!(d[0].try_take(&forked), Err(Error::SyncFork)));
}

#[test]
fn copies_of_other_vaults_and_tampered_copies_are_refused() {
    let (mut d, _, secret_key) = devices(2);
    let (mut others, _, _) = devices(1);
    let stranger = others[0].copy();
    assert!(matches!(d[0].try_take(&stranger), Err(Error::OtherVault)));
    let mut tampered = d[1].copy();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        d[0].try_take(&tampered),
        Err(Error::DecryptionFailed)
    ));
    assert!(matches!(
        d[0].try_take(b"not a vault"),
        Err(Error::NotAVault)
    ));
    // A copy that was never written by a device (sync not set up) has no writer.
    let mut unsynced = open(&d[1].copy(), &secret_key, PASSWORD).unwrap();
    unsynced.set_device(DeviceId::from_bytes([0; 16]));
    let bytes = unsynced.to_bytes().unwrap();
    assert!(matches!(d[0].try_take(&bytes), Err(Error::Malformed)));
}

#[test]
fn a_new_master_password_follows_the_copy_where_it_changed() {
    let (mut d, shared, secret_key) = devices(2);
    let kdf = d[0].vault.kdf_params().clone();
    d[0].vault
        .change_password("the new password", &secret_key, None, &kdf)
        .unwrap();
    let copy = d[0].copy();
    let report = d[1].take(&copy);
    assert!(report.unlock_changed);
    let phone = d[1].copy();
    assert!(matches!(
        open(&phone, &secret_key, PASSWORD),
        Err(Error::DecryptionFailed)
    ));
    let reopened = open(&phone, &secret_key, "the new password").unwrap();
    assert_eq!(
        reopened.get_item(&shared).unwrap().password,
        "first-password"
    );
    // The desktop doesn't go back to the old password from the phone's older header.
    let report = d[0].take(&phone);
    assert!(!report.unlock_changed);
}

#[test]
fn a_removed_device_is_refused_and_learns_it() {
    let (mut d, _, _) = devices(2);
    let phone = d[1].vault.device();
    d[0].vault
        .add_sync_device(SyncDevice {
            id: phone,
            name: "Phone".into(),
            signing_key: None,
            added_at: 1,
        })
        .unwrap();
    d[0].vault.remove_sync_device(&phone).unwrap();
    let from_phone = d[1].copy();
    assert!(matches!(
        d[0].try_take(&from_phone),
        Err(Error::DeviceRemoved)
    ));
    let from_desktop = d[0].copy();
    assert!(matches!(
        d[1].try_take(&from_desktop),
        Err(Error::DeviceRemoved)
    ));
    // Once removed, the same id can't be added again.
    assert!(matches!(
        d[0].vault.add_sync_device(SyncDevice {
            id: phone,
            name: "Phone".into(),
            signing_key: None,
            added_at: 2,
        }),
        Err(Error::DeviceRemoved)
    ));
}

#[test]
fn folders_merge_by_id_with_deletions_and_order() {
    let (mut d, _, _) = devices(2);
    let work = d[0].vault.add_folder("Work").unwrap();
    let home = d[0].vault.add_folder("Home").unwrap();
    exchange(&mut d);
    assert_eq!(d[1].vault.folders().len(), 2);
    d[0].vault.rename_folder(&work, "Work stuff").unwrap();
    d[1].vault.remove_folder(&home).unwrap();
    let mine = d[1].vault.add_folder("Phone only").unwrap();
    exchange(&mut d);
    for device in &d {
        let names: Vec<&str> = device
            .vault
            .folders()
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(names, ["Work stuff", "Phone only"]);
    }
    d[1].vault.move_folder(&mine, 0).unwrap();
    exchange(&mut d);
    assert_eq!(d[0].vault.folders()[0].id, mine);
}

#[test]
fn edits_under_a_closed_item_lock_wait_for_it() {
    let (mut d, shared, _) = devices(2);
    d[0].vault
        .set_item_guard(true, GuardCheck::Pin, Some("4821"), None)
        .unwrap();
    exchange(&mut d);
    assert!(d[1].vault.item_guard().encrypts());
    assert!(d[1].vault.unlock_secrets("4821").unwrap());
    set_password(&mut d[0].vault, &shared, "desktop-password");
    set_password(&mut d[1].vault, &shared, "phone-password");
    // A second later on the phone (within one second, the two are told apart only open).
    let mut later = d[1].vault.get_item(&shared).unwrap();
    later.updated_at += 1;
    d[1].vault.update_item(&shared, &later).unwrap();
    d[0].vault.lock_secrets();
    d[1].vault.lock_secrets();
    let (a, b) = (d[0].copy(), d[1].copy());
    let report = d[0].take(&b);
    assert_eq!(report.waiting_for_lock, 1);
    assert!(report.conflicts.is_empty());
    // Opened, the same copy is merged again and both passwords are kept.
    assert!(d[0].vault.unlock_secrets("4821").unwrap());
    let report = d[0].take(&b);
    assert_eq!(report.conflicts, [shared]);
    assert!(d[1].vault.unlock_secrets("4821").unwrap());
    d[1].take(&a);
    assert_eq!(contents(&d[0].vault), contents(&d[1].vault));
}

#[test]
fn an_item_lock_set_on_one_device_follows_on_the_others() {
    let (mut d, shared, _) = devices(2);
    d[1].vault
        .set_item_guard(true, GuardCheck::Pin, Some("4821"), None)
        .unwrap();
    d[1].vault.lock_secrets();
    let copy = d[1].copy();
    let report = d[0].take(&copy);
    assert!(report.guard_changed);
    assert!(d[0].vault.get_item(&shared).unwrap().is_locked());
    assert!(d[0].vault.unlock_secrets("4821").unwrap());
    assert_eq!(
        d[0].vault.get_item(&shared).unwrap().password,
        "first-password"
    );
}

#[derive(Clone, Debug)]
enum Op {
    Add(u8),
    Edit(u8, u8),
    Delete(u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        any::<u8>().prop_map(Op::Add),
        (any::<u8>(), any::<u8>()).prop_map(|(i, v)| Op::Edit(i, v)),
        any::<u8>().prop_map(Op::Delete),
    ]
}

/// Applies `op`; an edit returns the item and the password it set.
fn apply(vault: &mut Vault, op: &Op) -> Option<(ItemId, String)> {
    let ids: Vec<ItemId> = vault.item_ids().collect();
    let pick = |i: u8| (!ids.is_empty()).then(|| ids[usize::from(i) % ids.len()]);
    match op {
        Op::Add(n) => {
            vault
                .add_item(&ItemData::login(
                    &format!("Item {n}"),
                    "u",
                    &format!("pw-{n}"),
                    "https://x.example",
                ))
                .unwrap();
        }
        Op::Edit(i, v) => {
            if let Some(id) = pick(*i) {
                let password = format!("edited-{v}");
                set_password(vault, &id, &password);
                return Some((id, password));
            }
        }
        Op::Delete(i) => {
            if let Some(id) = pick(*i) {
                vault.remove_item(&id).unwrap();
            }
        }
    }
    None
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Whatever three devices do offline, after the copies have gone round they all hold
    /// the same items, and no password typed into an item that is still there was lost: it
    /// is the item's password or in its history.
    #[test]
    fn three_devices_converge(script in prop::collection::vec((0..3usize, op()), 0..14)) {
        let (mut d, _, _) = devices(3);
        let mut typed = Vec::new();
        for (device, op) in &script {
            typed.extend(apply(&mut d[*device].vault, op));
        }
        exchange(&mut d);
        let first = contents(&d[0].vault);
        prop_assert_eq!(&first, &contents(&d[1].vault));
        prop_assert_eq!(&first, &contents(&d[2].vault));
        for (id, password) in &typed {
            // Past the history limit (10) the oldest are dropped on purpose.
            if typed.iter().filter(|(other, _)| other == id).count() > 9 {
                continue;
            }
            if let Some((_, _, current, history)) = first.iter().find(|item| item.0 == *id) {
                prop_assert!(
                    current == password || history.contains(password),
                    "{password} lost from {id:?}"
                );
            }
        }
    }
}
