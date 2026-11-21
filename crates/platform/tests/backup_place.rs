//! A vault synced through a main place and a backup place: while the main one is down the
//! round goes on through the backup, and when it is back its older copies are passed over
//! (not refused as rollbacks) and it gets this device's copy again. Folders stand in for the
//! two servers here; the logic is the same for every kind of place.

use std::path::Path;

use vault_core::{
    ItemData, KdfParams, SecretKey, Unlock, Vault,
    sync::{DeviceId, SeenRevisions},
};
use vault_platform::{
    SyncPlace, SyncTo,
    sync::{self, FolderTarget, KnownTags, Role, Target},
};

const PASSWORD: &str = "test password for two places";

fn put(folder: &Path, vault: &Vault, device: DeviceId, bytes: &[u8]) {
    FolderTarget::new(folder, &vault.id_hex())
        .unwrap()
        .put(device, bytes)
        .unwrap();
}

/// The main folder stops answering: where its copies should be is a file.
fn take_down(folder: &Path, vault_id: &str) {
    let devices = folder.join(vault_id).join("devices");
    let _ = std::fs::remove_dir_all(&devices);
    std::fs::create_dir_all(devices.parent().unwrap()).unwrap();
    std::fs::write(&devices, b"not a folder").unwrap();
}

fn bring_back(folder: &Path, vault_id: &str) {
    std::fs::remove_file(folder.join(vault_id).join("devices")).unwrap();
}

#[test]
fn the_backup_keeps_the_round_going_and_the_main_place_catches_up() {
    let dir = tempfile::tempdir().unwrap();
    let (main, backup) = (dir.path().join("main"), dir.path().join("backup"));
    let key = SecretKey::generate().unwrap();
    let mut made = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
    let start = made.to_bytes().unwrap();
    let open = || {
        Vault::open(
            &start,
            Unlock::Password {
                password: PASSWORD,
                secret_key: &key,
            },
        )
        .unwrap()
    };
    let (a, b) = (DeviceId::from_bytes([1; 16]), DeviceId::from_bytes([2; 16]));
    let (mut on_a, mut on_b) = (open(), open());
    on_a.set_device(a);
    on_b.set_device(b);
    let id = on_a.id_hex();
    let mut place = SyncPlace {
        to: SyncTo::Folder { path: main.clone() },
        backup: Some(SyncTo::Folder {
            path: backup.clone(),
        }),
        seen: SeenRevisions::new(),
        at: 0,
        published: 0,
        published_backup: 0,
    };
    let mut known = KnownTags::default();

    // B publishes to both places; A reads both and takes B's item once.
    on_b.add_item(&ItemData::login(
        "First",
        "b",
        "pw",
        "https://first.example",
    ))
    .unwrap();
    let first = on_b.to_bytes().unwrap();
    put(&main, &on_b, b, &first);
    put(&backup, &on_b, b, &first);
    let reading = sync::read_all(&id, a, &place, &known);
    assert!(reading.reached() && reading.main_down().is_none() && reading.backup_down().is_none());
    let round = sync::merge_reading(&mut on_a, &reading, &mut place.seen);
    assert_eq!(on_a.len(), 1);
    assert!(round.refused.is_empty());
    known = reading.tags(&known);
    let revision = on_a.to_bytes().map(|_| on_a.revision()).unwrap();
    assert_eq!(
        sync::to_publish(&place, &reading, revision, round.changed()),
        vec![Role::Main, Role::Backup]
    );
    place.published = revision;
    place.published_backup = revision;

    // The main place goes down; B's next change reaches the backup only, and A still gets it.
    take_down(&main, &id);
    on_b.add_item(&ItemData::login(
        "Second",
        "b",
        "pw",
        "https://second.example",
    ))
    .unwrap();
    let second = on_b.to_bytes().unwrap();
    put(&backup, &on_b, b, &second);
    let reading = sync::read_all(&id, a, &place, &known);
    assert!(reading.reached(), "the backup answers");
    assert!(reading.main_down().is_some() && reading.backup_down().is_none());
    let round = sync::merge_reading(&mut on_a, &reading, &mut place.seen);
    assert_eq!(on_a.len(), 2, "the change came through the backup");
    known = reading.tags(&known);
    let revision = on_a.to_bytes().map(|_| on_a.revision()).unwrap();
    assert_eq!(
        sync::to_publish(&place, &reading, revision, round.changed()),
        vec![Role::Backup],
        "only the place that answers gets the copy"
    );
    let published = sync::publish_all(&id, a, &place, &on_a.to_bytes().unwrap(), &[Role::Backup]);
    assert!(matches!(published.as_slice(), [(Role::Backup, Ok(()))]));
    place.published_backup = on_a.revision();

    // The main place is back, still holding B's older copy: it is passed over without a
    // warning, and A's copy goes there at once.
    bring_back(&main, &id);
    let reading = sync::read_all(&id, a, &place, &known);
    assert!(reading.main_down().is_none());
    let round = sync::merge_reading(&mut on_a, &reading, &mut place.seen);
    assert!(round.refused.is_empty(), "{:?}", round.refused);
    assert_eq!(on_a.len(), 2);
    assert_eq!(
        sync::to_publish(&place, &reading, on_a.revision(), round.changed()),
        vec![Role::Main],
        "the main place catches up"
    );

    // Two places with different copies from one device: the newer wins, whichever has it.
    let mut seen = SeenRevisions::new();
    let mut fresh = open();
    fresh.set_device(DeviceId::from_bytes([3; 16]));
    put(&main, &on_b, b, &first);
    put(&backup, &on_b, b, &second);
    let reading = sync::read_all(&id, fresh.device(), &place, &KnownTags::default());
    sync::merge_reading(&mut fresh, &reading, &mut seen);
    assert_eq!(fresh.len(), 2, "the backup's newer copy was taken");
}

#[test]
fn with_one_place_nothing_changes() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate().unwrap();
    let mut vault = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
    vault.set_device(DeviceId::from_bytes([1; 16]));
    let place = SyncPlace {
        to: SyncTo::Folder {
            path: dir.path().to_owned(),
        },
        backup: None,
        seen: SeenRevisions::new(),
        at: 0,
        published: 0,
        published_backup: 0,
    };
    let reading = sync::read_all(
        &vault.id_hex(),
        vault.device(),
        &place,
        &KnownTags::default(),
    );
    assert!(reading.reached() && reading.backup.is_none());
    assert_eq!(
        sync::to_publish(&place, &reading, 1, false),
        vec![Role::Main]
    );
    take_down(dir.path(), &vault.id_hex());
    let reading = sync::read_all(
        &vault.id_hex(),
        vault.device(),
        &place,
        &KnownTags::default(),
    );
    assert!(
        !reading.reached(),
        "with no backup, a place that is down stops the round"
    );
}
