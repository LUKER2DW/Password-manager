//! Known-answer test for the v8 file format (three recovery parts in the header: any two bring
//! back the Secret Key, all three open the vault). This fixture uses Argon2id, recovery parts,
//! a PIN that guards only marked items, two sync devices, and a deleted item and folder.
//!
//! `fixtures/vault-v8.bin` was produced once by `generate_fixture` and committed. If this test
//! fails, the code no longer reads files written by earlier builds: either a bug, or a format
//! change that needs a new format version and a migration.
//!
//! The credentials below are test values for this fixture only.

use std::path::PathBuf;

use vault_core::{
    FolderId, GuardCheck, ItemData, ItemKind, KdfMethod, KdfStrength, PartLabel, PasswordChange,
    PasswordKdf, RecoveryCode, RecoveryPart, RecoveryParts, SecretKey, Unlock, Vault,
    VaultSettings,
    sync::{DeviceId, SeenRevisions, SyncDevice},
};

const PASSWORD: &str = "fixture password v8 ✓ çãé";
const GUARD_PIN: &str = "4821";
const FOLDER: &str = "Fixture folder ✓";
const VAULT_NAME: &str = "Fixture vault v8";
const WRITER: [u8; 16] = *b"fixture-desktop!";
const PHONE: [u8; 16] = *b"fixture-phone!!!";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn credentials() -> (SecretKey, [RecoveryPart; 3]) {
    let text = std::fs::read_to_string(fixture_dir().join("vault-v8.credentials.txt")).unwrap();
    let value = |name: &str| {
        text.lines()
            .find_map(|line| {
                line.strip_prefix(name)?
                    .trim()
                    .strip_prefix('=')
                    .map(str::trim)
            })
            .unwrap_or_else(|| panic!("{name} missing from fixture"))
            .to_owned()
    };
    (
        SecretKey::parse(&value("secret_key")).unwrap(),
        ["part_a", "part_b", "part_c"].map(|name| RecoveryPart::parse(&value(name)).unwrap()),
    )
}

fn expected_items(folder: Option<FolderId>) -> Vec<ItemData> {
    let mut login = ItemData::login(
        "Fixture Login",
        "fixture-user",
        "Fixture-P@ss-123",
        "https://fixture.example",
    );
    login.created_at = 1_795_000_000;
    login.updated_at = 1_795_000_100;
    login.totp = "JBSWY3DPEHPK3PXP".into();
    login.folder = folder;
    login.recovery_codes = RecoveryCode::parse_list("aaaa-1111");
    login.password_history = vec![PasswordChange {
        password: "Old-P@ss-1".into(),
        replaced_at: 1_795_000_050,
    }];
    login.password_changed_at = 1_795_000_050;
    login.reprompt = true;
    let mut note = ItemData::new(ItemKind::SecureNote, "Fixture Note");
    note.notes = "multi\nline ✓".into();
    note.created_at = 1_795_000_200;
    note.updated_at = 1_795_000_200;
    vec![login, note]
}

fn devices() -> Vec<SyncDevice> {
    vec![
        SyncDevice {
            id: DeviceId::from_bytes(WRITER),
            name: "Desktop".into(),
            signing_key: None,
            added_at: 1_795_000_000,
        },
        SyncDevice {
            id: DeviceId::from_bytes(PHONE),
            name: "Phone ✓".into(),
            signing_key: Some([7; 32]),
            added_at: 1_795_000_300,
        },
    ]
}

fn read(vault: &Vault) -> Vec<ItemData> {
    let mut items: Vec<ItemData> = vault
        .item_ids()
        .map(|id| vault.get_item(&id).unwrap())
        .collect();
    items.sort_by(|a, b| a.title.cmp(&b.title));
    items
}

#[test]
fn reads_the_committed_v8_fixture() {
    let bytes = std::fs::read(fixture_dir().join("vault-v8.bin")).unwrap();
    assert_eq!(&bytes[8..10], &8u16.to_le_bytes());
    let (secret_key, [a, b, c]) = credentials();
    assert_eq!(
        (a.label(), b.label(), c.label()),
        (PartLabel::A, PartLabel::B, PartLabel::C)
    );
    for (x, y) in [(&a, &b), (&a, &c), (&b, &c)] {
        assert_eq!(Vault::recover_secret_key(&bytes, x, y).unwrap(), secret_key);
    }
    for unlock in [
        Unlock::Password {
            password: PASSWORD,
            secret_key: &secret_key,
        },
        Unlock::Parts([&c, &a, &b]),
    ] {
        let mut vault = Vault::open(&bytes, unlock).unwrap();
        assert_eq!(vault.revision(), 1);
        assert!(vault.has_recovery_parts() && !vault.has_recovery_key());
        assert_eq!(vault.settings().name, VAULT_NAME);
        assert_eq!(vault.device(), DeviceId::from_bytes(WRITER));
        assert_eq!(vault.sync_devices(), devices().as_slice());
        let guard = vault.item_guard();
        assert_eq!((guard.all_items, guard.check), (false, GuardCheck::Pin));
        // The deleted folder is gone; the one left keeps its look.
        assert_eq!(vault.folders().len(), 1);
        let folder = &vault.folders()[0];
        assert_eq!(
            (folder.name.as_str(), folder.icon.as_str(), folder.color),
            (FOLDER, "star", 4)
        );
        let folder = folder.id;
        assert_eq!(
            vault.item_ids().count(),
            2,
            "the deleted item stays deleted"
        );
        let locked = read(&vault);
        assert!(locked[0].is_locked() && !locked[1].is_locked());
        assert!(vault.unlock_secrets(GUARD_PIN).unwrap());
        assert_eq!(read(&vault), expected_items(Some(folder)));
    }
}

#[test]
fn the_v8_fixture_is_upgraded_on_save() {
    let bytes = std::fs::read(fixture_dir().join("vault-v8.bin")).unwrap();
    let (secret_key, [a, b, c]) = credentials();
    let unlock = || Unlock::Password {
        password: PASSWORD,
        secret_key: &secret_key,
    };
    let mut vault = Vault::open(&bytes, unlock()).unwrap();
    let saved = vault.to_bytes().unwrap();
    assert_eq!(&saved[8..10], &11u16.to_le_bytes());
    let mut reopened = Vault::open(&saved, unlock()).unwrap();
    // The guarded item's secrets, sealed in the v8 layout, still open with the PIN.
    assert!(reopened.unlock_secrets(GUARD_PIN).unwrap());
    let folder = reopened.folders()[0].id;
    assert_eq!(read(&reopened), expected_items(Some(folder)));
    assert!(
        read(&reopened)
            .iter()
            .all(|item| item.attachments.is_empty())
    );
    assert!(Vault::open(&saved, Unlock::Parts([&a, &b, &c])).is_ok());
}

#[test]
fn the_fixture_merges_with_a_copy_from_its_other_device() {
    let bytes = std::fs::read(fixture_dir().join("vault-v8.bin")).unwrap();
    let (secret_key, _) = credentials();
    let unlock = || Unlock::Password {
        password: PASSWORD,
        secret_key: &secret_key,
    };
    let mut desktop = Vault::open(&bytes, unlock()).unwrap();
    let mut phone = Vault::open(&bytes, unlock()).unwrap();
    phone.set_device(DeviceId::from_bytes(PHONE));
    phone
        .add_item(&ItemData::login(
            "Added on the phone",
            "p",
            "phone-pw",
            "https://phone.example",
        ))
        .unwrap();
    let copy = phone.to_bytes().unwrap();
    let mut seen = SeenRevisions::new();
    let report = desktop.merge(&copy, &mut seen).unwrap();
    assert_eq!(report.writer, DeviceId::from_bytes(PHONE));
    assert_eq!(report.added, 1);
    assert_eq!(desktop.item_ids().count(), 3);
    assert_eq!(desktop.device(), DeviceId::from_bytes(WRITER));
    assert_eq!(seen.revision(&DeviceId::from_bytes(PHONE)), Some(2));
}

/// Regenerates the fixture. Run only when intentionally creating a new format version:
/// `cargo test -p vault-core --test format_v8 -- --ignored`
#[test]
#[ignore = "writes the committed fixture"]
fn generate_fixture() {
    let secret_key = SecretKey::generate().unwrap();
    let parts = RecoveryParts::generate().unwrap();
    let mut vault = Vault::create(
        PASSWORD,
        &secret_key,
        None,
        PasswordKdf::preset(KdfMethod::Argon2id, KdfStrength::Light).unwrap(),
    )
    .unwrap();
    vault.set_recovery_parts(&parts, &secret_key).unwrap();
    vault.set_device(DeviceId::from_bytes(WRITER));
    for device in devices() {
        vault.add_sync_device(device).unwrap();
    }
    vault
        .set_settings(VaultSettings {
            name: VAULT_NAME.into(),
            history_limit: 5,
        })
        .unwrap();
    let folder = vault.add_folder(FOLDER).unwrap();
    vault.style_folder(&folder, "star", 4).unwrap();
    let gone = vault.add_folder("Deleted folder").unwrap();
    vault.remove_folder(&gone).unwrap();
    for item in expected_items(Some(folder)) {
        vault.add_item(&item).unwrap();
    }
    let deleted = vault
        .add_item(&ItemData::login(
            "Deleted",
            "x",
            "y",
            "https://deleted.example",
        ))
        .unwrap();
    vault.remove_item(&deleted).unwrap();
    vault
        .set_item_guard(false, GuardCheck::Pin, Some(GUARD_PIN), Some(PASSWORD))
        .unwrap();
    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("vault-v8.bin"), vault.to_bytes().unwrap()).unwrap();
    let part = |label| parts.part(label).to_display_string();
    std::fs::write(
        dir.join("vault-v8.credentials.txt"),
        format!(
            "# Test credentials for vault-v8.bin (fixture only, not real secrets).\n\
             # password = see PASSWORD in tests/format_v8.rs\n\
             secret_key = {}\npart_a = {}\npart_b = {}\npart_c = {}\n",
            secret_key.to_display_string().as_str(),
            part(PartLabel::A).as_str(),
            part(PartLabel::B).as_str(),
            part(PartLabel::C).as_str()
        ),
    )
    .unwrap();
}
