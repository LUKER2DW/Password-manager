//! Known-answer test for the v11 file format (the trash, archived items, templates, identities,
//! tags and expiry, each item's earlier versions, items and folders kept out of the browser,
//! tombstones that name their versions). This fixture uses Argon2id, recovery parts, a PIN
//! that guards only marked items (one of them with a file, a passkey and an earlier version,
//! sealed with its secrets), an identity with a hidden document number, a template, an
//! archived note, an item in the trash, a login kept out of the browser, two folders with a
//! browser setting, two sync devices, and a deleted item and folder.
//!
//! `fixtures/vault-v11.bin` was produced once by `generate_fixture` and committed. If this test
//! fails, the code no longer reads files written by earlier builds: either a bug, or a format
//! change that needs a new format version and a migration.
//!
//! The credentials below are test values for this fixture only.

use std::path::PathBuf;

use vault_core::{
    Attachment, FolderBrowser, FolderId, GuardCheck, ItemData, ItemKind, ItemVersion, KdfMethod,
    KdfStrength, PartLabel, Passkey, PasswordChange, PasswordKdf, RecoveryCode, RecoveryPart,
    RecoveryParts, SecretKey, Unlock, Vault, VaultSettings, identity,
    sync::{DeviceId, SeenRevisions, SyncDevice},
};

const PASSWORD: &str = "fixture password v11 ✓ çãé";
const GUARD_PIN: &str = "4821";
const FOLDER: &str = "Fixture folder ✓";
const ONE_BROWSER: &str = "Kept to one browser";
const PAIRING: [u8; 8] = *b"pairing!";
const VAULT_NAME: &str = "Fixture vault v11";
const WRITER: [u8; 16] = *b"fixture-desktop!";
const PHONE: [u8; 16] = *b"fixture-phone!!!";
/// Far ahead, so the fixture's item stays in the trash whenever the tests run (an item is
/// deleted for good 30 days after it was put there).
const TRASHED_AT: i64 = 4_102_444_800;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn credentials() -> (SecretKey, [RecoveryPart; 3]) {
    let text = std::fs::read_to_string(fixture_dir().join("vault-v11.credentials.txt")).unwrap();
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

/// The items, sorted by title.
fn expected_items(folder: Option<FolderId>, one_browser: Option<FolderId>) -> Vec<ItemData> {
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
    login.attachments = vec![file(
        "guarded scan ✓.png",
        b"\x89PNG fixture",
        1_795_000_060,
    )];
    login.passkeys = vec![passkey(b"fixture-cred-one", "fixture.example", 0x11)];
    login.set_tags("work, Bank ✓").unwrap();
    login.expires_at = 1_800_000_000;
    let mut earlier = ItemData::login(
        "Fixture Login (before)",
        "fixture-user",
        "Old-P@ss-1",
        "https://fixture.example",
    );
    earlier.created_at = 1_795_000_000;
    earlier.updated_at = 1_795_000_040;
    earlier.notes = "an earlier note ✓".into();
    login.versions = vec![ItemVersion {
        saved_at: 1_795_000_050,
        item: earlier,
    }];

    let mut person = identity::new("Fixture Identity");
    person.username = "Test Person ✓".into();
    person.created_at = 1_795_000_200;
    person.updated_at = 1_795_000_200;
    identity::set(&mut person, identity::EMAIL, "person@example.invalid");
    identity::set(&mut person, identity::CITY, "Testville");
    identity::set(&mut person, identity::PASSPORT, "X0000000");
    person.folder = one_browser;

    let mut template = ItemData::new(ItemKind::Login, "Fixture Template");
    template.template = true;
    template.urls = vec!["https://intranet.example".into()];
    template.set_tags("work").unwrap();
    template.created_at = 1_795_000_250;
    template.updated_at = 1_795_000_250;

    let mut archived = ItemData::new(ItemKind::SecureNote, "Fixture Archived Note");
    archived.notes = "kept, not shown ✓".into();
    archived.archived = true;
    archived.created_at = 1_795_000_300;
    archived.updated_at = 1_795_000_300;

    let mut trashed = ItemData::login("Fixture Trashed", "t", "Trash-P@ss", "https://t.example");
    trashed.trashed_at = TRASHED_AT;
    trashed.created_at = 1_795_000_350;
    trashed.updated_at = 1_795_000_360;
    trashed.password_changed_at = 1_795_000_350;

    let mut private = ItemData::login(
        "Fixture Private",
        "private-user",
        "Private-P@ss",
        "https://private.example",
    );
    private.no_browser = true;
    private.created_at = 1_795_000_400;
    private.updated_at = 1_795_000_400;
    private.password_changed_at = 1_795_000_400;

    let mut items = vec![login, person, template, archived, trashed, private];
    items.sort_by(|a, b| a.title.cmp(&b.title));
    items
}

fn passkey(id: &[u8], rp_id: &str, key: u8) -> Passkey {
    Passkey::from_parts(
        id,
        rp_id,
        b"handle of fixture-user",
        "fixture-user",
        "fixture-user (display)",
        1_795_000_070,
        &[key; 32],
    )
    .unwrap()
}

fn file(name: &str, data: &[u8], added_at: i64) -> Attachment {
    let mut file = Attachment::new(name, data.to_vec()).unwrap();
    file.added_at = added_at;
    file
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

fn folders(vault: &Vault) -> (FolderId, FolderId) {
    let find = |name: &str| vault.folders().iter().find(|f| f.name == name).unwrap().id;
    (find(FOLDER), find(ONE_BROWSER))
}

#[test]
fn reads_the_committed_v11_fixture() {
    let bytes = std::fs::read(fixture_dir().join("vault-v11.bin")).unwrap();
    assert_eq!(&bytes[8..10], &11u16.to_le_bytes());
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
        // The deleted folder is gone; the two left keep their look and browser setting.
        assert_eq!(vault.folders().len(), 2);
        let (folder, one_browser) = folders(&vault);
        let look = |id: FolderId| {
            let f = vault.folders().iter().find(|f| f.id == id).unwrap();
            (f.icon.clone(), f.color, f.browser)
        };
        assert_eq!(look(folder), ("star".into(), 4, FolderBrowser::Never));
        assert_eq!(
            look(one_browser),
            (String::new(), 0, FolderBrowser::Only(PAIRING))
        );
        assert_eq!(
            vault.item_ids().count(),
            6,
            "the deleted item stays deleted"
        );
        let locked = read(&vault);
        let login = locked.iter().find(|i| i.title == "Fixture Login").unwrap();
        assert!(login.is_locked());
        assert!(
            login.versions.is_empty() && login.attachments.is_empty(),
            "the guarded version and file wait for the PIN"
        );
        assert_eq!(login.tags, ["work", "Bank ✓"]);
        assert!(login.has_tag("BANK ✓"));
        assert_eq!(login.expires_at, 1_800_000_000);
        // What reaches the browser: not the folder kept out, not the private login, not the
        // template, the archived note or the trash; the one-browser folder only for its pairing.
        let reaches = |title: &str, pairing| {
            let item = locked.iter().find(|i| i.title == title).unwrap();
            vault.reaches_browser(item, pairing)
        };
        assert!(!reaches("Fixture Login", Some(PAIRING)));
        assert!(!reaches("Fixture Private", Some(PAIRING)));
        assert!(!reaches("Fixture Template", Some(PAIRING)));
        assert!(!reaches("Fixture Archived Note", Some(PAIRING)));
        assert!(!reaches("Fixture Trashed", Some(PAIRING)));
        assert!(reaches("Fixture Identity", Some(PAIRING)));
        assert!(!reaches("Fixture Identity", Some(*b"another!")));
        assert!(!reaches("Fixture Identity", None));
        assert!(vault.unlock_secrets(GUARD_PIN).unwrap());
        assert_eq!(
            read(&vault),
            expected_items(Some(folder), Some(one_browser))
        );
    }
}

#[test]
fn the_fixture_merges_with_a_copy_from_its_other_device() {
    let bytes = std::fs::read(fixture_dir().join("vault-v11.bin")).unwrap();
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
    // Restored from the trash on the phone.
    let trashed = phone
        .item_ids()
        .find(|id| phone.get_item(id).unwrap().title == "Fixture Trashed")
        .unwrap();
    phone.restore_item(&trashed).unwrap();
    let copy = phone.to_bytes().unwrap();
    let mut seen = SeenRevisions::new();
    let report = desktop.merge(&copy, &mut seen).unwrap();
    assert_eq!(report.writer, DeviceId::from_bytes(PHONE));
    assert_eq!((report.added, report.updated), (1, 1));
    assert_eq!(desktop.item_ids().count(), 7);
    assert_eq!(desktop.get_item(&trashed).unwrap().trashed_at, 0);
    assert_eq!(desktop.device(), DeviceId::from_bytes(WRITER));
    assert_eq!(seen.revision(&DeviceId::from_bytes(PHONE)), Some(2));
}

/// Regenerates the fixture. Run only when intentionally creating a new format version:
/// `cargo test -p vault-core --test format_v11 -- --ignored`
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
    vault
        .set_folder_browser(&folder, FolderBrowser::Never)
        .unwrap();
    let one_browser = vault.add_folder(ONE_BROWSER).unwrap();
    vault
        .set_folder_browser(&one_browser, FolderBrowser::Only(PAIRING))
        .unwrap();
    let gone = vault.add_folder("Deleted folder").unwrap();
    vault.remove_folder(&gone).unwrap();
    for item in expected_items(Some(folder), Some(one_browser)) {
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
    std::fs::write(dir.join("vault-v11.bin"), vault.to_bytes().unwrap()).unwrap();
    let part = |label| parts.part(label).to_display_string();
    std::fs::write(
        dir.join("vault-v11.credentials.txt"),
        format!(
            "# Test credentials for vault-v11.bin (fixture only, not real secrets).\n\
             # password = see PASSWORD in tests/format_v11.rs\n\
             secret_key = {}\npart_a = {}\npart_b = {}\npart_c = {}\n",
            secret_key.to_display_string().as_str(),
            part(PartLabel::A).as_str(),
            part(PartLabel::B).as_str(),
            part(PartLabel::C).as_str()
        ),
    )
    .unwrap();
}
