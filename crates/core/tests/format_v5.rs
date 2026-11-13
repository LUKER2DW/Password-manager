//! Known-answer test for the v5 file format (a keyfile as a third factor, a re-prompt flag per
//! item, the item guard).
//!
//! `fixtures/vault-v5.bin` was produced once by `generate_fixture` and committed. If this test
//! fails, the code no longer reads files written by earlier builds: either a bug, or a format
//! change that needs a new format version and a migration.
//!
//! The credentials below are test values for this fixture only.

use std::path::PathBuf;

use vault_core::{
    Error, FolderId, GuardCheck, ItemData, ItemKind, KdfParams, Keyfile, PasswordChange,
    RecoveryCode, RecoveryKey, SecretKey, Unlock, Vault, VaultSettings,
};

const PASSWORD: &str = "fixture password v5 ✓ çãé";
const SECOND_FOLDER: &str = "Second fixture folder";
const ICON_URL: &str = "https://icons.fixture.example/folder.png";
const GUARD_PIN: &str = "4821";
const FOLDER: &str = "Fixture folder ✓";
const VAULT_NAME: &str = "Fixture vault ✓";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn credentials() -> (SecretKey, RecoveryKey) {
    let text = std::fs::read_to_string(fixture_dir().join("vault-v5.credentials.txt")).unwrap();
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
        RecoveryKey::parse(&value("recovery_key")).unwrap(),
    )
}

fn expected_items(folder: Option<FolderId>) -> Vec<ItemData> {
    let mut login = ItemData::login(
        "Fixture Login",
        "fixture-user",
        "Fixture-P@ss-123",
        "https://fixture.example",
    );
    login.created_at = 1_790_000_000;
    login.updated_at = 1_790_000_100;
    login.totp = "JBSWY3DPEHPK3PXP".into();
    login.favorite = true;
    login.folder = folder;
    login.recovery_codes = RecoveryCode::parse_list("aaaa-1111\nbbbb-2222");
    login.recovery_codes[0].used = true;
    login.password_history = vec![PasswordChange {
        password: "Old-P@ss-1".into(),
        replaced_at: 1_790_000_050,
    }];
    login.password_changed_at = 1_790_000_050;
    login.icon_url = "https://icons.fixture.example".into();
    login.reprompt = true;
    let mut note = ItemData::new(ItemKind::SecureNote, "Fixture Note");
    note.notes = "multi\nline ✓".into();
    note.created_at = 1_790_000_200;
    note.updated_at = 1_790_000_200;
    vec![login, note]
}

#[test]
fn reads_the_committed_v5_fixture() {
    let bytes = std::fs::read(fixture_dir().join("vault-v5.bin")).unwrap();
    assert_eq!(&bytes[8..10], &5u16.to_le_bytes());
    let (secret_key, recovery_key) = credentials();

    assert!(Vault::inspect(&bytes).unwrap().needs_keyfile);
    assert!(matches!(
        Vault::open(
            &bytes,
            Unlock::Password {
                password: PASSWORD,
                secret_key: &secret_key,
            }
        ),
        Err(Error::KeyfileRequired)
    ));
    let keyfile =
        Keyfile::from_bytes(&std::fs::read(fixture_dir().join("vault-v5.keyfile")).unwrap())
            .unwrap();
    for unlock in [
        Unlock::PasswordAndKeyfile {
            password: PASSWORD,
            secret_key: &secret_key,
            keyfile: &keyfile,
        },
        Unlock::Recovery(&recovery_key),
    ] {
        let vault = Vault::open(&bytes, unlock).unwrap();
        assert_eq!(vault.revision(), 1);
        assert_eq!(vault.settings().name, VAULT_NAME);
        assert_eq!(vault.settings().history_limit, 7);
        let guard = vault.item_guard();
        assert_eq!((guard.all_items, guard.check), (true, GuardCheck::Pin));
        assert!(guard.verify(GUARD_PIN).unwrap());
        assert!(!guard.verify("0000").unwrap());
        assert_eq!(vault.folders().len(), 2);
        // Created second, moved first.
        assert_eq!(vault.folders()[0].name, SECOND_FOLDER);
        let first = &vault.folders()[1];
        assert_eq!(first.name, FOLDER);
        assert_eq!(
            (first.icon.as_str(), first.color, first.icon_url.as_str()),
            ("star", 4, ICON_URL)
        );
        let folder = first.id;
        let mut items: Vec<ItemData> = vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .collect();
        items.sort_by(|a, b| a.title.cmp(&b.title));
        assert_eq!(items, expected_items(Some(folder)));
    }
}

/// Regenerates the fixture. Run only when intentionally creating a new format version:
/// `cargo test -p vault-core --test format_v5 -- --ignored`
#[test]
#[ignore = "writes the committed fixture"]
fn generate_fixture() {
    let secret_key = SecretKey::generate().unwrap();
    let recovery_key = RecoveryKey::generate().unwrap();
    let mut vault = Vault::create(
        PASSWORD,
        &secret_key,
        Some(&recovery_key),
        KdfParams::minimum().unwrap(),
    )
    .unwrap();
    vault
        .set_settings(VaultSettings {
            name: VAULT_NAME.into(),
            history_limit: 7,
        })
        .unwrap();
    let folder = vault.add_folder(FOLDER).unwrap();
    vault.style_folder(&folder, "star", 4).unwrap();
    vault.set_folder_icon_url(&folder, ICON_URL).unwrap();
    let second = vault.add_folder(SECOND_FOLDER).unwrap();
    vault.move_folder(&second, 0).unwrap();
    for item in expected_items(Some(folder)) {
        vault.add_item(&item).unwrap();
    }
    vault
        .set_item_guard(true, GuardCheck::Pin, Some(GUARD_PIN))
        .unwrap();
    let (keyfile, keyfile_bytes) = Keyfile::generate().unwrap();
    let kdf = vault.kdf_params().clone();
    vault
        .change_password(PASSWORD, &secret_key, Some(&keyfile), &kdf)
        .unwrap();
    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("vault-v5.keyfile"), &*keyfile_bytes).unwrap();
    std::fs::write(dir.join("vault-v5.bin"), vault.to_bytes().unwrap()).unwrap();
    std::fs::write(
        dir.join("vault-v5.credentials.txt"),
        format!(
            "# Test credentials for vault-v5.bin (fixture only, not real secrets).\n\
             # keyfile = vault-v5.keyfile (test value, next to this file)\n\
             # password = see PASSWORD in tests/format_v5.rs\n\
             secret_key = {}\nrecovery_key = {}\n",
            secret_key.to_display_string().as_str(),
            recovery_key.to_display_string().as_str()
        ),
    )
    .unwrap();
}
