//! Known-answer test for the v6 file format (the header names the password hashing method; the
//! item guard encrypts the secrets of guarded items). This fixture uses scrypt, a keyfile, and
//! a PIN that guards every item.
//!
//! `fixtures/vault-v6.bin` was produced once by `generate_fixture` and committed. If this test
//! fails, the code no longer reads files written by earlier builds: either a bug, or a format
//! change that needs a new format version and a migration.
//!
//! The credentials below are test values for this fixture only.

use std::path::PathBuf;

use vault_core::{
    Error, FolderId, GuardCheck, ItemData, ItemKind, KdfMethod, KdfStrength, Keyfile,
    PasswordChange, PasswordKdf, RecoveryCode, RecoveryKey, SecretKey, Unlock, Vault,
    VaultSettings,
};

const PASSWORD: &str = "fixture password v6 ✓ çãé";
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
    let text = std::fs::read_to_string(fixture_dir().join("vault-v6.credentials.txt")).unwrap();
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
fn reads_the_committed_v6_fixture() {
    let bytes = std::fs::read(fixture_dir().join("vault-v6.bin")).unwrap();
    assert_eq!(&bytes[8..10], &6u16.to_le_bytes());
    let (secret_key, recovery_key) = credentials();

    let info = Vault::inspect(&bytes).unwrap();
    assert!(info.needs_keyfile);
    assert_eq!(
        (info.kdf.method(), info.kdf.strength()),
        (KdfMethod::Scrypt, Some(KdfStrength::Light))
    );
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
        Keyfile::from_bytes(&std::fs::read(fixture_dir().join("vault-v6.keyfile")).unwrap())
            .unwrap();
    for (with_pin, unlock) in [
        (
            true,
            Unlock::PasswordAndKeyfile {
                password: PASSWORD,
                secret_key: &secret_key,
                keyfile: &keyfile,
            },
        ),
        (false, Unlock::Recovery(&recovery_key)),
    ] {
        let mut vault = Vault::open(&bytes, unlock).unwrap();
        assert_eq!(vault.revision(), 1);
        assert_eq!(vault.settings().name, VAULT_NAME);
        assert_eq!(vault.settings().history_limit, 7);
        let guard = vault.item_guard();
        assert_eq!((guard.all_items, guard.check), (true, GuardCheck::Pin));
        assert!(guard.encrypts() && guard.master_can_reset() && !guard.is_legacy());
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
        let read = |vault: &Vault| {
            let mut items: Vec<ItemData> = vault
                .item_ids()
                .map(|id| vault.get_item(&id).unwrap())
                .collect();
            items.sort_by(|a, b| a.title.cmp(&b.title));
            items
        };
        // The vault key alone shows who the accounts are, not their secrets.
        let locked = read(&vault);
        assert!(locked.iter().all(ItemData::is_locked));
        let (login, note) = (&locked[0], &locked[1]);
        assert_eq!(
            (login.title.as_str(), login.username.as_str()),
            ("Fixture Login", "fixture-user")
        );
        assert_eq!(login.urls, ["https://fixture.example"]);
        assert!(login.password.is_empty() && login.totp.is_empty());
        assert!(login.recovery_codes.is_empty() && login.password_history.is_empty());
        assert!(note.notes.is_empty());
        let summaries = vault.summaries().unwrap();
        let summary = summaries
            .iter()
            .find(|s| s.title == "Fixture Login")
            .unwrap();
        assert!(summary.locked && summary.has_totp && summary.has_password);

        assert!(!vault.unlock_secrets("0000").unwrap());
        assert!(!vault.secrets_open());
        assert!(
            !vault
                .unlock_secrets_with_master("not the master password")
                .unwrap()
        );
        if with_pin {
            assert!(vault.unlock_secrets(GUARD_PIN).unwrap());
        } else {
            assert!(vault.unlock_secrets_with_master(PASSWORD).unwrap());
        }
        assert_eq!(read(&vault), expected_items(Some(folder)));
        vault.lock_secrets();
        assert!(read(&vault).iter().all(ItemData::is_locked));
    }
}

/// Regenerates the fixture. Run only when intentionally creating a new format version:
/// `cargo test -p vault-core --test format_v6 -- --ignored`
#[test]
#[ignore = "writes the committed fixture"]
fn generate_fixture() {
    let secret_key = SecretKey::generate().unwrap();
    let recovery_key = RecoveryKey::generate().unwrap();
    let mut vault = Vault::create(
        PASSWORD,
        &secret_key,
        Some(&recovery_key),
        PasswordKdf::preset(KdfMethod::Scrypt, KdfStrength::Light).unwrap(),
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
        .set_item_guard(true, GuardCheck::Pin, Some(GUARD_PIN), Some(PASSWORD))
        .unwrap();
    let (keyfile, keyfile_bytes) = Keyfile::generate().unwrap();
    let kdf = vault.kdf_params().clone();
    vault
        .change_password(PASSWORD, &secret_key, Some(&keyfile), &kdf)
        .unwrap();
    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("vault-v6.keyfile"), &*keyfile_bytes).unwrap();
    std::fs::write(dir.join("vault-v6.bin"), vault.to_bytes().unwrap()).unwrap();
    std::fs::write(
        dir.join("vault-v6.credentials.txt"),
        format!(
            "# Test credentials for vault-v6.bin (fixture only, not real secrets).\n\
             # keyfile = vault-v6.keyfile (test value, next to this file)\n\
             # password = see PASSWORD in tests/format_v6.rs\n\
             secret_key = {}\nrecovery_key = {}\n",
            secret_key.to_display_string().as_str(),
            recovery_key.to_display_string().as_str()
        ),
    )
    .unwrap();
}
