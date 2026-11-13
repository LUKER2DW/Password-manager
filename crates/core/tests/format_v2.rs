//! Known-answer test for the v2 file format (vault settings, password history).
//!
//! `fixtures/vault-v2.bin` was produced once by `generate_fixture` and committed. If this test
//! fails, the code no longer reads files written by earlier builds: either a bug, or a format
//! change that needs a new format version and a migration.
//!
//! The credentials below are test values for this fixture only.

use std::path::PathBuf;

use vault_core::{
    FolderId, ItemData, ItemKind, KdfParams, PasswordChange, RecoveryCode, RecoveryKey, SecretKey,
    Unlock, Vault, VaultSettings,
};

const PASSWORD: &str = "fixture password v2 ✓ çãé";
const FOLDER: &str = "Fixture folder ✓";
const VAULT_NAME: &str = "Fixture vault ✓";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn credentials() -> (SecretKey, RecoveryKey) {
    let text = std::fs::read_to_string(fixture_dir().join("vault-v2.credentials.txt")).unwrap();
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
    let mut note = ItemData::new(ItemKind::SecureNote, "Fixture Note");
    note.notes = "multi\nline ✓".into();
    note.created_at = 1_790_000_200;
    note.updated_at = 1_790_000_200;
    vec![login, note]
}

#[test]
fn reads_the_committed_v2_fixture() {
    let bytes = std::fs::read(fixture_dir().join("vault-v2.bin")).unwrap();
    assert_eq!(&bytes[8..10], &2u16.to_le_bytes());
    let (secret_key, recovery_key) = credentials();

    for unlock in [
        Unlock::Password {
            password: PASSWORD,
            secret_key: &secret_key,
        },
        Unlock::Recovery(&recovery_key),
    ] {
        let vault = Vault::open(&bytes, unlock).unwrap();
        assert_eq!(vault.revision(), 1);
        assert_eq!(vault.settings().name, VAULT_NAME);
        assert_eq!(vault.settings().history_limit, 7);
        assert_eq!(vault.folders().len(), 1);
        assert_eq!(vault.folders()[0].name, FOLDER);
        let folder = vault.folders()[0].id;
        let mut items: Vec<ItemData> = vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .collect();
        items.sort_by(|a, b| a.title.cmp(&b.title));
        assert_eq!(items, expected_items(Some(folder)));
    }
}

/// Regenerates the fixture. Run only when intentionally creating a new format version:
/// `cargo test -p vault-core --test format_v2 -- --ignored`
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
    for item in expected_items(Some(folder)) {
        vault.add_item(&item).unwrap();
    }
    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("vault-v2.bin"), vault.to_bytes().unwrap()).unwrap();
    std::fs::write(
        dir.join("vault-v2.credentials.txt"),
        format!(
            "# Test credentials for vault-v2.bin (fixture only, not real secrets).\n\
             # password = see PASSWORD in tests/format_v2.rs\n\
             secret_key = {}\nrecovery_key = {}\n",
            secret_key.to_display_string().as_str(),
            recovery_key.to_display_string().as_str()
        ),
    )
    .unwrap();
}
