//! Known-answer test for the v0 file format.
//!
//! `fixtures/vault-v0.bin` was produced once by `generate_fixture` and committed. If this test
//! fails, the code no longer reads files written by earlier builds: either a bug, or a format
//! change that needs a new format version and a migration.
//!
//! The credentials below are test values for this fixture only.

use std::path::PathBuf;

use vault_core::{ItemData, ItemKind, KdfParams, RecoveryKey, SecretKey, Unlock, Vault};

const PASSWORD: &str = "fixture password ✓ çãé";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Reads `key = value` lines from the fixture's credential file.
fn credentials() -> (SecretKey, RecoveryKey) {
    let text = std::fs::read_to_string(fixture_dir().join("vault-v0.credentials.txt")).unwrap();
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

fn expected_items() -> Vec<ItemData> {
    let mut login = ItemData::login(
        "Fixture Login",
        "fixture-user",
        "Fixture-P@ss-123",
        "https://fixture.example",
    );
    login.created_at = 1_700_000_000;
    login.updated_at = 1_700_000_100;
    login.totp = "JBSWY3DPEHPK3PXP".into();
    login.favorite = true;
    let mut note = ItemData::new(ItemKind::SecureNote, "Fixture Note");
    note.notes = "multi\nline ✓".into();
    note.created_at = 1_700_000_200;
    note.updated_at = 1_700_000_200;
    vec![login, note]
}

#[test]
fn reads_the_committed_v0_fixture() {
    let bytes = std::fs::read(fixture_dir().join("vault-v0.bin")).unwrap();
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
        let mut items: Vec<ItemData> = vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .collect();
        items.sort_by(|a, b| a.title.cmp(&b.title));
        assert_eq!(items, expected_items());
    }
}

/// Regenerates the fixture. Run only when intentionally creating a new format version:
/// `cargo test -p vault-core --test format_v0 -- --ignored`
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
    for item in expected_items() {
        vault.add_item(&item).unwrap();
    }
    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("vault-v0.bin"), vault.to_bytes().unwrap()).unwrap();
    std::fs::write(
        dir.join("vault-v0.credentials.txt"),
        format!(
            "# Test credentials for vault-v0.bin (fixture only, not real secrets).\n\
             # password = see PASSWORD in tests/format_v0.rs\n\
             secret_key = {}\nrecovery_key = {}\n",
            secret_key.to_display_string().as_str(),
            recovery_key.to_display_string().as_str()
        ),
    )
    .unwrap();
}
