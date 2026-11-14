//! Known-answer test for the v0 file format.
//!
//! `fixtures/vault-v0.bin` was produced by the v0 builds and committed; this build can only read
//! it (and upgrades it to v1 on save). If this test fails, files written by earlier builds no
//! longer open: either a bug, or a broken migration.
//!
//! The credentials below are test values for this fixture only.

use std::path::PathBuf;

use vault_core::{ItemData, ItemKind, RecoveryKey, SecretKey, Unlock, Vault};

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

/// Opening a v0 file upgrades it in memory; the next save writes the current format, which
/// opens with the same credentials and the same items (no folders, no recovery codes).
#[test]
fn a_v0_vault_is_upgraded_on_save() {
    let bytes = std::fs::read(fixture_dir().join("vault-v0.bin")).unwrap();
    let (secret_key, recovery_key) = credentials();
    let unlock = || Unlock::Password {
        password: PASSWORD,
        secret_key: &secret_key,
    };
    let mut vault = Vault::open(&bytes, unlock()).unwrap();
    let upgraded = vault.to_bytes().unwrap();
    assert_eq!(
        &upgraded[8..10],
        &6u16.to_le_bytes(),
        "written in the current format"
    );

    let reopened = Vault::open(&upgraded, unlock()).unwrap();
    assert!(reopened.folders().is_empty());
    let mut items: Vec<ItemData> = reopened
        .item_ids()
        .map(|id| reopened.get_item(&id).unwrap())
        .collect();
    items.sort_by(|a, b| a.title.cmp(&b.title));
    assert_eq!(items, expected_items());
    assert!(Vault::open(&upgraded, Unlock::Recovery(&recovery_key)).is_ok());
}
