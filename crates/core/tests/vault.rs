//! End-to-end tests of the public `vault-core` API.

#[test]
fn password_changes_are_kept_in_the_history() {
    let secret_key = SecretKey::generate().unwrap();
    let mut vault = Vault::create("pw", &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    let mut item = ItemData::login("Site", "me", "first", "");
    item.created_at = 100;
    let id = vault.add_item(&item).unwrap();
    assert_eq!(vault.get_item(&id).unwrap().password_changed_at, 100);

    // Same password: nothing recorded.
    let mut same = vault.get_item(&id).unwrap();
    same.notes = "changed notes".into();
    vault.update_item(&id, &same).unwrap();
    assert!(vault.get_item(&id).unwrap().password_history.is_empty());

    vault
        .set_settings(vault_core::VaultSettings {
            name: "  Home  ".into(),
            history_limit: 2,
        })
        .unwrap();
    assert_eq!(vault.settings().name, "Home");
    for next in ["second", "third", "fourth"] {
        let mut changed = vault.get_item(&id).unwrap();
        changed.password = next.into();
        changed.password_history.clear(); // ignored: the vault keeps its own record
        vault.update_item(&id, &changed).unwrap();
    }
    let stored = vault.get_item(&id).unwrap();
    let old: Vec<&str> = stored
        .password_history
        .iter()
        .map(|c| c.password.as_str())
        .collect();
    assert_eq!(old, ["second", "third"], "oldest dropped past the limit");
    assert!(stored.password_changed_at > 100);
    assert!(stored.password_history.iter().all(|c| c.replaced_at > 0));

    vault.clear_password_history(&id).unwrap();
    assert!(vault.get_item(&id).unwrap().password_history.is_empty());
    assert_eq!(vault.get_item(&id).unwrap().password, "fourth");

    assert!(
        vault
            .set_settings(vault_core::VaultSettings {
                name: "x".repeat(61),
                history_limit: 2,
            })
            .is_err()
    );
    assert!(
        vault
            .set_settings(vault_core::VaultSettings {
                name: String::new(),
                history_limit: 101,
            })
            .is_err()
    );
}

use vault_core::{
    CustomField, Error, ItemData, ItemKind, KdfParams, RecoveryKey, SecretKey, Unlock, Vault,
    storage,
};

const PASSWORD: &str = "correct horse battery staple";

struct Fixture {
    secret_key: SecretKey,
    recovery_key: RecoveryKey,
    vault: Vault,
}

fn fixture() -> Fixture {
    let secret_key = SecretKey::generate().unwrap();
    let recovery_key = RecoveryKey::generate().unwrap();
    let vault = Vault::create(
        PASSWORD,
        &secret_key,
        Some(&recovery_key),
        KdfParams::minimum().unwrap(),
    )
    .unwrap();
    Fixture {
        secret_key,
        recovery_key,
        vault,
    }
}

fn unlock_with_password<'a>(password: &'a str, secret_key: &'a SecretKey) -> Unlock<'a> {
    Unlock::Password {
        password,
        secret_key,
    }
}

#[test]
fn create_save_and_reopen_with_password() {
    let mut f = fixture();
    let mut login = ItemData::login("GitHub", "octocat", "s3cr3t!", "https://github.com");
    login.custom_fields.push(CustomField {
        name: "Recovery code".into(),
        value: "abcd-efgh".into(),
        sensitive: true,
    });
    let id = f.vault.add_item(&login).unwrap();
    let mut note = ItemData::new(ItemKind::SecureNote, "Wi-Fi");
    note.notes = "password on the router".into();
    let note_id = f.vault.add_item(&note).unwrap();

    let bytes = f.vault.to_bytes().unwrap();
    let reopened = Vault::open(&bytes, unlock_with_password(PASSWORD, &f.secret_key)).unwrap();

    assert_eq!(reopened.len(), 2);
    assert_eq!(reopened.revision(), 1);
    assert_eq!(reopened.id_hex(), f.vault.id_hex());
    let mut expected = login.clone();
    expected.password_changed_at = login.created_at; // set when added
    assert_eq!(reopened.get_item(&id).unwrap(), expected);
    assert_eq!(reopened.get_item(&note_id).unwrap(), note);
}

#[test]
fn reopen_with_recovery_key() {
    let mut f = fixture();
    let id = f
        .vault
        .add_item(&ItemData::login("Bank", "me", "pin", ""))
        .unwrap();
    let bytes = f.vault.to_bytes().unwrap();
    let reopened = Vault::open(&bytes, Unlock::Recovery(&f.recovery_key)).unwrap();
    assert_eq!(reopened.get_item(&id).unwrap().password, "pin");
}

#[test]
fn printed_keys_unlock_the_vault() {
    let mut f = fixture();
    let bytes = f.vault.to_bytes().unwrap();
    let typed_secret = SecretKey::parse(&f.secret_key.to_display_string().to_lowercase()).unwrap();
    assert!(Vault::open(&bytes, unlock_with_password(PASSWORD, &typed_secret)).is_ok());
    let typed_recovery = RecoveryKey::parse(&f.recovery_key.to_display_string()).unwrap();
    assert!(Vault::open(&bytes, Unlock::Recovery(&typed_recovery)).is_ok());
}

#[test]
fn wrong_credentials_fail_identically() {
    let mut f = fixture();
    let bytes = f.vault.to_bytes().unwrap();

    let wrong_password = Vault::open(
        &bytes,
        unlock_with_password("correct horse battery stapl", &f.secret_key),
    );
    assert!(matches!(wrong_password, Err(Error::DecryptionFailed)));

    let other_secret = SecretKey::generate().unwrap();
    let wrong_secret = Vault::open(&bytes, unlock_with_password(PASSWORD, &other_secret));
    assert!(matches!(wrong_secret, Err(Error::DecryptionFailed)));

    let other_recovery = RecoveryKey::generate().unwrap();
    let wrong_recovery = Vault::open(&bytes, Unlock::Recovery(&other_recovery));
    assert!(matches!(wrong_recovery, Err(Error::DecryptionFailed)));

    assert!(matches!(
        Vault::open(&bytes, unlock_with_password("", &f.secret_key)),
        Err(Error::EmptyPassword)
    ));
}

#[test]
fn file_reveals_no_plaintext() {
    let mut f = fixture();
    f.vault
        .add_item(&ItemData::login(
            "VeryUniqueTitle",
            "unique-user",
            "UniquePassword123",
            "https://unique.example",
        ))
        .unwrap();
    let bytes = f.vault.to_bytes().unwrap();
    for needle in [
        "VeryUniqueTitle",
        "unique-user",
        "UniquePassword123",
        "unique.example",
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} found in the vault file"
        );
    }
}

#[test]
fn padding_hides_small_changes_in_content() {
    let mut f = fixture();
    let empty = f.vault.to_bytes().unwrap().len();
    f.vault
        .add_item(&ItemData::login("a", "b", "c", ""))
        .unwrap();
    let one_item = f.vault.to_bytes().unwrap().len();
    f.vault
        .add_item(&ItemData::login("d", "e", "f", ""))
        .unwrap();
    let two_items = f.vault.to_bytes().unwrap().len();
    assert_eq!(
        empty, one_item,
        "a small item must not change the file size"
    );
    assert_eq!(one_item, two_items);
}

#[test]
fn every_byte_is_protected() {
    let mut f = fixture();
    f.vault
        .add_item(&ItemData::login("t", "u", "p", ""))
        .unwrap();
    let bytes = f.vault.to_bytes().unwrap();
    // Recovery unlock skips Argon2, so this exhaustive loop stays fast.
    for i in 0..bytes.len() {
        let mut tampered = bytes.clone();
        tampered[i] ^= 0x80;
        assert!(
            Vault::open(&tampered, Unlock::Recovery(&f.recovery_key)).is_err(),
            "flipping byte {i} of {} was not detected",
            bytes.len()
        );
    }
}

#[test]
fn truncation_and_trailing_bytes_are_rejected() {
    let mut f = fixture();
    let bytes = f.vault.to_bytes().unwrap();
    for len in [0, 7, 8, 13, 14, bytes.len() / 2, bytes.len() - 1] {
        assert!(Vault::open(&bytes[..len], Unlock::Recovery(&f.recovery_key)).is_err());
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(
        Vault::open(&longer, Unlock::Recovery(&f.recovery_key)),
        Err(Error::Malformed)
    ));
}

#[test]
fn foreign_files_and_future_versions_are_rejected() {
    let mut f = fixture();
    assert!(matches!(
        Vault::open(
            b"hello world, definitely not a vault",
            Unlock::Recovery(&f.recovery_key)
        ),
        Err(Error::NotAVault)
    ));
    let mut bytes = f.vault.to_bytes().unwrap();
    bytes[8] = 3; // format_version = 3: from the future
    assert!(matches!(
        Vault::open(&bytes, Unlock::Recovery(&f.recovery_key)),
        Err(Error::UnsupportedVersion(3))
    ));
    // Relabelling a current file as an older version changes the authenticated header: the body won't open.
    let mut relabelled = f.vault.to_bytes().unwrap();
    relabelled[8] = 0;
    assert!(matches!(
        Vault::open(&relabelled, Unlock::Recovery(&f.recovery_key)),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn folders_and_recovery_codes() {
    let mut f = fixture();
    let google = f.vault.add_folder("  Google accounts ").unwrap();
    let work = f.vault.add_folder("Work").unwrap();
    assert!(matches!(f.vault.add_folder("   "), Err(Error::InvalidName)));
    assert_eq!(f.vault.folders()[0].name, "Google accounts");

    let mut gmail = ItemData::login("Gmail", "me", "pw", "https://mail.google.com");
    gmail.folder = Some(google);
    gmail.recovery_codes = vault_core::RecoveryCode::parse_list("1111-2222\n3333-4444");
    let gmail_id = f.vault.add_item(&gmail).unwrap();
    let mut jira = ItemData::login("Jira", "me", "pw", "");
    jira.folder = Some(work);
    let jira_id = f.vault.add_item(&jira).unwrap();

    // Survives a save and reopen.
    let bytes = f.vault.to_bytes().unwrap();
    let mut reopened = Vault::open(&bytes, Unlock::Recovery(&f.recovery_key)).unwrap();
    assert_eq!(reopened.folders().len(), 2);
    let loaded = reopened.get_item(&gmail_id).unwrap();
    assert_eq!(loaded.folder, Some(google));
    assert_eq!(loaded.recovery_codes.len(), 2);
    let summaries = reopened.summaries().unwrap();
    assert!(summaries.iter().any(|s| s.folder == Some(work)));

    reopened.rename_folder(&work, "Job").unwrap();
    assert_eq!(reopened.folders()[1].name, "Job");
    // Deleting a folder keeps its items, outside any folder.
    reopened.remove_folder(&work).unwrap();
    assert_eq!(reopened.folders().len(), 1);
    assert_eq!(reopened.get_item(&jira_id).unwrap().folder, None);
    assert!(matches!(
        reopened.remove_folder(&work),
        Err(Error::FolderNotFound)
    ));

    // Folder names are encrypted like everything else.
    let bytes = reopened.to_bytes().unwrap();
    assert!(!bytes.windows(6).any(|w| w == b"Google"));
}

#[test]
fn update_and_remove_items() {
    let mut f = fixture();
    let id = f
        .vault
        .add_item(&ItemData::login("Mail", "me", "old", ""))
        .unwrap();
    let mut changed = f.vault.get_item(&id).unwrap();
    changed.password = "new".into();
    changed.favorite = true;
    f.vault.update_item(&id, &changed).unwrap();
    assert_eq!(f.vault.get_item(&id).unwrap().password, "new");

    let bytes = f.vault.to_bytes().unwrap();
    let mut reopened = Vault::open(&bytes, Unlock::Recovery(&f.recovery_key)).unwrap();
    assert!(reopened.get_item(&id).unwrap().favorite);

    reopened.remove_item(&id).unwrap();
    assert!(reopened.is_empty());
    assert!(matches!(reopened.get_item(&id), Err(Error::ItemNotFound)));
    assert!(matches!(
        reopened.remove_item(&id),
        Err(Error::ItemNotFound)
    ));
}

#[test]
fn summaries_list_items() {
    let mut f = fixture();
    f.vault
        .add_item(&ItemData::login("B", "bob", "x", "https://b.example"))
        .unwrap();
    f.vault
        .add_item(&ItemData::login("A", "alice", "y", ""))
        .unwrap();
    let mut summaries = f.vault.summaries().unwrap();
    summaries.sort_by(|a, b| a.title.cmp(&b.title));
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].title, "A");
    assert_eq!(summaries[1].url, "https://b.example");
}

#[test]
fn change_password_and_secret_key() {
    let mut f = fixture();
    let id = f
        .vault
        .add_item(&ItemData::login("t", "u", "p", ""))
        .unwrap();
    let new_secret = SecretKey::generate().unwrap();
    f.vault
        .change_password(
            "a brand new passphrase",
            &new_secret,
            &KdfParams::minimum().unwrap(),
        )
        .unwrap();
    let bytes = f.vault.to_bytes().unwrap();

    assert!(Vault::open(&bytes, unlock_with_password(PASSWORD, &f.secret_key)).is_err());
    assert!(
        Vault::open(
            &bytes,
            unlock_with_password("a brand new passphrase", &f.secret_key)
        )
        .is_err()
    );
    let reopened = Vault::open(
        &bytes,
        unlock_with_password("a brand new passphrase", &new_secret),
    )
    .unwrap();
    assert_eq!(reopened.get_item(&id).unwrap().password, "p");
    // The recovery key keeps working: the vault key did not change.
    assert!(Vault::open(&bytes, Unlock::Recovery(&f.recovery_key)).is_ok());
}

#[test]
fn recovery_slot_can_be_removed_and_replaced() {
    let mut f = fixture();
    f.vault.set_recovery_key(None).unwrap();
    assert!(!f.vault.has_recovery_key());
    let bytes = f.vault.to_bytes().unwrap();
    assert!(matches!(
        Vault::open(&bytes, Unlock::Recovery(&f.recovery_key)),
        Err(Error::NoMatchingSlot)
    ));

    let new_recovery = RecoveryKey::generate().unwrap();
    f.vault.set_recovery_key(Some(&new_recovery)).unwrap();
    let bytes = f.vault.to_bytes().unwrap();
    assert!(Vault::open(&bytes, Unlock::Recovery(&new_recovery)).is_ok());
    assert!(Vault::open(&bytes, Unlock::Recovery(&f.recovery_key)).is_err());
}

#[test]
fn revision_increments_on_every_save() {
    let mut f = fixture();
    f.vault.to_bytes().unwrap();
    f.vault.to_bytes().unwrap();
    let bytes = f.vault.to_bytes().unwrap();
    assert_eq!(f.vault.revision(), 3);
    let reopened = Vault::open(&bytes, Unlock::Recovery(&f.recovery_key)).unwrap();
    assert_eq!(reopened.revision(), 3);
}

#[test]
fn storage_round_trip() {
    let mut f = fixture();
    f.vault
        .add_item(&ItemData::login("t", "u", "p", ""))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("personal.vault");
    storage::write_atomic(&path, &f.vault.to_bytes().unwrap()).unwrap();
    storage::write_atomic(&path, &f.vault.to_bytes().unwrap()).unwrap();

    let current = Vault::open(
        &storage::read(&path).unwrap(),
        Unlock::Recovery(&f.recovery_key),
    )
    .unwrap();
    let backup = Vault::open(
        &storage::read(&storage::backup_path(&path)).unwrap(),
        Unlock::Recovery(&f.recovery_key),
    )
    .unwrap();
    assert_eq!(current.revision(), 2);
    assert_eq!(backup.revision(), 1);
}

#[test]
fn debug_output_never_contains_secrets() {
    let mut f = fixture();
    let id = f
        .vault
        .add_item(&ItemData::login("Title", "user", "TopSecretPassword", ""))
        .unwrap();
    let rendered = format!(
        "{:?} {:?} {:?} {:?}",
        f.vault,
        f.secret_key,
        f.recovery_key,
        f.vault.get_item(&id).unwrap()
    );
    assert!(!rendered.contains("TopSecretPassword"));
    assert!(!rendered.contains(f.secret_key.to_display_string().as_str()));
}
