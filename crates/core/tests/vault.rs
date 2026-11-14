//! End-to-end tests of the public `vault-core` API.

#[test]
fn every_hash_method_opens_its_vault_and_can_be_switched() {
    use vault_core::{KdfMethod, KdfStrength, PasswordKdf};
    let secret_key = SecretKey::generate().unwrap();
    let unlock = || Unlock::Password {
        password: "pw",
        secret_key: &secret_key,
    };
    let mut vault = Vault::create(
        "pw",
        &secret_key,
        None,
        PasswordKdf::preset(KdfMethod::Pbkdf2Sha256, KdfStrength::Light).unwrap(),
    )
    .unwrap();
    let id = vault
        .add_item(&ItemData::login(
            "Site",
            "me",
            "s3cret",
            "https://site.example",
        ))
        .unwrap();
    for method in [
        KdfMethod::Pbkdf2Sha256,
        KdfMethod::Scrypt,
        KdfMethod::Argon2id,
    ] {
        let kdf = PasswordKdf::preset(method, KdfStrength::Light).unwrap();
        vault
            .change_password("pw", &secret_key, None, &kdf)
            .unwrap();
        let bytes = vault.to_bytes().unwrap();
        let info = Vault::inspect(&bytes).unwrap();
        assert_eq!(info.kdf.method(), method);
        assert_eq!(info.kdf.strength(), Some(KdfStrength::Light));
        let opened = Vault::open(&bytes, unlock()).unwrap();
        assert_eq!(opened.get_item(&id).unwrap().password, "s3cret");
        assert!(matches!(
            Vault::open(
                &bytes,
                Unlock::Password {
                    password: "pw2",
                    secret_key: &secret_key
                }
            ),
            Err(Error::DecryptionFailed)
        ));
    }
}

#[test]
fn guarded_secrets_are_encrypted_under_the_pin() {
    use vault_core::{CustomField, GuardCheck, RecoveryCode};
    let secret_key = SecretKey::generate().unwrap();
    let recovery_key = RecoveryKey::generate().unwrap();
    let kdf = KdfParams::minimum().unwrap();
    let mut vault = Vault::create("pw", &secret_key, Some(&recovery_key), kdf.clone()).unwrap();
    let mut bank = ItemData::login("Bank", "me@bank", "s3cret", "https://bank.example");
    bank.totp = "JBSWY3DPEHPK3PXP".into();
    bank.notes = "branch 12".into();
    bank.recovery_codes = RecoveryCode::parse_list("aaaa-1111");
    bank.custom_fields = vec![
        CustomField {
            name: "Agency".into(),
            value: "0001".into(),
            sensitive: false,
        },
        CustomField {
            name: "Card PIN".into(),
            value: "7788".into(),
            sensitive: true,
        },
    ];
    bank.reprompt = true;
    let bank_id = vault.add_item(&bank).unwrap();
    let forum = ItemData::login("Forum", "me", "forum-pw", "");
    let forum_id = vault.add_item(&forum).unwrap();

    // Only marked items, opened by a PIN; the master password can replace a forgotten PIN.
    assert!(matches!(
        vault.set_item_guard(false, GuardCheck::Pin, Some("12"), Some("pw")),
        Err(Error::InvalidGuardSecret)
    ));
    assert!(matches!(
        vault.set_item_guard(false, GuardCheck::Pin, None, Some("pw")),
        Err(Error::InvalidGuardSecret)
    ));
    vault
        .set_item_guard(false, GuardCheck::Pin, Some("4821"), Some("pw"))
        .unwrap();
    assert!(vault.item_guard().encrypts() && vault.secrets_open());
    assert_eq!(vault.get_item(&bank_id).unwrap().password, "s3cret");
    vault.lock_secrets();

    let locked = vault.get_item(&bank_id).unwrap();
    assert!(locked.is_locked());
    assert_eq!(
        (locked.title.as_str(), locked.username.as_str()),
        ("Bank", "me@bank")
    );
    assert_eq!(locked.notes, "branch 12", "a login's notes stay readable");
    assert_eq!(locked.custom_fields[0].value, "0001");
    assert_eq!(
        locked.custom_fields[1].value, "",
        "hidden fields are secrets"
    );
    assert!(locked.password.is_empty() && locked.totp.is_empty());
    assert!(locked.recovery_codes.is_empty());
    assert!(!format!("{locked:?}").contains("s3cret"));
    assert_eq!(vault.get_item(&forum_id).unwrap().password, "forum-pw");

    // Locked secrets can't be changed; what is visible can.
    let mut changed = bank.clone();
    changed.password = "other".into();
    assert!(matches!(
        vault.update_item(&bank_id, &changed),
        Err(Error::SecretsLocked)
    ));
    assert!(matches!(
        vault.clear_password_history(&bank_id),
        Err(Error::SecretsLocked)
    ));
    assert!(vault.needs_unlock_to_store(&bank));
    // A new item needs no PIN: it is sealed the next time the guard opens.
    let shop = vault.add_item(&bank).unwrap();
    assert_eq!(vault.pending_seal().unwrap(), 1);
    assert_eq!(vault.seal_pending().unwrap(), 0, "the guard is closed");
    // Until then it can be starred or edited, and keeps waiting.
    let mut starred = vault.get_item(&shop).unwrap();
    assert!(!starred.is_locked());
    starred.favorite = true;
    starred.password = "shop-pw-2".into();
    vault.update_item(&shop, &starred).unwrap();
    assert_eq!(vault.pending_seal().unwrap(), 1);
    assert_eq!(vault.get_item(&shop).unwrap().password, "shop-pw-2");
    assert!(vault.unlock_secrets("4821").unwrap());
    assert_eq!(vault.seal_pending().unwrap(), 1);
    assert_eq!(vault.pending_seal().unwrap(), 0);
    vault.lock_secrets();
    assert!(vault.get_item(&shop).unwrap().is_locked());
    vault.remove_item(&shop).unwrap();
    let mut view = locked.clone();
    view.favorite = true;
    view.title = "Bank ✓".into();
    vault.update_item(&bank_id, &view).unwrap();

    // The saved file keeps them sealed, for the Recovery Key too.
    let bytes = vault.to_bytes().unwrap();
    for unlock in [
        Unlock::Password {
            password: "pw",
            secret_key: &secret_key,
        },
        Unlock::Recovery(&recovery_key),
    ] {
        let mut opened = Vault::open(&bytes, unlock).unwrap();
        assert!(opened.get_item(&bank_id).unwrap().is_locked());
        let summaries = opened.summaries().unwrap();
        let summary = summaries.iter().find(|s| s.id == bank_id).unwrap();
        assert!(summary.locked && summary.has_totp && summary.has_password);
        assert!(!opened.unlock_secrets("0000").unwrap());
        assert!(opened.unlock_secrets("4821").unwrap());
        let open = opened.get_item(&bank_id).unwrap();
        assert!(!open.is_locked() && open.favorite);
        assert_eq!(
            (
                open.title.as_str(),
                open.password.as_str(),
                open.totp.as_str()
            ),
            ("Bank ✓", "s3cret", "JBSWY3DPEHPK3PXP")
        );
        assert_eq!(open.custom_fields[1].value, "7788");
        assert_eq!(open.recovery_codes.len(), 1);
    }

    // A view read while locked and written after the unlock keeps the secrets.
    let view = vault.get_item(&bank_id).unwrap();
    assert!(vault.unlock_secrets("4821").unwrap());
    vault.update_item(&bank_id, &view).unwrap();
    assert_eq!(vault.get_item(&bank_id).unwrap().password, "s3cret");
    // Open, a password change is recorded as usual.
    let mut open = vault.get_item(&bank_id).unwrap();
    open.password = "n3w".into();
    vault.update_item(&bank_id, &open).unwrap();
    assert_eq!(vault.get_item(&bank_id).unwrap().password_history.len(), 1);

    // The device (Windows Hello) can stand in for the PIN, until the PIN changes.
    let device = [7u8; 64];
    let sealed = vault.seal_guard_for_device(&device).unwrap();
    vault.lock_secrets();
    assert!(matches!(
        vault.seal_guard_for_device(&device),
        Err(Error::SecretsLocked)
    ));
    assert!(
        !vault
            .unlock_secrets_with_device(&[8u8; 64], &sealed)
            .unwrap()
    );
    assert!(!vault.secrets_open());
    assert!(vault.unlock_secrets_with_device(&device, &sealed).unwrap());
    assert_eq!(vault.get_item(&bank_id).unwrap().password, "n3w");
    let old_device_copy = sealed;

    // A forgotten PIN: the master password opens the way to a new one, for every item now.
    vault.lock_secrets();
    assert!(matches!(
        vault.set_item_guard(true, GuardCheck::Pin, Some("9999"), None),
        Err(Error::SecretsLocked)
    ));
    assert!(matches!(
        vault.set_item_guard(true, GuardCheck::Pin, Some("9999"), Some("not it")),
        Err(Error::SecretsLocked)
    ));
    vault
        .set_item_guard(true, GuardCheck::Pin, Some("9999"), Some("pw"))
        .unwrap();
    vault.lock_secrets();
    assert!(vault.get_item(&forum_id).unwrap().is_locked());
    assert!(!vault.unlock_secrets("4821").unwrap());
    assert!(
        !vault
            .unlock_secrets_with_device(&device, &old_device_copy)
            .unwrap(),
        "a new PIN revokes the device copy"
    );
    assert!(vault.unlock_secrets("9999").unwrap());
    assert_eq!(vault.get_item(&forum_id).unwrap().password, "forum-pw");

    // A new master password takes over the reset copy while secrets are open.
    vault
        .change_password("pw2", &secret_key, None, &kdf)
        .unwrap();
    vault.lock_secrets();
    assert!(!vault.unlock_secrets_with_master("pw").unwrap());
    assert!(vault.unlock_secrets_with_master("pw2").unwrap());

    // Back to the master password as the check: nothing stays sealed.
    vault.lock_secrets();
    vault
        .set_item_guard(false, GuardCheck::Master, None, Some("pw2"))
        .unwrap();
    assert!(!vault.item_guard().encrypts() && !vault.secrets_open());
    let bytes = vault.to_bytes().unwrap();
    let opened = Vault::open(
        &bytes,
        Unlock::Password {
            password: "pw2",
            secret_key: &secret_key,
        },
    )
    .unwrap();
    let plain = opened.get_item(&bank_id).unwrap();
    assert!(!plain.is_locked() && plain.reprompt);
    assert_eq!(plain.password, "n3w");
}

#[test]
fn a_keyfile_is_a_third_factor() {
    use vault_core::Keyfile;
    let secret_key = SecretKey::generate().unwrap();
    let recovery_key = RecoveryKey::generate().unwrap();
    let kdf = KdfParams::minimum().unwrap();
    let mut vault = Vault::create("pw", &secret_key, Some(&recovery_key), kdf.clone()).unwrap();
    let mut item = ItemData::login("Bank", "me", "s3cret", "https://bank.example");
    item.reprompt = true;
    let id = vault.add_item(&item).unwrap();
    assert!(!vault.needs_keyfile());

    let (keyfile, file) = Keyfile::generate().unwrap();
    assert!(file.starts_with(b"vault-keyfile-v1 "));
    vault
        .change_password("pw", &secret_key, Some(&keyfile), &kdf)
        .unwrap();
    assert!(vault.needs_keyfile());
    let bytes = vault.to_bytes().unwrap();
    assert!(Vault::inspect(&bytes).unwrap().needs_keyfile);

    // The password and Secret Key alone are refused, before any hashing.
    assert!(matches!(
        Vault::open(
            &bytes,
            Unlock::Password {
                password: "pw",
                secret_key: &secret_key
            }
        ),
        Err(Error::KeyfileRequired)
    ));
    // Another file, or the same file with one byte changed, doesn't open it.
    let mut changed = file.to_vec();
    changed[20] ^= 1;
    for wrong in [
        Keyfile::generate().unwrap().0,
        Keyfile::from_bytes(&changed).unwrap(),
    ] {
        assert!(matches!(
            Vault::open(
                &bytes,
                Unlock::PasswordAndKeyfile {
                    password: "pw",
                    secret_key: &secret_key,
                    keyfile: &wrong
                }
            ),
            Err(Error::DecryptionFailed)
        ));
    }
    // The same bytes read again do; so does the Recovery Key on its own.
    let again = Keyfile::from_bytes(&file).unwrap();
    let opened = Vault::open(
        &bytes,
        Unlock::PasswordAndKeyfile {
            password: "pw",
            secret_key: &secret_key,
            keyfile: &again,
        },
    )
    .unwrap();
    assert!(opened.get_item(&id).unwrap().reprompt);
    assert!(opened.summaries().unwrap()[0].reprompt);
    let mut recovered = Vault::open(&bytes, Unlock::Recovery(&recovery_key)).unwrap();

    // Removing the keyfile goes back to two factors; a keyfile offered to such a vault is
    // simply not used.
    recovered
        .change_password("pw2", &secret_key, None, &kdf)
        .unwrap();
    assert!(!recovered.needs_keyfile());
    let plain = recovered.to_bytes().unwrap();
    for unlock in [
        Unlock::Password {
            password: "pw2",
            secret_key: &secret_key,
        },
        Unlock::PasswordAndKeyfile {
            password: "pw2",
            secret_key: &secret_key,
            keyfile: &again,
        },
    ] {
        Vault::open(&plain, unlock).unwrap();
    }
    // Too small or too large to be a keyfile.
    assert!(Keyfile::from_bytes(b"short").is_err());
    assert!(Keyfile::from_bytes(&vec![0u8; Keyfile::MAX_LEN + 1]).is_err());
}

#[test]
fn folders_can_be_reordered_and_get_a_picture_link() {
    let secret_key = SecretKey::generate().unwrap();
    let mut vault = Vault::create("pw", &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    let a = vault.add_folder("A").unwrap();
    let b = vault.add_folder("B").unwrap();
    let c = vault.add_folder("C").unwrap();
    let names = |v: &Vault| {
        v.folders()
            .iter()
            .map(|f| f.name.clone())
            .collect::<Vec<_>>()
    };
    vault.move_folder(&c, 0).unwrap();
    assert_eq!(names(&vault), ["C", "A", "B"]);
    vault.move_folder(&c, 99).unwrap();
    assert_eq!(names(&vault), ["A", "B", "C"]);
    vault.move_folder(&a, 1).unwrap();
    assert_eq!(names(&vault), ["B", "A", "C"]);

    vault
        .set_folder_icon_url(&b, "  https://example.com/logo.png ")
        .unwrap();
    assert_eq!(vault.folders()[0].icon_url, "https://example.com/logo.png");
    assert!(vault.set_folder_icon_url(&b, "two words").is_err());
    assert!(vault.set_folder_icon_url(&b, &"x".repeat(3000)).is_err());

    let reopened = Vault::open(
        &vault.to_bytes().unwrap(),
        Unlock::Password {
            password: "pw",
            secret_key: &secret_key,
        },
    )
    .unwrap();
    assert_eq!(names(&reopened), ["B", "A", "C"]);
    assert_eq!(
        reopened.folders()[0].icon_url,
        "https://example.com/logo.png"
    );
}

#[test]
fn folders_get_an_icon_and_a_colour() {
    let secret_key = SecretKey::generate().unwrap();
    let mut vault = Vault::create("pw", &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    let id = vault.add_folder("Google").unwrap();
    assert_eq!(vault.folders()[0].icon, "");
    vault.style_folder(&id, "globe", 3).unwrap();
    assert_eq!(
        (vault.folders()[0].icon.as_str(), vault.folders()[0].color),
        ("globe", 3)
    );
    assert!(vault.style_folder(&id, "bad icon!", 0).is_err());
    assert!(vault.style_folder(&id, "globe", 16).is_err());
    let bytes = vault.to_bytes().unwrap();
    let reopened = Vault::open(
        &bytes,
        Unlock::Password {
            password: "pw",
            secret_key: &secret_key,
        },
    )
    .unwrap();
    assert_eq!(reopened.folders()[0].icon, "globe");
}

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
    bytes[8] = 7; // format_version = 7: from the future
    assert!(matches!(
        Vault::open(&bytes, Unlock::Recovery(&f.recovery_key)),
        Err(Error::UnsupportedVersion(7))
    ));
    // Relabelling a current file as an older version never opens it: the header no longer
    // parses in the old layout, and where it does (v5, same body layout aside) the version is
    // part of the authenticated header, so the body won't decrypt.
    for older in 0..6u8 {
        let mut relabelled = f.vault.to_bytes().unwrap();
        relabelled[8] = older;
        assert!(matches!(
            Vault::open(&relabelled, Unlock::Recovery(&f.recovery_key)),
            Err(Error::DecryptionFailed | Error::Malformed)
        ));
    }
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
            None,
            KdfParams::minimum().unwrap(),
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
