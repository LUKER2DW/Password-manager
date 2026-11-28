//! The three recovery parts of an emergency kit (format v8, CRYPTO.md §3.6): any two bring
//! back the Secret Key, all three open the vault, one alone opens nothing.

use vault_core::{
    Error, ItemData, KdfParams, Keyfile, PartLabel, RecoveryKey, RecoveryParts, SecretKey, Unlock,
    Vault,
};

const PASSWORD: &str = "test password for parts";

struct Fixture {
    vault: Vault,
    secret_key: SecretKey,
    parts: RecoveryParts,
}

fn fixture() -> Fixture {
    let secret_key = SecretKey::generate().unwrap();
    let mut vault =
        Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    let parts = RecoveryParts::generate().unwrap();
    vault.set_recovery_parts(&parts, &secret_key).unwrap();
    vault
        .add_item(&ItemData::login("Site", "me", "pw", "https://site.example"))
        .unwrap();
    Fixture {
        vault,
        secret_key,
        parts,
    }
}

#[test]
fn all_three_parts_open_the_vault_in_any_order() {
    let mut f = fixture();
    let bytes = f.vault.to_bytes().unwrap();
    let [a, b, c] = PartLabel::ALL.map(|label| f.parts.part(label));
    for order in [[a, b, c], [c, a, b], [b, c, a]] {
        let vault = Vault::open(&bytes, Unlock::Parts(order)).unwrap();
        assert_eq!(vault.len(), 1);
    }
    // The same part twice is not three parts.
    assert!(matches!(
        Vault::open(&bytes, Unlock::Parts([a, a, b])),
        Err(Error::InvalidKeyFormat)
    ));
    let info = Vault::inspect(&bytes).unwrap();
    assert!(info.has_recovery_parts && !info.has_recovery_key);
}

#[test]
fn any_two_parts_bring_back_the_secret_key_but_one_does_not() {
    let mut f = fixture();
    let bytes = f.vault.to_bytes().unwrap();
    let [a, b, c] = PartLabel::ALL.map(|label| f.parts.part(label));
    for (x, y) in [(a, b), (b, a), (a, c), (c, b)] {
        let secret_key = Vault::recover_secret_key(&bytes, x, y).unwrap();
        assert_eq!(secret_key, f.secret_key);
        // …and the Secret Key still needs the master password.
        assert!(
            Vault::open(
                &bytes,
                Unlock::Password {
                    password: PASSWORD,
                    secret_key: &secret_key,
                },
            )
            .is_ok()
        );
    }
    assert!(Vault::recover_secret_key(&bytes, a, a).is_err());
    // Two parts don't open the vault on their own: there is no such unlock, and two parts
    // with the third from another kit fail.
    let other = RecoveryParts::generate().unwrap();
    assert!(matches!(
        Vault::open(&bytes, Unlock::Parts([a, b, other.part(PartLabel::C)])),
        Err(Error::DecryptionFailed)
    ));
    assert!(matches!(
        Vault::recover_secret_key(&bytes, a, other.part(PartLabel::B)),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn a_new_password_or_secret_key_keeps_the_parts_working() {
    let mut f = fixture();
    let kdf = f.vault.kdf_params().clone();
    let new_secret_key = SecretKey::generate().unwrap();
    f.vault
        .change_password("a new password", &new_secret_key, None, &kdf)
        .unwrap();
    let bytes = f.vault.to_bytes().unwrap();
    let [a, b, c] = PartLabel::ALL.map(|label| f.parts.part(label));
    // Two parts bring back the new Secret Key, not the old one.
    let recovered = Vault::recover_secret_key(&bytes, b, c).unwrap();
    assert_eq!(recovered, new_secret_key);
    assert!(Vault::open(&bytes, Unlock::Parts([a, b, c])).is_ok());

    // With a keyfile too: the parts still open the vault and bring back the Secret Key.
    let keyfile = Keyfile::from_bytes(&[9u8; 32]).unwrap();
    f.vault
        .change_password("a new password", &new_secret_key, Some(&keyfile), &kdf)
        .unwrap();
    let bytes = f.vault.to_bytes().unwrap();
    assert!(Vault::open(&bytes, Unlock::Parts([a, b, c])).is_ok());
    assert_eq!(
        Vault::recover_secret_key(&bytes, a, c).unwrap(),
        new_secret_key
    );
}

#[test]
fn used_parts_are_retired() {
    let mut f = fixture();
    let before = f.vault.to_bytes().unwrap();
    let [a, b, c] = PartLabel::ALL.map(|label| f.parts.part(label));
    let mut opened = Vault::open(&before, Unlock::Parts([a, b, c])).unwrap();
    opened.clear_recovery_parts();
    let after = opened.to_bytes().unwrap();
    assert!(!Vault::inspect(&after).unwrap().has_recovery_parts);
    assert!(matches!(
        Vault::open(&after, Unlock::Parts([a, b, c])),
        Err(Error::NoMatchingSlot)
    ));
    assert!(Vault::recover_secret_key(&after, a, b).is_err());
    // The password and the items are as they were.
    let vault = Vault::open(
        &after,
        Unlock::Password {
            password: PASSWORD,
            secret_key: &f.secret_key,
        },
    )
    .unwrap();
    assert_eq!(vault.len(), 1);
    // Clearing twice is harmless.
    opened.clear_recovery_parts();
}

#[test]
fn a_new_kit_makes_the_old_parts_useless() {
    let mut f = fixture();
    let old = std::mem::replace(&mut f.parts, RecoveryParts::generate().unwrap());
    f.vault.set_recovery_parts(&f.parts, &f.secret_key).unwrap();
    let bytes = f.vault.to_bytes().unwrap();
    let [a, b, c] = PartLabel::ALL.map(|label| old.part(label));
    assert!(Vault::open(&bytes, Unlock::Parts([a, b, c])).is_err());
    assert!(Vault::recover_secret_key(&bytes, a, b).is_err());
    let [a, b, c] = PartLabel::ALL.map(|label| f.parts.part(label));
    assert!(Vault::open(&bytes, Unlock::Parts([a, b, c])).is_ok());
}

#[test]
fn parts_replace_a_recovery_key_and_the_other_way_round() {
    let secret_key = SecretKey::generate().unwrap();
    let recovery_key = RecoveryKey::generate().unwrap();
    let mut vault = Vault::create(
        PASSWORD,
        &secret_key,
        Some(&recovery_key),
        KdfParams::minimum().unwrap(),
    )
    .unwrap();
    assert!(vault.has_recovery_key() && !vault.has_recovery_parts());
    let parts = RecoveryParts::generate().unwrap();
    vault.set_recovery_parts(&parts, &secret_key).unwrap();
    assert!(!vault.has_recovery_key() && vault.has_recovery_parts());
    let bytes = vault.to_bytes().unwrap();
    assert!(matches!(
        Vault::open(&bytes, Unlock::Recovery(&recovery_key)),
        Err(Error::NoMatchingSlot)
    ));
    let all = PartLabel::ALL.map(|label| parts.part(label));
    assert!(Vault::open(&bytes, Unlock::Parts(all)).is_ok());

    // No recovery at all: the parts stop opening it too.
    vault.set_recovery_key(None).unwrap();
    assert!(!vault.has_recovery_parts());
    let bytes = vault.to_bytes().unwrap();
    assert!(matches!(
        Vault::open(&bytes, Unlock::Parts(all)),
        Err(Error::NoMatchingSlot)
    ));
    assert!(matches!(
        Vault::recover_secret_key(&bytes, all[0], all[1]),
        Err(Error::NoMatchingSlot)
    ));
}

#[test]
fn a_tampered_parts_slot_opens_nothing() {
    let mut f = fixture();
    let bytes = f.vault.to_bytes().unwrap();
    let [a, b, c] = PartLabel::ALL.map(|label| f.parts.part(label));
    // Flip every byte of the header in turn (past the envelope prefix): nothing opens with
    // the parts, and the Secret Key comes back only untouched.
    let header_len = u32::from_le_bytes(bytes[10..14].try_into().unwrap()) as usize;
    let mut checked_with_password = false;
    for index in 14..14 + header_len {
        let mut tampered = bytes.clone();
        tampered[index] ^= 0x01;
        assert!(Vault::open(&tampered, Unlock::Parts([a, b, c])).is_err());
        if let Ok(secret_key) = Vault::recover_secret_key(&tampered, a, b) {
            // The byte flipped was outside what this pair reads; the key is still right,
            // and the tampered file still won't open with it (checked once: it is slow).
            assert_eq!(secret_key, f.secret_key);
            if !checked_with_password {
                checked_with_password = true;
                assert!(
                    Vault::open(
                        &tampered,
                        Unlock::Password {
                            password: PASSWORD,
                            secret_key: &secret_key,
                        },
                    )
                    .is_err()
                );
            }
        }
    }
}

#[test]
fn the_parts_follow_the_header_through_sync() {
    let mut f = fixture();
    let bytes = f.vault.to_bytes().unwrap();
    let unlock = || Unlock::Password {
        password: PASSWORD,
        secret_key: &f.secret_key,
    };
    let mut other = Vault::open(&bytes, unlock()).unwrap();
    other.set_device(vault_core::sync::DeviceId::from_bytes([2; 16]));
    let new_parts = RecoveryParts::generate().unwrap();
    other.set_recovery_parts(&new_parts, &f.secret_key).unwrap();
    let copy = other.to_bytes().unwrap();
    f.vault
        .set_device(vault_core::sync::DeviceId::from_bytes([1; 16]));
    let mut seen = vault_core::sync::SeenRevisions::new();
    f.vault.merge(&copy, &mut seen).unwrap();
    let merged = f.vault.to_bytes().unwrap();
    let all = PartLabel::ALL.map(|label| new_parts.part(label));
    assert!(Vault::open(&merged, Unlock::Parts(all)).is_ok());
    let old = PartLabel::ALL.map(|label| f.parts.part(label));
    assert!(Vault::open(&merged, Unlock::Parts(old)).is_err());
}

/// The password of the kit's saved PDF files (CRYPTO.md §3.10): the same whenever the vault
/// is open, new with a new kit, a new Secret Key or a renewed vault key.
#[test]
fn the_kit_pdf_password_follows_the_kit() {
    let mut f = fixture();
    let first = f.vault.kit_pdf_password(&f.secret_key);
    let text = first.as_str().to_owned();
    assert_eq!(text.split(' ').count(), 4, "four words");
    assert_eq!(format!("{first:?}"), "KitPdfPassword(<redacted>)");

    // Shown again after the vault is opened again: nothing was stored for it.
    let bytes = f.vault.to_bytes().unwrap();
    let reopened = Vault::open(
        &bytes,
        Unlock::Password {
            password: PASSWORD,
            secret_key: &f.secret_key,
        },
    )
    .unwrap();
    assert_eq!(reopened.kit_pdf_password(&f.secret_key).as_str(), text);

    // A new master password keeps it.
    f.vault
        .change_password(
            "another test password",
            &f.secret_key,
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
    assert_eq!(f.vault.kit_pdf_password(&f.secret_key).as_str(), text);

    // A new Secret Key changes it.
    let other_key = SecretKey::generate().unwrap();
    assert_ne!(f.vault.kit_pdf_password(&other_key).as_str(), text);

    // New recovery parts change it.
    f.vault
        .set_recovery_parts(&RecoveryParts::generate().unwrap(), &f.secret_key)
        .unwrap();
    let after_parts = f.vault.kit_pdf_password(&f.secret_key).as_str().to_owned();
    assert_ne!(after_parts, text);

    // A vault without parts has one too, and its own.
    f.vault.clear_recovery_parts();
    let without_parts = f.vault.kit_pdf_password(&f.secret_key).as_str().to_owned();
    assert_ne!(without_parts, after_parts);

    // So does a renewed vault key (with its new Secret Key and kit).
    let renewed = f
        .vault
        .renew_key("another test password", &f.secret_key, None)
        .unwrap();
    let after_renewal = f
        .vault
        .kit_pdf_password(&renewed.secret_key)
        .as_str()
        .to_owned();
    assert!(![text, after_parts, without_parts].contains(&after_renewal));
}
