//! A key shield installed by the program (`vault_core::memory`): every use of the vault key
//! and the item guard key goes through it, and a vault works the same with it.
//!
//! A process of its own (an integration test): the shield is installed once for the whole
//! process.

use std::sync::atomic::{AtomicUsize, Ordering};

use vault_core::{
    GuardCheck, ItemData, KdfParams, SecretKey, Unlock, Vault,
    memory::{KeyShield, install_key_shield, key_shield_installed},
};

/// "Encrypts" by XOR with a fixed pattern and counts what it is asked: enough to show the
/// keys go through it and come back right.
struct CountingShield {
    shielded: AtomicUsize,
    opened: AtomicUsize,
}

impl CountingShield {
    fn flip(key: &mut [u8; 32]) {
        for (i, byte) in key.iter_mut().enumerate() {
            *byte ^= 0xa5 ^ (i as u8);
        }
    }
}

impl KeyShield for CountingShield {
    fn shield(&self, key: &mut [u8; 32]) -> bool {
        Self::flip(key);
        self.shielded.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn unshield(&self, key: &mut [u8; 32]) -> bool {
        Self::flip(key);
        self.opened.fetch_add(1, Ordering::SeqCst);
        true
    }
}

static SHIELD: CountingShield = CountingShield {
    shielded: AtomicUsize::new(0),
    opened: AtomicUsize::new(0),
};

#[test]
fn the_vault_and_guard_keys_go_through_the_shield() {
    assert!(install_key_shield(&SHIELD));
    assert!(key_shield_installed());
    assert!(!install_key_shield(&SHIELD), "only once");

    let secret_key = SecretKey::generate().unwrap();
    let kdf = KdfParams::minimum().unwrap();
    let mut vault = Vault::create("shield test passphrase", &secret_key, None, kdf).unwrap();
    let shielded = SHIELD.shielded.load(Ordering::SeqCst);
    assert!(shielded >= 1, "the new vault key went in");
    let id = vault
        .add_item(&ItemData::login(
            "Shielded",
            "me",
            "shield test password",
            "https://example.com",
        ))
        .unwrap();
    assert!(
        SHIELD.opened.load(Ordering::SeqCst) >= 1,
        "and came out to seal the item"
    );
    vault
        .set_item_guard(true, GuardCheck::Pin, Some("2468"), None)
        .unwrap();
    assert!(
        SHIELD.shielded.load(Ordering::SeqCst) > shielded,
        "the guard key went in too"
    );
    let bytes = vault.to_bytes().unwrap();

    let mut reopened = Vault::open(
        &bytes,
        Unlock::Password {
            password: "shield test passphrase",
            secret_key: &secret_key,
        },
    )
    .unwrap();
    assert!(reopened.get_item(&id).unwrap().is_locked());
    assert!(reopened.unlock_secrets("2468").unwrap());
    assert_eq!(
        reopened.get_item(&id).unwrap().password,
        "shield test password"
    );
    reopened.lock_secrets();
    assert!(reopened.get_item(&id).unwrap().is_locked());
}
