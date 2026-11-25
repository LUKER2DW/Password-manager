//! Renewing the vault key (CRYPTO.md §3.8): what an older copy, its factors and its kit open
//! afterwards, and other devices taking the new key (SYNC.md §4.7).

use vault_core::{
    Error, GuardCheck, ItemData, KdfParams, Keyfile, PartLabel, RecoveryParts, SecretKey, Unlock,
    Vault,
    sync::{DeviceId, SeenRevisions},
};

const PASSWORD: &str = "test master password";
const PIN: &str = "4821";

fn open(bytes: &[u8], secret_key: &SecretKey) -> vault_core::Result<Vault> {
    Vault::open(
        bytes,
        Unlock::Password {
            password: PASSWORD,
            secret_key,
        },
    )
}

fn parts_of(parts: &RecoveryParts) -> [&vault_core::RecoveryPart; 3] {
    [
        parts.part(PartLabel::A),
        parts.part(PartLabel::B),
        parts.part(PartLabel::C),
    ]
}

/// A vault with a kit, an item lock (PIN) over every item, two logins and something this
/// device sealed outside the file.
fn made() -> (Vault, SecretKey, RecoveryParts) {
    let secret_key = SecretKey::generate().unwrap();
    let mut vault =
        Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    let parts = RecoveryParts::generate().unwrap();
    vault.set_recovery_parts(&parts, &secret_key).unwrap();
    vault
        .set_item_guard(true, GuardCheck::Pin, Some(PIN), Some(PASSWORD))
        .unwrap();
    for (title, password) in [("Mail", "mail-test-pw"), ("Bank", "bank-test-pw")] {
        vault
            .add_item(&ItemData::login(
                title,
                "me",
                password,
                "https://site.example",
            ))
            .unwrap();
    }
    (vault, secret_key, parts)
}

fn password_of(vault: &Vault, title: &str) -> String {
    let id = vault
        .item_ids()
        .find(|id| vault.get_item(id).unwrap().title == title)
        .unwrap();
    vault.get_item(&id).unwrap().password.clone()
}

#[test]
fn after_a_renewal_an_older_copy_opens_only_itself() {
    let (mut vault, secret_key, old_parts) = made();
    let sealed_here = vault
        .seal_local("test-history", b"kept on this device")
        .unwrap();
    let old_bytes = vault.to_bytes().unwrap();

    // A typo is not taken for the master password, and changes nothing.
    assert!(matches!(
        vault.renew_key("test master passwort", &secret_key, None),
        Err(Error::DecryptionFailed)
    ));
    assert!(open(&vault.to_bytes().unwrap(), &secret_key).is_ok());

    let before = vault.unlock_id();
    assert_eq!(Vault::inspect(&old_bytes).unwrap().unlock_id, before);
    let renewed = vault.renew_key(PASSWORD, &secret_key, None).unwrap();
    assert_ne!(renewed.secret_key, secret_key);
    let new_bytes = vault.to_bytes().unwrap();
    // What opens it changed, and an older copy says so in its public header.
    assert_ne!(vault.unlock_id(), before);
    assert_eq!(
        Vault::inspect(&new_bytes).unwrap().unlock_id,
        vault.unlock_id()
    );

    // The old factors and the old kit open nothing of it.
    assert!(open(&new_bytes, &secret_key).is_err());
    assert!(
        Vault::recover_secret_key(
            &new_bytes,
            old_parts.part(PartLabel::A),
            old_parts.part(PartLabel::B)
        )
        .is_err()
    );
    assert!(Vault::open(&new_bytes, Unlock::Parts(parts_of(&old_parts))).is_err());
    // The vault key an older copy opens is no key to it either.
    let mut old = open(&old_bytes, &secret_key).unwrap();
    old.set_device(DeviceId::generate().unwrap());
    assert!(matches!(
        old.merge(&new_bytes, &mut SeenRevisions::new()),
        Err(Error::DecryptionFailed)
    ));

    // The master password and the new Secret Key open it, items and locked secrets whole.
    let mut reopened = open(&new_bytes, &renewed.secret_key).unwrap();
    assert!(
        reopened.unlock_secrets(PIN).unwrap(),
        "the item lock keeps its PIN"
    );
    assert_eq!(password_of(&reopened, "Mail"), "mail-test-pw");
    assert_eq!(password_of(&reopened, "Bank"), "bank-test-pw");
    // The new kit works, and only it is in the file.
    assert!(Vault::inspect(&new_bytes).unwrap().has_recovery_parts);
    assert_eq!(
        Vault::recover_secret_key(
            &new_bytes,
            renewed.parts.part(PartLabel::B),
            renewed.parts.part(PartLabel::C)
        )
        .unwrap(),
        renewed.secret_key
    );
    assert!(Vault::open(&new_bytes, Unlock::Parts(parts_of(&renewed.parts))).is_ok());

    // What this device sealed outside the file opens with the former key only, to be sealed
    // again under the new one.
    assert!(vault.open_local("test-history", &sealed_here).is_err());
    let moved = renewed
        .former
        .open_local("test-history", &sealed_here)
        .unwrap();
    assert_eq!(moved.as_slice(), b"kept on this device");
    let again = vault.seal_local("test-history", &moved).unwrap();
    assert_eq!(
        reopened
            .open_local("test-history", &again)
            .unwrap()
            .as_slice(),
        b"kept on this device"
    );
}

#[test]
fn a_vault_with_a_keyfile_renews_with_it() {
    let secret_key = SecretKey::generate().unwrap();
    let mut vault =
        Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    let (keyfile, keyfile_bytes) = Keyfile::generate().unwrap();
    vault
        .change_password(
            PASSWORD,
            &secret_key,
            Some(&keyfile),
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
    vault
        .add_item(&ItemData::login(
            "Mail",
            "me",
            "mail-test-pw",
            "site.example",
        ))
        .unwrap();
    assert!(matches!(
        vault.renew_key(PASSWORD, &secret_key, None),
        Err(Error::KeyfileRequired)
    ));
    let renewed = vault
        .renew_key(PASSWORD, &secret_key, Some(&keyfile))
        .unwrap();
    let bytes = vault.to_bytes().unwrap();
    assert!(matches!(
        open(&bytes, &renewed.secret_key),
        Err(Error::KeyfileRequired)
    ));
    let keyfile = Keyfile::from_bytes(&keyfile_bytes).unwrap();
    let opened = Vault::open(
        &bytes,
        Unlock::PasswordAndKeyfile {
            password: PASSWORD,
            secret_key: &renewed.secret_key,
            keyfile: &keyfile,
        },
    )
    .unwrap();
    assert_eq!(password_of(&opened, "Mail"), "mail-test-pw");
}

/// One device's copy and what it has seen.
struct Device {
    vault: Vault,
    seen: SeenRevisions,
}

impl Device {
    fn copy(&mut self) -> Vec<u8> {
        self.vault.to_bytes().unwrap()
    }

    fn take(&mut self, copy: &[u8]) -> vault_core::Result<vault_core::sync::MergeReport> {
        self.vault.merge(copy, &mut self.seen)
    }

    fn titles(&self) -> Vec<String> {
        let mut titles: Vec<String> = self
            .vault
            .summaries()
            .unwrap()
            .into_iter()
            .map(|s| s.title.clone())
            .collect();
        titles.sort();
        titles
    }
}

fn devices(n: usize) -> (Vec<Device>, SecretKey) {
    let secret_key = SecretKey::generate().unwrap();
    let mut first =
        Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    first
        .add_item(&ItemData::login(
            "Shared",
            "me",
            "shared-pw",
            "shared.example",
        ))
        .unwrap();
    let bytes = first.to_bytes().unwrap();
    let devices = (0..n)
        .map(|_| {
            let mut vault = open(&bytes, &secret_key).unwrap();
            vault.set_device(DeviceId::generate().unwrap());
            Device {
                vault,
                seen: SeenRevisions::new(),
            }
        })
        .collect();
    (devices, secret_key)
}

#[test]
fn other_devices_take_the_new_key_and_keep_what_they_changed() {
    let (mut d, secret_key) = devices(3);
    // Everyone has everyone's copy once.
    let copies: Vec<Vec<u8>> = d.iter_mut().map(Device::copy).collect();
    for device in &mut d {
        for copy in &copies {
            device.take(copy).unwrap();
        }
    }
    // Device 1 changes something it hasn't published yet; device 0 renews the key.
    d[1].vault
        .add_item(&ItemData::login("Made on 1", "me", "one-pw", "one.example"))
        .unwrap();
    let renewed = d[0].vault.renew_key(PASSWORD, &secret_key, None).unwrap();
    let from_0 = d[0].copy();

    // Device 1 can't read it with the key it holds.
    assert!(matches!(d[1].take(&from_0), Err(Error::DecryptionFailed)));
    // With the master password and the new Secret Key, it takes the new key...
    let opened = open(&from_0, &renewed.secret_key).unwrap();
    let former = d[1].vault.adopt_key(&opened).unwrap();
    assert!(former.is_some());
    assert!(
        d[1].vault.adopt_key(&opened).unwrap().is_none(),
        "taken once"
    );
    // ...after which device 0's copy merges as usual: nothing changed twice.
    let report = d[1].take(&from_0).unwrap();
    assert!(report.conflicts.is_empty(), "{report:?}");
    assert_eq!(report.updated, 0, "the same items, under the new key");
    assert_eq!(d[1].titles(), ["Made on 1", "Shared"]);
    // Its own copy now opens with the new factors only, and brings its change to device 0.
    let from_1 = d[1].copy();
    assert!(open(&from_1, &secret_key).is_err());
    assert!(open(&from_1, &renewed.secret_key).is_ok());
    let report = d[0].take(&from_1).unwrap();
    assert_eq!(report.added, 1);
    assert_eq!(d[0].titles(), ["Made on 1", "Shared"]);

    // Device 2, still on the old key, can read neither; it takes the key from either copy.
    assert!(matches!(d[2].take(&from_1), Err(Error::DecryptionFailed)));
    let opened = open(&from_1, &renewed.secret_key).unwrap();
    d[2].vault.adopt_key(&opened).unwrap().unwrap();
    d[2].take(&from_1).unwrap();
    d[2].take(&from_0).unwrap();
    assert_eq!(d[2].titles(), ["Made on 1", "Shared"]);
    // And the old copy of device 2, written before, is no use to the new ones.
    assert!(matches!(
        d[0].take(&copies[2]),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn a_renewal_whose_write_failed_is_put_back() {
    let (mut vault, secret_key, parts) = made();
    vault.set_device(DeviceId::generate().unwrap());
    let before = vault.to_bytes().unwrap();
    let sealed_here = vault.seal_local("test-history", b"kept here").unwrap();
    let snapshot = vault.snapshot();
    let renewed = vault.renew_key(PASSWORD, &secret_key, None).unwrap();
    // Sealed again under the new key, it opens with the vault as it is now...
    let again = vault
        .reseal_local(&renewed.former, "test-history", &sealed_here)
        .unwrap();
    assert_eq!(
        vault.open_local("test-history", &again).unwrap().as_slice(),
        b"kept here"
    );
    // ...but the write failed: everything goes back, the key too.
    vault.put_back_key(snapshot, renewed.former).unwrap();
    assert_eq!(
        vault.unlock_id(),
        Vault::inspect(&before).unwrap().unlock_id
    );
    assert_eq!(
        vault
            .open_local("test-history", &sealed_here)
            .unwrap()
            .as_slice(),
        b"kept here"
    );
    let bytes = vault.to_bytes().unwrap();
    let mut reopened = open(&bytes, &secret_key).unwrap();
    assert!(reopened.unlock_secrets(PIN).unwrap());
    assert_eq!(password_of(&reopened, "Mail"), "mail-test-pw");
    assert!(Vault::open(&bytes, Unlock::Parts(parts_of(&parts))).is_ok());
    // The old copy and the one put back still merge: one key.
    let mut old = open(&before, &secret_key).unwrap();
    old.set_device(DeviceId::generate().unwrap());
    old.merge(&bytes, &mut SeenRevisions::new()).unwrap();
}

#[test]
fn a_key_from_another_vault_is_not_taken() {
    let (mut d, _) = devices(1);
    let (other, _, _) = made();
    assert!(matches!(
        d[0].vault.adopt_key(&other),
        Err(Error::OtherVault)
    ));
    // Nor is anything sealed with it opened, or put back with it.
    let (mut other, other_key, _) = made();
    let renewed = other.renew_key(PASSWORD, &other_key, None).unwrap();
    assert!(matches!(
        d[0].vault.reseal_local(&renewed.former, "x", b""),
        Err(Error::OtherVault)
    ));
    let snapshot = d[0].vault.snapshot();
    assert!(matches!(
        d[0].vault.put_back_key(snapshot, renewed.former),
        Err(Error::OtherVault)
    ));
}
