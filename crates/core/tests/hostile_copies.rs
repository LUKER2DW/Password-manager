//! Copies of the vault as a hostile sync place could hand them over (THREAT_MODEL A2, SYNC.md
//! §4.1 and §9): one byte altered anywhere, cut short, longer, empty, garbage, another vault's
//! (also with this vault's id written into it), an older copy served again, a copy under
//! another device's name, a removed device's. Each is refused with its own error, this copy
//! stays exactly as it was (its items, folders, devices, settings, revision and what was seen
//! from each device), and an honest copy offered next is still merged.

use vault_core::{
    Error, ItemData, ItemId, KdfParams, SecretKey, Unlock, Vault, VaultSettings,
    sync::{DeviceId, MergeReport, SeenRevisions, SyncDevice},
};

const PASSWORD: &str = "test master password";

/// One device: its copy of the vault and what it has seen from the others.
struct Device {
    vault: Vault,
    seen: SeenRevisions,
}

impl Device {
    fn copy(&mut self) -> Vec<u8> {
        self.vault.to_bytes().unwrap()
    }

    fn id(&self) -> DeviceId {
        self.vault.device()
    }

    /// The copy as a place lists it: under `listed`'s name.
    fn take_from(&mut self, listed: DeviceId, copy: &[u8]) -> vault_core::Result<MergeReport> {
        self.vault.merge_from(listed, copy, &mut self.seen)
    }

    /// Everything a merge could change here, as the person would see it, and what was seen.
    fn state(&self) -> State {
        let mut items: Vec<(ItemId, ItemData)> = self
            .vault
            .item_ids()
            .map(|id| (id, self.vault.get_item(&id).unwrap()))
            .collect();
        items.sort_by_key(|(id, _)| *id);
        State {
            items,
            folders: self
                .vault
                .folders()
                .iter()
                .map(|f| (f.id.to_hex(), f.name.clone()))
                .collect(),
            devices: self.vault.sync_devices().to_vec(),
            settings: self.vault.settings().clone(),
            revision: self.vault.revision(),
            unlock_id: self.vault.unlock_id(),
            guard_waiting: self.vault.guard_waiting(),
            seen: self.seen.clone(),
        }
    }
}

#[derive(Debug, PartialEq)]
struct State {
    items: Vec<(ItemId, ItemData)>,
    folders: Vec<(String, String)>,
    devices: Vec<SyncDevice>,
    settings: VaultSettings,
    revision: u64,
    unlock_id: [u8; 16],
    guard_waiting: bool,
    seen: SeenRevisions,
}

/// Two devices of one vault, each listed in it, with two logins both have; the second has
/// written a copy with one more item and a folder, which the first hasn't seen yet.
fn two_devices() -> (Device, Device, Vec<u8>, SecretKey) {
    let secret_key = SecretKey::generate().unwrap();
    let mut first =
        Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    for title in ["Shared", "Also shared"] {
        first
            .add_item(&ItemData::login(
                title,
                "me",
                "first-password",
                "https://shared.example",
            ))
            .unwrap();
    }
    let bytes = first.to_bytes().unwrap();
    let device = |n: u8| {
        let mut vault = open(&bytes, &secret_key).unwrap();
        let id = DeviceId::from_bytes([n; 16]);
        vault.set_device(id);
        vault
            .add_sync_device(SyncDevice {
                id,
                name: format!("Device {n}"),
                signing_key: None,
                added_at: 1,
            })
            .unwrap();
        Device {
            vault,
            seen: SeenRevisions::new(),
        }
    };
    let (a, mut b) = (device(1), device(2));
    b.vault
        .add_item(&ItemData::login(
            "From B",
            "b",
            "b-password",
            "https://b.example",
        ))
        .unwrap();
    b.vault.add_folder("B's folder").unwrap();
    let copy = b.copy();
    (a, b, copy, secret_key)
}

fn open(bytes: &[u8], secret_key: &SecretKey) -> vault_core::Result<Vault> {
    Vault::open(
        bytes,
        Unlock::Password {
            password: PASSWORD,
            secret_key,
        },
    )
}

/// The refusals a copy that wasn't sealed by a holder of this vault's key may get: it never
/// gets as far as the device checks.
fn unauthenticated(err: &Error) -> bool {
    matches!(
        err,
        Error::NotAVault
            | Error::UnsupportedVersion(_)
            | Error::Malformed
            | Error::KdfParamsOutOfRange
            | Error::DecryptionFailed
            | Error::OtherVault
    )
}

/// The honest copy still goes in after whatever was refused before it.
fn honest_copy_still_merges(a: &mut Device, from: DeviceId, copy: &[u8]) {
    let report = a.take_from(from, copy).unwrap();
    assert_eq!(report.added, 1, "{report:?}");
    assert_eq!(report.writer, from);
    let titles: Vec<String> = a
        .vault
        .summaries()
        .unwrap()
        .into_iter()
        .map(|s| s.title.clone())
        .collect();
    assert!(titles.iter().any(|t| t == "From B"), "{titles:?}");
}

#[test]
fn a_copy_with_any_byte_altered_is_refused_and_changes_nothing() {
    let (mut a, b, copy, _) = two_devices();
    let before = a.state();
    let mut tried = 0;
    for at in 0..copy.len() {
        for flip in [0x01u8, 0x80, 0xff] {
            let mut altered = copy.clone();
            altered[at] ^= flip;
            let err = a.take_from(b.id(), &altered).expect_err("an altered copy");
            assert!(unauthenticated(&err), "byte {at} ^ {flip:#x}: {err:?}");
            tried += 1;
        }
    }
    assert_eq!(tried, copy.len() * 3);
    assert_eq!(a.state(), before);
    honest_copy_still_merges(&mut a, b.id(), &copy);
}

#[test]
fn a_copy_cut_short_longer_empty_or_garbage_is_refused() {
    let (mut a, b, copy, _) = two_devices();
    let before = a.state();
    let mut hostile: Vec<Vec<u8>> = (0..copy.len()).map(|len| copy[..len].to_vec()).collect();
    for extra in [&b"\0"[..], b"x", &[0u8; 4096]] {
        hostile.push([copy.as_slice(), extra].concat());
    }
    // Garbage of every kind of size, from a fixed seed so a failure can be replayed.
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut noise = |len: usize| -> Vec<u8> {
        (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed.to_le_bytes()[0]
            })
            .collect()
    };
    for len in [1, 16, 100, 1000, copy.len(), 70_000] {
        hostile.push(noise(len));
        hostile.push(vec![0; len]);
        hostile.push(vec![0xff; len]);
    }
    // The real header with garbage after it, and the copy's first half twice.
    let half = copy.len() / 2;
    hostile.push([&copy[..half], noise(copy.len() - half).as_slice()].concat());
    hostile.push([&copy[..half], &copy[..half]].concat());
    for bytes in &hostile {
        let err = a.take_from(b.id(), bytes).expect_err("not a whole copy");
        assert!(unauthenticated(&err), "{} bytes: {err:?}", bytes.len());
    }
    assert_eq!(a.state(), before);
    honest_copy_still_merges(&mut a, b.id(), &copy);
}

#[test]
fn another_vaults_copy_is_refused_even_under_this_vaults_id() {
    let (mut a, b, copy, _) = two_devices();
    let (_, mut stranger, _, _) = two_devices();
    let before = a.state();
    let theirs = stranger.copy();
    assert!(matches!(
        a.take_from(stranger.id(), &theirs),
        Err(Error::OtherVault)
    ));
    // The vault id is public (it names the folder): written into the stranger's copy, which
    // is sealed under another key, it still opens nothing here.
    let ours = id_bytes(&a.vault.id_hex());
    let their_id = id_bytes(&Vault::inspect(&theirs).unwrap().id_hex);
    let at = theirs
        .windows(16)
        .position(|w| w == their_id)
        .expect("the id is in the header");
    let mut relabelled = theirs.clone();
    relabelled[at..at + 16].copy_from_slice(&ours);
    assert_eq!(
        Vault::inspect(&relabelled).unwrap().id_hex,
        a.vault.id_hex()
    );
    assert!(matches!(
        a.take_from(stranger.id(), &relabelled),
        Err(Error::DecryptionFailed)
    ));
    assert_eq!(a.state(), before);
    honest_copy_still_merges(&mut a, b.id(), &copy);
}

fn id_bytes(hex: &str) -> [u8; 16] {
    let mut bytes = [0; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    bytes
}

/// A place serves a device's older copy again, after a newer one was merged here: refused as a
/// rollback, so the app says so. The newer copy offered again is fine, and changes nothing.
#[test]
fn an_older_copy_served_again_is_refused_as_a_rollback() {
    let (mut a, mut b, older, secret_key) = two_devices();
    a.take_from(b.id(), &older).unwrap();
    b.vault
        .add_item(&ItemData::login(
            "Newer from B",
            "b",
            "b-password-2",
            "https://b2.example",
        ))
        .unwrap();
    let newer = b.copy();
    assert_eq!(a.take_from(b.id(), &newer).unwrap().added, 1);
    let before = a.state();

    assert!(matches!(
        a.take_from(b.id(), &older),
        Err(Error::SyncRollback)
    ));
    assert_eq!(a.state(), before);
    // The copy merged last, served again: taken, and nothing changes.
    let again = a.take_from(b.id(), &newer).unwrap();
    assert!(!again.changed(), "{again:?}");
    assert_eq!(a.state(), before);

    // Two different copies with the same revision from B (someone holding the key wrote one
    // beside B's): whichever comes second is refused as a fork.
    let mut twin = open(&newer, &secret_key).unwrap();
    twin.add_item(&ItemData::login("Twin", "t", "t", "https://t.example"))
        .unwrap();
    let forked = twin.to_bytes().unwrap();
    b.vault
        .add_item(&ItemData::login("Later", "b", "b3", "https://b3.example"))
        .unwrap();
    let later = b.copy();
    assert_eq!(a.take_from(b.id(), &later).unwrap().added, 1);
    let before = a.state();
    assert!(matches!(a.take_from(b.id(), &forked), Err(Error::SyncFork)));
    assert_eq!(a.state(), before);
}

/// A place that withheld a device's newer copies serves an old one: this device's own later
/// changes (an edit, a deletion, a new master password) are never taken back by it.
#[test]
fn an_old_copy_never_takes_back_what_changed_here_since() {
    let (mut a, b, old_from_b, secret_key) = two_devices();
    let id_of = |vault: &Vault, title: &str| {
        vault
            .summaries()
            .unwrap()
            .into_iter()
            .find(|s| s.title == title)
            .unwrap()
            .id
    };
    let (shared, also) = (id_of(&a.vault, "Shared"), id_of(&a.vault, "Also shared"));
    // Since B's copy was written, here: a new password for one login both had, the other one
    // deleted, and a new master password.
    let mut item = a.vault.get_item(&shared).unwrap();
    item.password = "changed-here".into();
    item.touch();
    a.vault.update_item(&shared, &item).unwrap();
    a.vault.remove_item(&also).unwrap();
    let kdf = a.vault.kdf_params().clone();
    a.vault
        .change_password("the new master password", &secret_key, None, &kdf)
        .unwrap();
    let unlock_before = a.vault.unlock_id();

    // The place held back B's later copies and serves this one: what is new in it comes in,
    // nothing of what changed here goes back.
    let report = a.take_from(b.id(), &old_from_b).unwrap();
    assert!(!report.unlock_changed, "{report:?}");
    assert_eq!(report.added, 1, "{report:?}");
    let item = a.vault.get_item(&shared).unwrap();
    assert_eq!(item.password, "changed-here");
    assert!(a.vault.get_item(&also).is_err(), "stays deleted");
    assert_eq!(a.vault.unlock_id(), unlock_before);
    let mine = a.copy();
    assert!(matches!(
        open(&mine, &secret_key),
        Err(Error::DecryptionFailed)
    ));
    let reopened = Vault::open(
        &mine,
        Unlock::Password {
            password: "the new master password",
            secret_key: &secret_key,
        },
    )
    .unwrap();
    assert_eq!(reopened.get_item(&shared).unwrap().password, "changed-here");
}

/// A place lists one device's copy under another's name, or this device's own copy as someone
/// else's: refused before anything of it is used, and the same copy under its own name goes in.
#[test]
fn a_copy_under_another_devices_name_is_refused() {
    let (mut a, b, copy, _) = two_devices();
    let before = a.state();
    let stranger = DeviceId::from_bytes([9; 16]);
    for listed in [stranger, a.id()] {
        assert!(
            matches!(a.take_from(listed, &copy), Err(Error::WrongWriter)),
            "{listed:?}"
        );
    }
    assert_eq!(a.state(), before);
    let own = a.copy();
    let before_own = a.state();
    assert!(matches!(a.take_from(b.id(), &own), Err(Error::WrongWriter)));
    assert_eq!(a.state(), before_own);
    // Under its own name, this device's copy changes nothing.
    assert!(!a.take_from(a.id(), &own).unwrap().changed());
    honest_copy_still_merges(&mut a, b.id(), &copy);
}

/// A removed device's copies (older or newer than its removal) are refused, and change nothing.
#[test]
fn a_removed_devices_copies_are_refused() {
    let (mut a, mut b, older, _) = two_devices();
    a.take_from(b.id(), &older).unwrap();
    a.vault.remove_sync_device(&b.id()).unwrap();
    let before = a.state();
    b.vault
        .add_item(&ItemData::login("After", "b", "b", "https://after.example"))
        .unwrap();
    let newer = b.copy();
    for copy in [&older, &newer] {
        assert!(matches!(
            a.take_from(b.id(), copy),
            Err(Error::DeviceRemoved)
        ));
    }
    assert_eq!(a.state(), before);
}
