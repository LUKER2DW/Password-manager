//! One sync round, as the apps run it (`read_all` or `fetch`, then `merge_reading` or
//! `merge_all`, then `to_publish`), against places that lie (THREAT_MODEL A2, SYNC.md §4.1,
//! §5.4): a backup place serving altered, older or foreign copies beside an honest main place
//! (and the other way round), and a target that lists one copy twice, this device's own copy
//! under another name, or a copy it then fails to hand over. Nothing unauthenticated is merged,
//! the vault in memory is as it was after each refusal, each refusal is reported against the
//! device it was listed for, and the honest copy still goes in. The HTTP targets' own answers
//! are in `src/sync/hostile.rs`; the whole round through the CLI (the vault file itself) in
//! `apps/cli/tests/cli.rs`.

use std::{path::Path, sync::Mutex};

use anyhow::{Result, bail};
use vault_core::{
    Error, ItemData, KdfParams, SecretKey, Unlock, Vault,
    sync::{DeviceId, SeenRevisions},
};
use vault_platform::{
    SyncPlace, SyncTo,
    sync::{self, FolderTarget, KnownTags, Listed, Role, Tags, Target},
};

const PASSWORD: &str = "test password for a hostile place";

struct Vaults {
    a: Vault,
    b: Vault,
    key: SecretKey,
}

/// Two devices of one vault; B has one item A hasn't seen.
fn vaults() -> Vaults {
    let key = SecretKey::generate().unwrap();
    let mut made = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
    let start = made.to_bytes().unwrap();
    let open = |n: u8| {
        let mut vault = Vault::open(
            &start,
            Unlock::Password {
                password: PASSWORD,
                secret_key: &key,
            },
        )
        .unwrap();
        vault.set_device(DeviceId::from_bytes([n; 16]));
        vault
    };
    let (a, mut b) = (open(1), open(2));
    b.add_item(&ItemData::login("From B", "b", "pw", "https://b.example"))
        .unwrap();
    Vaults { a, b, key }
}

fn put(folder: &Path, vault_id: &str, device: DeviceId, bytes: &[u8]) {
    FolderTarget::new(folder, vault_id)
        .unwrap()
        .put(device, bytes)
        .unwrap();
}

/// What a merge could change, as the person sees it.
fn titles(vault: &Vault) -> Vec<String> {
    let mut titles: Vec<String> = vault
        .summaries()
        .unwrap()
        .into_iter()
        .map(|s| s.title.clone())
        .collect();
    titles.sort();
    titles
}

fn place(main: &Path, backup: &Path) -> SyncPlace {
    SyncPlace {
        to: SyncTo::Folder {
            path: main.to_owned(),
        },
        backup: Some(SyncTo::Folder {
            path: backup.to_owned(),
        }),
        seen: SeenRevisions::new(),
        at: 0,
        published: 0,
        published_backup: 0,
    }
}

/// One place honest, the other holding B's copy altered, cut short, as garbage or as another
/// vault's: whichever place lies, only B's real copy is merged, and with nothing honest to
/// take a lie is refused, not passed over.
#[test]
fn a_lying_place_beside_an_honest_one_changes_nothing() {
    let (mut stranger, _) = {
        let other = vaults();
        (other.b, other.key)
    };
    let foreign = stranger.to_bytes().unwrap();
    for lying_is_main in [false, true] {
        let mut v = vaults();
        let id = v.a.id_hex();
        let (b, a) = (v.b.device(), v.a.device());
        let honest = v.b.to_bytes().unwrap();
        let mut altered = honest.clone();
        let at = altered.len() / 3;
        altered[at] ^= 0x10;
        for lie in [
            altered,
            honest[..honest.len() - 1].to_vec(),
            b"garbage".repeat(50),
            foreign.clone(),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (main, backup) = (dir.path().join("main"), dir.path().join("backup"));
            let (liar, truthful) = if lying_is_main {
                (&main, &backup)
            } else {
                (&backup, &main)
            };
            put(liar, &id, b, &lie);
            let mut p = place(&main, &backup);
            // The liar alone: refused, said against B, nothing changes.
            let before = titles(&v.a);
            let reading = sync::read_all(&id, a, &p, &KnownTags::default());
            let round = sync::merge_reading(&mut v.a, &reading, &mut p.seen);
            assert!(round.reports.is_empty(), "{:?}", round.reports);
            assert_eq!(round.refused.len(), 1, "{:?}", round.refused);
            assert_eq!(round.refused[0].0, b);
            assert!(!round.changed());
            assert_eq!(titles(&v.a), before);
            assert_eq!(p.seen.revision(&b), None, "nothing was seen from B");
            // With the honest copy in the other place: that one is taken.
            put(truthful, &id, b, &honest);
            let reading = sync::read_all(&id, a, &p, &KnownTags::default());
            let mut a_now = Vault::open(
                &v.a.to_bytes().unwrap(),
                Unlock::Password {
                    password: PASSWORD,
                    secret_key: &v.key,
                },
            )
            .unwrap();
            a_now.set_device(a);
            let round = sync::merge_reading(&mut a_now, &reading, &mut p.seen);
            assert!(round.refused.is_empty(), "{:?}", round.refused);
            assert_eq!(titles(&a_now), ["From B"]);
        }
    }
}

/// After B's newer copy was merged, a place serves its older one again: with one place that is
/// a rollback, refused and reported; beside a place that has the newer one it is passed over
/// (a place that was down holds older copies until it catches up).
#[test]
fn an_older_copy_from_one_place_is_refused_or_passed_over() {
    let mut v = vaults();
    let id = v.a.id_hex();
    let (a, b) = (v.a.device(), v.b.device());
    let older = v.b.to_bytes().unwrap();
    v.b.add_item(&ItemData::login(
        "Later",
        "b",
        "pw",
        "https://later.example",
    ))
    .unwrap();
    let newer = v.b.to_bytes().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (main, backup) = (dir.path().join("main"), dir.path().join("backup"));
    let mut p = place(&main, &backup);
    put(&main, &id, b, &newer);
    let reading = sync::read_all(&id, a, &p, &KnownTags::default());
    sync::merge_reading(&mut v.a, &reading, &mut p.seen);
    assert_eq!(titles(&v.a), ["From B", "Later"]);

    // One place only, serving the older copy: a rollback.
    let mut alone = SyncPlace {
        backup: None,
        ..p.clone()
    };
    put(&main, &id, b, &older);
    let reading = sync::read_all(&id, a, &alone, &KnownTags::default());
    let round = sync::merge_reading(&mut v.a, &reading, &mut alone.seen);
    assert!(
        matches!(round.refused.as_slice(), [(device, Error::SyncRollback)] if *device == b),
        "{:?}",
        round.refused
    );
    assert_eq!(titles(&v.a), ["From B", "Later"]);
    // Beside a place with the newer one: passed over, nothing to say.
    put(&backup, &id, b, &newer);
    let reading = sync::read_all(&id, a, &p, &KnownTags::default());
    let round = sync::merge_reading(&mut v.a, &reading, &mut p.seen);
    assert!(round.refused.is_empty(), "{:?}", round.refused);
    assert!(!round.changed());
    assert_eq!(titles(&v.a), ["From B", "Later"]);
}

/// A target that lists what it likes and hands over what it likes.
struct Lister {
    listed: Vec<Listed>,
    copies: Vec<(DeviceId, Result<Vec<u8>, String>)>,
    /// How many times each listed copy was asked for so far (the n-th answer is given).
    asked: Mutex<Vec<DeviceId>>,
}

impl Target for Lister {
    fn list(&self) -> Result<Vec<Listed>> {
        Ok(self.listed.clone())
    }

    fn get(&self, device: DeviceId) -> Result<Vec<u8>> {
        let mut asked = self.asked.lock().unwrap();
        let nth = asked.iter().filter(|d| **d == device).count();
        asked.push(device);
        match self.copies.iter().filter(|(d, _)| *d == device).nth(nth) {
            Some((_, Ok(bytes))) => Ok(bytes.clone()),
            Some((_, Err(why))) => bail!("{why}"),
            None => bail!("not there"),
        }
    }

    fn put(&self, _own: DeviceId, _bytes: &[u8]) -> Result<()> {
        bail!("this place takes nothing")
    }

    fn remove(&self, _device: DeviceId) -> Result<()> {
        bail!("this place removes nothing")
    }
}

fn listed(device: DeviceId) -> Listed {
    Listed { device, tag: None }
}

/// One device listed twice (garbage, then its real copy), this device's own copy under a third
/// device's name, B's copy under that name too, and a copy that is listed but can't be had:
/// the real copy is merged once, every other one is refused or unreadable, said against the
/// name it was listed under, and this device's own state isn't touched by its own copy.
#[test]
fn a_target_that_lists_what_it_likes() {
    let mut v = vaults();
    let (a, b) = (v.a.device(), v.b.device());
    let third = DeviceId::from_bytes([3; 16]);
    let missing = DeviceId::from_bytes([4; 16]);
    let own = v.a.to_bytes().unwrap();
    let honest = v.b.to_bytes().unwrap();
    let target = Lister {
        listed: vec![
            listed(a),
            listed(b),
            listed(b),
            listed(third),
            listed(third),
            listed(missing),
        ],
        copies: vec![
            (b, Ok(b"garbage".to_vec())),
            (b, Ok(honest.clone())),
            (third, Ok(own)),
            (third, Ok(honest)),
            (missing, Err("the place failed half-way".to_owned())),
        ],
        asked: Mutex::new(Vec::new()),
    };
    let fetched = sync::fetch(&target, a, &Tags::new()).unwrap();
    assert!(
        !target.asked.lock().unwrap().contains(&a),
        "this device's own copy is never read"
    );
    assert_eq!(fetched.copies.len(), 4);
    assert_eq!(
        fetched
            .unreadable
            .iter()
            .map(|(d, _)| *d)
            .collect::<Vec<_>>(),
        [missing]
    );
    let mut seen = SeenRevisions::new();
    let round = sync::merge_all(&mut v.a, &fetched, &mut seen);
    assert_eq!(round.reports.len(), 1, "{:?}", round.reports);
    assert_eq!(round.reports[0].writer, b);
    let refused: Vec<(DeviceId, String)> = round
        .refused
        .iter()
        .map(|(d, err)| (*d, format!("{err:?}")))
        .collect();
    assert_eq!(
        refused,
        [
            (b, "NotAVault".to_owned()),
            (third, "WrongWriter".to_owned()),
            (third, "WrongWriter".to_owned()),
        ]
    );
    assert_eq!(seen.revision(&third), None);
    assert_eq!(titles(&v.a), ["From B"]);
    // Nothing published to a place that takes nothing: the round says so, and the next one
    // tries again (the place's revision isn't moved on).
    assert!(target.put(a, b"copy").is_err());
    let place = SyncPlace {
        to: SyncTo::Folder {
            path: std::env::temp_dir(),
        },
        backup: None,
        seen,
        at: 0,
        published: 0,
        published_backup: 0,
    };
    let reading = sync::Reading {
        main: Ok(fetched),
        backup: None,
    };
    assert_eq!(
        sync::to_publish(&place, &reading, v.a.revision(), false),
        [Role::Main]
    );
}
