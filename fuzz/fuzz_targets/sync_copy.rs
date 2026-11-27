//! A copy of the vault handed over by a sync place (a folder, WebDAV, a server: THREAT_MODEL
//! A2, SYNC.md §4.1), checked and merged into a vault that is open: the committed v10 fixture,
//! opened once with its test credentials. Mutations of the fixture keep its vault id, so they
//! get as far as the key check. Whatever the bytes, nothing is taken from a copy this vault's
//! key didn't seal, and nothing panics; the fixture itself is this vault's own copy and
//! changes nothing.
#![no_main]

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use vault_core::{
    SecretKey, Unlock, Vault,
    sync::{DeviceId, SeenRevisions},
};

const FIXTURE: &[u8] = include_bytes!("../../crates/core/tests/fixtures/vault-v10.bin");
const CREDENTIALS: &str =
    include_str!("../../crates/core/tests/fixtures/vault-v10.credentials.txt");
/// The fixture's test password (`crates/core/tests/format_v10.rs`).
const PASSWORD: &str = "fixture password v10 ✓ çãé";

thread_local! {
    static VAULT: RefCell<Option<Vault>> = const { RefCell::new(None) };
}

fn open_fixture() -> Vault {
    let secret_key = CREDENTIALS
        .lines()
        .find_map(|line| line.strip_prefix("secret_key ="))
        .map(str::trim)
        .and_then(|text| SecretKey::parse(text).ok())
        .expect("the fixture's Secret Key");
    Vault::open(
        FIXTURE,
        Unlock::Password {
            password: PASSWORD,
            secret_key: &secret_key,
        },
    )
    .expect("the fixture opens")
}

fuzz_target!(|data: &[u8]| {
    VAULT.with(|vault| {
        let mut vault = vault.borrow_mut();
        let vault = vault.get_or_insert_with(open_fixture);
        let _ = vault.check_copy(data);
        for listed in [vault.device(), DeviceId::from_bytes([9; 16])] {
            if let Ok(report) = vault.merge_from(listed, data, &mut SeenRevisions::new()) {
                assert!(!report.changed(), "a copy changed the vault: {report:?}");
            }
        }
    });
});
