//! Property tests: the parser must never panic on hostile input, only return errors.
//! (The `vault_file` and `sync_copy` fuzz targets extend this, every day in CI: `fuzz/`.)

use std::sync::OnceLock;

use proptest::prelude::*;
use vault_core::{ItemData, KdfParams, RecoveryKey, SecretKey, Unlock, Vault};

/// One valid vault file + the text of its recovery key, built once (Argon2 is slow on purpose).
fn sample() -> &'static (Vec<u8>, String) {
    static SAMPLE: OnceLock<(Vec<u8>, String)> = OnceLock::new();
    SAMPLE.get_or_init(|| {
        let secret_key = SecretKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        let mut vault = Vault::create(
            "robustness",
            &secret_key,
            Some(&recovery_key),
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        vault
            .add_item(&ItemData::login("t", "u", "p", "https://x.example"))
            .unwrap();
        (
            vault.to_bytes().unwrap(),
            recovery_key.to_display_string().to_string(),
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let recovery_key = RecoveryKey::generate().unwrap();
        let _ = Vault::open(&bytes, Unlock::Recovery(&recovery_key));
    }

    #[test]
    fn random_bytes_after_valid_magic_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let recovery_key = RecoveryKey::generate().unwrap();
        let mut bytes = b"PMVAULT\0\0\0".to_vec();
        bytes.extend_from_slice(&tail);
        let _ = Vault::open(&bytes, Unlock::Recovery(&recovery_key));
    }

    #[test]
    fn mutated_valid_files_are_rejected_without_panicking(
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
        truncate in proptest::option::of(any::<prop::sample::Index>()),
    ) {
        let (original, recovery_text) = sample();
        let recovery_key = RecoveryKey::parse(recovery_text).unwrap();
        let mut bytes = original.clone();
        for (index, value) in edits {
            let i = index.index(bytes.len());
            bytes[i] = value;
        }
        if let Some(index) = truncate {
            bytes.truncate(index.index(bytes.len()));
        }
        let result = Vault::open(&bytes, Unlock::Recovery(&recovery_key));
        if bytes != *original {
            prop_assert!(result.is_err(), "a modified file was accepted");
        }
    }

    #[test]
    fn key_parsers_never_panic(text in "\\PC{0,80}") {
        let _ = SecretKey::parse(&text);
        let _ = RecoveryKey::parse(&text);
    }
}
