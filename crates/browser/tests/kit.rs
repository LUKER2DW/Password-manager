//! The emergency kit's keys that the extension's own test refuses in a page
//! (`apps/extension/test/kit.test.mjs`): the same strings, made for these tests from obvious
//! test bytes (0x00, 0x01, … and the like), are real keys to `vault_core` (their checksums
//! hold) and are recognised by the app's check (`vault_browser::kit`).

use vault_browser::kit::holds_kit_key;
use vault_core::{RecoveryKey, RecoveryPart, SecretKey};

/// The same list as `KEYS` in `apps/extension/test/kit.test.mjs`.
const KEYS: [&str; 6] = [
    "S0-000G40R-40M30E2-09185GR-38E1WMT",
    "S0-MPHAQC5-SGT7S97-CTWFMF3-ZP7SGX4",
    "A0-208H44R-M2MB1E6-0S38DHR-78Y3WKG",
    "B0-40GJ48S-44MK2EA-1958NJR-B9E5W0M",
    "C0-60RK4CS-M6MV3EE-1S78XKR-F9Y7WEV",
    "R0-001GC2-8C1W91-A60V3R-GJ89SA-5MR36D-HS7GZM-4HA89D-752N2Q-B9EGYV",
];

#[test]
fn the_extensions_test_keys_are_real_keys_and_recognised() {
    for key in KEYS {
        let parsed = match &key[..2] {
            "S0" => SecretKey::parse(key).is_ok(),
            "R0" => RecoveryKey::parse(key).is_ok(),
            _ => RecoveryPart::parse(key).is_ok(),
        };
        assert!(parsed, "{key} is a key vault_core reads");
        assert!(holds_kit_key(key), "{key}");
        assert!(holds_kit_key(&key.to_lowercase()), "{key}");
        assert!(holds_kit_key(&key.replace('-', "")), "{key}");
    }
}
