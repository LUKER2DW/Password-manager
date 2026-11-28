//! The payload of an authenticator app's transfer QR code (`otpauth-migration://offline?data=`,
//! a protocol buffer in Base64), read by hand in `vault_import::authenticator`: whatever the
//! bytes, it is refused or read, never a panic, and every key read gives codes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_core::totp::Totp;

fuzz_target!(|data: &[u8]| {
    // The raw payload, as the link would carry it.
    let link = format!(
        "otpauth-migration://offline?data={}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
    );
    if let Some(report) = vault_import::authenticator::migration(&link) {
        for item in &report.items {
            assert!(Totp::parse(&item.totp).is_ok());
        }
    }
    // And the text as it came.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = vault_import::authenticator::migration(text);
    }
});
