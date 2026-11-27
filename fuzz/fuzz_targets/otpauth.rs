//! A one-time code's secret as it comes in: a scanned or pasted `otpauth://` link (a QR code
//! on a website, an import) or a bare Base32 secret (`vault_core::totp`). What isn't one is
//! refused; a code made from what is has its digits, and nothing panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_core::totp::{self, Totp};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(code) = Totp::parse(text) {
        for at in [0, 1_700_000_000, u64::MAX] {
            let shown = code.code_at(at);
            assert_eq!(shown.len(), code.digits() as usize);
            assert!(shown.bytes().all(|b| b.is_ascii_digit()));
        }
        let _ = code.code_for(u64::MAX);
        let _ = code.counter();
    }
    let _ = totp::next_counter(text);
    let _ = totp::with_kind(text, true);
    let _ = totp::names(text);
});
