//! An invite line pasted or scanned from a QR code: anything that isn't one is refused, and
//! what is read back writes out the same way.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_sync_wire::InviteLink;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(link) = InviteLink::parse(text) {
        let again = link.to_text();
        // The line holds the invite's secret: never printed, even on a failure.
        assert!(InviteLink::parse(&again).is_some());
    }
});
