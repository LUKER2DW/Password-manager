//! What reaches the desktop app from the browser's side before anything is trusted (AGENTS.md
//! §2.4.1): the envelope, the sealed data and an older extension's proof in it, the request
//! (JSON), and the page addresses requests name. What isn't one is refused (an `Invalid`
//! envelope, `None`, an error), never a panic; nothing the fuzzer makes opens or verifies
//! under a key it doesn't hold.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_browser::{
    origin::{self, Origin},
    pairing::{Envelope, PairingKey},
    protocol::Request,
};

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let key = PairingKey::from_bytes(&[7; 32]).expect("a 32-byte key");
    match pick % 3 {
        0 => match Envelope::parse(rest) {
            Envelope::Sealed { counter, data } => {
                if let Some(opened) = key.open_request(counter, &data) {
                    let _ = serde_json::from_slice::<Request>(&opened.body);
                }
            }
            Envelope::Signed { counter, body, mac } => {
                let _ = key.verify(counter, body.as_bytes(), &mac);
                let _ = serde_json::from_str::<Request>(&body);
            }
            _ => {}
        },
        1 => {
            let _ = serde_json::from_slice::<Request>(rest);
        }
        _ => {
            let Ok(text) = std::str::from_utf8(rest) else {
                return;
            };
            let (page, saved) = text.split_once('\n').unwrap_or((text, text));
            if let Ok(page) = Origin::of_page(page) {
                let _ = origin::saved_matches(saved, &page);
                let _ = origin::item_matches(&[saved], &page);
                let _ = origin::passkey_site(saved, &page);
                let _ = origin::wildcard_covers_host(saved, page.host());
            }
            let _ = Origin::of_saved(saved);
            let _ = origin::wildcard_base(saved);
        }
    }
});
