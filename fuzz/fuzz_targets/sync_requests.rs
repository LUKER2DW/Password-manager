//! What a sync server reads from anyone who reaches it (THREAT_MODEL A10, SYNC.md §5.3), read
//! the way `vault-server` reads it (`api.rs`: `enroll`, `verify_request`): an enrollment's
//! body, and a signed request's headers. What isn't one is refused, never a panic; a signature
//! made here for a fixed key verifies, and nothing the fuzzer makes passes for it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_sync_wire::{self as wire, DeviceKey, Enroll};

/// The most an enrollment's body may be (`api.rs` `ENROLL_BYTES`).
const ENROLL_BYTES: usize = 4 * 1024;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let key = DeviceKey::from_seed(&[7; 32]);
    if pick % 2 == 0 {
        // POST /v1/enroll: plain fields, each checked before anything is looked up.
        if rest.len() > ENROLL_BYTES {
            return;
        }
        let Ok(request) = serde_json::from_slice::<Enroll>(rest) else {
            return;
        };
        let _ = wire::invite_digest(&request.invite);
        if !wire::is_id(&request.vault)
            || !wire::is_id(&request.device)
            || !wire::is_device_name(&request.name)
        {
            return;
        }
        let Some(public) = wire::unhex::<32>(&request.key) else {
            return;
        };
        let message = wire::enroll_message(&request);
        let _ = wire::verify(&public, &message, &request.signature);
    } else {
        // A signed request's headers, one per line: method, path and query, device, time,
        // nonce, signature, body digest.
        let Ok(text) = std::str::from_utf8(rest) else {
            return;
        };
        let mut lines = text.split('\n');
        let mut next = || lines.next().unwrap_or_default();
        let (method, path, device, time, nonce, signature, digest) =
            (next(), next(), next(), next(), next(), next(), next());
        let _ = wire::is_body_digest(digest);
        let Ok(time) = time.parse::<i64>() else {
            return;
        };
        if !wire::is_id(device) || !wire::is_id(nonce) {
            return;
        }
        let message = wire::request_message_for(method, path, device, time, nonce, digest);
        let good = key.sign(&message);
        assert!(wire::verify(&key.public_key(), &message, &good));
        if wire::verify(&key.public_key(), &message, signature) {
            // Only the key's own signature (its hex in either case) opens the door.
            assert!(signature.eq_ignore_ascii_case(&good));
        }
    }
});
