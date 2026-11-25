//! A vault file from anywhere (a sync folder, a server, a stolen-and-altered copy): reading its
//! public header must fail cleanly, never panic or read out of bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vault_core::Vault::inspect(data);
});
