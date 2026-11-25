//! A file brought in from another manager or a browser: each reader must refuse what it can't
//! read, never panic. The first byte picks the format; KeePass and sealed exports are tried
//! with a fixed password, so the readers' parsing runs up to the key check.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_import::{Format, import};

fuzz_target!(|data: &[u8]| {
    let Some((&pick, bytes)) = data.split_first() else {
        return;
    };
    let format = match pick % 4 {
        0 => Format::Json,
        1 => Format::Csv,
        2 => Format::Kdbx,
        _ => Format::Sealed,
    };
    let _ = import(bytes, format, "fuzz test password", None);
});
