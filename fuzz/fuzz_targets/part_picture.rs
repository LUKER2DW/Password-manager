//! A picture said to hold recovery part C (`vault_platform::part_picture`): the person picks
//! the file, which may be any picture or none. It is read as a PNG within the size limits and
//! gives a part or an error, never a panic or an allocation past the limits.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vault_platform::part_picture::read(data);
});
