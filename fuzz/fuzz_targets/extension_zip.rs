//! The browser extension's zip from a GitHub release (`vault_platform::extension_source`),
//! read by a strict reader of our own before any file of it is written. Whatever the bytes, it
//! refuses them or gives files within the limits, each named inside the folder, and a version.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_platform::extension_source::Extension;

fuzz_target!(|data: &[u8]| {
    if let Ok(extension) = Extension::from_zip(data) {
        assert!(!extension.version.is_empty());
        let total: usize = extension.files.iter().map(|(_, bytes)| bytes.len()).sum();
        assert!(total <= 32 * 1024 * 1024);
        for (name, _) in &extension.files {
            assert!(!name.is_empty() && !name.starts_with('/') && !name.contains('\\'));
            assert!(!name.split('/').any(|part| part == ".." || part.is_empty()));
        }
        let _ = extension.digest();
    }
});
