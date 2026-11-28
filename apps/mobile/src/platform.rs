//! What the phone app needs from the system: the platform crate on a phone or a computer, and
//! a stand-in in a browser (the web preview, `apps/mobile-web`), where there is no file
//! system, no credential store and no clipboard the app may read.

#[cfg(not(target_arch = "wasm32"))]
pub use vault_platform::{
    DeviceState, RollbackStatus, SecretBuffer, StateFile, clipboard, device, leak_check,
    secret_store,
};

/// The computer's language, where the system tells it through the process (not Android).
#[cfg(not(target_arch = "wasm32"))]
pub fn system_language() -> Option<String> {
    vault_platform::locale::system_language()
}

/// Seconds since the device started (nobody sets it), where the system tells it: unlock
/// attempts are timed by it too.
#[cfg(not(target_arch = "wasm32"))]
pub fn uptime_seconds() -> Option<i64> {
    vault_platform::device::uptime_seconds()
}

/// The vault file: on disk, or (in a browser) in this page's memory.
#[cfg(not(target_arch = "wasm32"))]
pub mod files {
    use std::path::Path;

    pub use vault_core::storage::{read, write_atomic};

    pub fn read_any(path: &Path) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    pub fn create_dir_all(path: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }

    /// Deletes a file, if it is there.
    pub fn remove(path: &Path) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(target_arch = "wasm32")]
mod web;
#[cfg(target_arch = "wasm32")]
pub use web::*;
