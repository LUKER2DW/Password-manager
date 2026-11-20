//! What the phone app needs from the system: the platform crate on a phone or a computer, and
//! a stand-in in a browser (the web preview, `crates/mobile-web`), where there is no file
//! system, no credential store and no clipboard the app may read.

#[cfg(not(target_arch = "wasm32"))]
pub use vault_platform::{
    DeviceState, RollbackStatus, SecretBuffer, StateFile, clipboard, device, secret_store,
};

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
}

#[cfg(target_arch = "wasm32")]
mod web;
#[cfg(target_arch = "wasm32")]
pub use web::*;
