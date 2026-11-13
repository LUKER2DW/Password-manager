//! OS integration shared by the `vault` CLI and the desktop app.
//!
//! Everything here is about *where* things live on this device and *how* the OS is asked to
//! protect them. Cryptography stays in `vault-core`.

pub mod clipboard;
pub mod device;
pub mod paths;
pub mod quick_unlock;
pub mod screen;
pub mod secret_store;
pub mod secure_buffer;

pub use device::{DeviceState, RollbackStatus};
pub use secure_buffer::SecretBuffer;
