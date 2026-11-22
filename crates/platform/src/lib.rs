//! OS integration shared by the apps (the `vault` CLI, the desktop app, the phone app).
//!
//! Everything here is about *where* things live on this device and *how* the OS is asked to
//! protect them. Cryptography stays in `vault-core`.

pub mod browser_link;
pub mod browsers;
#[cfg(not(target_os = "android"))]
pub mod clipboard;
/// On Android the clipboard is the system's `ClipboardManager`, reached through JNI.
#[cfg(target_os = "android")]
#[path = "clipboard_android.rs"]
pub mod clipboard;
pub mod device;
pub mod dpapi;
pub mod files;
pub mod keyfile;
pub mod kit_pdf;
pub mod leak_check;
pub mod locale;
pub mod part_picture;
pub mod paths;
pub mod quick_unlock;
pub mod screen;
pub mod secret_store;
pub mod secure_buffer;
pub mod sync;
pub mod website_icons;

pub use device::{DeviceState, RollbackStatus, StateFile, SyncPlace, SyncTo};
pub use secure_buffer::SecretBuffer;
