//! OS integration shared by the apps (the `vault` CLI, the desktop app, the phone app).
//!
//! Everything here is about *where* things live on this device and *how* the OS is asked to
//! protect them. Cryptography stays in `vault-core`.

pub mod autostart;
pub mod autotype;
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
pub mod extension_folder;
pub mod extension_source;
pub mod file_types;
pub mod files;
pub mod hardware_key;
pub mod keyfile;
pub mod kit_pdf;
pub mod leak_check;
pub mod locale;
pub mod os_notice;
pub mod part_picture;
pub mod paths;
pub mod process;
pub mod quick_unlock;
#[cfg(windows)]
mod registry;
pub mod screen;
pub mod secret_store;
pub mod secure_buffer;
pub mod secure_desktop;
pub mod secure_memory;
pub mod security_log;
pub mod self_update;
pub mod session_watch;
pub mod single_instance;
pub mod ssh_agent;
pub mod sync;
#[cfg(windows)]
pub mod tpm;
pub mod updates;
pub mod website_icons;
pub mod wiping_alloc;

pub use device::{DeviceState, RollbackStatus, StateFile, SyncPlace, SyncTo, VersionStatus};
pub use secure_buffer::SecretBuffer;
