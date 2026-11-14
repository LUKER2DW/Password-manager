//! The browser extension's link to the vault.
//!
//! The extension holds no secrets and does no cryptography. When the person clicks its button
//! it sends the address of the page to the desktop app (through the native host and a local
//! pipe, see `vault_platform::browser_link`) and gets back the logins saved for exactly that
//! site, without passwords. A password leaves the app only for the one login the person then
//! picks in the extension's own window, and only for a page of the same origin.
//!
//! - [`origin`]: which saved website belongs to which page (exact scheme, host and port).
//! - [`protocol`]: the JSON messages.
//! - [`service`]: how the app answers them from an unlocked vault.
//! - [`host`]: the relay the native host runs.

pub mod host;
pub mod origin;
pub mod protocol;
pub mod service;
