//! The browser extension's link to the vault.
//!
//! The extension holds no secrets and does no cryptography. When the person clicks its button
//! it sends the address of the page to the desktop app (through the native host and a local
//! pipe, see `vault_platform::browser_link`) and gets back the logins saved for exactly that
//! site, without passwords. A password leaves the app only for the one login the person then
//! picks in the extension's own window, and only for a page of the same origin.
//!
//! - [`origin`]: which saved website belongs to which page (exact scheme, host and port).
//! - [`lookalike`]: pages that look like a saved site without being it, and how a host is
//!   shown (in punycode when it mixes scripts).
//! - [`kit`]: the emergency kit's keys, recognised in what a page sends, never taken.
//! - [`protocol`]: the JSON messages.
//! - [`resources`]: where a site changes its password, and its password rules (built in).
//! - [`rules`]: the person's rules per site (never save, no card, never fill, no passkeys).
//! - [`service`]: how the app answers them from an unlocked vault.
//! - [`locked`]: how it answers while the vault is locked (Windows Hello only).
//! - [`host`]: the relay the native host runs.

pub mod host;
pub mod kit;
pub mod locked;
pub mod lookalike;
pub mod origin;
pub mod pairing;
pub mod protocol;
pub mod resources;
pub mod rules;
pub mod service;
