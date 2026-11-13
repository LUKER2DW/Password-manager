//! `vault-core`: the security-critical heart of the password manager.
//!
//! This crate owns all key material and cryptography. It has no UI and no network access.
//! The specification it implements lives in `docs/spec/CRYPTO.md` and
//! `docs/spec/VAULT_FORMAT.md`.
//!
//! ```no_run
//! use vault_core::{ItemData, KdfParams, RecoveryKey, SecretKey, Unlock, Vault};
//!
//! let secret_key = SecretKey::generate()?;
//! let recovery_key = RecoveryKey::generate()?;
//! let mut vault = Vault::create("correct horse", &secret_key, Some(&recovery_key), KdfParams::recommended()?)?;
//! let id = vault.add_item(&ItemData::login("GitHub", "me", "s3cret", "https://github.com"))?;
//! let bytes = vault.to_bytes()?;
//!
//! let reopened = Vault::open(&bytes, Unlock::Password { password: "correct horse", secret_key: &secret_key })?;
//! assert_eq!(reopened.get_item(&id)?.password, "s3cret");
//! # Ok::<(), vault_core::Error>(())
//! ```

mod aead;
mod encoding;
mod error;
mod format;
mod guard;
mod item;
mod kdf;
mod keys;
mod padding;
mod random;
mod vault;

pub mod generator;
pub mod health;
pub mod storage;
pub mod totp;

pub mod card;
pub use error::Error;
pub use guard::{GuardCheck, ItemGuard};
pub use item::{
    CustomField, Folder, FolderId, ItemData, ItemId, ItemKind, ItemSummary, PasswordChange,
    RecoveryCode, VaultSettings,
};
pub use kdf::{KdfParams, KdfStrength};
pub use keys::{Keyfile, RecoveryKey, SecretKey};
pub use vault::{Unlock, Vault, VaultInfo};

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
