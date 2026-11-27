//! `vault-core`: the security-critical heart of the password manager.
//!
//! This crate owns all key material and cryptography. It has no UI and no network access.
//! The specification it implements lives in `docs/spec/CRYPTO.md` and
//! `docs/spec/VAULT_FORMAT.md`.
//!
//! ```no_run
//! use vault_core::{ItemData, KdfParams, RecoveryParts, SecretKey, Unlock, Vault};
//!
//! let secret_key = SecretKey::generate()?;
//! let mut vault = Vault::create("correct horse", &secret_key, None, KdfParams::recommended()?)?;
//! vault.set_recovery_parts(&RecoveryParts::generate()?, &secret_key)?;
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

pub mod drop_box;
pub mod generator;
pub mod health;
pub mod locked_fill;
pub mod memory;
pub mod passkey;
pub mod sealed_export;
pub mod ssh;
pub mod storage;
pub mod sync;
pub mod totp;

pub mod card;
pub use error::Error;
pub use guard::{GuardCheck, GuardOpened, ItemGuard};
pub use item::{
    Attachment, CustomField, Folder, FolderId, ItemData, ItemId, ItemKind, ItemSummary,
    PasswordChange, RecoveryCode, SealedSecrets, VaultSettings,
};
pub use kdf::{KdfMethod, KdfParams, KdfStrength, PasswordKdf};
pub use keys::{Keyfile, PartLabel, RecoveryKey, RecoveryPart, RecoveryParts, SecretKey};
pub use passkey::Passkey;
pub use vault::{FormerKey, RenewedKey, Unlock, Vault, VaultInfo, VaultSnapshot};

/// The keys no public call gives out, for the memory test of the desktop app
/// (`apps/desktop/tests/memory.rs`), which looks for them in the memory of a running copy.
/// Built only with the `memory-test` feature, which only that test turns on.
#[cfg(feature = "memory-test")]
#[doc(hidden)]
pub mod memory_test {
    use zeroize::Zeroizing;

    use crate::{SecretKey, Vault};

    /// The vault key.
    pub fn vault_key(vault: &Vault) -> Zeroizing<[u8; 32]> {
        vault.keys_for_memory_test().0
    }

    /// The item guard key, while guarded secrets are open.
    pub fn guard_key(vault: &Vault) -> Option<Zeroizing<[u8; 32]>> {
        vault.keys_for_memory_test().1
    }

    /// The Secret Key's 16 bytes.
    pub fn secret_key(key: &SecretKey) -> Zeroizing<[u8; 16]> {
        Zeroizing::new(*key.as_bytes())
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
