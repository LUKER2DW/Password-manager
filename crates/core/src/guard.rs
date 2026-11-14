//! The item guard: a second check before an unlocked vault shows an item's secrets.
//!
//! With the vault open, usernames, websites and notes are visible, but passwords, one-time
//! codes, recovery codes and hidden fields of guarded items stay closed until the person types
//! a PIN, a separate password, or the master password again.
//!
//! With a PIN or a separate password the guard is also encryption (format v6): the secrets of
//! guarded items are sealed under a random guard key, and that key is stored only wrapped by
//! the PIN or password (and, so a forgotten PIN can be replaced, by the master password). The
//! vault key alone no longer reads them, so malware that takes an unlocked vault from memory
//! gets nothing from items that are still locked. Two limits remain: a 4-digit PIN has only
//! 10 000 values, so someone who already holds the vault key can try them all offline in hours
//! (a longer PIN or a password fixes that), and secrets are readable while they are open.
//!
//! With the master password as the check, the guard is a rule clients enforce, not
//! encryption: it stops a person at an unlocked computer. That keeps the Recovery Key able to
//! open everything.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, KdfParams, KdfStrength, Result, aead, kdf, keys};

/// What the person types to open a guarded item.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardCheck {
    /// The master password, checked by the client against the vault file. No extra encryption.
    #[default]
    Master,
    /// A PIN of 4 to 8 digits that unwraps the guard key.
    Pin,
    /// A separate password that unwraps the guard key.
    Password,
}

/// Which wrapped copy of the guard key (part of its AAD).
#[derive(Clone, Copy)]
pub(crate) enum GuardSlot {
    /// Wrapped by the PIN or password.
    Check = 1,
    /// Wrapped by the master password, to replace a forgotten PIN or password.
    Master = 2,
}

/// Guard settings, stored inside the encrypted vault body. (Format v5; the key in v6.)
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemGuard {
    /// Guard every item; otherwise only items with `ItemData::reprompt`.
    pub all_items: bool,
    pub check: GuardCheck,
    /// Format v5 guards: only a hash of the PIN or password, no encryption. Replaced by `key`
    /// the first time the PIN or password is typed.
    verifier: Option<Verifier>,
    /// The wrapped guard key (PIN and password checks).
    pub(crate) key: Option<GuardKeySlots>,
}

/// Guard settings as stored by format v5.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ItemGuardV5 {
    all_items: bool,
    check: GuardCheck,
    verifier: Option<Verifier>,
}

impl ItemGuardV5 {
    pub(crate) fn upgrade(self) -> ItemGuard {
        ItemGuard {
            all_items: self.all_items,
            check: self.check,
            verifier: self.verifier,
            key: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Verifier {
    kdf: KdfParams,
    hash: [u8; 32],
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Verifier(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GuardKeySlots {
    pub(crate) check: WrappedGuardKey,
    pub(crate) master: Option<WrappedGuardKey>,
}

/// The guard key sealed under Argon2id(PIN, password or master password).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WrappedGuardKey {
    kdf: KdfParams,
    wrapped: Vec<u8>,
}

impl std::fmt::Debug for WrappedGuardKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WrappedGuardKey(..)")
    }
}

impl WrappedGuardKey {
    /// Wraps `key` under `secret`. The cost is the standard unlock level: with the vault key
    /// in an attacker's hands, this hash is all that stands between them and a short PIN.
    pub(crate) fn wrap(
        secret: &str,
        key: &aead::Key,
        vault_id: &[u8; 16],
        slot: GuardSlot,
    ) -> Result<Self> {
        let kdf = KdfStrength::Standard.params()?;
        let kek = Self::kek(secret, &kdf, vault_id)?;
        let wrapped = aead::seal(&kek, key, &guard_key_aad(vault_id, slot))?;
        Ok(Self { kdf, wrapped })
    }

    /// The guard key, or `None` when `secret` is not the one that wrapped it.
    pub(crate) fn unwrap(
        &self,
        secret: &str,
        vault_id: &[u8; 16],
        slot: GuardSlot,
    ) -> Result<Option<Zeroizing<aead::Key>>> {
        if secret.is_empty() {
            return Ok(None);
        }
        let kek = Self::kek(secret, &self.kdf, vault_id)?;
        let Ok(bytes) = aead::open(&kek, &self.wrapped, &guard_key_aad(vault_id, slot)) else {
            return Ok(None);
        };
        let key: aead::Key = bytes.as_slice().try_into().map_err(|_| Error::Malformed)?;
        Ok(Some(Zeroizing::new(key)))
    }

    fn kek(secret: &str, kdf: &KdfParams, vault_id: &[u8; 16]) -> Result<Zeroizing<aead::Key>> {
        let stretched = kdf::derive_password_key(secret, kdf)?;
        Ok(keys::guard_kek(&stretched, vault_id))
    }
}

fn guard_key_aad(vault_id: &[u8; 16], slot: GuardSlot) -> Vec<u8> {
    [b"vault-v0/guard-key".as_slice(), vault_id, &[slot as u8]].concat()
}

impl ItemGuard {
    pub const MIN_PIN_DIGITS: usize = 4;
    pub const MAX_PIN_DIGITS: usize = 8;
    pub const MIN_PASSWORD_CHARS: usize = 6;
    /// Wrong tries a client allows before it locks the whole vault.
    pub const MAX_ATTEMPTS: u32 = 5;

    /// Whether `secret` can be a PIN (4 to 8 digits) or a guard password (6+ characters).
    pub fn check_secret(check: GuardCheck, secret: &str) -> Result<()> {
        let chars = secret.chars().count();
        let valid = match check {
            GuardCheck::Master => true,
            GuardCheck::Pin => {
                (Self::MIN_PIN_DIGITS..=Self::MAX_PIN_DIGITS).contains(&chars)
                    && secret.chars().all(|c| c.is_ascii_digit())
            }
            GuardCheck::Password => chars >= Self::MIN_PASSWORD_CHARS,
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidGuardSecret)
        }
    }

    /// Whether guarded items' secrets are encrypted under the guard key (PIN and password
    /// checks), not just hidden by the client.
    pub fn encrypts(&self) -> bool {
        self.key.is_some()
    }

    /// Whether the master password can stand in for a forgotten PIN or password.
    pub fn master_can_reset(&self) -> bool {
        self.key.as_ref().is_some_and(|key| key.master.is_some())
    }

    /// A format v5 guard that has not been turned into encryption yet.
    pub fn is_legacy(&self) -> bool {
        self.verifier.is_some()
    }

    /// Checks a PIN or password against a format v5 hash.
    pub(crate) fn verify_legacy(&self, secret: &str) -> Result<bool> {
        let Some(verifier) = &self.verifier else {
            return Ok(false);
        };
        if secret.is_empty() {
            return Ok(false);
        }
        let hash = kdf::derive_password_key(secret, &verifier.kdf)?;
        Ok(bool::from(hash.ct_eq(&verifier.hash)))
    }

    /// A stored guard must be consistent: nothing kept for the master password; for a PIN or
    /// password either the wrapped key or (from format v5) the hash, with acceptable KDF
    /// parameters.
    pub(crate) fn validate(&self) -> Result<()> {
        match (self.check, &self.verifier, &self.key) {
            (GuardCheck::Master, None, None) => Ok(()),
            (GuardCheck::Pin | GuardCheck::Password, Some(verifier), None) => {
                verifier.kdf.validate()
            }
            (GuardCheck::Pin | GuardCheck::Password, None, Some(key)) => {
                key.check.kdf.validate()?;
                key.master.as_ref().map_or(Ok(()), |m| m.kdf.validate())
            }
            _ => Err(Error::Malformed),
        }
    }

    pub(crate) fn with_key(all_items: bool, check: GuardCheck, key: Option<GuardKeySlots>) -> Self {
        Self {
            all_items,
            check,
            verifier: None,
            key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_and_passwords_have_a_shape() {
        for bad in ["123", "12a4", "123456789", ""] {
            assert!(ItemGuard::check_secret(GuardCheck::Pin, bad).is_err());
        }
        assert!(ItemGuard::check_secret(GuardCheck::Pin, "4821").is_ok());
        assert!(ItemGuard::check_secret(GuardCheck::Password, "short").is_err());
        assert!(ItemGuard::check_secret(GuardCheck::Password, "longer one").is_ok());
        let off = ItemGuard::default();
        assert_eq!((off.all_items, off.check), (false, GuardCheck::Master));
        assert!(!off.encrypts() && !off.master_can_reset());
        off.validate().unwrap();
    }

    #[test]
    fn the_guard_key_opens_only_with_its_secret_vault_and_slot() {
        let key = [7u8; 32];
        let vault = [1u8; 16];
        let wrapped = WrappedGuardKey::wrap("4821", &key, &vault, GuardSlot::Check).unwrap();
        assert_eq!(
            *wrapped
                .unwrap("4821", &vault, GuardSlot::Check)
                .unwrap()
                .unwrap(),
            key
        );
        assert!(
            wrapped
                .unwrap("4822", &vault, GuardSlot::Check)
                .unwrap()
                .is_none()
        );
        assert!(
            wrapped
                .unwrap("", &vault, GuardSlot::Check)
                .unwrap()
                .is_none()
        );
        assert!(
            wrapped
                .unwrap("4821", &[2u8; 16], GuardSlot::Check)
                .unwrap()
                .is_none()
        );
        assert!(
            wrapped
                .unwrap("4821", &vault, GuardSlot::Master)
                .unwrap()
                .is_none()
        );
        assert!(!format!("{wrapped:?}").contains("4821"));
    }
}
