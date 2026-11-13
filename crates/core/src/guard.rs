//! The item guard: a second check before an unlocked vault shows an item's secrets.
//!
//! With the vault open, usernames, websites and notes are visible, but passwords, one-time
//! codes, recovery codes and hidden fields of guarded items stay closed until the person types
//! a PIN, a separate password, or the master password again.
//!
//! This is a rule clients enforce, not extra encryption: the vault key is already in memory,
//! so the guard stops a person at an unlocked computer, not malware that reads the process. A
//! short PIN is acceptable only because clients lock the whole vault after a few wrong tries.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{Error, KdfParams, Result, kdf};

/// What the person types to open a guarded item.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardCheck {
    /// The master password, checked by the client against the vault file.
    #[default]
    Master,
    /// A PIN of 4 to 8 digits kept (hashed) in the vault.
    Pin,
    /// A separate password kept (hashed) in the vault.
    Password,
}

/// Guard settings, stored inside the encrypted vault body. (Format v5.)
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemGuard {
    /// Guard every item; otherwise only items with `ItemData::reprompt`.
    pub all_items: bool,
    pub check: GuardCheck,
    /// Argon2id hash of the PIN or password (`None` for [`GuardCheck::Master`]).
    verifier: Option<Verifier>,
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

impl ItemGuard {
    pub const MIN_PIN_DIGITS: usize = 4;
    pub const MAX_PIN_DIGITS: usize = 8;
    pub const MIN_PASSWORD_CHARS: usize = 6;
    /// Wrong tries a client allows before it locks the whole vault.
    pub const MAX_ATTEMPTS: u32 = 5;

    /// Builds new guard settings. `secret` is the new PIN or password; it may be `None` to
    /// keep the one `current` already has (same kind of check), and is ignored for
    /// [`GuardCheck::Master`].
    pub fn new(
        current: &ItemGuard,
        all_items: bool,
        check: GuardCheck,
        secret: Option<&str>,
    ) -> Result<Self> {
        let verifier = match (check, secret) {
            (GuardCheck::Master, _) => None,
            (_, Some(secret)) => {
                let chars = secret.chars().count();
                let valid = match check {
                    GuardCheck::Pin => {
                        (Self::MIN_PIN_DIGITS..=Self::MAX_PIN_DIGITS).contains(&chars)
                            && secret.chars().all(|c| c.is_ascii_digit())
                    }
                    _ => chars >= Self::MIN_PASSWORD_CHARS,
                };
                if !valid {
                    return Err(Error::InvalidGuardSecret);
                }
                // The format's minimum cost: the hash lives inside the encrypted vault, so
                // its job is only to keep the PIN itself out of the file and out of memory.
                let kdf = KdfParams::minimum()?;
                let hash = *kdf::derive_password_key(secret, &kdf)?;
                Some(Verifier { kdf, hash })
            }
            (_, None) if current.check == check && current.verifier.is_some() => {
                current.verifier.clone()
            }
            (_, None) => return Err(Error::InvalidGuardSecret),
        };
        Ok(Self {
            all_items,
            check,
            verifier,
        })
    }

    /// Whether `secret` is the PIN or password. Always `false` for [`GuardCheck::Master`]
    /// (the client checks the master password against the file instead).
    pub fn verify(&self, secret: &str) -> Result<bool> {
        let Some(verifier) = &self.verifier else {
            return Ok(false);
        };
        if secret.is_empty() {
            return Ok(false);
        }
        let hash = kdf::derive_password_key(secret, &verifier.kdf)?;
        Ok(bool::from(hash.ct_eq(&verifier.hash)))
    }

    /// A stored guard must be consistent: a verifier exactly when the check needs one, with
    /// acceptable KDF parameters.
    pub(crate) fn validate(&self) -> Result<()> {
        match (&self.verifier, self.check) {
            (None, GuardCheck::Master) => Ok(()),
            (Some(verifier), GuardCheck::Pin | GuardCheck::Password) => verifier.kdf.validate(),
            _ => Err(Error::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_and_passwords_are_checked_and_kept_hashed() {
        let off = ItemGuard::default();
        assert_eq!((off.all_items, off.check), (false, GuardCheck::Master));
        assert!(!off.verify("1234").unwrap());

        for bad in ["123", "12a4", "123456789", ""] {
            assert!(ItemGuard::new(&off, true, GuardCheck::Pin, Some(bad)).is_err());
        }
        assert!(ItemGuard::new(&off, true, GuardCheck::Pin, None).is_err());
        assert!(ItemGuard::new(&off, true, GuardCheck::Password, Some("short")).is_err());

        let pin = ItemGuard::new(&off, true, GuardCheck::Pin, Some("4821")).unwrap();
        pin.validate().unwrap();
        assert!(pin.verify("4821").unwrap());
        assert!(!pin.verify("4822").unwrap());
        assert!(!pin.verify("").unwrap());
        assert!(!format!("{pin:?}").contains("4821"));

        // Changing only the scope keeps the PIN; changing the kind needs a new secret.
        let scoped = ItemGuard::new(&pin, false, GuardCheck::Pin, None).unwrap();
        assert!(scoped.verify("4821").unwrap() && !scoped.all_items);
        assert!(ItemGuard::new(&pin, true, GuardCheck::Password, None).is_err());
        let master = ItemGuard::new(&pin, true, GuardCheck::Master, None).unwrap();
        master.validate().unwrap();
        assert!(!master.verify("4821").unwrap());
    }
}
