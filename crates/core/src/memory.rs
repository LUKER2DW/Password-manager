//! Keys in memory: the vault key and the item guard key kept encrypted between uses, and the
//! stack cleared where key work ran.
//!
//! Those two keys stay in memory for as long as a vault (or its guarded secrets) is open. A
//! program can hand the core a [`KeyShield`] once, at start ([`install_key_shield`]): from
//! then on both are kept encrypted by it, and opened into a copy that is wiped when dropped
//! only for the moment one is used. On Windows the desktop app and the CLI install one that
//! encrypts with a key the system holds for this process (`CryptProtectMemory`), so a dump of
//! the process's memory, the pagefile or a crash report holds only the encrypted form.
//! Without one (the phone, the browser build, most tests) the keys are kept as they are, and
//! wiped when dropped as before.
//!
//! The core holds no OS code: the shield is the program's. Nothing here changes what is
//! written to disk.

use std::{fmt, sync::OnceLock};

use zeroize::{Zeroize, Zeroizing};

use crate::aead;

/// Encrypts a 32-byte key in place and decrypts it back, with a key the program keeps out of
/// the process's ordinary memory (on Windows, one the system holds for this process).
///
/// The encrypted form may be copied and decrypted anywhere in the same process: it must not
/// depend on the address it is at. Both are called from any thread.
pub trait KeyShield: Send + Sync {
    /// Encrypts `key` in place. `false` if it couldn't: the key must then be left as it was.
    fn shield(&self, key: &mut [u8; 32]) -> bool;
    /// Decrypts in place what [`shield`](Self::shield) encrypted. `false` if it couldn't.
    fn unshield(&self, key: &mut [u8; 32]) -> bool;
}

static SHIELD: OnceLock<&'static dyn KeyShield> = OnceLock::new();

/// Hands the core the program's [`KeyShield`], once, before a vault is opened or created (a
/// key made before stays unshielded until it is dropped). Answers whether it was taken:
/// `false` when one was installed already.
pub fn install_key_shield(shield: &'static dyn KeyShield) -> bool {
    SHIELD.set(shield).is_ok()
}

/// Whether a [`KeyShield`] was installed.
pub fn key_shield_installed() -> bool {
    SHIELD.get().is_some()
}

/// How much of the stack [`clear_stack`] writes over. The key work of opening, unlocking,
/// reading and saving a vault reaches a few kilobytes below the frame that started it (the
/// password hash's own blocks live on the heap); this leaves a wide margin.
const CLEARED_STACK: usize = 64 * 1024;

/// Writes zeros over the part of the calling thread's stack just below the caller: where
/// key work started from about the same place (a UI callback, say) left copies behind that
/// nothing wipes, a key moved by value or a hash's state. The apps call it when the vault
/// locks, on the thread that used it.
#[inline(never)]
pub fn clear_stack() {
    let mut area = [0u8; CLEARED_STACK];
    // Volatile writes: they can't be left out as useless.
    area.zeroize();
    std::hint::black_box(&mut area);
}

/// A 32-byte key kept encrypted by the installed [`KeyShield`], if there is one.
pub(crate) struct ShieldedKey {
    bytes: Zeroizing<aead::Key>,
    /// The shield that encrypted `bytes`, kept so the same one always opens it; none when
    /// `bytes` is the key itself.
    shield: Option<&'static dyn KeyShield>,
}

impl ShieldedKey {
    pub(crate) fn new(mut key: Zeroizing<aead::Key>) -> Self {
        let shield = SHIELD
            .get()
            .copied()
            .filter(|shield| shield.shield(&mut key));
        Self { bytes: key, shield }
    }

    /// The key itself, in a copy wiped when dropped: keep it no longer than its use.
    ///
    /// # Panics
    /// When the shield can't decrypt what it encrypted, which it never should: going on with
    /// a wrong key could seal the vault under it.
    pub(crate) fn open(&self) -> Zeroizing<aead::Key> {
        let mut key = self.bytes.clone();
        if let Some(shield) = self.shield {
            assert!(
                shield.unshield(&mut key),
                "the key shield could not decrypt a key"
            );
        }
        key
    }
}

impl Clone for ShieldedKey {
    /// A copy of the encrypted form: the key itself never leaves its shield for it.
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            shield: self.shield,
        }
    }
}

impl fmt::Debug for ShieldedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShieldedKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No shield in this test binary: the key is kept as it is and opens as it was.
    #[test]
    fn without_a_shield_the_key_is_kept_as_it_is() {
        let key = ShieldedKey::new(Zeroizing::new([5u8; 32]));
        assert!(key.shield.is_none() && !key_shield_installed());
        assert_eq!(*key.open(), [5u8; 32]);
        assert_eq!(*key.clone().open(), [5u8; 32]);
        assert_eq!(format!("{key:?}"), "ShieldedKey(<redacted>)");
        clear_stack();
    }
}
