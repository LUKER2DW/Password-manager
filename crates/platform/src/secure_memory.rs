//! Secrets in memory: one locked area for what the person types, and the key shield that
//! keeps the vault's keys encrypted between uses.
//!
//! [`SecretSlot`]: 1 KiB in one area of memory the process sets aside the first time one is
//! asked for. On Windows the area is locked into RAM once (`VirtualLock`: its pages are never
//! written to the pagefile) and kept out of crash reports (`WerRegisterExcludedMemoryBlock`).
//! It is never unlocked: Windows keeps no count of locks, so unlocking one buffer's page
//! would unlock it for every other secret on that page too. [`SecretBuffer`] keeps typed
//! secrets there. When the area is full or Windows refused it, a slot is on the heap instead
//! (wiped all the same). Locking doesn't keep memory out of the hibernation file: locking the
//! vault when Windows sleeps does that (`session_watch`).
//!
//! [`install_key_shield`]: on Windows, the vault key and the item guard key are kept encrypted
//! between uses (`vault_core::memory`) with `CryptProtectMemory` and a key the system holds
//! for this process, so a dump of the process, the pagefile or a crash report holds only the
//! encrypted form. It doesn't stop an administrator, or code running inside the process,
//! from asking the system to decrypt them.
//!
//! [`SecretBuffer`]: crate::SecretBuffer

use std::{
    fmt,
    ops::{Deref, DerefMut},
};

use zeroize::Zeroize;

/// The size of a [`SecretSlot`].
pub const SLOT_BYTES: usize = 1024;

/// 1 KiB for a secret, wiped when dropped; in the locked area when there is room (see the
/// module's notes).
pub struct SecretSlot {
    place: Place,
}

enum Place {
    /// Slot `index` of the locked area.
    Area {
        index: usize,
        bytes: &'static mut [u8; SLOT_BYTES],
    },
    Heap(Box<[u8; SLOT_BYTES]>),
}

impl SecretSlot {
    /// A slot of zeros.
    pub fn new() -> Self {
        let place = match area::take() {
            Some((index, bytes)) => Place::Area { index, bytes },
            None => Place::Heap(Box::new([0u8; SLOT_BYTES])),
        };
        Self { place }
    }

    /// Whether the slot is in the area locked into RAM (never on Windows' pagefile).
    pub fn is_locked(&self) -> bool {
        matches!(self.place, Place::Area { .. }) && area::locked()
    }
}

impl Default for SecretSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for SecretSlot {
    type Target = [u8; SLOT_BYTES];

    fn deref(&self) -> &Self::Target {
        match &self.place {
            Place::Area { bytes, .. } => bytes,
            Place::Heap(bytes) => bytes,
        }
    }
}

impl DerefMut for SecretSlot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.place {
            Place::Area { bytes, .. } => bytes,
            Place::Heap(bytes) => bytes,
        }
    }
}

impl Drop for SecretSlot {
    fn drop(&mut self) {
        self.deref_mut().zeroize();
        if let Place::Area { index, .. } = self.place {
            area::give_back(index);
        }
    }
}

/// Tests that fill the area, or count on a slot in it, take turns (the others may get a slot
/// on the heap while the area is full, which changes nothing for them).
#[cfg(test)]
pub(crate) static AREA_TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl fmt::Debug for SecretSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretSlot(locked: {}, <redacted>)", self.is_locked())
    }
}

#[cfg(windows)]
mod area {
    use std::sync::{Mutex, OnceLock, PoisonError};

    use windows_sys::Win32::System::{
        ErrorReporting::WerRegisterExcludedMemoryBlock,
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualLock},
        Threading::{GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize},
    };

    use super::SLOT_BYTES;

    /// Slots in the area: 64 KiB, enough for every secret field of two windows of the app.
    const SLOTS: usize = 64;
    const LENGTH: usize = SLOTS * SLOT_BYTES;

    struct Area {
        base: usize,
        locked: bool,
        /// Bit `i` set: slot `i` is in use.
        taken: Mutex<u64>,
    }

    static AREA: OnceLock<Option<Area>> = OnceLock::new();

    fn area() -> Option<&'static Area> {
        AREA.get_or_init(set_aside).as_ref()
    }

    /// Sets the area aside, locks it into RAM and keeps it out of crash reports. The area is
    /// never freed: slots of it live as long as the process.
    fn set_aside() -> Option<Area> {
        // SAFETY: plain calls on memory this function allocates itself; `min` and `max` are
        // written by GetProcessWorkingSetSize before they are used.
        #[allow(unsafe_code)]
        unsafe {
            let base = VirtualAlloc(
                std::ptr::null(),
                LENGTH,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if base.is_null() {
                return None;
            }
            let mut locked = VirtualLock(base, LENGTH) != 0;
            if !locked {
                // Locked pages count against the working set's minimum: make room once.
                let process = GetCurrentProcess();
                let (mut min, mut max) = (0usize, 0usize);
                if GetProcessWorkingSetSize(process, &raw mut min, &raw mut max) != 0 {
                    let min = min + 2 * LENGTH;
                    SetProcessWorkingSetSize(process, min, max.max(min + LENGTH));
                    locked = VirtualLock(base, LENGTH) != 0;
                }
            }
            // One entry of the 512 Windows allows a process.
            WerRegisterExcludedMemoryBlock(base.cast_const(), LENGTH as u32);
            Some(Area {
                base: base as usize,
                locked,
                taken: Mutex::new(0),
            })
        }
    }

    pub(super) fn locked() -> bool {
        area().is_some_and(|area| area.locked)
    }

    /// A free slot, or `None` when the area is full or couldn't be set aside.
    pub(super) fn take() -> Option<(usize, &'static mut [u8; SLOT_BYTES])> {
        let area = area()?;
        let mut taken = area.taken.lock().unwrap_or_else(PoisonError::into_inner);
        let index = (!*taken).trailing_zeros() as usize;
        if index >= SLOTS {
            return None;
        }
        *taken |= 1 << index;
        // SAFETY: slot `index` lies inside the area, which is never freed, and is handed out
        // to one owner at a time (its bit stays set until `give_back`); the area's pages are
        // committed, readable and writable, and a byte array needs no alignment.
        #[allow(unsafe_code)]
        let bytes = unsafe { &mut *((area.base + index * SLOT_BYTES) as *mut [u8; SLOT_BYTES]) };
        Some((index, bytes))
    }

    /// Slot `index` is free again (its owner wiped it and no longer uses it).
    pub(super) fn give_back(index: usize) {
        if let Some(area) = area() {
            let mut taken = area.taken.lock().unwrap_or_else(PoisonError::into_inner);
            *taken &= !(1 << index);
        }
    }

    /// The area's first byte, for the tests.
    #[cfg(test)]
    pub(super) fn base() -> Option<usize> {
        area().map(|area| area.base)
    }
}

/// Elsewhere secrets stay on the heap (the phone has no pagefile).
#[cfg(not(windows))]
mod area {
    use super::SLOT_BYTES;

    pub(super) fn locked() -> bool {
        false
    }

    pub(super) fn take() -> Option<(usize, &'static mut [u8; SLOT_BYTES])> {
        None
    }

    pub(super) fn give_back(_index: usize) {}
}

/// Hands `vault-core` the key shield of this system (see the module's notes), once, before a
/// vault is opened. Answers whether one is installed. Only Windows has one: elsewhere the
/// keys stay as they are.
pub fn install_key_shield() -> bool {
    shield::install()
}

#[cfg(windows)]
mod shield {
    use vault_core::memory::{KeyShield, install_key_shield, key_shield_installed};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_SAME_PROCESS, CryptProtectMemory,
        CryptUnprotectMemory,
    };

    /// `CryptProtectMemory` takes whole blocks: a key is two.
    const _: () = assert!(32 % CRYPTPROTECTMEMORY_BLOCK_SIZE as usize == 0);

    /// `CryptProtectMemory` with a key the system keeps for this process.
    #[derive(Debug)]
    struct ProcessKeyShield;

    impl KeyShield for ProcessKeyShield {
        fn shield(&self, key: &mut [u8; 32]) -> bool {
            // SAFETY: `key` is 32 writable bytes, a whole number of blocks, encrypted in place.
            #[allow(unsafe_code)]
            unsafe {
                CryptProtectMemory(key.as_mut_ptr().cast(), 32, CRYPTPROTECTMEMORY_SAME_PROCESS)
                    != 0
            }
        }

        fn unshield(&self, key: &mut [u8; 32]) -> bool {
            // SAFETY: as in `shield`, decrypted in place.
            #[allow(unsafe_code)]
            unsafe {
                CryptUnprotectMemory(key.as_mut_ptr().cast(), 32, CRYPTPROTECTMEMORY_SAME_PROCESS)
                    != 0
            }
        }
    }

    static SHIELD: ProcessKeyShield = ProcessKeyShield;

    pub(super) fn install() -> bool {
        if key_shield_installed() {
            return true;
        }
        // A shield that can't give a key back must never hold one: a round trip first.
        let original = [0x5a_u8; 32];
        let mut probe = original;
        let works = SHIELD.shield(&mut probe)
            && probe != original
            && SHIELD.unshield(&mut probe)
            && probe == original;
        works && (install_key_shield(&SHIELD) || key_shield_installed())
    }

    #[cfg(test)]
    pub(super) fn round_trip(key: &mut [u8; 32]) -> (bool, [u8; 32]) {
        let shielded = SHIELD.shield(key);
        let seen = *key;
        (shielded && SHIELD.unshield(key), seen)
    }
}

#[cfg(not(windows))]
mod shield {
    pub(super) fn install() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area_turn() -> std::sync::MutexGuard<'static, ()> {
        AREA_TURN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn slots_are_wiped_and_given_back() {
        let _turn = area_turn();
        let mut slot = SecretSlot::new();
        assert!(slot.iter().all(|&b| b == 0));
        slot[..5].copy_from_slice(b"hello");
        assert_eq!(&slot[..5], b"hello");
        assert!(format!("{slot:?}").ends_with("<redacted>)"));
        drop(slot);
        // More than the area holds: the rest are on the heap, and all work the same.
        let mut many: Vec<SecretSlot> = (0..100).map(|_| SecretSlot::new()).collect();
        for (i, slot) in many.iter_mut().enumerate() {
            slot[0] = i as u8;
        }
        assert!(many.iter().enumerate().all(|(i, slot)| slot[0] == i as u8));
        drop(many);
        // A slot taken again starts as zeros.
        assert!(SecretSlot::new().iter().all(|&b| b == 0));
    }

    /// The area is locked into RAM: Windows says each page of it is resident and locked.
    #[cfg(windows)]
    #[test]
    fn the_area_is_locked_in_ram() {
        use windows_sys::Win32::System::{
            ProcessStatus::{K32QueryWorkingSetEx, PSAPI_WORKING_SET_EX_INFORMATION},
            Threading::GetCurrentProcess,
        };

        let _turn = area_turn();
        let slot = SecretSlot::new();
        assert!(slot.is_locked(), "VirtualLock took the area");
        let base = area::base().unwrap();
        let pages: Vec<PSAPI_WORKING_SET_EX_INFORMATION> = (0..64 * 1024 / 4096)
            .map(|page| {
                // SAFETY: a plain struct; only its address field is set.
                #[allow(unsafe_code)]
                let mut info: PSAPI_WORKING_SET_EX_INFORMATION = unsafe { std::mem::zeroed() };
                info.VirtualAddress = (base + page * 4096) as *mut _;
                info
            })
            .collect();
        let mut pages = pages;
        // SAFETY: `pages` is a writable array of the size passed.
        #[allow(unsafe_code)]
        let asked = unsafe {
            K32QueryWorkingSetEx(
                GetCurrentProcess(),
                pages.as_mut_ptr().cast(),
                u32::try_from(size_of_val(pages.as_slice())).unwrap(),
            )
        };
        assert_ne!(asked, 0);
        for page in &pages {
            // SAFETY: the union's flags, as Windows filled them in.
            #[allow(unsafe_code)]
            let flags = unsafe { page.VirtualAttributes.Flags };
            // Valid is bit 0; Locked is bit 22 (after ShareCount, Win32Protection, Shared
            // and Node).
            assert_eq!(flags & 1, 1, "resident");
            assert_eq!((flags >> 22) & 1, 1, "locked");
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_shield_encrypts_and_gives_back() {
        let original: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mut key = original;
        let (back, seen) = shield::round_trip(&mut key);
        assert!(back);
        assert_ne!(seen, original, "encrypted while shielded");
        assert_eq!(key, original);
        assert!(install_key_shield());
        assert!(vault_core::memory::key_shield_installed());
        assert!(install_key_shield(), "a second call says it is installed");
    }
}
