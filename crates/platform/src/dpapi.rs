//! Windows DPAPI: data protected for the signed-in Windows user. Undone when the user imports
//! from a browser (Chromium protects the key to its saved passwords this way); used to keep
//! what the browser extension's link needs while the vault is locked (never a password).

use zeroize::Zeroizing;

/// Protects `data` for the current Windows user (`CryptProtectData`). `None` on failure or
/// off Windows.
pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
    imp::protect(data)
}

/// Decrypts `data` protected with `CryptProtectData` for the current Windows user.
/// `None` on any failure (other user, corrupted data, not on Windows).
pub fn unprotect(data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    imp::unprotect(data)
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    };
    use zeroize::{Zeroize, Zeroizing};

    #[allow(unsafe_code)]
    pub(super) fn protect(data: &[u8]) -> Option<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(data.len()).ok()?,
            pbData: data.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: `input` points at `data`, alive for the whole call; the API only reads it.
        // Null is allowed for the description, entropy, reserved and prompt parameters.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 || output.pbData.is_null() {
            return None;
        }
        // SAFETY: on success the API returns `cbData` valid bytes at `pbData`, allocated with
        // LocalAlloc; they are copied, then freed exactly once.
        unsafe {
            let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(output.pbData.cast());
            Some(bytes)
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn unprotect(data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(data.len()).ok()?,
            pbData: data.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: `input` points at `data`, alive for the whole call; the API only reads it.
        // Null is allowed for the description, entropy, reserved and prompt parameters.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                &mut output,
            )
        };
        if ok == 0 || output.pbData.is_null() {
            return None;
        }
        // SAFETY: on success the API returns `cbData` valid bytes at `pbData`, allocated with
        // LocalAlloc; they are copied, wiped, then freed exactly once.
        unsafe {
            let bytes = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
            let copy = Zeroizing::new(bytes.to_vec());
            bytes.zeroize();
            LocalFree(output.pbData.cast());
            Some(copy)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn protect_and_unprotect() {
            let sealed = protect(b"pairing key").unwrap();
            assert_ne!(sealed.as_slice(), b"pairing key");
            assert_eq!(unprotect(&sealed).unwrap().as_slice(), b"pairing key");
        }

        #[test]
        #[allow(unsafe_code)]
        fn round_trip() {
            let secret = b"browser key";
            let input = CRYPT_INTEGER_BLOB {
                cbData: secret.len() as u32,
                pbData: secret.as_ptr().cast_mut(),
            };
            let mut output = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            // SAFETY: as in `unprotect`; test only.
            let protected = unsafe {
                assert_ne!(
                    CryptProtectData(
                        &input,
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        std::ptr::null(),
                        0,
                        &mut output,
                    ),
                    0
                );
                let copy =
                    std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
                LocalFree(output.pbData.cast());
                copy
            };
            assert_eq!(unprotect(&protected).unwrap().as_slice(), secret);
            assert!(unprotect(b"not protected").is_none());
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub(super) fn protect(_data: &[u8]) -> Option<Vec<u8>> {
        None
    }

    pub(super) fn unprotect(_data: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        None
    }
}
