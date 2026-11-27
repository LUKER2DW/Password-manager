//! A key that never leaves this computer's TPM: RSA-2048, made in the chip through NCrypt's
//! "Microsoft Platform Crypto Provider", per Windows user and named per vault, that decrypts
//! (OAEP with SHA-256) without a prompt and can't be exported. The Secret Key's store wraps
//! the key that seals the Secret Key with it (CRYPTO.md §2.2.1, [`crate::secret_store`]).
//!
//! The provider keeps the private key in the user's profile encrypted under the TPM's own
//! storage key, so the file opens nowhere but in this chip: a copied disk or profile doesn't
//! carry it, and clearing or replacing the TPM makes it useless ([`ChipError::Lost`]). A
//! program running as the same user can still ask the chip to decrypt while it runs.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::anyhow;
use zeroize::Zeroizing;

use crate::secret_store::{ChipError, KeyWrapper};

/// This computer's TPM, when NCrypt's Platform Crypto Provider opens and answers.
#[derive(Debug, Default)]
pub struct Tpm {
    /// Making a key failed once in this run (a TPM that refuses RSA keys, one locked out):
    /// it isn't asked again until the program starts anew, so each save doesn't wait for it.
    refused: AtomicBool,
}

impl Tpm {
    /// The TPM, when this computer has one the provider can use.
    pub fn open() -> Option<Self> {
        imp::platform_type().ok().map(|_| Self::default())
    }
}

impl KeyWrapper for Tpm {
    fn create(&self, name: &str) -> Result<(), ChipError> {
        if self.refused.load(Ordering::Relaxed) {
            return Err(ChipError::Failed(anyhow!(
                "the security chip (TPM) refused to make a key earlier"
            )));
        }
        let made = imp::provider().and_then(|provider| imp::create_key(&provider, Some(name)));
        match made {
            Ok(_) => Ok(()),
            Err(status) => {
                self.refused.store(true, Ordering::Relaxed);
                Err(imp::error(status))
            }
        }
    }

    fn wrap(&self, name: &str, label: &[u8], data: &[u8]) -> Result<Vec<u8>, ChipError> {
        let provider = imp::provider().map_err(imp::error)?;
        let key = imp::open_key(&provider, name).map_err(imp::error)?;
        imp::encrypt(&key, label, data).map_err(imp::error)
    }

    fn unwrap(
        &self,
        name: &str,
        label: &[u8],
        wrapped: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChipError> {
        let provider = imp::provider().map_err(imp::error)?;
        let key = imp::open_key(&provider, name).map_err(imp::error)?;
        imp::decrypt(&key, label, wrapped).map_err(imp::error)
    }

    fn delete(&self, name: &str) -> Result<bool, ChipError> {
        let provider = imp::provider().map_err(imp::error)?;
        imp::delete_key(&provider, name).map_err(imp::error)
    }
}

mod imp {
    use anyhow::anyhow;
    use windows_sys::{
        Win32::Foundation::{
            NTE_BAD_DATA, NTE_BAD_KEY, NTE_BAD_KEYSET, NTE_NO_KEY, NTE_NOT_FOUND,
            TPM_E_PCP_KEY_HANDLE_INVALIDATED, TPM_E_PCP_WRONG_PARENT,
        },
        Win32::Security::Cryptography::{
            BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
            MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_KEY_USAGE_PROPERTY,
            NCRYPT_LENGTH_PROPERTY, NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PAD_OAEP_FLAG,
            NCRYPT_PCP_PLATFORM_TYPE_PROPERTY, NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey,
            NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey, NCryptFreeObject,
            NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
        },
        core::HRESULT,
    };
    use zeroize::Zeroizing;

    use crate::secret_store::ChipError;

    /// The key's size: one RSA-2048 block is what it encrypts to.
    const BITS: u32 = 2048;
    const BLOCK: usize = (BITS / 8) as usize;

    /// An NCrypt provider or key handle, freed once when dropped.
    pub(super) struct Object(usize);

    impl Drop for Object {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: the handle came from NCrypt, is still open (nothing else frees it:
            // `delete_key` forgets the object it hands to NCryptDeleteKey) and is freed once.
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn check(status: HRESULT) -> Result<(), HRESULT> {
        if status == 0 { Ok(()) } else { Err(status) }
    }

    /// Whether a failure says the key is gone for good: missing, made under another chip
    /// (cleared, reset by a firmware update, replaced) or not the one the data was wrapped to.
    /// Anything else may pass (the chip busy, its service starting) and keeps what is stored.
    pub(super) fn lost(status: HRESULT) -> bool {
        // TPM 2.0 answers, as NCrypt passes them on: 0x80280000 + the response code. Format-1
        // codes (bit 7) carry a parameter number in their upper bits; the low six bits name it.
        // VALUE is what a decryption that doesn't open under this key gets (0x80280084 here,
        // for data another key wrapped or a changed byte); KEY and INTEGRITY, a key blob the
        // chip's storage key no longer opens.
        const TPM_20: u32 = 0x8028_0000;
        const FORMAT_1: u32 = 0x080;
        const RC_VALUE: u32 = 0x004;
        const RC_KEY: u32 = 0x01C;
        const RC_INTEGRITY: u32 = 0x01F;
        let code = status as u32;
        let tpm_lost = code & 0xFFFF_F000 == TPM_20
            && code & FORMAT_1 != 0
            && matches!(code & 0x03F, RC_VALUE | RC_KEY | RC_INTEGRITY);
        tpm_lost
            || matches!(
                status,
                NTE_BAD_KEYSET
                    | NTE_NO_KEY
                    | NTE_NOT_FOUND
                    | NTE_BAD_KEY
                    | NTE_BAD_DATA
                    | TPM_E_PCP_WRONG_PARENT
                    | TPM_E_PCP_KEY_HANDLE_INVALIDATED
            )
    }

    pub(super) fn error(status: HRESULT) -> ChipError {
        if lost(status) {
            ChipError::Lost
        } else {
            ChipError::Failed(anyhow!(
                "the security chip (TPM) didn't answer (error 0x{:08X})",
                status as u32
            ))
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn provider() -> Result<Object, HRESULT> {
        let mut handle = 0;
        // SAFETY: `handle` is a valid out-pointer; the provider name is a static wide string.
        check(unsafe { NCryptOpenStorageProvider(&mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0) })?;
        Ok(Object(handle))
    }

    /// The provider's description of the chip; fails where there is no TPM it can use.
    #[allow(unsafe_code)]
    pub(super) fn platform_type() -> Result<String, HRESULT> {
        let provider = provider()?;
        let mut out = [0u16; 256];
        let mut written = 0u32;
        // SAFETY: `out` is writable for its whole size in bytes, `written` a valid
        // out-pointer, and the property name a static wide string.
        check(unsafe {
            NCryptGetProperty(
                provider.0,
                NCRYPT_PCP_PLATFORM_TYPE_PROPERTY,
                out.as_mut_ptr().cast(),
                std::mem::size_of_val(&out) as u32,
                &mut written,
                0,
            )
        })?;
        let chars = (written as usize / 2).min(out.len());
        let text = String::from_utf16_lossy(&out[..chars]);
        Ok(text.trim_end_matches('\0').to_owned())
    }

    #[allow(unsafe_code)]
    pub(super) fn open_key(provider: &Object, name: &str) -> Result<Object, HRESULT> {
        let name = wide(name);
        let mut key = 0;
        // SAFETY: `provider` is an open provider handle, `name` a NUL-terminated wide string
        // alive for the call, `key` a valid out-pointer.
        check(unsafe {
            NCryptOpenKey(provider.0, &mut key, name.as_ptr(), 0, NCRYPT_SILENT_FLAG)
        })?;
        Ok(Object(key))
    }

    /// Makes the key `name` in the chip, replacing one of that name; `None` makes one that
    /// lives only as long as its handle (the tests' keys, which leave nothing behind).
    #[allow(unsafe_code)]
    pub(super) fn create_key(provider: &Object, name: Option<&str>) -> Result<Object, HRESULT> {
        let name = name.map(wide);
        let name_ptr = name.as_ref().map_or(std::ptr::null(), |name| name.as_ptr());
        let mut handle = 0;
        // SAFETY: `provider` is open, the algorithm id a static wide string, `name_ptr` null
        // or a NUL-terminated wide string alive for the call, `handle` a valid out-pointer.
        check(unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut handle,
                BCRYPT_RSA_ALGORITHM,
                name_ptr,
                0,
                if name.is_some() {
                    NCRYPT_OVERWRITE_KEY_FLAG
                } else {
                    0
                },
            )
        })?;
        let key = Object(handle);
        let set = |property, value: u32| {
            let bytes = value.to_le_bytes();
            // SAFETY: `key` is a key handle not yet finalized; `bytes` is the property's
            // 4-byte value, alive for the call; the property name is a static wide string.
            check(unsafe { NCryptSetProperty(key.0, property, bytes.as_ptr(), 4, 0) })
        };
        set(NCRYPT_LENGTH_PROPERTY, BITS)?;
        // Decrypting is all it is for: no signing. The export policy is left at none.
        set(NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_DECRYPT_FLAG)?;
        // SAFETY: `key` is the handle just made; finalizing generates the key in the chip.
        check(unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) })?;
        Ok(key)
    }

    fn padding(label: &[u8]) -> BCRYPT_OAEP_PADDING_INFO {
        BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            // NCrypt only reads the label.
            pbLabel: label.as_ptr().cast_mut(),
            cbLabel: label.len() as u32,
        }
    }

    /// RSA-OAEP with SHA-256 to the key's public half (done by the provider, in software).
    #[allow(unsafe_code)]
    pub(super) fn encrypt(key: &Object, label: &[u8], data: &[u8]) -> Result<Vec<u8>, HRESULT> {
        let padding = padding(label);
        let mut out = vec![0u8; BLOCK];
        let mut written = 0u32;
        // SAFETY: `key` is an open key handle; `data`, `padding` (and the label it points at)
        // and `out` are alive for the call, `out` writable for its length; `written` is a
        // valid out-pointer.
        check(unsafe {
            NCryptEncrypt(
                key.0,
                data.as_ptr(),
                data.len() as u32,
                std::ptr::from_ref(&padding).cast(),
                out.as_mut_ptr(),
                out.len() as u32,
                &mut written,
                NCRYPT_PAD_OAEP_FLAG,
            )
        })?;
        out.truncate(written as usize);
        Ok(out)
    }

    /// Decrypts in the chip, without a prompt.
    #[allow(unsafe_code)]
    pub(super) fn decrypt(
        key: &Object,
        label: &[u8],
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, HRESULT> {
        let padding = padding(label);
        let mut out = Zeroizing::new(vec![0u8; BLOCK]);
        let mut written = 0u32;
        // SAFETY: as in `encrypt`; `out` is the zeroized buffer the result goes to.
        check(unsafe {
            NCryptDecrypt(
                key.0,
                data.as_ptr(),
                data.len() as u32,
                std::ptr::from_ref(&padding).cast(),
                out.as_mut_ptr(),
                out.len() as u32,
                &mut written,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        })?;
        out.truncate(written as usize);
        Ok(out)
    }

    /// Deletes the key `name`; whether there was one.
    #[allow(unsafe_code)]
    pub(super) fn delete_key(provider: &Object, name: &str) -> Result<bool, HRESULT> {
        let key = match open_key(provider, name) {
            Ok(key) => key,
            Err(NTE_BAD_KEYSET | NTE_NOT_FOUND) => return Ok(false),
            Err(status) => return Err(status),
        };
        // SAFETY: `key` is an open key handle. On success NCryptDeleteKey frees it, so the
        // object is forgotten instead of dropped; on failure it stays ours and is dropped.
        // No flags: the provider refuses the silent one here (NTE_BAD_FLAGS), and deleting
        // a key without a UI policy never prompts.
        let status = unsafe { NCryptDeleteKey(key.0, 0) };
        if status == 0 {
            std::mem::forget(key);
        }
        check(status).map(|()| true)
    }

    #[cfg(test)]
    pub(super) mod tests_support {
        use super::*;
        use windows_sys::Win32::Security::Cryptography::{
            BCRYPT_RSAFULLPRIVATE_BLOB, NCryptExportKey,
        };

        /// Tries to export the private half; returns the status (it must fail).
        #[allow(unsafe_code)]
        pub fn export_private(key: &Object) -> HRESULT {
            let mut out = vec![0u8; 4096];
            let mut written = 0u32;
            // SAFETY: `key` is open, `out` writable for its length, `written` a valid
            // out-pointer; no parameter list.
            unsafe {
                NCryptExportKey(
                    key.0,
                    0,
                    BCRYPT_RSAFULLPRIVATE_BLOB,
                    std::ptr::null(),
                    out.as_mut_ptr(),
                    out.len() as u32,
                    &mut written,
                    0,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    /// The chip, unless this machine has none or the tests run in CI (whose machines may
    /// have a virtual one that is slow or shared): those skip, saying so.
    fn chip() -> Option<imp::Object> {
        if std::env::var_os("CI").is_some() {
            eprintln!("skipped: no TPM tests in CI");
            return None;
        }
        match imp::platform_type() {
            Ok(kind) => {
                eprintln!("TPM: {kind}");
                imp::provider().ok()
            }
            Err(status) => {
                eprintln!("skipped: no TPM here (0x{:08X})", status as u32);
                None
            }
        }
    }

    #[test]
    fn ephemeral_key_wraps_in_the_chip_and_never_leaves_it() {
        let Some(provider) = chip() else { return };
        let started = Instant::now();
        let key = imp::create_key(&provider, None).expect("an RSA key made in the TPM");
        eprintln!("key made in the TPM in {:?}", started.elapsed());

        let label = vault_core::kept_key::WRAP_LABEL;
        let secret = [0x5Au8; 32];
        let started = Instant::now();
        let wrapped = imp::encrypt(&key, label, &secret).unwrap();
        eprintln!("wrapped in {:?}", started.elapsed());
        assert_eq!(wrapped.len(), 256);
        let started = Instant::now();
        let unwrapped = imp::decrypt(&key, label, &wrapped).unwrap();
        eprintln!("unwrapped in the TPM in {:?}", started.elapsed());
        assert_eq!(unwrapped.as_slice(), secret);

        // Bound to its label and to every byte: refused, and for good.
        let refused = imp::decrypt(&key, b"vault-v0/another-label\0", &wrapped).unwrap_err();
        eprintln!("another label: 0x{:08X}", refused as u32);
        assert!(imp::lost(refused), "0x{:08X}", refused as u32);
        let mut changed = wrapped.clone();
        changed[100] ^= 1;
        let refused = imp::decrypt(&key, label, &changed).unwrap_err();
        eprintln!("a changed byte: 0x{:08X}", refused as u32);
        assert!(imp::lost(refused), "0x{:08X}", refused as u32);

        // Why the label is short and ends in a zero (CRYPTO.md §2.2.1): what this chip takes.
        for (size, zero) in [(28, true), (28, false), (34, true), (48, true)] {
            let mut probe = vec![b'a'; size];
            if zero {
                probe[size - 1] = 0;
            }
            let wrapped = imp::encrypt(&key, &probe, &secret).unwrap();
            let answer = imp::decrypt(&key, &probe, &wrapped);
            eprintln!(
                "a label of {size} bytes{}: {}",
                if zero { " ending in zero" } else { "" },
                answer.map_or_else(
                    |s| format!("refused, 0x{:08X}", s as u32),
                    |_| "taken".into()
                )
            );
        }

        // The private half can't be taken out.
        let status = imp::tests_support::export_private(&key);
        eprintln!("export: 0x{:08X}", status as u32);
        assert_ne!(status, 0);
    }

    #[test]
    fn named_key_is_found_replaced_and_deleted() {
        let Some(_provider) = chip() else { return };
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).unwrap();
        let name = format!("vault-secret-key-test-{:016x}", u64::from_le_bytes(random));
        struct Delete<'a>(&'a str);
        impl Drop for Delete<'_> {
            fn drop(&mut self) {
                let _ = Tpm::default().delete(self.0);
            }
        }
        let _cleanup = Delete(&name);
        let tpm = Tpm::open().unwrap();
        let label = vault_core::kept_key::WRAP_LABEL;

        assert!(matches!(
            tpm.wrap(&name, label, &[1; 32]),
            Err(ChipError::Lost)
        ));
        let started = Instant::now();
        tpm.create(&name).unwrap();
        eprintln!("named key made in the TPM in {:?}", started.elapsed());
        let wrapped = tpm.wrap(&name, label, &[1; 32]).unwrap();
        let started = Instant::now();
        assert_eq!(
            tpm.unwrap(&name, label, &wrapped).unwrap().as_slice(),
            [1; 32]
        );
        eprintln!("opened by name and unwrapped in {:?}", started.elapsed());

        // Made again under the same name: what the old key wrapped no longer opens.
        tpm.create(&name).unwrap();
        let answer = tpm.unwrap(&name, label, &wrapped);
        assert!(matches!(answer, Err(ChipError::Lost)), "{answer:?}");
        assert!(tpm.delete(&name).unwrap());
        assert!(!tpm.delete(&name).unwrap());
        assert!(matches!(
            tpm.unwrap(&name, label, &wrapped),
            Err(ChipError::Lost)
        ));
    }
}
