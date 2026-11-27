//! The few registry calls the app needs (Windows): text values read anywhere, and values of
//! this user's (`HKEY_CURRENT_USER`) written or removed. Used by the vault file type
//! (`file_types.rs`) and the start at sign-in (`autostart.rs`).

use anyhow::{Result, bail};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND},
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_BINARY, RRF_RT_REG_SZ, RegDeleteKeyValueW,
        RegGetValueW, RegSetKeyValueW,
    },
};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Reads one value of type `kind` into `buffer`; answers the bytes written, or `None` when the
/// key or the value is missing (or of another type, or larger than `buffer`).
fn get(root: HKEY, key: &str, name: Option<&str>, kind: u32, buffer: &mut [u8]) -> Option<usize> {
    let key = wide(key);
    let name = name.map(wide);
    let name_ptr = name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr());
    let mut bytes = u32::try_from(buffer.len()).ok()?;
    // SAFETY: `key` and `name` are NUL-terminated UTF-16 buffers that outlive the call (a null
    // name reads the key's default value); `buffer` has room for `bytes` bytes, and the call
    // writes at most that many and sets `bytes` to what it wrote.
    #[allow(unsafe_code)]
    let status = unsafe {
        RegGetValueW(
            root,
            key.as_ptr(),
            name_ptr,
            kind,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &raw mut bytes,
        )
    };
    (status == 0).then(|| (bytes as usize).min(buffer.len()))
}

/// A text value, or `None` when the key or the value is missing (or not text).
pub(crate) fn read_text(root: HKEY, key: &str, name: Option<&str>) -> Option<String> {
    let mut buffer = vec![0u8; 2048];
    let bytes = get(root, key, name, RRF_RT_REG_SZ, &mut buffer)?;
    let (pairs, _) = buffer[..bytes].as_chunks::<2>();
    let text: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
    Some(String::from_utf16_lossy(&text[..end]))
}

/// A binary value of this user's (at most 256 bytes), or `None` when it is missing.
pub(crate) fn read_bytes(key: &str, name: &str) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; 256];
    let bytes = get(
        HKEY_CURRENT_USER,
        key,
        Some(name),
        RRF_RT_REG_BINARY,
        &mut buffer,
    )?;
    buffer.truncate(bytes);
    Some(buffer)
}

/// Writes a text value of this user's, making the key when it is missing. A `None` name sets
/// the key's default value.
pub(crate) fn write_text(key: &str, name: Option<&str>, data: &str) -> Result<()> {
    let key_w = wide(key);
    let name = name.map(wide);
    let name_ptr = name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr());
    let value = wide(data);
    let Ok(bytes) = u32::try_from(value.len() * 2) else {
        bail!("registry value too long");
    };
    // SAFETY: `key_w`, `name` and `value` are NUL-terminated UTF-16 buffers that outlive the
    // call; `bytes` is the size of `value` in bytes. The call creates the key when it is
    // missing; a null name sets the key's default value.
    #[allow(unsafe_code)]
    let status = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            key_w.as_ptr(),
            name_ptr,
            REG_SZ,
            value.as_ptr().cast(),
            bytes,
        )
    };
    if status != 0 {
        bail!("writing to the registry failed (Windows error {status})");
    }
    Ok(())
}

/// Removes a value of this user's. A value (or key) that isn't there is already removed.
pub(crate) fn delete_value(key: &str, name: &str) -> Result<()> {
    let key = wide(key);
    let name = wide(name);
    // SAFETY: `key` and `name` are NUL-terminated UTF-16 buffers that outlive the call.
    #[allow(unsafe_code)]
    let status = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr()) };
    if status != 0 && status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND {
        bail!("removing a registry value failed (Windows error {status})");
    }
    Ok(())
}

/// Removes a key of this user's with everything under it (tests clean their throwaway keys).
#[cfg(test)]
pub(crate) fn delete_tree(key: &str) {
    use windows_sys::Win32::System::Registry::RegDeleteTreeW;
    let key = wide(key);
    // SAFETY: `key` is a NUL-terminated UTF-16 buffer that outlives the call; the tests only
    // remove the throwaway keys they made.
    #[allow(unsafe_code)]
    unsafe {
        RegDeleteTreeW(HKEY_CURRENT_USER, key.as_ptr());
    }
}
