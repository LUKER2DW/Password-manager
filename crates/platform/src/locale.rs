//! The language the person uses on this computer, for the app's translations.

/// The user's display language as a BCP 47 tag (`pt-BR`, `en-US`), when the system says.
pub fn system_language() -> Option<String> {
    imp::system_language().filter(|tag| !tag.is_empty())
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;

    /// LOCALE_NAME_MAX_LENGTH.
    const MAX: usize = 85;

    pub(super) fn system_language() -> Option<String> {
        let mut buffer = [0u16; MAX];
        #[allow(unsafe_code)]
        // SAFETY: the buffer is valid for MAX UTF-16 units, as the length passed says; the
        // call writes at most that many and returns how many (with the final NUL), or 0.
        let written = unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), MAX as i32) };
        let len = usize::try_from(written).ok()?.checked_sub(1)?;
        String::from_utf16(&buffer[..len]).ok()
    }
}

#[cfg(not(windows))]
mod imp {
    pub(super) fn system_language() -> Option<String> {
        // `pt_BR.UTF-8` → `pt-BR`.
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|name| std::env::var(name).ok())
            .find(|value| !value.is_empty() && value != "C" && value != "POSIX")
            .map(|value| {
                value
                    .split(['.', '@'])
                    .next()
                    .unwrap_or_default()
                    .replace('_', "-")
            })
    }
}
