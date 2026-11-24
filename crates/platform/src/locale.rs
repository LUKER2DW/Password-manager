//! The language the person uses on this computer, for the app's translations, and how far
//! its clock is from UTC, for the times the app shows.

/// The user's display language as a BCP 47 tag (`pt-BR`, `en-US`), when the system says.
pub fn system_language() -> Option<String> {
    imp::system_language().filter(|tag| !tag.is_empty())
}

/// How far this computer's clock is from UTC now, in minutes (-180 for UTC-3), summer time
/// included; 0 when the system doesn't say.
pub fn utc_offset_minutes() -> i32 {
    imp::utc_offset_minutes()
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::{
        Globalization::GetUserDefaultLocaleName,
        System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION},
    };

    /// GetTimeZoneInformation's answer while summer time is on.
    const DAYLIGHT: u32 = 2;
    const INVALID: u32 = u32::MAX;

    pub(super) fn utc_offset_minutes() -> i32 {
        // SAFETY: an all-zero TIME_ZONE_INFORMATION is valid (plain integers and arrays).
        #[allow(unsafe_code)]
        let mut zone: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
        #[allow(unsafe_code)]
        // SAFETY: `zone` is a valid, writable TIME_ZONE_INFORMATION for the call to fill.
        let which = unsafe { GetTimeZoneInformation(&mut zone) };
        if which == INVALID {
            return 0;
        }
        // UTC = local time + bias, in minutes.
        let extra = if which == DAYLIGHT {
            zone.DaylightBias
        } else {
            zone.StandardBias
        };
        -(zone.Bias + extra)
    }

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
    pub(super) fn utc_offset_minutes() -> i32 {
        0
    }

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
