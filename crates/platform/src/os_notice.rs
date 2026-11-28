//! A notification from Windows itself (a balloon, which Windows 10 and 11 show as a toast and
//! keep in the notification centre): for what can't wait for the person to look at the app,
//! such as passwords the leak watch just found in a breach. It carries only counts and where
//! to look, never an item's name or a secret: the notification centre keeps it after the vault
//! locks.

use raw_window_handle::RawWindowHandle;

/// Shows `title` and `text` from the window `handle`, as a warning. Answers whether Windows
/// took it. The icon it needs beside the clock goes away again after a moment.
pub fn show(handle: RawWindowHandle, title: &str, text: &str) -> bool {
    match handle {
        RawWindowHandle::Win32(win32) => imp::show(win32.hwnd.get(), title, text),
        _ => false,
    }
}

/// `text` as a NUL-terminated UTF-16 buffer of `N`, cut to fit.
pub fn wide<const N: usize>(text: &str) -> [u16; N] {
    let mut out = [0u16; N];
    for (slot, unit) in out.iter_mut().zip(text.encode_utf16().take(N - 1)) {
        *slot = unit;
    }
    out
}

#[cfg(windows)]
mod imp {
    use std::time::Duration;

    use windows_sys::Win32::UI::{
        Shell::{
            NIF_ICON, NIF_INFO, NIF_TIP, NIIF_WARNING, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
            Shell_NotifyIconW,
        },
        WindowsAndMessaging::{IDI_WARNING, LoadIconW},
    };

    use super::wide;

    /// The id of this icon of the window's (the tray icon has its own window).
    const ICON_ID: u32 = 0x5641;
    /// How long the icon stays beside the clock (Windows keeps the notification itself).
    const SHOWN_FOR: Duration = Duration::from_secs(12);

    pub(super) fn show(hwnd: isize, title: &str, text: &str) -> bool {
        // SAFETY: a stock icon of the system's, loaded by its id; null on failure, which
        // Shell_NotifyIconW accepts.
        #[allow(unsafe_code)]
        let icon = unsafe { LoadIconW(std::ptr::null_mut(), IDI_WARNING) };
        // SAFETY: NOTIFYICONDATAW is plain data; all zeros is a valid empty value.
        #[allow(unsafe_code)]
        let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        data.cbSize = u32::try_from(std::mem::size_of::<NOTIFYICONDATAW>()).unwrap_or(0);
        data.hWnd = hwnd as _;
        data.uID = ICON_ID;
        data.uFlags = NIF_ICON | NIF_INFO | NIF_TIP;
        data.hIcon = icon;
        data.szTip = wide(title);
        data.szInfoTitle = wide(title);
        data.szInfo = wide(text);
        data.dwInfoFlags = NIIF_WARNING;
        // SAFETY: `data` is a filled NOTIFYICONDATAW with its size set, alive for the call.
        #[allow(unsafe_code)]
        let added = unsafe { Shell_NotifyIconW(NIM_ADD, &data) } != 0;
        if added {
            let handle = hwnd;
            std::thread::spawn(move || {
                std::thread::sleep(SHOWN_FOR);
                // SAFETY: as above; NIM_DELETE needs only the window and the id.
                #[allow(unsafe_code)]
                let mut gone: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
                gone.cbSize = u32::try_from(std::mem::size_of::<NOTIFYICONDATAW>()).unwrap_or(0);
                gone.hWnd = handle as _;
                gone.uID = ICON_ID;
                // SAFETY: `gone` is alive for the call.
                #[allow(unsafe_code)]
                unsafe {
                    Shell_NotifyIconW(NIM_DELETE, &gone);
                }
            });
        }
        added
    }
}

#[cfg(not(windows))]
mod imp {
    /// Only Windows for now.
    pub(super) fn show(_hwnd: isize, _title: &str, _text: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::wide;

    #[test]
    fn texts_are_cut_to_fit_and_end_in_nul() {
        let short: [u16; 8] = wide("abc");
        assert_eq!(&short[..4], &[97, 98, 99, 0]);
        let long: [u16; 4] = wide("abcdef");
        assert_eq!(long, [97, 98, 99, 0]);
    }
}
