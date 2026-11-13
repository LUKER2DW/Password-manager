//! Keeping windows out of screenshots and screen recordings.

use raw_window_handle::RawWindowHandle;

/// Excludes the window from screen capture (screenshots, recordings, remote desktop capture,
/// most malware screen grabbers). Returns whether the protection is active.
#[allow(unsafe_code)]
pub fn exclude_from_capture(handle: RawWindowHandle) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE,
        };
        if let RawWindowHandle::Win32(win32) = handle {
            let hwnd = win32.hwnd.get() as *mut core::ffi::c_void;
            // SAFETY: `hwnd` comes from a live window handle provided by the windowing backend,
            // and SetWindowDisplayAffinity only reads it; failure is reported via the return value.
            return unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) != 0 };
        }
        false
    }
    #[cfg(not(windows))]
    {
        let _ = handle;
        false
    }
}
