//! Hardening of the app's own process on Windows, done first thing in `main`.
//!
//! DLL loading: the desktop app is one exe people run from wherever they saved it, Downloads
//! often, and Windows looks for a DLL next to the exe before System32. The linker's
//! `/DEPENDENTLOADFLAG:0x800` (`.cargo/config.toml`, checked by `apps/desktop/check-exe.ps1`)
//! covers the DLLs the exe imports; [`restrict_dll_search`] covers the ones loaded later by
//! name (by Windows itself or a dependency), so a DLL dropped next to the exe is never loaded.

/// From now on, a DLL loaded by name is looked for in System32 only (not next to the exe, not
/// in the current folder, not on `PATH`). Answers whether Windows took it.
pub fn restrict_dll_search() -> bool {
    imp::restrict_dll_search()
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::System::LibraryLoader::{
        LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories, SetDllDirectoryW,
    };

    pub(super) fn restrict_dll_search() -> bool {
        let empty = [0u16];
        // SAFETY: plain calls with a flag and a NUL-terminated (empty) UTF-16 string that
        // outlives the call. The empty string takes the current folder out of the search;
        // SetDefaultDllDirectories then limits every later search to System32.
        #[allow(unsafe_code)]
        unsafe {
            SetDllDirectoryW(empty.as_ptr());
            SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != 0
        }
    }
}

#[cfg(not(windows))]
mod imp {
    /// Elsewhere the loader doesn't look next to the program first.
    pub(super) fn restrict_dll_search() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    /// Taken by Windows, and a system DLL still loads by name afterwards.
    #[cfg(windows)]
    #[test]
    fn system_dlls_still_load() {
        use windows_sys::Win32::{Foundation::FreeLibrary, System::LibraryLoader::LoadLibraryW};

        assert!(super::restrict_dll_search());
        let name: Vec<u16> = "dwmapi.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `name` is a NUL-terminated UTF-16 buffer that outlives the call; the
        // module loaded is freed once.
        #[allow(unsafe_code)]
        unsafe {
            let module = LoadLibraryW(name.as_ptr());
            assert!(!module.is_null(), "found in System32");
            FreeLibrary(module);
        }
    }
}
