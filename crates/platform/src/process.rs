//! Hardening of the app's own process on Windows, done first thing in `main`.
//!
//! DLL loading: the desktop app is one exe people run from wherever they saved it, Downloads
//! often, and Windows looks for a DLL next to the exe before System32. The linker's
//! `/DEPENDENTLOADFLAG:0x800` (`.cargo/config.toml`, checked by `apps/desktop/check-exe.ps1`)
//! covers the DLLs the exe imports; [`restrict_dll_search`] covers the ones loaded later by
//! name (by Windows itself or a dependency), so a DLL dropped next to the exe is never loaded.
//!
//! Memory: [`protect_memory`] gives the process, and each of its threads, an access list that
//! lets other programs of the same user only see that it runs, wait for it and end it: not
//! read or write its memory, start a thread in it, take its handles, steer its threads or
//! change that list. An "OWNER RIGHTS" entry takes from the owner the right to rewrite the list
//! that owners otherwise always keep (a list without it is undone in two calls). Threads get
//! their list from a TLS callback as they start, and from a sweep now and then for the few
//! started without one. It doesn't stop the program that started the app (it keeps the
//! handle it was given), an administrator, or a hook aimed at the window's thread.
//!
//! [`apply_mitigations`]: DLLs from a network share or a low-integrity folder refused, System32
//! preferred, the legacy extension points (AppInit DLLs, global hooks' DLLs, legacy input
//! methods) closed when no legacy input method is installed, the heap ended on corruption, and
//! crash reports without the heap's contents. Policies that break GPU drivers, screen readers
//! or shell extensions (signed images only, no dynamic code) are left alone.

/// From now on, a DLL loaded by name is looked for in System32 only (not next to the exe, not
/// in the current folder, not on `PATH`). Answers whether Windows took it.
pub fn restrict_dll_search() -> bool {
    imp::restrict_dll_search()
}

/// Closes the process's memory and threads to other programs of the same user (see the
/// module's notes). Answers whether Windows took the process's list. Release builds only: a
/// debugger can't attach afterwards.
pub fn protect_memory() -> bool {
    imp::protect_memory()
}

/// Turns on the mitigation policies that leave the app's own features working (see the
/// module's notes). Best effort: a policy Windows refuses is skipped.
pub fn apply_mitigations() {
    imp::apply_mitigations();
}

#[cfg(windows)]
mod imp {
    use std::{
        ffi::c_void,
        sync::{
            OnceLock,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce,
            Authorization::{SE_KERNEL_OBJECT, SetSecurityInfo},
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetLengthSid, GetTokenInformation,
            InitializeAcl, PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_MAX_SID_SIZE, TOKEN_QUERY,
            TOKEN_USER, TokenUser, WinCreatorOwnerRightsSid,
        },
        Storage::FileSystem::{READ_CONTROL, SYNCHRONIZE, WRITE_DAC},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            ErrorReporting::{WER_FAULT_REPORTING_FLAG_NOHEAP, WerSetFlags},
            LibraryLoader::{
                LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories, SetDllDirectoryW,
            },
            Memory::{HeapEnableTerminationOnCorruption, HeapSetInformation},
            Threading::{
                GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, OpenProcessToken,
                OpenThread, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
                ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
                SetProcessMitigationPolicy, THREAD_QUERY_LIMITED_INFORMATION,
            },
        },
        UI::Input::{
            Ime::ImmGetIMEFileNameW,
            KeyboardAndMouse::{GetKeyboardLayoutList, HKL},
        },
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

    /// What other programs of this user may do to the process: wait for it, see that it runs
    /// (and its exe's path: the browser extension's link checks it), end it.
    const PROCESS_ALLOWED: u32 =
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE;
    /// And to each of its threads: wait for it, see that it runs.
    const THREAD_ALLOWED: u32 = SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION;
    /// DLL_THREAD_ATTACH: a thread starts.
    const THREAD_STARTS: u32 = 2;

    /// The threads' access list, made once (the TLS callback runs under the loader's lock and
    /// only applies it). Kept as `u32`s for the ACL's alignment.
    static THREAD_LIST: OnceLock<Vec<u32>> = OnceLock::new();
    /// Set once the process is protected: from then on each new thread protects itself.
    static PROTECTING: AtomicBool = AtomicBool::new(false);

    /// Called by Windows for each thread that starts (and in the other DLL_* cases, ignored).
    /// A safe function: the loader only ever passes it the module, a reason and a reserved
    /// pointer, none of which it reads but the reason.
    extern "system" fn on_thread(_module: *mut c_void, reason: u32, _reserved: *mut c_void) {
        if reason == THREAD_STARTS
            && PROTECTING.load(Ordering::Acquire)
            && let Some(list) = THREAD_LIST.get()
        {
            // SAFETY: GetCurrentThread is a pseudo-handle to this very thread; `list` is a
            // valid ACL that lives for the rest of the process.
            #[allow(unsafe_code)]
            unsafe {
                apply_list(GetCurrentThread(), list);
            }
        }
    }

    /// The TLS callback: the CRT's table of them runs from `.CRT$XLA` to `.CRT$XLZ`, and Rust's
    /// own sits at `.CRT$XLB`. `#[used]` keeps it in its object file, and `protect_memory`
    /// reads it so that object file is linked in.
    // SAFETY: the section holds only this pointer to a function of the callback's signature.
    #[allow(unsafe_code)]
    #[used]
    #[unsafe(link_section = ".CRT$XLY")]
    static TLS_CALLBACK: extern "system" fn(*mut c_void, u32, *mut c_void) = on_thread;

    /// Builds an access list: `allowed` for this process's user, and only READ_CONTROL for
    /// OWNER RIGHTS (so the owner can't rewrite the list). `None` if Windows refused a step.
    fn access_list(allowed: u32) -> Option<Vec<u32>> {
        // SAFETY: every buffer handed over is sized as the call asks (the token's user in a
        // buffer of the length GetTokenInformation reported, the well-known SID in
        // SECURITY_MAX_SID_SIZE bytes, the ACL in `size` bytes rounded up to u32s); the user's
        // SID points into `user`, alive until the ACL is built (AddAccessAllowedAce copies it);
        // the token handle is closed once.
        #[allow(unsafe_code)]
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) == 0 {
                return None;
            }
            let mut length = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &raw mut length);
            let mut user = vec![0u64; (length as usize).div_ceil(8).max(1)];
            let read = GetTokenInformation(
                token,
                TokenUser,
                user.as_mut_ptr().cast(),
                length,
                &raw mut length,
            );
            CloseHandle(token);
            if read == 0 {
                return None;
            }
            let user_sid = (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            let mut owner = [0u32; SECURITY_MAX_SID_SIZE as usize / 4];
            let mut owner_length = SECURITY_MAX_SID_SIZE;
            if CreateWellKnownSid(
                WinCreatorOwnerRightsSid,
                std::ptr::null_mut(),
                owner.as_mut_ptr().cast(),
                &raw mut owner_length,
            ) == 0
            {
                return None;
            }
            // Each entry's `SidStart` is the SID's first four bytes.
            let entry = u32::try_from(size_of::<ACCESS_ALLOWED_ACE>()).ok()? - 4;
            let size = u32::try_from(size_of::<ACL>()).ok()?
                + entry
                + GetLengthSid(user_sid)
                + entry
                + GetLengthSid(owner.as_mut_ptr().cast());
            let mut list = vec![0u32; (size as usize).div_ceil(4)];
            let acl = list.as_mut_ptr().cast::<ACL>();
            if InitializeAcl(acl, size, ACL_REVISION) == 0
                || AddAccessAllowedAce(acl, ACL_REVISION, allowed, user_sid) == 0
                || AddAccessAllowedAce(acl, ACL_REVISION, READ_CONTROL, owner.as_mut_ptr().cast())
                    == 0
            {
                return None;
            }
            Some(list)
        }
    }

    /// Puts `list` on the kernel object `handle`, replacing what it inherited. Answers whether
    /// Windows took it.
    ///
    /// # Safety
    /// `handle` must be a process or thread handle with WRITE_DAC (or a pseudo-handle), and
    /// `list` a valid ACL.
    #[allow(unsafe_code)]
    unsafe fn apply_list(handle: HANDLE, list: &[u32]) -> bool {
        // SAFETY: per the function's contract; no owner, group or SACL is changed.
        unsafe {
            SetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                list.as_ptr().cast::<ACL>(),
                std::ptr::null(),
            ) == 0
        }
    }

    /// Gives every thread of this process that doesn't have it yet the threads' list. A thread
    /// still has its old list when this process can open it with WRITE_DAC.
    fn sweep_threads(list: &[u32]) {
        // SAFETY: the snapshot and each thread handle are closed once; THREADENTRY32 is sized
        // as Thread32First requires; `apply_list` gets a handle opened with WRITE_DAC.
        #[allow(unsafe_code)]
        unsafe {
            let me = GetCurrentProcessId();
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
                return;
            }
            let mut thread: THREADENTRY32 = std::mem::zeroed();
            thread.dwSize = u32::try_from(size_of::<THREADENTRY32>()).unwrap_or(0);
            let mut more = Thread32First(snapshot, &raw mut thread) != 0;
            while more {
                if thread.th32OwnerProcessID == me {
                    let handle = OpenThread(WRITE_DAC, 0, thread.th32ThreadID);
                    if !handle.is_null() {
                        apply_list(handle, list);
                        CloseHandle(handle);
                    }
                }
                more = Thread32Next(snapshot, &raw mut thread) != 0;
            }
            CloseHandle(snapshot);
        }
    }

    pub(super) fn protect_memory() -> bool {
        // Keeps the TLS callback's object file in the program (see TLS_CALLBACK).
        // SAFETY: a plain read of a static that is always initialised.
        #[allow(unsafe_code)]
        let _ = unsafe { std::ptr::read_volatile(&raw const TLS_CALLBACK) };
        let (Some(process_list), Some(thread_list)) =
            (access_list(PROCESS_ALLOWED), access_list(THREAD_ALLOWED))
        else {
            return false;
        };
        // SAFETY: GetCurrentProcess is a pseudo-handle with every right; the list is valid.
        #[allow(unsafe_code)]
        let closed = unsafe { apply_list(GetCurrentProcess(), &process_list) };
        let thread_list = THREAD_LIST.get_or_init(|| thread_list);
        PROTECTING.store(true, Ordering::Release);
        sweep_threads(thread_list);
        // Threads started without the TLS callback (some of the loader's and the thread
        // pool's) are caught by later sweeps: soon after start, then every minute.
        let _ = std::thread::Builder::new()
            .name("thread-guard".into())
            .spawn(move || {
                for wait in [500, 2_000, 10_000, 30_000] {
                    std::thread::sleep(Duration::from_millis(wait));
                    sweep_threads(thread_list);
                }
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                    sweep_threads(thread_list);
                }
            });
        closed
    }

    /// Whether a legacy (IMM32) input method is installed: closing the extension points would
    /// cut it off, so they stay open then (as Chrome decides).
    fn legacy_input_method() -> bool {
        // SAFETY: the list is sized from the first call's count; each HKL is only passed back
        // to ImmGetIMEFileNameW with a null buffer, which asks for a length.
        #[allow(unsafe_code)]
        unsafe {
            let count = GetKeyboardLayoutList(0, std::ptr::null_mut());
            let Ok(length) = usize::try_from(count) else {
                return true;
            };
            let mut layouts: Vec<HKL> = vec![std::ptr::null_mut(); length];
            let read = GetKeyboardLayoutList(count, layouts.as_mut_ptr());
            layouts.truncate(usize::try_from(read).unwrap_or(0));
            layouts
                .iter()
                .any(|&layout| ImmGetIMEFileNameW(layout, std::ptr::null_mut(), 0) != 0)
        }
    }

    pub(super) fn apply_mitigations() {
        // ProcessImageLoadPolicy: no images from a remote share, none with a low integrity
        // label, System32 first. ProcessExtensionPointDisablePolicy: the legacy extension
        // points closed. (Locals: the calls take their address.)
        let image_load: u32 = 0b111;
        let extension_points: u32 = 1;
        let closing_extension_points = !legacy_input_method();
        // SAFETY: each policy's structure is one u32 of flags, passed with its size; the heap
        // call takes no buffer; WerSetFlags takes flags only.
        #[allow(unsafe_code)]
        unsafe {
            SetProcessMitigationPolicy(
                ProcessImageLoadPolicy,
                (&raw const image_load).cast(),
                size_of::<u32>(),
            );
            if closing_extension_points {
                SetProcessMitigationPolicy(
                    ProcessExtensionPointDisablePolicy,
                    (&raw const extension_points).cast(),
                    size_of::<u32>(),
                );
            }
            HeapSetInformation(
                std::ptr::null_mut(),
                HeapEnableTerminationOnCorruption,
                std::ptr::null(),
                0,
            );
            WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
        }
    }
}

#[cfg(not(windows))]
mod imp {
    /// Elsewhere the loader doesn't look next to the program first.
    pub(super) fn restrict_dll_search() -> bool {
        true
    }

    /// Only the Windows app does this for now.
    pub(super) fn protect_memory() -> bool {
        false
    }

    pub(super) fn apply_mitigations() {}
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

    /// A protected process (this test again, as a process of its own) can't be read, written,
    /// steered or opened up again by another program of the same user, which still sees it run
    /// and its path; a thread it starts afterwards is closed too.
    #[cfg(windows)]
    #[test]
    fn other_programs_cant_reach_a_protected_process() {
        use std::io::{BufRead, BufReader, Write};

        use windows_sys::Win32::{
            Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError},
            Storage::FileSystem::WRITE_DAC,
            System::{
                Diagnostics::ToolHelp::{
                    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                    Thread32Next,
                },
                Threading::{
                    GetCurrentProcess, GetProcessMitigationPolicy, OpenProcess, OpenThread,
                    PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
                    PROCESS_VM_READ, PROCESS_VM_WRITE, ProcessImageLoadPolicy, THREAD_SET_CONTEXT,
                    THREAD_SUSPEND_RESUME,
                },
            },
        };

        const CHILD: &str = "VAULT_TEST_PROTECTED_PROCESS";
        if std::env::var_os(CHILD).is_some() {
            assert!(super::protect_memory(), "Windows took the process's list");
            super::apply_mitigations();
            let mut flags = 0u32;
            // SAFETY: one u32 of flags, with its size, for this process's pseudo-handle.
            #[allow(unsafe_code)]
            unsafe {
                GetProcessMitigationPolicy(
                    GetCurrentProcess(),
                    ProcessImageLoadPolicy,
                    (&raw mut flags).cast(),
                    size_of::<u32>(),
                );
            }
            assert_eq!(flags & 0b111, 0b111, "image load policy on");
            // A thread started after the protection.
            std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_secs(120)));
            // Past the guard's first sweep.
            std::thread::sleep(std::time::Duration::from_millis(1_500));
            println!("ready");
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            return;
        }

        // What is checked is another program of the same user. One that holds SeDebugPrivilege
        // turned on (an administrator's debugger; CI's runner hands it to every step) passes
        // any process's access list, which the threat model leaves out: turned off here first.
        turn_off_debug_privilege();

        let (_, tests) = module_path!().split_once("::").unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!(
                "{tests}::other_programs_cant_reach_a_protected_process"
            ))
            .arg("--nocapture")
            .env(CHILD, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut said = String::new();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        while !said.contains("ready") {
            let mut line = String::new();
            if out.read_line(&mut line).unwrap() == 0 {
                let _ = child.kill();
                panic!("the protected process ended early: {said}");
            }
            said.push_str(&line);
        }

        // SAFETY: each handle opened is closed once; the snapshot is read as Thread32First
        // requires. Nothing is done with the handles but checking they could be opened.
        #[allow(unsafe_code)]
        let (refused, allowed, threads, open_threads) = unsafe {
            let try_open = |rights: u32| {
                let handle = OpenProcess(rights, 0, pid);
                if handle.is_null() {
                    Err(GetLastError())
                } else {
                    CloseHandle(handle);
                    Ok(())
                }
            };
            let refused: Vec<(u32, Result<(), u32>)> = [
                PROCESS_VM_READ,
                PROCESS_VM_WRITE,
                PROCESS_CREATE_THREAD,
                PROCESS_DUP_HANDLE,
                WRITE_DAC,
            ]
            .into_iter()
            .map(|rights| (rights, try_open(rights)))
            .collect();
            let allowed = try_open(PROCESS_QUERY_LIMITED_INFORMATION);
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            let mut thread: THREADENTRY32 = std::mem::zeroed();
            thread.dwSize = u32::try_from(size_of::<THREADENTRY32>()).unwrap();
            let mut threads = 0;
            let mut open_threads = Vec::new();
            let mut more = Thread32First(snapshot, &raw mut thread) != 0;
            while more {
                if thread.th32OwnerProcessID == pid {
                    threads += 1;
                    for rights in [THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME, WRITE_DAC] {
                        let handle = OpenThread(rights, 0, thread.th32ThreadID);
                        if !handle.is_null() {
                            open_threads.push((thread.th32ThreadID, rights));
                            CloseHandle(handle);
                        }
                    }
                }
                more = Thread32Next(snapshot, &raw mut thread) != 0;
            }
            CloseHandle(snapshot);
            (refused, allowed, threads, open_threads)
        };
        let _ = child.stdin.take().unwrap().write_all(b"done\n");
        let ended = child.wait().unwrap();

        for (rights, result) in refused {
            assert_eq!(
                result,
                Err(ERROR_ACCESS_DENIED),
                "rights {rights:#x} refused to another program"
            );
        }
        assert_eq!(allowed, Ok(()), "it can still be seen to run");
        assert!(threads >= 2, "the main thread and the one started after");
        assert!(
            open_threads.is_empty(),
            "threads left open: {open_threads:?}"
        );
        assert!(ended.success());
    }

    /// Turns SeDebugPrivilege off in this test process's token, if it holds it at all.
    fn turn_off_debug_privilege() {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, GetLastError, HANDLE, LUID},
            Security::{
                AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
                TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
            },
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };
        let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        // SAFETY: the token handle is a valid out-pointer and is closed once; the name is
        // NUL-terminated; `privileges` holds the one entry its count says, and no previous
        // state is asked for.
        #[allow(unsafe_code)]
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            assert_ne!(
                OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &raw mut token),
                0,
                "this process's token"
            );
            let mut luid = LUID {
                LowPart: 0,
                HighPart: 0,
            };
            if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &raw mut luid) != 0 {
                let privileges = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    // No attribute: the privilege off (it stays in the token, unused).
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: 0,
                    }],
                };
                let changed = AdjustTokenPrivileges(
                    token,
                    0,
                    &raw const privileges,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                // ERROR_NOT_ALL_ASSIGNED (a token without it) is fine: nothing to turn off.
                assert_ne!(changed, 0, "AdjustTokenPrivileges: {}", GetLastError());
            }
            CloseHandle(token);
        }
    }
}
