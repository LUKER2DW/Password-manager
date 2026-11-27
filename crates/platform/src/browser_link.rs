//! The local link between the browser extension and the desktop app.
//!
//! A browser starts the native host when the extension asks for it and talks to it over
//! stdin/stdout. The host is the desktop app's own executable, started with the extension's
//! origin as its first argument (Chrome, Edge) or with the path of the host's manifest and the
//! extension's id (Firefox) (`vault_browser::host::run`): it relays each message to the running
//! desktop app through a named pipe, and the app's answer back. Nothing here touches the
//! network.
//!
//! Each browser finds the host through one registry value of the signed-in user, which names
//! the host's manifest: Chrome and Edge read one that allows the extension's origin
//! (`allowed_origins`), Firefox one that allows its add-on id (`allowed_extensions`).
//!
//! What protects the pipe:
//! - only the signed-in user may open it (its access list names that user alone), and remote
//!   clients are refused;
//! - the app answers only when the program at the other end is its own executable, and the
//!   host sends only to that same executable (both checked by the path of the process);
//! - the pipe is created as the first of its name, so another program can't have taken the
//!   name before.
//!
//! This does not stop malware that already runs as the same user from starting the host
//! itself; see `docs/THREAT_MODEL.md`. The app limits what such a caller gets: nothing while
//! the vault is locked, and nothing from items behind the item lock.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Name the extension uses for the native host (`chrome.runtime.sendNativeMessage`).
pub const HOST_NAME: &str = "vault.desktop.browser_host";
/// Id of the extension in Chrome and Edge (fixed by the public `key` in its manifest). Only it
/// may start the host there.
pub const EXTENSION_ID: &str = "ebfeneijifledfnmjgelpifpjgmkbpcn";
/// Id of the extension in Firefox (`browser_specific_settings.gecko.id` in its manifest). Only
/// it may start the host there.
pub const GECKO_ID: &str = "{71837927-6420-4e18-9ecf-1faa0afbf5f5}";
/// Largest message accepted in either direction.
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// The origin a browser reports for the extension (first argument given to the host).
pub fn extension_origin() -> String {
    format!("chrome-extension://{EXTENSION_ID}/")
}

/// Which manifest of the host a browser reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostManifest {
    /// Chrome and Edge: [`manifest_json`], allowing the extension's origin.
    Chromium,
    /// Firefox: [`firefox_manifest_json`], allowing its add-on id.
    Firefox,
}

/// The per-user registry keys under which browsers look for native hosts, and the manifest
/// each one reads. The host's own key, named [`HOST_NAME`], goes under each.
pub const BROWSER_KEYS: [(&str, HostManifest); 3] = [
    (
        r"Software\Google\Chrome\NativeMessagingHosts",
        HostManifest::Chromium,
    ),
    (
        r"Software\Microsoft\Edge\NativeMessagingHosts",
        HostManifest::Chromium,
    ),
    (
        r"Software\Mozilla\NativeMessagingHosts",
        HostManifest::Firefox,
    ),
];

/// Where the host's manifest for Chrome and Edge is written (`<app dir>/browser/<name>.json`).
pub fn manifest_path() -> Result<PathBuf> {
    Ok(crate::paths::app_dir()?
        .join("browser")
        .join(format!("{HOST_NAME}.json")))
}

/// Where the host's manifest for Firefox is written (`<app dir>/browser/<name>.firefox.json`).
pub fn firefox_manifest_path() -> Result<PathBuf> {
    Ok(crate::paths::app_dir()?
        .join("browser")
        .join(format!("{HOST_NAME}.firefox.json")))
}

/// The manifest Chrome and Edge read to find and start the host.
pub fn manifest_json(host_exe: &Path) -> String {
    serde_json::json!({
        "name": HOST_NAME,
        "description": "Connects the browser extension to the desktop password manager",
        "path": host_exe,
        "type": "stdio",
        "allowed_origins": [extension_origin()],
    })
    .to_string()
}

/// The manifest Firefox reads to find and start the host: the same host, allowed to the
/// extension's add-on id alone.
pub fn firefox_manifest_json(host_exe: &Path) -> String {
    serde_json::json!({
        "name": HOST_NAME,
        "description": "Connects the browser extension to the desktop password manager",
        "path": host_exe,
        "type": "stdio",
        "allowed_extensions": [GECKO_ID],
    })
    .to_string()
}

/// Tells Chrome, Edge and Firefox (for this user) where the native host is. Writes the two
/// manifest files and one registry value per browser.
pub fn register_host(host_exe: &Path) -> Result<()> {
    let chromium = manifest_path()?;
    let firefox = firefox_manifest_path()?;
    for (path, json) in [
        (&chromium, manifest_json(host_exe)),
        (&firefox, firefox_manifest_json(host_exe)),
    ] {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    }
    imp::register(&chromium, &firefox)
}

/// Undoes [`register_host`]: browsers can no longer start the host.
pub fn unregister_host() {
    imp::unregister();
    for path in [manifest_path(), firefox_manifest_path()]
        .into_iter()
        .flatten()
    {
        let _ = std::fs::remove_file(path);
    }
}

/// The pipe of the signed-in user.
pub fn pipe_name() -> Result<String> {
    imp::pipe_name()
}

/// The app's end of the pipe.
#[derive(Debug)]
pub struct Server {
    inner: imp::Server,
}

impl Server {
    /// Creates the pipe. Fails when the name is already taken (another copy of the app, or
    /// something that should not be there). Only `allowed_client` (a program's full path) gets
    /// answers.
    pub fn bind(name: &str, allowed_client: &Path) -> Result<Self> {
        Ok(Self {
            inner: imp::Server::bind(name, allowed_client)?,
        })
    }

    /// Waits for one caller, reads its message and writes back what `answer` returns. A caller
    /// that is not the allowed program is hung up on without being read (`Ok(false)`).
    pub fn serve_one(&mut self, answer: impl FnOnce(&[u8]) -> Vec<u8>) -> Result<bool> {
        self.inner.serve_one(answer)
    }
}

/// Makes a [`Server::serve_one`] that is waiting return, so its thread can stop.
pub fn wake(name: &str) {
    imp::wake(name);
}

/// The host's end: sends one message to the app and returns its answer. Fails when the app is
/// not running (or the extension link is off), or when the pipe belongs to another program
/// than `expected_server`.
pub fn request(name: &str, expected_server: &Path, message: &[u8]) -> Result<Vec<u8>> {
    imp::request(name, expected_server, message)
}

/// Writes one message: a 32-bit little-endian length, then the bytes.
pub fn write_frame(mut to: impl std::io::Write, message: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(message.len())
        .ok()
        .filter(|_| message.len() <= MAX_MESSAGE)
        .ok_or(std::io::ErrorKind::InvalidInput)?;
    to.write_all(&len.to_le_bytes())?;
    to.write_all(message)?;
    to.flush()
}

/// Reads one message written by [`write_frame`]. `Ok(None)` at a clean end of input.
pub fn read_frame(mut from: impl std::io::Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match from.read_exact(&mut len) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut message = vec![0u8; len];
    from.read_exact(&mut message)?;
    Ok(Some(message))
}

#[cfg(windows)]
mod imp {
    use std::{
        fs::File,
        os::windows::{
            fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle},
        },
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    use anyhow::{Context, Result, anyhow, bail};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
            LocalFree,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
            },
            Registry::{HKEY_CURRENT_USER, REG_SZ, RegDeleteTreeW, RegSetKeyValueW},
            Threading::{
                GetCurrentProcess, OpenProcess, OpenProcessToken,
                PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
            },
        },
    };

    use super::{BROWSER_KEYS, HOST_NAME, HostManifest, read_frame, write_frame};
    /// The server may identify the client but not act as it.
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    const ERROR_PIPE_BUSY: i32 = 231;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Opens and closes the pipe. Whoever holds the name may identify this program but not
    /// act as it (the name could be held by another account's program).
    pub(super) fn wake(name: &str) {
        let _ = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(name);
    }

    pub(super) fn register(chromium: &Path, firefox: &Path) -> Result<()> {
        for (key, manifest) in BROWSER_KEYS {
            let manifest = match manifest {
                HostManifest::Chromium => chromium,
                HostManifest::Firefox => firefox,
            };
            let value = wide(&manifest.display().to_string());
            let bytes = u32::try_from(value.len() * 2).context("manifest path too long")?;
            let subkey = wide(&format!(r"{key}\{HOST_NAME}"));
            // SAFETY: `subkey` and `value` are NUL-terminated UTF-16 buffers that outlive the
            // call; `bytes` is the size of `value` in bytes; a null value name means the
            // key's default value. The call creates the key when it is missing.
            #[allow(unsafe_code)]
            let status = unsafe {
                RegSetKeyValueW(
                    HKEY_CURRENT_USER,
                    subkey.as_ptr(),
                    std::ptr::null(),
                    REG_SZ,
                    value.as_ptr().cast(),
                    bytes,
                )
            };
            if status != 0 {
                bail!("registering the browser host failed (Windows error {status})");
            }
        }
        Ok(())
    }

    pub(super) fn unregister() {
        for (key, _) in BROWSER_KEYS {
            let subkey = wide(&format!(r"{key}\{HOST_NAME}"));
            // SAFETY: `subkey` is a NUL-terminated UTF-16 buffer that outlives the call. Only
            // this app's own key (ending in the host name) is removed.
            #[allow(unsafe_code)]
            unsafe {
                RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr());
            }
        }
    }

    /// The signed-in user's SID as text ("S-1-5-21-…").
    fn user_sid() -> Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-handle of the current process is always valid; `token` receives
        // a handle that is closed below.
        #[allow(unsafe_code)]
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            bail!("cannot read the user of this process");
        }
        // 8-byte aligned (TOKEN_USER starts with a pointer) and larger than any SID.
        let mut buffer = [0u64; 64];
        let mut needed = 0u32;
        // SAFETY: `buffer` is writable for the 512 bytes announced, and aligned for
        // TOKEN_USER; `token` is the handle opened above.
        #[allow(unsafe_code)]
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                &mut needed,
            )
        };
        // SAFETY: `token` was opened above and is closed exactly once.
        #[allow(unsafe_code)]
        unsafe {
            CloseHandle(token);
        }
        if read == 0 {
            bail!("cannot read the user of this process");
        }
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID pointer points
        // into the same buffer, which is still alive. `text` receives a LocalAlloc string.
        #[allow(unsafe_code)]
        let converted = unsafe {
            let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            ConvertSidToStringSidW(user.User.Sid, &mut text)
        };
        if converted == 0 || text.is_null() {
            bail!("cannot read the user of this process");
        }
        // SAFETY: `text` is a NUL-terminated UTF-16 string allocated by the call above; it is
        // read up to its terminator and freed exactly once.
        #[allow(unsafe_code)]
        let sid = unsafe {
            let mut len = 0;
            while *text.add(len) != 0 {
                len += 1;
            }
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            sid
        };
        Ok(sid)
    }

    pub(super) fn pipe_name() -> Result<String> {
        Ok(format!(r"\\.\pipe\vault-desktop-browser-{}", user_sid()?))
    }

    /// Full path of the program running as process `pid`.
    fn process_image(pid: u32) -> Option<PathBuf> {
        // SAFETY: plain call; a null handle (no such process, no access) is handled.
        #[allow(unsafe_code)]
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; 32_768];
        let mut len = buffer.len() as u32;
        // SAFETY: `buffer` is writable for `len` UTF-16 units; `process` is the handle opened
        // above, closed exactly once right after.
        #[allow(unsafe_code)]
        let ok = unsafe {
            let ok = QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut len);
            CloseHandle(process);
            ok
        };
        (ok != 0).then(|| PathBuf::from(String::from_utf16_lossy(&buffer[..len as usize])))
    }

    fn same_program(a: &Path, b: &Path) -> bool {
        match (a.canonicalize(), b.canonicalize()) {
            (Ok(a), Ok(b)) => a
                .to_string_lossy()
                .eq_ignore_ascii_case(&b.to_string_lossy()),
            _ => false,
        }
    }

    #[derive(Debug)]
    pub(super) struct Server {
        pipe: File,
        allowed_client: PathBuf,
    }

    impl Server {
        pub(super) fn bind(name: &str, allowed_client: &Path) -> Result<Self> {
            // Full access for the signed-in user, nobody else (not even read).
            let sddl = wide(&format!("D:P(A;;GA;;;{})", user_sid()?));
            let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `sddl` is a NUL-terminated UTF-16 buffer; `descriptor` receives a
            // LocalAlloc block freed below; the size output is optional.
            #[allow(unsafe_code)]
            let converted = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            };
            if converted == 0 {
                bail!("cannot build the access list of the pipe");
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let wide_name = wide(name);
            // SAFETY: `wide_name` and `attributes` (with the descriptor it points to) are
            // alive for the call. The handle returned is owned by the `File` below, and the
            // descriptor is freed exactly once after the pipe has copied it.
            #[allow(unsafe_code)]
            let handle = unsafe {
                let handle = CreateNamedPipeW(
                    wide_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    64 * 1024,
                    64 * 1024,
                    0,
                    &attributes,
                );
                LocalFree(descriptor);
                handle
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error()).context("creating the browser pipe");
            }
            // SAFETY: `handle` is a valid pipe handle owned by nothing else; `File` closes it.
            #[allow(unsafe_code)]
            let pipe = unsafe { File::from_raw_handle(handle.cast()) };
            Ok(Self {
                pipe,
                allowed_client: allowed_client.to_owned(),
            })
        }

        pub(super) fn serve_one(&mut self, answer: impl FnOnce(&[u8]) -> Vec<u8>) -> Result<bool> {
            let handle: HANDLE = self.pipe.as_raw_handle().cast();
            // SAFETY: `handle` is this server's pipe; a null OVERLAPPED means a blocking wait.
            #[allow(unsafe_code)]
            let connected = unsafe {
                ConnectNamedPipe(handle, std::ptr::null_mut()) != 0
                    || GetLastError() == ERROR_PIPE_CONNECTED
            };
            if !connected {
                return Err(std::io::Error::last_os_error()).context("waiting on the browser pipe");
            }
            let outcome = self.talk(handle, answer);
            // SAFETY: `handle` is this server's pipe; disconnecting makes it ready for the
            // next caller whatever happened with this one.
            #[allow(unsafe_code)]
            unsafe {
                DisconnectNamedPipe(handle);
            }
            outcome
        }

        fn talk(&mut self, handle: HANDLE, answer: impl FnOnce(&[u8]) -> Vec<u8>) -> Result<bool> {
            let mut pid = 0u32;
            // SAFETY: `handle` is this server's connected pipe; `pid` is a valid output.
            #[allow(unsafe_code)]
            let known = unsafe { GetNamedPipeClientProcessId(handle, &mut pid) != 0 };
            let allowed = known
                && process_image(pid)
                    .is_some_and(|image| same_program(&image, &self.allowed_client));
            if !allowed {
                return Ok(false);
            }
            // A caller that connects and then says nothing would hold the only instance of
            // the pipe: it gets a few seconds.
            let waiting = Patient {
                pipe: &self.pipe,
                until: Instant::now() + Duration::from_secs(5),
            };
            let Some(message) = read_frame(waiting)? else {
                return Ok(false);
            };
            let mut reply = answer(&message);
            let written = write_frame(&self.pipe, &reply);
            // The answer may hold a password.
            zeroize::Zeroize::zeroize(&mut reply);
            written?;
            // Waits until the caller has read the answer, so the disconnect doesn't drop it.
            self.pipe.sync_all().ok();
            Ok(true)
        }
    }

    /// Reads from the pipe, giving up when nothing arrives before `until`.
    struct Patient<'a> {
        pipe: &'a File,
        until: Instant,
    }

    impl std::io::Read for Patient<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            loop {
                let mut ready = 0u32;
                // SAFETY: the handle belongs to `self.pipe`, alive for the call; no data is
                // copied (null buffer of size 0) and `ready` is a valid output.
                #[allow(unsafe_code)]
                let peeked = unsafe {
                    PeekNamedPipe(
                        self.pipe.as_raw_handle().cast(),
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut ready,
                        std::ptr::null_mut(),
                    ) != 0
                };
                if !peeked {
                    return Err(std::io::Error::last_os_error());
                }
                if ready > 0 {
                    let mut pipe = self.pipe;
                    return pipe.read(buffer);
                }
                if Instant::now() >= self.until {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    pub(super) fn request(name: &str, expected_server: &Path, message: &[u8]) -> Result<Vec<u8>> {
        let started = Instant::now();
        let pipe = loop {
            let opened = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(name);
            match opened {
                Ok(pipe) => break pipe,
                // Busy with another caller: it answers quickly, try again shortly.
                Err(err)
                    if err.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && started.elapsed() < Duration::from_secs(3) =>
                {
                    std::thread::sleep(Duration::from_millis(40));
                }
                Err(err) => return Err(err).context("the app is not listening"),
            }
        };
        let mut pid = 0u32;
        // SAFETY: the handle belongs to `pipe`, alive for the call; `pid` is a valid output.
        #[allow(unsafe_code)]
        let known =
            unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut pid) != 0 };
        if !(known && process_image(pid).is_some_and(|image| same_program(&image, expected_server)))
        {
            bail!("the pipe belongs to another program");
        }
        write_frame(&pipe, message)?;
        read_frame(&pipe)?.ok_or_else(|| anyhow!("the app hung up"))
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    use anyhow::{Result, bail};

    pub(super) fn register(_chromium: &Path, _firefox: &Path) -> Result<()> {
        bail!("the browser extension link is available on Windows only for now")
    }

    pub(super) fn unregister() {}

    pub(super) fn wake(_name: &str) {}

    pub(super) fn pipe_name() -> Result<String> {
        bail!("the browser extension link is available on Windows only for now")
    }

    #[derive(Debug)]
    pub(super) struct Server;

    impl Server {
        pub(super) fn bind(_name: &str, _allowed_client: &Path) -> Result<Self> {
            bail!("the browser extension link is available on Windows only for now")
        }

        pub(super) fn serve_one(&mut self, _answer: impl FnOnce(&[u8]) -> Vec<u8>) -> Result<bool> {
            bail!("the browser extension link is available on Windows only for now")
        }
    }

    pub(super) fn request(_name: &str, _expected: &Path, _message: &[u8]) -> Result<Vec<u8>> {
        bail!("the browser extension link is available on Windows only for now")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_are_bounded() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, b"{\"type\":\"status\"}").unwrap();
        write_frame(&mut bytes, b"").unwrap();
        let mut input = bytes.as_slice();
        assert_eq!(
            read_frame(&mut input).unwrap().unwrap(),
            b"{\"type\":\"status\"}"
        );
        assert_eq!(read_frame(&mut input).unwrap().unwrap(), b"");
        assert!(read_frame(&mut input).unwrap().is_none(), "clean end");
        // A length beyond the limit is refused before anything is allocated for it.
        let huge = (MAX_MESSAGE as u32 + 1).to_le_bytes();
        assert!(read_frame(huge.as_slice()).is_err());
        assert!(write_frame(Vec::new(), &vec![0u8; MAX_MESSAGE + 1]).is_err());
        // Cut short in the middle of a message.
        assert!(read_frame([5u8, 0, 0, 0, b'a'].as_slice()).is_err());
    }

    #[test]
    fn the_manifest_names_the_host_and_only_our_extension() {
        let json: serde_json::Value =
            serde_json::from_str(&manifest_json(Path::new(r"C:\apps\vault-desktop.exe"))).unwrap();
        assert_eq!(json["name"], HOST_NAME);
        assert_eq!(json["type"], "stdio");
        assert_eq!(json["path"], r"C:\apps\vault-desktop.exe");
        assert_eq!(
            json["allowed_origins"],
            serde_json::json!([format!("chrome-extension://{EXTENSION_ID}/")])
        );
        assert_eq!(EXTENSION_ID.len(), 32);
        assert!(EXTENSION_ID.bytes().all(|b| (b'a'..=b'p').contains(&b)));
        assert!(json.get("allowed_extensions").is_none());
    }

    #[test]
    fn firefox_gets_a_manifest_of_its_own_naming_only_our_add_on() {
        let json: serde_json::Value = serde_json::from_str(&firefox_manifest_json(Path::new(
            r"C:\apps\vault-desktop.exe",
        )))
        .unwrap();
        assert_eq!(json["name"], HOST_NAME);
        assert_eq!(json["type"], "stdio");
        assert_eq!(json["path"], r"C:\apps\vault-desktop.exe");
        assert_eq!(json["allowed_extensions"], serde_json::json!([GECKO_ID]));
        assert!(json.get("allowed_origins").is_none());
        // Firefox's rule for host names (dot-separated words), and a braced GUID as the id.
        assert!(HOST_NAME.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }));
        let guid = GECKO_ID
            .strip_prefix('{')
            .and_then(|id| id.strip_suffix('}'))
            .unwrap();
        let groups: Vec<usize> = guid.split('-').map(str::len).collect();
        assert_eq!(groups, [8, 4, 4, 4, 12]);
        assert!(guid.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit()));
    }

    #[test]
    fn each_browser_reads_the_manifest_made_for_it() {
        for (key, manifest) in BROWSER_KEYS {
            assert!(key.starts_with(r"Software\") && key.ends_with(r"\NativeMessagingHosts"));
            assert_eq!(
                key.contains(r"\Mozilla\"),
                manifest == HostManifest::Firefox,
                "{key}"
            );
        }
        let firefox = BROWSER_KEYS
            .iter()
            .filter(|(_, manifest)| *manifest == HostManifest::Firefox)
            .count();
        assert_eq!(firefox, 1);
    }

    #[cfg(windows)]
    #[test]
    fn the_pipe_answers_its_own_program_and_nobody_else() {
        let me = std::env::current_exe().unwrap();
        let name = format!("{}-test-{}", pipe_name().unwrap(), std::process::id());
        assert!(name.starts_with(r"\\.\pipe\vault-desktop-browser-S-1-"));

        let mut server = Server::bind(&name, &me).unwrap();
        assert!(
            Server::bind(&name, &me).is_err(),
            "the name can't be taken twice"
        );
        let thread = std::thread::spawn(move || {
            let first = server
                .serve_one(|message| [b"echo:".as_slice(), message].concat())
                .unwrap();
            // The second caller expects another program on the server side and never writes.
            let second = server.serve_one(|_| b"never".to_vec());
            (first, second.is_ok())
        });
        assert_eq!(request(&name, &me, b"hello").unwrap(), b"echo:hello");
        let other = std::env::var_os("SystemRoot")
            .map(|root| PathBuf::from(root).join("System32").join("cmd.exe"))
            .unwrap();
        assert!(request(&name, &other, b"hello").is_err());
        let (first, _) = thread.join().unwrap();
        assert!(first);

        // A server that only accepts another program hangs up without answering.
        let mut picky = Server::bind(&name, &other).unwrap();
        let thread = std::thread::spawn(move || picky.serve_one(|_| b"secret".to_vec()).unwrap());
        assert!(request(&name, &me, b"hello").is_err());
        assert!(!thread.join().unwrap());
    }
}
