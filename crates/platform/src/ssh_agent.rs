//! The SSH agent the desktop app answers as (M10 F9): OpenSSH's agent protocol
//! (draft-miller-ssh-agent) on a named pipe, so `ssh`, `git` and `scp` sign in with the
//! vault's SSH key items.
//!
//! This module is the protocol and the pipe; what is answered (which keys, whether a
//! signature is made) is the app's (`apps/desktop/src/controller/ssh_agent.rs`), which asks
//! the person for every signature.
//!
//! The protocol is a handful of messages: a length (32 bits, big-endian), a type byte, and
//! fields in SSH's own encoding, read and written with RustCrypto's `ssh-encoding` (the
//! release `ssh-key` uses). Only three requests are answered: the list of keys, a signature,
//! and nothing else (adding or removing keys, locking the agent, extensions get a failure):
//! the keys are the vault's, changed in the app only. (`ssh-agent-lib`, the crate that
//! implements the whole protocol, needs `ssh-key`'s RSA support, on an `rsa` release with an
//! advisory that `deny.toml` refuses.)
//!
//! The pipe: Windows' OpenSSH (`ssh.exe`, and Git for Windows set to use it) looks for its
//! agent at `\\.\pipe\openssh-ssh-agent` unless `SSH_AUTH_SOCK` names another pipe. The app
//! takes that name when it is free; when Windows' own agent service ("OpenSSH Authentication
//! Agent") or another program holds it, it uses a pipe of its own and Settings shows the
//! `SSH_AUTH_SOCK` line that points programs at it. Either pipe is created as the first of
//! its name (nobody holds it before), only the signed-in user may open it (its access list
//! names that user alone, as the browser's pipe), and remote clients are refused. Which
//! program connected is read from Windows (the client's process and the program that
//! started it), to show the person; it is a hint, not a check: any program of this user can
//! connect, which is why each signature is approved in the app.

use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::Result;
use ssh_encoding::{Decode, Encode};

/// The name Windows' OpenSSH looks for when `SSH_AUTH_SOCK` isn't set.
pub const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// The longest message read (OpenSSH's own agent takes the same).
pub const MAX_MESSAGE: usize = 256 * 1024;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;

/// What a client asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The keys this agent has.
    Identities,
    /// A signature of `data` with the key whose public half (wire form) is `key`.
    Sign {
        key: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// Anything else (adding keys, locking, an extension): refused.
    Other(u8),
}

impl Request {
    /// Reads one message's body (its type byte and fields, without the length). `None` when
    /// it doesn't read as the protocol.
    pub fn parse(message: &[u8]) -> Option<Self> {
        let (&kind, mut rest) = message.split_first()?;
        match kind {
            REQUEST_IDENTITIES => rest.is_empty().then_some(Self::Identities),
            SIGN_REQUEST => {
                let key = Vec::<u8>::decode(&mut rest).ok()?;
                let data = Vec::<u8>::decode(&mut rest).ok()?;
                let flags = u32::decode(&mut rest).ok()?;
                rest.is_empty().then_some(Self::Sign { key, data, flags })
            }
            other => Some(Self::Other(other)),
        }
    }
}

/// A key the agent lists: its public half in wire form and the comment shown next to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub blob: Vec<u8>,
    pub comment: String,
}

/// The answer to [`Request::Identities`].
pub fn identities_answer(keys: &[Identity]) -> Vec<u8> {
    let mut out = vec![IDENTITIES_ANSWER];
    let count = u32::try_from(keys.len()).unwrap_or(0);
    let written = count.encode(&mut out).is_ok()
        && keys.iter().take(count as usize).all(|key| {
            key.blob.as_slice().encode(&mut out).is_ok()
                && key.comment.as_str().encode(&mut out).is_ok()
        });
    if written { out } else { failure() }
}

/// The answer to [`Request::Sign`]: `signature` as `vault_core::ssh::agent_sign` makes it.
pub fn sign_response(signature: &[u8]) -> Vec<u8> {
    let mut out = vec![SIGN_RESPONSE];
    if signature.encode(&mut out).is_ok() {
        out
    } else {
        failure()
    }
}

/// The answer to anything refused.
pub fn failure() -> Vec<u8> {
    vec![FAILURE]
}

/// What the data of a sign request says it is for, shown to the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    /// Signing in to a server (RFC 4252 §7) as `user`.
    Login { user: String },
    /// A signature of a file or a commit (`ssh-keygen -Y sign`, git's SSH signing):
    /// `namespace` says for what (`git`, `file`).
    Signature { namespace: String },
    /// Something else.
    Unknown,
}

/// Reads a sign request's data as a sign-in or a file signature. The client writes it: a
/// hint for the person, never a check.
pub fn purpose(data: &[u8]) -> Purpose {
    let text = |bytes: Vec<u8>| {
        let text: String = String::from_utf8_lossy(&bytes)
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect();
        text
    };
    if let Some(mut rest) = data.strip_prefix(b"SSHSIG") {
        return match Vec::<u8>::decode(&mut rest) {
            Ok(namespace) => Purpose::Signature {
                namespace: text(namespace),
            },
            Err(_) => Purpose::Unknown,
        };
    }
    let mut rest = data;
    let login = (|| {
        let _session = Vec::<u8>::decode(&mut rest).ok()?;
        // SSH_MSG_USERAUTH_REQUEST
        (u8::decode(&mut rest).ok()? == 50).then_some(())?;
        let user = Vec::<u8>::decode(&mut rest).ok()?;
        let _service = Vec::<u8>::decode(&mut rest).ok()?;
        (Vec::<u8>::decode(&mut rest).ok()? == b"publickey").then_some(user)
    })();
    match login {
        Some(user) => Purpose::Login { user: text(user) },
        None => Purpose::Unknown,
    }
}

/// Reads one message: `Ok(None)` at a clean end (the client hung up).
pub fn read_message(mut from: impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match from.read_exact(&mut len) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut message = vec![0u8; len];
    from.read_exact(&mut message)?;
    Ok(Some(message))
}

/// Writes one message (`body`: the type byte and fields).
pub fn write_message(mut to: impl Write, body: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(body);
    to.write_all(&framed)?;
    to.flush()
}

/// Answers one client until it hangs up: each request read, handed to `answer`, and its
/// answer written. A message that doesn't read as the protocol gets a failure; one too long
/// ends the connection.
pub fn serve<S: Read + Write>(
    mut stream: S,
    mut answer: impl FnMut(Request) -> Vec<u8>,
) -> std::io::Result<()> {
    while let Some(message) = read_message(&mut stream)? {
        let reply = Request::parse(&message).map_or_else(failure, &mut answer);
        write_message(&mut stream, &reply)?;
    }
    Ok(())
}

/// The program at the other end of a connection, as Windows tells it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Client {
    /// Its full path (`C:\Windows\System32\OpenSSH\ssh.exe`).
    pub program: Option<PathBuf>,
    /// The program that started it (`git.exe`), when it still runs and started before it.
    pub parent: Option<PathBuf>,
}

/// The agent's pipe: listens, and hands each connection over with its client.
#[derive(Debug)]
pub struct Listener {
    inner: imp::Listener,
}

impl Listener {
    /// Creates the pipe under the first of `names` that is free. Fails when none is.
    pub fn bind(names: &[String]) -> Result<Self> {
        Ok(Self {
            inner: imp::Listener::bind(names)?,
        })
    }

    /// The name in use (what `SSH_AUTH_SOCK` must say when it isn't [`OPENSSH_PIPE`]).
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Waits for the next client.
    pub fn accept(&mut self) -> Result<(Connection, Client)> {
        let (file, client) = self.inner.accept()?;
        Ok((Connection { file }, client))
    }
}

/// One client's connection.
#[derive(Debug)]
pub struct Connection {
    file: std::fs::File,
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// This user's own pipe, used when [`OPENSSH_PIPE`] is taken.
pub fn own_pipe_name() -> Result<String> {
    imp::own_pipe_name()
}

/// Makes a [`Listener::accept`] that is waiting return, so its thread can stop.
pub fn wake(name: &str) {
    crate::browser_link::wake(name);
}

#[cfg(windows)]
mod imp {
    use std::{
        fs::File,
        os::windows::io::{AsRawHandle, FromRawHandle},
    };

    use anyhow::{Context, Result, bail};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_PIPE_CONNECTED, FILETIME, GetLastError, HANDLE,
            INVALID_HANDLE_VALUE, LocalFree,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
                PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
                PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
            },
            Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
        },
    };

    use super::Client;
    use crate::browser_link::{process_image, user_sid};

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn own_pipe_name() -> Result<String> {
        Ok(format!(r"\\.\pipe\vault-ssh-agent-{}", user_sid()?))
    }

    /// One instance of the pipe `name`, open to the signed-in user only. `first`: fails when
    /// the name exists already.
    fn instance(name: &str, first: bool) -> Result<File> {
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
        let open_mode = PIPE_ACCESS_DUPLEX
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        // SAFETY: `wide_name` and `attributes` (with the descriptor it points to) are alive
        // for the call. The handle returned is owned by the `File` below, and the descriptor
        // is freed exactly once after the pipe has copied it.
        #[allow(unsafe_code)]
        let handle = unsafe {
            let handle = CreateNamedPipeW(
                wide_name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &attributes,
            );
            LocalFree(descriptor);
            handle
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error()).context("creating the SSH agent pipe");
        }
        // SAFETY: `handle` is a valid pipe handle owned by nothing else; `File` closes it.
        #[allow(unsafe_code)]
        Ok(unsafe { File::from_raw_handle(handle.cast()) })
    }

    #[derive(Debug)]
    pub(super) struct Listener {
        name: String,
        /// The instance the next client connects to.
        waiting: File,
    }

    impl Listener {
        pub(super) fn bind(names: &[String]) -> Result<Self> {
            let mut last = None;
            for name in names {
                match instance(name, true) {
                    Ok(waiting) => {
                        return Ok(Self {
                            name: name.clone(),
                            waiting,
                        });
                    }
                    Err(err) => last = Some(err),
                }
            }
            Err(last.unwrap_or_else(|| anyhow::anyhow!("no pipe name to use")))
        }

        pub(super) fn name(&self) -> &str {
            &self.name
        }

        pub(super) fn accept(&mut self) -> Result<(File, Client)> {
            let handle: HANDLE = self.waiting.as_raw_handle().cast();
            // SAFETY: `handle` is this listener's pipe; a null OVERLAPPED means a blocking
            // wait.
            #[allow(unsafe_code)]
            let connected = unsafe {
                ConnectNamedPipe(handle, std::ptr::null_mut()) != 0
                    || GetLastError() == ERROR_PIPE_CONNECTED
            };
            if !connected {
                return Err(std::io::Error::last_os_error())
                    .context("waiting on the SSH agent pipe");
            }
            // The next client gets the next instance; this one is the connection's.
            let next = instance(&self.name, false)?;
            let connected = std::mem::replace(&mut self.waiting, next);
            let client = client_of(&connected);
            Ok((connected, client))
        }
    }

    fn client_of(pipe: &File) -> Client {
        let mut pid = 0u32;
        // SAFETY: the handle belongs to `pipe`, alive for the call; `pid` is a valid output.
        #[allow(unsafe_code)]
        let known =
            unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle().cast(), &mut pid) != 0 };
        if !known {
            return Client::default();
        }
        let parent = parent_of(pid).filter(|&parent| {
            started_at(parent).is_some_and(|p| started_at(pid).is_some_and(|c| p <= c))
        });
        Client {
            program: process_image(pid),
            parent: parent.and_then(process_image),
        }
    }

    /// The process that started `pid`, as Windows remembers it (the number may since belong
    /// to another process: the caller compares start times).
    fn parent_of(pid: u32) -> Option<u32> {
        // SAFETY: plain call; the snapshot handle is closed below.
        #[allow(unsafe_code)]
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: PROCESSENTRY32W is plain data; all zeros is a valid value.
        #[allow(unsafe_code)]
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        // SAFETY: `snapshot` is the handle made above and `entry` a writable PROCESSENTRY32W
        // with its size set; the handle is closed exactly once.
        #[allow(unsafe_code)]
        unsafe {
            let mut more = Process32FirstW(snapshot, &mut entry) != 0;
            while more {
                if entry.th32ProcessID == pid {
                    found = Some(entry.th32ParentProcessID).filter(|&p| p != 0);
                    break;
                }
                more = Process32NextW(snapshot, &mut entry) != 0;
            }
            CloseHandle(snapshot);
        }
        found
    }

    /// When process `pid` started (FILETIME as one number).
    fn started_at(pid: u32) -> Option<u64> {
        // SAFETY: plain call; a null handle is handled.
        #[allow(unsafe_code)]
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return None;
        }
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: `process` is the handle opened above, closed exactly once; the four
        // outputs are valid FILETIMEs.
        #[allow(unsafe_code)]
        let ok = unsafe {
            let ok = GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user);
            CloseHandle(process);
            ok != 0
        };
        ok.then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::{Result, bail};

    use super::Client;

    pub(super) fn own_pipe_name() -> Result<String> {
        bail!("the SSH agent is only on Windows for now")
    }

    #[derive(Debug)]
    pub(super) struct Listener;

    impl Listener {
        pub(super) fn bind(_names: &[String]) -> Result<Self> {
            bail!("the SSH agent is only on Windows for now")
        }
        pub(super) fn name(&self) -> &str {
            ""
        }
        pub(super) fn accept(&mut self) -> Result<(std::fs::File, Client)> {
            bail!("the SSH agent is only on Windows for now")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        bytes.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn requests_are_read_and_what_isnt_the_protocol_is_refused() {
        assert_eq!(Request::parse(&[11]), Some(Request::Identities));
        assert_eq!(Request::parse(&[11, 0]), None);
        let mut sign = vec![13];
        sign.extend(string(b"key"));
        sign.extend(string(b"data"));
        sign.extend(4u32.to_be_bytes());
        assert_eq!(
            Request::parse(&sign),
            Some(Request::Sign {
                key: b"key".to_vec(),
                data: b"data".to_vec(),
                flags: 4
            })
        );
        // Cut anywhere, or with bytes after it, it isn't a request.
        for cut in 1..sign.len() {
            assert_eq!(Request::parse(&sign[..cut]), None, "cut at {cut}");
        }
        let mut longer = sign.clone();
        longer.push(0);
        assert_eq!(Request::parse(&longer), None);
        // A length past the end.
        assert_eq!(Request::parse(&[13, 0xff, 0xff, 0xff, 0xff]), None);
        // Adding a key (17), locking (22), an extension (27): refused by the caller.
        assert_eq!(Request::parse(&[17, 1, 2]), Some(Request::Other(17)));
        assert_eq!(Request::parse(&[]), None);
    }

    #[test]
    fn answers_are_written_as_the_protocol_says() {
        let answer = identities_answer(&[
            Identity {
                blob: b"one".to_vec(),
                comment: "first".into(),
            },
            Identity {
                blob: b"two".to_vec(),
                comment: String::new(),
            },
        ]);
        let mut expected = vec![12, 0, 0, 0, 2];
        expected.extend(string(b"one"));
        expected.extend(string(b"first"));
        expected.extend(string(b"two"));
        expected.extend(string(b""));
        assert_eq!(answer, expected);
        assert_eq!(identities_answer(&[]), vec![12, 0, 0, 0, 0]);
        let mut signed = vec![14];
        signed.extend(string(b"sig"));
        assert_eq!(sign_response(b"sig"), signed);
        assert_eq!(failure(), vec![5]);
    }

    #[test]
    fn a_sign_requests_data_says_what_it_is_for() {
        // A sign-in (RFC 4252 §7): session id, 50, user, service, "publickey", …
        let mut login = string(&[9u8; 32]);
        login.push(50);
        login.extend(string(b"git"));
        login.extend(string(b"ssh-connection"));
        login.extend(string(b"publickey"));
        login.push(1);
        login.extend(string(b"ssh-ed25519"));
        assert_eq!(purpose(&login), Purpose::Login { user: "git".into() });
        // ssh-keygen -Y sign: the magic, then the namespace.
        let mut file = b"SSHSIG".to_vec();
        file.extend(string(b"git"));
        assert_eq!(
            purpose(&file),
            Purpose::Signature {
                namespace: "git".into()
            }
        );
        // Control characters from the client never reach the screen.
        let mut odd = string(&[1u8; 32]);
        odd.push(50);
        odd.extend(string(b"ro\x1b[2Jot\n"));
        odd.extend(string(b"ssh-connection"));
        odd.extend(string(b"publickey"));
        assert_eq!(
            purpose(&odd),
            Purpose::Login {
                user: "ro[2Jot".into()
            }
        );
        assert_eq!(purpose(b"anything"), Purpose::Unknown);
        assert_eq!(purpose(b""), Purpose::Unknown);
    }

    /// Both directions of a connection in memory.
    struct Duplex {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_connection_is_answered_message_by_message() {
        let mut input = Vec::new();
        write_message(&mut input, &[11]).unwrap();
        write_message(&mut input, &[13, 0]).unwrap();
        write_message(&mut input, &[22]).unwrap();
        let mut duplex = Duplex {
            input: std::io::Cursor::new(input),
            output: Vec::new(),
        };
        let mut asked = Vec::new();
        serve(&mut duplex, |request| {
            asked.push(request);
            identities_answer(&[])
        })
        .unwrap();
        // The malformed one never reaches the app.
        assert_eq!(asked, vec![Request::Identities, Request::Other(22)]);
        let mut output = duplex.output.as_slice();
        assert_eq!(
            read_message(&mut output).unwrap().unwrap(),
            vec![12, 0, 0, 0, 0]
        );
        assert_eq!(read_message(&mut output).unwrap().unwrap(), vec![5]);
        assert_eq!(
            read_message(&mut output).unwrap().unwrap(),
            vec![12, 0, 0, 0, 0]
        );
        assert_eq!(read_message(&mut output).unwrap(), None);
        // A length over the limit ends the connection.
        let mut huge = ((MAX_MESSAGE + 1) as u32).to_be_bytes().to_vec();
        huge.push(11);
        assert!(read_message(huge.as_slice()).is_err());
        assert!(read_message([0u8, 0, 0, 0].as_slice()).is_err());
    }

    /// The real pipe, under a name of the test's own, with a test client in this process.
    #[cfg(windows)]
    #[test]
    fn the_pipe_answers_its_user_and_takes_a_name_only_when_free() {
        let name = format!(
            r"\\.\pipe\vault-ssh-agent-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        );
        let mut listener = Listener::bind(std::slice::from_ref(&name)).unwrap();
        assert_eq!(listener.name(), name);
        // A second agent can't take the same name, and moves on to the next one.
        assert!(Listener::bind(std::slice::from_ref(&name)).is_err());
        let fallback = format!("{name}-own");
        let second = Listener::bind(&[name.clone(), fallback.clone()]).unwrap();
        assert_eq!(second.name(), fallback);
        drop(second);

        let server = std::thread::spawn(move || {
            // Two clients at once: each gets its own instance.
            let mut threads = Vec::new();
            for _ in 0..2 {
                let (connection, client) = listener.accept().unwrap();
                // This test's own program is the client.
                let program = client.program.clone().unwrap();
                assert_eq!(
                    program.canonicalize().unwrap(),
                    std::env::current_exe().unwrap().canonicalize().unwrap()
                );
                threads.push(std::thread::spawn(move || {
                    serve(connection, |request| match request {
                        Request::Identities => identities_answer(&[Identity {
                            blob: b"blob".to_vec(),
                            comment: "test key".into(),
                        }]),
                        Request::Sign { data, .. } => sign_response(&data),
                        Request::Other(_) => failure(),
                    })
                    .unwrap();
                }));
            }
            for thread in threads {
                thread.join().unwrap();
            }
        });
        let open = || {
            for _ in 0..100 {
                if let Ok(pipe) = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&name)
                {
                    return pipe;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            panic!("the pipe never opened");
        };
        let mut first = open();
        let mut second = open();
        write_message(&mut first, &[11]).unwrap();
        let listed = read_message(&mut first).unwrap().unwrap();
        assert_eq!(&listed[..5], &[12, 0, 0, 0, 1]);
        let mut sign = vec![13];
        sign.extend(string(b"blob"));
        sign.extend(string(b"hello"));
        sign.extend(0u32.to_be_bytes());
        write_message(&mut second, &sign).unwrap();
        let mut expected = vec![14];
        expected.extend(string(b"hello"));
        assert_eq!(read_message(&mut second).unwrap().unwrap(), expected);
        drop(first);
        drop(second);
        server.join().unwrap();
    }
}
