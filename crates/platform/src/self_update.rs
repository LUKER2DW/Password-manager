//! The desktop app replacing itself with a newer release (Settings → About → Updates; F12).
//!
//! A release is taken only once [`crate::updates::latest`] has checked its manifest against
//! `releases::RELEASE_KEYS`, and only when it is newer than the running app. Its program
//! (`vault-desktop.exe`) is then downloaded, at most the size its signed manifest lists, into a
//! file next to the running one (the same folder, so the same volume), its SHA-256 checked
//! against the manifest, and only then swapped in:
//!
//! 1. the running program is renamed aside (`vault-desktop.exe.old`: Windows lets a running
//!    program be renamed, not deleted or overwritten);
//! 2. the new one is renamed to the running one's name, so every shortcut, the start at
//!    sign-in and the browser extension's native host start it from then on;
//! 3. if step 2 fails, step 1 is undone, and the folder is as it was.
//!
//! The program renamed aside is deleted at the next start ([`clean_leftovers`]), once nothing
//! runs from it. A folder the app can't write in (Program Files, for one) is told
//! ([`UpdateError::NotWritable`]): the release page opens instead. Nothing here runs the new
//! program: the app asks the person first, and a new copy started then waits for this one to
//! end ([`wait_for_exit`]) before it takes over (`single_instance`).

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use sha2::{Digest, Sha256};
use vault_sync_wire::releases::{ManifestError, Package, Verified};

use crate::updates::{NETWORK, RETRY_WAITS, USER_AGENT, with_retries};

/// What the update is doing, for its progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The release and its signed manifest are read and checked.
    Manifest,
    /// The program is coming: `done` of `total` bytes.
    Download { done: u64, total: u64 },
    /// Its SHA-256 is checked against the manifest's.
    Check,
    /// It replaces the running program.
    Install,
}

/// Why the app wasn't replaced. In every case the running program is left as it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    /// The program's folder can't be written (the detail is the folder).
    NotWritable(String),
    /// The release isn't newer than the running app.
    NotNewer,
    /// The release, or what was downloaded, isn't what the signed manifest lists.
    Refused(String),
    /// The network failed (the detail says how).
    Network(String),
    /// The swap failed and was undone (the detail says why).
    Install(String),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotWritable(folder) => write!(f, "{folder} can't be written"),
            Self::NotNewer => write!(f, "the release isn't newer"),
            Self::Refused(why) | Self::Network(why) | Self::Install(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for UpdateError {}

/// The suffix of a program renamed aside.
const OLD: &str = ".old";
/// The suffix of a program being downloaded.
const DOWNLOAD: &str = ".download";

/// How large each read of the download is, and how often the progress is told.
const CHUNK: usize = 64 * 1024;

/// Replaces `exe` (the running program) with `release`'s, when that release is newer than
/// `running`. Blocks for as long as the download takes: call it off the UI thread. `progress`
/// hears each step.
pub fn install(
    release: &Verified,
    exe: &Path,
    running: &str,
    progress: &mut dyn FnMut(Step),
) -> Result<(), UpdateError> {
    if !release.is_newer_than(running) {
        return Err(UpdateError::NotNewer);
    }
    let package = release
        .desktop_exe()
        .map_err(|err: ManifestError| UpdateError::Refused(err.to_string()))?;
    let temp = download_path(exe);
    let file = create(&temp, exe)?;
    let downloaded = download(&package, file, &temp, progress);
    if let Err(err) = downloaded {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    progress(Step::Install);
    swap(exe, &temp).map_err(UpdateError::Install)
}

/// The file the program is downloaded into, next to `exe`.
pub fn download_path(exe: &Path) -> PathBuf {
    sibling(exe, DOWNLOAD)
}

/// Where `exe` is renamed aside.
pub fn old_path(exe: &Path) -> PathBuf {
    sibling(exe, OLD)
}

fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let mut name = exe.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    exe.with_file_name(name)
}

/// The download's file, new and empty (one left by an update that didn't finish is replaced).
fn create(temp: &Path, exe: &Path) -> Result<File, UpdateError> {
    let not_writable = || {
        UpdateError::NotWritable(
            exe.parent()
                .map(|folder| folder.display().to_string())
                .unwrap_or_default(),
        )
    };
    match fs::remove_file(temp) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return Err(not_writable()),
        Err(err) => return Err(UpdateError::Install(err.to_string())),
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp)
        .map_err(|err| match err.kind() {
            io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => not_writable(),
            _ => UpdateError::Install(err.to_string()),
        })
}

/// Downloads `package` into `file` (at `temp`) and checks it.
fn download(
    package: &Package,
    file: File,
    temp: &Path,
    progress: &mut dyn FnMut(Step),
) -> Result<(), UpdateError> {
    // github.com sends the file on to its file store: HTTPS only, as every update download.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(4)
        .timeout_global(Some(Duration::from_secs(30 * 60)))
        .user_agent(USER_AGENT)
        .build()
        .into();
    let answer = with_retries(&RETRY_WAITS, || agent.get(&package.url).call())
        .map_err(|err| UpdateError::Network(format!("{NETWORK}{err}")))?;
    let body = answer.into_body().into_reader();
    write_checked(body, package, file, progress)?;
    // Written and checked: read back once more, as it now is on disk.
    progress(Step::Check);
    check_file(temp, package)
}

/// Copies `body` into `file`, at most the size `package` lists, telling the progress as it
/// goes; then checks the size and SHA-256 of what came.
pub fn write_checked(
    mut body: impl Read,
    package: &Package,
    mut file: File,
    progress: &mut dyn FnMut(Step),
) -> Result<(), UpdateError> {
    let total = package.size;
    let mut done: u64 = 0;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    progress(Step::Download { done, total });
    loop {
        let read = match body.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(UpdateError::Network(format!("{NETWORK}{err}"))),
        };
        done += read as u64;
        if done > total {
            return Err(UpdateError::Refused(
                "the program downloaded is larger than the release's manifest lists".into(),
            ));
        }
        hasher.update(&buffer[..read]);
        file.write_all(&buffer[..read])
            .map_err(|err| UpdateError::Install(err.to_string()))?;
        progress(Step::Download { done, total });
    }
    if done != total {
        return Err(UpdateError::Refused(
            "the program downloaded isn't the size the release's manifest lists".into(),
        ));
    }
    file.sync_all()
        .map_err(|err| UpdateError::Install(err.to_string()))?;
    drop(file);
    let got = hex(&hasher.finalize());
    if got != package.sha256 {
        return Err(UpdateError::Refused(
            "the program downloaded isn't the one the release's manifest lists (SHA-256 differs)"
                .into(),
        ));
    }
    Ok(())
}

/// Whether the file at `path` is `package`: its size and SHA-256.
pub fn check_file(path: &Path, package: &Package) -> Result<(), UpdateError> {
    let mut file = File::open(path).map_err(|err| UpdateError::Install(err.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut size: u64 = 0;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| UpdateError::Install(err.to_string()))?;
        if read == 0 {
            break;
        }
        size += read as u64;
        if size > package.size {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if size != package.size || hex(&hasher.finalize()) != package.sha256 {
        return Err(UpdateError::Refused(
            "the program on disk isn't the one the release's manifest lists".into(),
        ));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Puts `new` in `exe`'s place, `exe` renamed aside; undone when the second step fails.
pub fn swap(exe: &Path, new: &Path) -> Result<(), String> {
    swap_with(exe, new, &mut |from, to| fs::rename(from, to))
}

/// [`swap`], with the renames made by `rename` (the tests make one fail).
pub fn swap_with(
    exe: &Path,
    new: &Path,
    rename: &mut dyn FnMut(&Path, &Path) -> io::Result<()>,
) -> Result<(), String> {
    let old = free_old_path(exe);
    if let Err(err) = rename(exe, &old) {
        let _ = fs::remove_file(new);
        return Err(format!(
            "the running program couldn't be moved aside: {err}"
        ));
    }
    if let Err(err) = rename(new, exe) {
        let _ = fs::remove_file(new);
        return match rename(&old, exe) {
            Ok(()) => Err(format!("the new program couldn't be put in place: {err}")),
            Err(back) => Err(format!(
                "the new program couldn't be put in place ({err}), and the running one couldn't \
                 be put back ({back}): it is at {}",
                old.display()
            )),
        };
    }
    Ok(())
}

/// Where to rename `exe` aside: `.old`, or `.old-2`… when an earlier one is still in use.
fn free_old_path(exe: &Path) -> PathBuf {
    let first = old_path(exe);
    if remove_if_there(&first) {
        return first;
    }
    for n in 2..100 {
        let path = sibling(exe, &format!("{OLD}-{n}"));
        if remove_if_there(&path) {
            return path;
        }
    }
    first
}

/// Whether `path` is free now (it wasn't there, or it was deleted).
fn remove_if_there(path: &Path) -> bool {
    match fs::remove_file(path) {
        Ok(()) => true,
        Err(err) => err.kind() == io::ErrorKind::NotFound,
    }
}

/// Deletes what an update left next to `exe`: the program renamed aside, and a download that
/// didn't finish. Answers how many files went. Those still in use stay for the next start.
pub fn clean_leftovers(exe: &Path) -> usize {
    let (Some(folder), Some(name)) = (exe.parent(), exe.file_name()) else {
        return 0;
    };
    let name = name.to_string_lossy().to_lowercase();
    let Ok(entries) = fs::read_dir(folder) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let file = entry.file_name().to_string_lossy().to_lowercase();
        let Some(rest) = file.strip_prefix(&name) else {
            continue;
        };
        let ours = rest == DOWNLOAD
            || rest == OLD
            || rest
                .strip_prefix(OLD)
                .and_then(|n| n.strip_prefix('-'))
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if ours
            && entry.file_type().is_ok_and(|kind| kind.is_file())
            && fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// Waits up to `timeout` for process `pid` to end (the copy that started this one after an
/// update). Answers whether it ended (or wasn't running).
pub fn wait_for_exit(pid: u32, timeout: Duration) -> bool {
    imp::wait_for_exit(pid, timeout)
}

/// The argument a copy started after an update gets, followed by the old copy's process id.
pub const AFTER_UPDATE: &str = "--after-update";

/// The old copy's process id, when the arguments `args` (without the program) say this copy
/// was started after an update.
pub fn after_update(args: impl IntoIterator<Item = std::ffi::OsString>) -> Option<u32> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == AFTER_UPDATE {
            return args.next()?.to_str()?.parse().ok();
        }
    }
    None
}

#[cfg(windows)]
mod imp {
    use std::time::Duration;

    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };

    pub(super) fn wait_for_exit(pid: u32, timeout: Duration) -> bool {
        // SAFETY: OpenProcess takes plain values; a null handle means there is no such process
        // (or it can't be waited for), checked before any use.
        #[allow(unsafe_code)]
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        if handle.is_null() {
            return true;
        }
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: the handle is open until CloseHandle below, called once.
        #[allow(unsafe_code)]
        let woke = unsafe {
            let woke = WaitForSingleObject(handle, millis);
            CloseHandle(handle);
            woke
        };
        woke == WAIT_OBJECT_0
    }
}

#[cfg(not(windows))]
mod imp {
    use std::time::Duration;

    /// Only the Windows app replaces itself for now.
    pub(super) fn wait_for_exit(_pid: u32, _timeout: Duration) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use vault_sync_wire::releases::{
        DESKTOP_EXE,
        testing::{TestKey, sha256, verified},
    };

    use super::*;

    fn package(bytes: &[u8]) -> Package {
        Package {
            name: DESKTOP_EXE.into(),
            size: bytes.len() as u64,
            sha256: sha256(bytes),
            url: "https://github.com/o/r/releases/download/v9.0.0/vault-desktop.exe".into(),
        }
    }

    fn folder() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join(DESKTOP_EXE);
        fs::write(&exe, b"MZ the running program").unwrap();
        (dir, exe)
    }

    /// Writes `bytes` as the download of `listed` would, and answers what `write_checked` said.
    fn download_of(bytes: &[u8], listed: &Package, exe: &Path) -> Result<(), UpdateError> {
        let temp = download_path(exe);
        let file = create(&temp, exe).unwrap();
        let mut steps = Vec::new();
        let got = write_checked(bytes, listed, file, &mut |step| steps.push(step));
        assert_eq!(
            steps[0],
            Step::Download {
                done: 0,
                total: listed.size
            }
        );
        got
    }

    #[test]
    fn a_download_is_taken_only_as_the_manifest_lists_it() {
        let (_dir, exe) = folder();
        let program: &[u8] = b"MZ the new program";
        let listed = package(program);
        assert_eq!(download_of(program, &listed, &exe), Ok(()));
        assert_eq!(check_file(&download_path(&exe), &listed), Ok(()));

        // Other bytes of the same size: the SHA-256 differs.
        let swapped: &[u8] = b"MZ the bad program";
        assert_eq!(swapped.len(), program.len());
        assert!(matches!(
            download_of(swapped, &listed, &exe),
            Err(UpdateError::Refused(why)) if why.contains("SHA-256")
        ));
        // Shorter, or longer, than listed.
        assert!(matches!(
            download_of(&program[..10], &listed, &exe),
            Err(UpdateError::Refused(why)) if why.contains("size")
        ));
        let longer = [program, b"and more"].concat();
        assert!(matches!(
            download_of(&longer, &listed, &exe),
            Err(UpdateError::Refused(why)) if why.contains("larger")
        ));
        // A file changed on disk after the download is refused before it is installed.
        fs::write(download_path(&exe), b"MZ changed on disk").unwrap();
        assert!(check_file(&download_path(&exe), &listed).is_err());
    }

    #[test]
    fn the_progress_counts_the_bytes() {
        let (_dir, exe) = folder();
        let program = vec![7u8; CHUNK * 2 + 10];
        let listed = package(&program);
        let file = create(&download_path(&exe), &exe).unwrap();
        let mut steps = Vec::new();
        write_checked(program.as_slice(), &listed, file, &mut |step| {
            steps.push(step)
        })
        .unwrap();
        let total = program.len() as u64;
        assert_eq!(steps.first(), Some(&Step::Download { done: 0, total }));
        assert_eq!(steps.last(), Some(&Step::Download { done: total, total }));
        assert!(steps.windows(2).all(|pair| match pair {
            [
                Step::Download { done: a, .. },
                Step::Download { done: b, .. },
            ] => a < b,
            _ => false,
        }));
    }

    /// A release without the program, one whose manifest doesn't list it, and one that isn't
    /// newer: refused before anything is written.
    #[test]
    fn a_release_is_installed_only_when_newer_and_listed() {
        let (dir, exe) = folder();
        let key = TestKey::new();
        let program: &[u8] = b"MZ the new program";
        let mut steps = 0;
        let mut count = |_: Step| steps += 1;

        let same = verified("1.0.0", &[(DESKTOP_EXE, program)], &key);
        assert_eq!(
            install(&same, &exe, "1.0.0", &mut count),
            Err(UpdateError::NotNewer)
        );
        let older = verified("0.9.0", &[(DESKTOP_EXE, program)], &key);
        assert_eq!(
            install(&older, &exe, "1.0.0", &mut count),
            Err(UpdateError::NotNewer)
        );
        let without = verified("2.0.0", &[("vault.exe", program)], &key);
        assert!(matches!(
            install(&without, &exe, "1.0.0", &mut count),
            Err(UpdateError::Refused(why)) if why.contains(DESKTOP_EXE)
        ));
        assert_eq!(steps, 0);
        assert_eq!(fs::read(&exe).unwrap(), b"MZ the running program");
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "nothing written"
        );
    }

    #[test]
    fn the_new_program_takes_the_running_ones_place() {
        let (dir, exe) = folder();
        let new = download_path(&exe);
        fs::write(&new, b"MZ the new program").unwrap();
        swap(&exe, &new).unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"MZ the new program");
        assert_eq!(fs::read(old_path(&exe)).unwrap(), b"MZ the running program");
        assert!(!new.exists());

        // The next start deletes what is left; another program in the folder stays.
        fs::write(dir.path().join("notes.txt"), b"mine").unwrap();
        fs::write(dir.path().join("vault-desktop.exe.old-2"), b"MZ").unwrap();
        fs::write(dir.path().join("vault-desktop.exe.older"), b"not ours").unwrap();
        fs::write(&new, b"half a download").unwrap();
        assert_eq!(clean_leftovers(&exe), 3);
        let mut left: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            ["notes.txt", "vault-desktop.exe", "vault-desktop.exe.older"]
        );
    }

    #[test]
    fn a_swap_that_fails_is_undone() {
        let (dir, exe) = folder();
        let new = download_path(&exe);

        // The new program can't be put in place: the running one is put back.
        fs::write(&new, b"MZ the new program").unwrap();
        let mut calls = 0;
        let got = swap_with(&exe, &new, &mut |from, to| {
            calls += 1;
            if calls == 2 {
                Err(io::Error::other("refused"))
            } else {
                fs::rename(from, to)
            }
        });
        assert!(got.unwrap_err().contains("couldn't be put in place"));
        assert_eq!(calls, 3, "moved aside, refused, put back");
        assert_eq!(fs::read(&exe).unwrap(), b"MZ the running program");
        assert!(!new.exists(), "the download is deleted");
        assert!(!old_path(&exe).exists());

        // The running program can't be moved aside: nothing moved.
        fs::write(&new, b"MZ the new program").unwrap();
        let got = swap_with(&exe, &new, &mut |_, _| Err(io::Error::other("in use")));
        assert!(got.unwrap_err().contains("moved aside"));
        assert_eq!(fs::read(&exe).unwrap(), b"MZ the running program");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn started_after_an_update_names_the_old_copy() {
        let args =
            |list: &[&str]| -> Vec<std::ffi::OsString> { list.iter().map(Into::into).collect() };
        assert_eq!(after_update(args(&[AFTER_UPDATE, "4242"])), Some(4242));
        assert_eq!(after_update(args(&["--at-sign-in"])), None);
        assert_eq!(after_update(args(&[AFTER_UPDATE])), None);
        assert_eq!(after_update(args(&[AFTER_UPDATE, "x"])), None);
    }

    #[test]
    fn a_process_that_isnt_running_has_ended() {
        // Process ids are multiples of four on Windows: this one is never given.
        assert!(wait_for_exit(u32::MAX - 2, Duration::from_millis(10)));
    }
}
