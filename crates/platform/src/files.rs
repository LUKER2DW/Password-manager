//! Files that hold secrets for a short time (the printable kit) and handing a file to the OS.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::paths;

/// Folder for files made only to be printed. Emptied (overwritten, then deleted) on lock, on
/// exit and at the next start.
pub fn print_dir() -> Result<PathBuf> {
    Ok(paths::app_dir()?.join("print"))
}

/// Writes `bytes` to a new file in [`print_dir`] and returns its path.
pub fn write_for_printing(name: &str, bytes: &[u8]) -> Result<PathBuf> {
    let dir = print_dir()?;
    std::fs::create_dir_all(&dir).context("cannot create the print folder")?;
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).context("cannot create the file to print")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(path)
}

/// Overwrites a file with zeros and deletes it. On SSDs and copy-on-write file systems the old
/// blocks may survive until reused; this still removes the obvious copy.
pub fn wipe(path: &Path) -> Result<()> {
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; usize::try_from(meta.len()).unwrap_or(0).min(16 << 20)];
            let _ = file.write_all(&zeros);
            let _ = file.sync_all();
        }
        std::fs::remove_file(path).context("cannot delete the file")?;
    }
    Ok(())
}

/// Wipes everything left in [`print_dir`]. Files still open in a viewer may fail to delete;
/// they are retried next time.
pub fn wipe_print_dir() {
    let Ok(dir) = print_dir() else { return };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let _ = wipe(&entry.path());
    }
}

/// Opens a file with the app Windows associates with it (e.g. the PDF viewer, to print).
pub fn open_with_default_app(path: &Path) -> Result<()> {
    shell_open(path.as_os_str()).with_context(|| format!("no app could open {}", path.display()))
}

/// Opens a web address in the default browser. Only `http(s)://` links pass
/// (see [`crate::browsers::web_link`]); anything else is refused before reaching the shell.
pub fn open_web_link(text: &str) -> Result<()> {
    let link = crate::browsers::web_link(text).context("not a web address")?;
    shell_open(link.as_ref()).context("no browser could open it")
}

#[allow(unsafe_code)]
fn shell_open(target: &std::ffi::OsStr) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
        let wide = |s: &std::ffi::OsStr| s.encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let verb = wide("open".as_ref());
        let file = wide(target);
        // SAFETY: both strings are NUL-terminated UTF-16 buffers alive for the whole call; null
        // parameters/directory are allowed. The result is a status code, checked below.
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        // Values above 32 mean success.
        if result as usize > 32 {
            Ok(())
        } else {
            anyhow::bail!("the shell refused to open it")
        }
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("xdg-open")
            .arg(target)
            .spawn()
            .map(drop)
            .context("cannot open it")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kit.pdf");
        std::fs::write(&path, b"secret").unwrap();
        wipe(&path).unwrap();
        assert!(!path.exists());
        wipe(&path).unwrap(); // missing file: fine
    }
}
