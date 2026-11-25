//! Files that hold secrets for a short time (the printable kit) and handing a file to the OS.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::paths;

/// Seals the file at `path` again under the vault's key, after a renewal of the vault key
/// (`Vault::renew_key`, `Vault::adopt_key`): all of it was sealed with `Vault::seal_local` for
/// `purpose` under `former`. Its `.bak` copy (still under the former key) goes. A file that
/// isn't there, or that the former key doesn't open, is left as it is; `true` when it was
/// sealed again.
pub fn reseal(
    path: &Path,
    vault: &vault_core::Vault,
    former: &vault_core::FormerKey,
    purpose: &str,
) -> bool {
    let Ok(sealed) = std::fs::read(path) else {
        return false;
    };
    let Ok(again) = vault.reseal_local(former, purpose, &sealed) else {
        return false;
    };
    if vault_core::storage::write_atomic(path, &again).is_err() {
        return false;
    }
    let _ = std::fs::remove_file(vault_core::storage::backup_path(path));
    true
}

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
///
/// A link (symbolic link or junction) is refused and left alone: writing through it would
/// zero whatever file it points at, and deleting only the link would leave the real file.
pub fn wipe(path: &Path) -> Result<()> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    if is_link(&meta) {
        anyhow::bail!(
            "{} is a link, not the file itself: nothing was wiped",
            path.display()
        );
    }
    if meta.is_file()
        && let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path)
    {
        let _ = overwrite_with_zeros(&mut file, meta.len());
    }
    std::fs::remove_file(path).context("cannot delete the file")?;
    Ok(())
}

/// [`wipe`], only when the file still holds `expected`: the bytes read from it before (an
/// export just imported). A file put in its place meanwhile (in a shared or synced folder,
/// say) is left alone, and the error says so. It is an error too when no file is there any
/// more, or it can't be looked at: one moved elsewhere still holds the passwords, so `Ok` means
/// it was wiped (the `std::io::Error` is in the error, for a caller that words "gone" itself).
/// The check and the overwrite go through one open handle, so what is zeroed is what was
/// compared.
pub fn wipe_if_same(path: &Path, expected: &[u8]) -> Result<()> {
    use std::io::{ErrorKind, Read, Seek, SeekFrom};
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) => {
            let why = match err.kind() {
                ErrorKind::NotFound => "is not there any more",
                _ => "can't be looked at",
            };
            let message = format!("{} {why}: nothing was wiped", path.display());
            return Err(anyhow::Error::new(err).context(message));
        }
    };
    if is_link(&meta) || !meta.is_file() {
        anyhow::bail!(
            "{} is not the file that was read: nothing was wiped",
            path.display()
        );
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .context("cannot open the file")?;
    // One byte more than expected, so that a longer file shows, and of that size from the
    // start: a buffer that grows leaves copies of the passwords behind.
    let mut now = zeroize::Zeroizing::new(vec![0; expected.len() + 1]);
    let mut read = 0;
    while read < now.len() {
        match file.read(&mut now[read..]) {
            Ok(0) => break,
            Ok(more) => read += more,
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(err).context("cannot read the file"),
        }
    }
    if &now[..read] != expected {
        anyhow::bail!(
            "{} changed since it was read: nothing was wiped",
            path.display()
        );
    }
    file.seek(SeekFrom::Start(0))?;
    overwrite_with_zeros(&mut file, expected.len() as u64)?;
    drop(file);
    std::fs::remove_file(path).context("cannot delete the file")?;
    Ok(())
}

/// Writes `len` zero bytes from the start of `file` and flushes them.
pub fn overwrite_with_zeros(file: &mut std::fs::File, len: u64) -> std::io::Result<()> {
    let zeros = vec![0u8; 64 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    file.sync_all()
}

/// Whether `meta` (from `symlink_metadata`) describes a link rather than the file itself.
pub fn is_link(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink() || is_reparse_point(meta)
}

/// Windows: junctions and other reparse points count as links too.
#[cfg(windows)]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_: &std::fs::Metadata) -> bool {
    false
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
    fn a_file_sealed_under_the_former_key_is_sealed_again() {
        use vault_core::{KdfParams, SecretKey, Vault};
        let secret_key = SecretKey::generate().unwrap();
        let mut vault = Vault::create(
            "test master password",
            &secret_key,
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.bin");
        std::fs::write(&path, vault.seal_local("test", b"kept here").unwrap()).unwrap();
        let renewed = vault
            .renew_key("test master password", &secret_key, None)
            .unwrap();
        assert!(reseal(&path, &vault, &renewed.former, "test"));
        let sealed = std::fs::read(&path).unwrap();
        assert_eq!(
            vault.open_local("test", &sealed).unwrap().as_slice(),
            b"kept here"
        );
        assert!(!vault_core::storage::backup_path(&path).exists());
        // Once is enough: under the new key, the former one opens it no more.
        assert!(!reseal(&path, &vault, &renewed.former, "test"));
        assert!(!reseal(
            &dir.path().join("missing.bin"),
            &vault,
            &renewed.former,
            "test"
        ));
    }

    #[test]
    fn wipe_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kit.pdf");
        std::fs::write(&path, b"secret").unwrap();
        wipe(&path).unwrap();
        assert!(!path.exists());
        wipe(&path).unwrap(); // missing file: fine
    }

    #[test]
    fn only_the_file_that_was_read_is_wiped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        std::fs::write(&path, b"name,password\nmail,pw1\n").unwrap();
        let read = std::fs::read(&path).unwrap();
        // Put in its place before the wipe was approved: left alone.
        std::fs::write(&path, b"someone else's file").unwrap();
        assert!(wipe_if_same(&path, &read).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"someone else's file");
        // A longer file that starts the same is another file too.
        std::fs::write(&path, [read.as_slice(), b"more"].concat()).unwrap();
        assert!(wipe_if_same(&path, &read).is_err());
        assert!(path.exists());
        // The very file read: wiped.
        std::fs::write(&path, &read).unwrap();
        wipe_if_same(&path, &read).unwrap();
        assert!(!path.exists());
    }

    /// A file moved or renamed before the wipe still holds the passwords somewhere: it is not
    /// reported as wiped.
    #[test]
    fn a_file_that_is_gone_is_not_reported_as_wiped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        let moved = dir.path().join("moved.csv");
        std::fs::write(&path, b"name,password\nmail,pw1\n").unwrap();
        let read = std::fs::read(&path).unwrap();
        std::fs::rename(&path, &moved).unwrap();
        let err = wipe_if_same(&path, &read).unwrap_err();
        assert!(err.to_string().contains("nothing was wiped"), "{err}");
        assert!(!format!("{err:#}").contains("pw1"));
        assert_eq!(
            err.downcast_ref::<std::io::Error>().map(|e| e.kind()),
            Some(std::io::ErrorKind::NotFound),
            "a caller can tell it is gone"
        );
        assert_eq!(std::fs::read(&moved).unwrap(), read);
        // A folder there instead: not wiped either.
        std::fs::create_dir(&path).unwrap();
        assert!(wipe_if_same(&path, &read).is_err());
        assert!(path.is_dir());
    }

    #[test]
    fn the_comparison_covers_every_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        std::fs::write(&path, b"").unwrap();
        wipe_if_same(&path, b"").unwrap();
        assert!(!path.exists());
        std::fs::write(&path, b"longer").unwrap();
        assert!(wipe_if_same(&path, b"").is_err());
        assert!(wipe_if_same(&path, b"longeR").is_err());
        assert!(wipe_if_same(&path, b"longer and longer").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"longer");
        wipe_if_same(&path, b"longer").unwrap();
        assert!(!path.exists());
    }
}
