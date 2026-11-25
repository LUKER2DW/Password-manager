//! Crash-safe file storage for vault files (spec: VAULT_FORMAT.md §5).

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::Result;

/// Reads a vault file.
pub fn read(path: &Path) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

/// What a file holds, in 32 bytes: compared before a save to notice that someone else wrote
/// the file since it was read (AGENTS.md §4.1, rule 7).
pub fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Writes `bytes` to `path` atomically:
/// 1. write and flush a new temporary file next to it (a fresh random name, created only if
///    nothing is there, so a file or link left in the folder is never written through),
/// 2. copy the current file (if any) to `<path>.bak`, as a new file in place of the old one,
/// 3. rename the temporary file over `path`.
///
/// A crash at any point leaves either the old or the new file intact.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = temp_path(path)?;
    let result = write_new(&tmp, bytes).and_then(|()| {
        if path.exists() {
            replace_backup(path)?;
        }
        fs::rename(&tmp, path)
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    Ok(result?)
}

/// [`write_atomic`], only while `path` still holds what was read from it (`expected`, its
/// [`fingerprint`]): someone else's save in the meantime is never written over (AGENTS.md
/// §4.1, rule 7).
///
/// The file is compared when the new bytes are already on disk, and once more right before
/// the rename, so the only moment left unchecked is the rename itself. The `.bak` copy is
/// made from the bytes compared, never from another writer's file.
///
/// # Errors
/// [`Error::FileChanged`](crate::Error::FileChanged) when the file holds anything else (or is
/// gone): nothing was written, and no temporary file is left.
pub fn write_atomic_if_unchanged(path: &Path, expected: &[u8; 32], bytes: &[u8]) -> Result<()> {
    write_checked(path, expected, bytes, || {})
}

/// [`write_atomic_if_unchanged`], with `before_rename` run between the last two steps (the
/// tests change the file there).
fn write_checked(
    path: &Path,
    expected: &[u8; 32],
    bytes: &[u8],
    before_rename: impl FnOnce(),
) -> Result<()> {
    let still = || -> Result<Vec<u8>> {
        let now = match fs::read(path) {
            Ok(now) => now,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(crate::Error::FileChanged);
            }
            Err(err) => return Err(err.into()),
        };
        if fingerprint(&now) != *expected {
            return Err(crate::Error::FileChanged);
        }
        Ok(now)
    };
    let tmp = temp_path(path)?;
    let result = (|| -> Result<()> {
        write_new(&tmp, bytes)?;
        let current = still()?;
        write_backup(path, &current)?;
        before_rename();
        still()?;
        Ok(fs::rename(&tmp, path)?)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Location of the previous generation kept by [`write_atomic`].
pub fn backup_path(path: &Path) -> PathBuf {
    sibling(path, "bak")
}

/// Creates `path` (it must not exist) with `bytes`, flushed to disk.
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Copies the current file to `<path>.bak`. Whatever had that name goes first: removing a
/// link removes only the link, so the copy can't be sent to the file it points at.
fn replace_backup(path: &Path) -> io::Result<()> {
    let backup = backup_path(path);
    match fs::remove_file(&backup) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let mut from = File::open(path)?;
    let mut to = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&backup)?;
    io::copy(&mut from, &mut to)?;
    to.sync_all()
}

/// Writes `bytes` (what `path` holds now) as `<path>.bak`, the same way as `replace_backup`.
fn write_backup(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let backup = backup_path(path);
    match fs::remove_file(&backup) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    write_new(&backup, bytes)
}

/// `<file>.<random>.tmp` next to `path`.
fn temp_path(path: &Path) -> Result<PathBuf> {
    let random: [u8; 6] = crate::random::array()?;
    let tag: String = random.iter().map(|b| format!("{b:02x}")).collect();
    Ok(sibling(path, &format!("{tag}.tmp")))
}

fn sibling(path: &Path, extension: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(extension);
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn writes_and_keeps_one_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("my.vault");

        write_atomic(&path, b"first").unwrap();
        assert_eq!(read(&path).unwrap(), b"first");
        assert!(!backup_path(&path).exists());

        write_atomic(&path, b"second").unwrap();
        assert_eq!(read(&path).unwrap(), b"second");
        assert_eq!(read(&backup_path(&path)).unwrap(), b"first");

        write_atomic(&path, b"third").unwrap();
        assert_eq!(read(&backup_path(&path)).unwrap(), b"second");
        // Nothing temporary is left behind.
        assert_eq!(names(dir.path()), ["my.vault", "my.vault.bak"]);
    }

    #[test]
    fn a_file_left_at_the_old_temporary_name_is_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("my.vault");
        let planted = sibling(&path, "tmp");
        fs::write(&planted, b"someone else's").unwrap();

        write_atomic(&path, b"vault").unwrap();
        assert_eq!(read(&path).unwrap(), b"vault");
        assert_eq!(read(&planted).unwrap(), b"someone else's");
    }

    #[test]
    fn a_conditional_write_never_replaces_another_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("my.vault");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"as read").unwrap();
        let read = fingerprint(b"as read");

        // Saved by someone else before the write: refused, nothing touched.
        fs::write(&path, b"saved elsewhere").unwrap();
        let refused = write_atomic_if_unchanged(&path, &read, b"mine");
        assert!(matches!(refused, Err(crate::Error::FileChanged)));
        assert_eq!(read_back(&path), b"saved elsewhere");
        assert_eq!(read_back(&backup_path(&path)), b"first");
        assert_eq!(names(dir.path()), ["my.vault", "my.vault.bak"]);

        // Saved by someone else while the new file was being written, right before the
        // rename: still refused, their save stays.
        fs::write(&path, b"as read").unwrap();
        let refused = write_checked(&path, &read, b"mine", || {
            fs::write(&path, b"saved meanwhile").unwrap();
        });
        assert!(matches!(refused, Err(crate::Error::FileChanged)));
        assert_eq!(read_back(&path), b"saved meanwhile");
        assert_eq!(names(dir.path()), ["my.vault", "my.vault.bak"]);

        // A file that is gone counts as changed (it is not created).
        let missing = dir.path().join("gone.vault");
        assert!(matches!(
            write_atomic_if_unchanged(&missing, &read, b"mine"),
            Err(crate::Error::FileChanged)
        ));
        assert!(!missing.exists());

        // Unchanged: written, the backup is what was read.
        fs::write(&path, b"as read").unwrap();
        write_atomic_if_unchanged(&path, &read, b"mine").unwrap();
        assert_eq!(read_back(&path), b"mine");
        assert_eq!(read_back(&backup_path(&path)), b"as read");
        assert_eq!(names(dir.path()), ["my.vault", "my.vault.bak"]);
    }

    fn read_back(path: &Path) -> Vec<u8> {
        read(path).unwrap()
    }

    #[test]
    fn the_fingerprint_follows_the_bytes() {
        assert_eq!(fingerprint(b"a"), fingerprint(b"a"));
        assert_ne!(fingerprint(b"a"), fingerprint(b"b"));
    }
}
