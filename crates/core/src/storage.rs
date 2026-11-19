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
    fn the_fingerprint_follows_the_bytes() {
        assert_eq!(fingerprint(b"a"), fingerprint(b"a"));
        assert_ne!(fingerprint(b"a"), fingerprint(b"b"));
    }
}
