//! Crash-safe file storage for vault files (spec: VAULT_FORMAT.md §5).

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use crate::Result;

/// Reads a vault file.
pub fn read(path: &Path) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

/// Writes `bytes` to `path` atomically:
/// 1. write and flush `<path>.tmp`,
/// 2. copy the current file (if any) to `<path>.bak`,
/// 3. rename the temp file over `path`.
///
/// A crash at any point leaves either the old or the new file intact.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = sibling(path, "tmp");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if path.exists() {
        fs::copy(path, backup_path(path))?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Location of the previous generation kept by [`write_atomic`].
pub fn backup_path(path: &Path) -> PathBuf {
    sibling(path, "bak")
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
        assert!(!sibling(&path, "tmp").exists());
    }
}
