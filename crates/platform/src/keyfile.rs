//! Keyfiles on disk: reading one, creating one, and remembering where a vault's keyfile is.
//!
//! Only the *location* is remembered on the device (so the app can find the file again); the
//! key itself stays in the file. Kept on removable storage, the keyfile is a real third factor:
//! without the stick plugged in, the vault doesn't open.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use vault_core::Keyfile;
use zeroize::Zeroizing;

use crate::DeviceState;

/// Reads a keyfile (at most [`Keyfile::MAX_LEN`] bytes are accepted).
pub fn read(path: &Path) -> Result<Keyfile> {
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(Keyfile::MAX_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    Keyfile::from_bytes(&bytes).map_err(|_| {
        anyhow::anyhow!(
            "{} can't be a keyfile: it must hold between {} bytes and 1 MiB",
            path.display(),
            Keyfile::MIN_LEN
        )
    })
}

/// Writes a new random keyfile. Never overwrites: an existing file there is an error.
pub fn create(path: &Path) -> Result<Keyfile> {
    let (keyfile, bytes) = Keyfile::generate().context("no randomness for a keyfile")?;
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("{} already exists; choose a new file name", path.display())
        }
        Err(err) => return Err(err).with_context(|| format!("cannot create {}", path.display())),
    };
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(keyfile)
}

/// Where this device last found the vault's keyfile.
pub fn remembered_path(vault_id: &str) -> Option<PathBuf> {
    DeviceState::load().ok()?.keyfile_path(vault_id)
}

/// Remembers (or with `None` forgets) where the vault's keyfile is.
pub fn remember_path(vault_id: &str, path: Option<&Path>) -> Result<()> {
    let mut state = DeviceState::load()?;
    state.set_keyfile_path(vault_id, path);
    state.save()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_read_gives_the_same_key_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("my.keyfile");
        let created = create(&path).unwrap();
        let read_back = read(&path).unwrap();
        // Same key: both open the same vault.
        let secret_key = vault_core::SecretKey::generate().unwrap();
        let kdf = vault_core::KdfParams::minimum().unwrap();
        let mut vault = vault_core::Vault::create("pw", &secret_key, None, kdf.clone()).unwrap();
        vault
            .change_password("pw", &secret_key, Some(&created), &kdf)
            .unwrap();
        let bytes = vault.to_bytes().unwrap();
        vault_core::Vault::open(
            &bytes,
            vault_core::Unlock::PasswordAndKeyfile {
                password: "pw",
                secret_key: &secret_key,
                keyfile: &read_back,
            },
        )
        .unwrap();

        assert!(create(&path).is_err(), "an existing file is never replaced");
        std::fs::write(dir.path().join("tiny"), b"abc").unwrap();
        assert!(read(&dir.path().join("tiny")).is_err());
        assert!(read(&dir.path().join("missing")).is_err());
    }
}
