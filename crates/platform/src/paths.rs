//! Where the app keeps its files on this device.

use std::path::PathBuf;

use anyhow::{Context, Result};

const APP_DIR: &str = "vault";

/// App data directory: `<local data dir>/vault`. `VAULT_HOME` overrides it (portable use, tests).
pub fn app_dir() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("VAULT_HOME") {
        return Ok(PathBuf::from(home));
    }
    let base = dirs::data_local_dir().context("cannot determine the local data directory")?;
    Ok(base.join(APP_DIR))
}

/// Word lists the user added for passphrases (`<app dir>/wordlists`).
pub fn wordlists_dir() -> Result<PathBuf> {
    Ok(app_dir()?.join("wordlists"))
}

/// Default vault file: `<app dir>/default.vault`. `VAULT_FILE` overrides it.
pub fn default_vault_path() -> Result<PathBuf> {
    if let Some(file) = std::env::var_os("VAULT_FILE") {
        return Ok(PathBuf::from(file));
    }
    Ok(app_dir()?.join("default.vault"))
}
