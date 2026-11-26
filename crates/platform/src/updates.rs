//! The project's releases on GitHub, as the apps ask for them: the desktop's "Check for
//! updates" (Settings → About) and the phone's updates when they come from GitHub (the phone's
//! default; Settings → About and updates). Asked only when the person presses the button, or
//! by the phone at most every few hours while a vault is open when its updates come from GitHub
//! (AGENTS.md §4.1, rule 5): anonymous HTTPS requests to GitHub, nothing about the vault or this
//! device in them. The answer is read and checked by `vault_sync_wire::releases`.
//!
//! The phone's package is taken only as GitHub lists it in the release (its size and SHA-256),
//! and Android installs it only when it is this app, newer, and signed with the same
//! certificate as the app already installed (the phone checks that before Android's installer
//! gets it, and Android checks it again).

use std::{io::Read, time::Duration};

use sha2::{Digest, Sha256};
use vault_sync_wire::{
    MAX_APP_BYTES,
    releases::{self, Release},
};

const USER_AGENT: &str = "vault-password-manager";

/// The newest release of the project. Blocks: call it off the UI thread.
pub fn latest() -> Result<Release, String> {
    // GitHub's API answers directly: no redirect is followed.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(20)))
        .user_agent(USER_AGENT)
        .build()
        .into();
    let mut response = agent
        .get(releases::latest_url(releases::REPOSITORY))
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| e.to_string())?;
    let body = response
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_vec()
        .map_err(|e| e.to_string())?;
    Release::parse(&body).ok_or_else(|| "GitHub's answer isn't a release".to_owned())
}

/// The phone app's package of `release`, downloaded and checked against what the release lists
/// for it (size and SHA-256). Blocks: call it off the UI thread.
pub fn phone_package(release: &Release) -> Result<Vec<u8>, String> {
    let asset = release
        .phone_package()
        .ok_or_else(|| format!("release {} has no phone app", release.version))?;
    let expected = asset.sha256.as_deref().ok_or("no SHA-256 listed")?;
    let size = usize::try_from(asset.size).map_err(|_| "the package is too large")?;
    if size > MAX_APP_BYTES {
        return Err("the package is too large".into());
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        // github.com sends a package on to its file store.
        .max_redirects(4)
        .timeout_global(Some(Duration::from_secs(15 * 60)))
        .user_agent(USER_AGENT)
        .build()
        .into();
    let response = agent.get(&asset.url).call().map_err(|e| e.to_string())?;
    let mut bytes = Vec::with_capacity(size);
    response
        .into_body()
        .into_reader()
        .take(asset.size + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    check_package(&bytes, asset.size, expected)?;
    Ok(bytes)
}

/// Whether `bytes` are the package a release lists: `size` bytes with SHA-256 `sha256`.
fn check_package(bytes: &[u8], size: u64, sha256: &str) -> Result<(), String> {
    if u64::try_from(bytes.len()).ok() != Some(size) {
        return Err("the package downloaded isn't the size GitHub lists".into());
    }
    let got: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != sha256 {
        return Err("the package downloaded isn't the one GitHub lists (SHA-256 differs)".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_package_is_taken_only_as_the_release_lists_it() {
        let bytes = b"a test package";
        let sha256: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(check_package(bytes, 14, &sha256).is_ok());
        assert!(check_package(bytes, 15, &sha256).is_err(), "another size");
        assert!(
            check_package(b"a test packagE", 14, &sha256).is_err(),
            "other bytes"
        );
        assert!(
            check_package(bytes, 14, &"0".repeat(64)).is_err(),
            "another digest"
        );
    }
}
