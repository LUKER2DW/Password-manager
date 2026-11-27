//! The project's releases on GitHub, as the apps ask for them: the desktop's updates (Settings
//! → About) and the phone's when they come from GitHub (the phone's default; Settings → About
//! and updates). Asked on the button, and every hour while the app runs unless the person turns
//! that off (AGENTS.md §4.1, rule 5): anonymous HTTPS requests to GitHub, nothing about the
//! vault or this device in them. The answer is read and checked by `vault_sync_wire::releases`.
//! A request the network failed (a name that didn't resolve, a connection that didn't open) is
//! made again after a moment: a phone's DNS often fails for a second, for every app on it.
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

/// How long to wait before each further try of a request the network failed.
const RETRY_WAITS: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(5)];

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
    let body = with_retries(&RETRY_WAITS, || {
        agent
            .get(releases::latest_url(releases::REPOSITORY))
            .header("Accept", "application/vnd.github+json")
            .call()?
            .body_mut()
            .with_config()
            .limit(1024 * 1024)
            .read_to_vec()
    })?;
    Release::parse(&body).ok_or_else(|| "GitHub's answer isn't a release".to_owned())
}

/// The phone app's package of `release`, downloaded and checked against what the release lists
/// for it (size and SHA-256). Blocks: call it off the UI thread.
pub fn phone_package(release: &Release) -> Result<Vec<u8>, String> {
    let asset = release
        .phone_package()
        .ok_or_else(|| format!("release {} has no phone app", release.version))?;
    download(asset, MAX_APP_BYTES)
}

/// Why the extension's zip of a release wasn't had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageError {
    /// The release lists none (or none with a SHA-256): nothing to take.
    None,
    /// What came isn't what the release lists (size or SHA-256), or GitHub refused: said.
    Refused(String),
    /// The network failed: tried again at the next look.
    Network(String),
}

/// The browser extension's zip of `release` (`vault-extension-<version>.zip`), downloaded and
/// checked against what the release lists for it (size and SHA-256), like the phone's package.
/// Blocks: call it off the UI thread.
pub fn extension_package(release: &Release) -> Result<Vec<u8>, PackageError> {
    let asset = release.extension_package().ok_or(PackageError::None)?;
    download(asset, releases::MAX_EXTENSION_BYTES).map_err(|err| {
        if err.starts_with(NETWORK) {
            PackageError::Network(err)
        } else {
            PackageError::Refused(err)
        }
    })
}

/// How a failure of the network starts, in [`download`]'s errors.
const NETWORK: &str = "the network failed: ";

/// `asset`, downloaded (at most `max` bytes) and checked against what the release lists for
/// it.
fn download(asset: &releases::Asset, max: usize) -> Result<Vec<u8>, String> {
    let expected = asset.sha256.as_deref().ok_or("no SHA-256 listed")?;
    let size = usize::try_from(asset.size).map_err(|_| "the package is too large")?;
    if size > max {
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
    let mut failed_network = false;
    let bytes = with_retries(&RETRY_WAITS, || {
        let mut bytes = Vec::with_capacity(size);
        let got = agent.get(&asset.url).call().and_then(|answer| {
            answer
                .into_body()
                .into_reader()
                .take(asset.size + 1)
                .read_to_end(&mut bytes)
                .map_err(ureq::Error::from)
        });
        failed_network = got.as_ref().is_err_and(network_failed);
        got.map(|_| bytes)
    })
    .map_err(|err| {
        if failed_network {
            format!("{NETWORK}{err}")
        } else {
            err
        }
    })?;
    check_package(&bytes, asset.size, expected)?;
    Ok(bytes)
}

/// Makes `request`, and again after each of `waits` while the network fails it. What the
/// server answered (an HTTP error, a body too large) is never asked again.
fn with_retries<T>(
    waits: &[Duration],
    mut request: impl FnMut() -> Result<T, ureq::Error>,
) -> Result<T, String> {
    let mut waits = waits.iter();
    loop {
        match request() {
            Ok(value) => return Ok(value),
            Err(err) => match waits.next() {
                Some(wait) if network_failed(&err) => std::thread::sleep(*wait),
                _ => return Err(err.to_string()),
            },
        }
    }
}

/// The network failed the request: the name didn't resolve, the connection didn't open or
/// broke off. A timeout isn't tried again (the next would take as long).
fn network_failed(err: &ureq::Error) -> bool {
    matches!(
        err,
        ureq::Error::Io(_) | ureq::Error::HostNotFound | ureq::Error::ConnectionFailed
    )
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
    fn a_request_the_network_failed_is_made_again_an_answer_is_not() {
        let no_wait = [Duration::ZERO; 2];
        let mut tries = 0;
        let got = with_retries(&no_wait, || {
            tries += 1;
            if tries < 3 {
                Err(ureq::Error::HostNotFound)
            } else {
                Ok(tries)
            }
        });
        assert_eq!(got, Ok(3), "a name that didn't resolve, twice");

        let mut tries = 0;
        let got: Result<(), String> = with_retries(&no_wait, || {
            tries += 1;
            Err(ureq::Error::ConnectionFailed)
        });
        assert!(got.is_err());
        assert_eq!(tries, 3, "three tries, then the error");

        let mut tries = 0;
        let got: Result<(), String> = with_retries(&no_wait, || {
            tries += 1;
            Err(ureq::Error::StatusCode(404))
        });
        assert!(got.is_err());
        assert_eq!(tries, 1, "GitHub's answer isn't asked again");
    }

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
