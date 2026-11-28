//! The project's releases on GitHub, as the apps ask for them: the desktop's updates (Settings
//! → About) and the phone's when they come from GitHub (the phone's default; Settings → About
//! and updates). Asked on the button, and every hour while the app runs unless the person turns
//! that off (AGENTS.md §4.1, rule 5): anonymous HTTPS requests to GitHub, nothing about the
//! vault or this device in them. The answer is read and checked by `vault_sync_wire::releases`.
//! A request the network failed (a name that didn't resolve, a connection that didn't open) is
//! made again after a moment: a phone's DNS often fails for a second, for every app on it.
//!
//! A release counts only with its manifest signed offline by one of
//! `releases::RELEASE_KEYS` (CRYPTO.md §9): [`latest`] downloads `manifest.json` and its
//! `manifest.json.minisig` with the release list and hands back the release only once they
//! check out, so no newer version is ever told or offered without them. A file is then taken
//! only as that manifest lists it (its size and SHA-256, which GitHub's own digest, when it
//! gives one, must agree with): the phone's package, and the browser extension's zip. Android
//! installs the package only when it is this app, newer, and signed with the same certificate
//! as the app already installed (the phone checks that before Android's installer gets it, and
//! Android checks it again).

use std::{io::Read, time::Duration};

use sha2::{Digest, Sha256};
use vault_sync_wire::{
    MAX_APP_BYTES,
    releases::{self, ManifestError, Package, Release, Verified},
};

const USER_AGENT: &str = "vault-password-manager";

/// How long to wait before each further try of a request the network failed.
const RETRY_WAITS: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(5)];

/// The newest release of the project, with its manifest checked against
/// `releases::RELEASE_KEYS`. Blocks: call it off the UI thread.
pub fn latest() -> Result<Verified, String> {
    let release = latest_unchecked()?;
    let version = release.version.clone();
    checked(release).map_err(|err| format!("release {version}: {err}"))
}

/// `release` with its manifest and signature downloaded and checked.
fn checked(release: Release) -> Result<Verified, String> {
    let (manifest, signature) = release.manifest_assets().map_err(|err| err.to_string())?;
    let manifest = fetch(&manifest.url, manifest.size, releases::MAX_MANIFEST_BYTES)?;
    let signature = fetch(
        &signature.url,
        signature.size,
        releases::MAX_SIGNATURE_BYTES,
    )?;
    release
        .verify(&manifest, &signature, &releases::RELEASE_KEYS)
        .map_err(|err| err.to_string())
}

/// GitHub's answer for the newest release, not checked yet.
fn latest_unchecked() -> Result<Release, String> {
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

/// The phone app's package of `release`, downloaded and checked against what its manifest
/// lists for it (size and SHA-256). Blocks: call it off the UI thread.
pub fn phone_package(release: &Verified) -> Result<Vec<u8>, String> {
    let package = release
        .phone_package()
        .map_err(|err| format!("release {}: {err}", release.version()))?;
    download(&package, MAX_APP_BYTES)
}

/// Why the extension's zip of a release wasn't had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageError {
    /// The release has none: nothing to take.
    None,
    /// What came isn't what the manifest lists (size or SHA-256), the manifest doesn't list it,
    /// or GitHub refused: said.
    Refused(String),
    /// The network failed: tried again at the next look.
    Network(String),
}

/// The browser extension's zip of `release` (`vault-extension-<version>.zip`), downloaded and
/// checked against what its manifest lists for it (size and SHA-256), like the phone's package.
/// Blocks: call it off the UI thread.
pub fn extension_package(release: &Verified) -> Result<Vec<u8>, PackageError> {
    let package = match release.extension_package() {
        Ok(package) => package,
        Err(ManifestError::NoFile(_)) => return Err(PackageError::None),
        Err(err) => return Err(PackageError::Refused(err.to_string())),
    };
    download(&package, releases::MAX_EXTENSION_BYTES).map_err(|err| {
        if err.starts_with(NETWORK) {
            PackageError::Network(err)
        } else {
            PackageError::Refused(err)
        }
    })
}

/// How a failure of the network starts, in [`fetch`]'s errors.
const NETWORK: &str = "the network failed: ";

/// `package`, downloaded (at most `max` bytes) and checked against what the manifest lists for
/// it.
fn download(package: &Package, max: usize) -> Result<Vec<u8>, String> {
    let bytes = fetch(&package.url, package.size, max)?;
    check_package(&bytes, package.size, &package.sha256)?;
    Ok(bytes)
}

/// The file at `url` (github.com, which sends it on to its file store): `size` bytes, at most
/// `max`.
fn fetch(url: &str, size: u64, max: usize) -> Result<Vec<u8>, String> {
    let capacity = usize::try_from(size).map_err(|_| "the file is too large")?;
    if capacity > max {
        return Err("the file is too large".into());
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        // github.com sends a file on to its file store.
        .max_redirects(4)
        .timeout_global(Some(Duration::from_secs(15 * 60)))
        .user_agent(USER_AGENT)
        .build()
        .into();
    let mut failed_network = false;
    let bytes = with_retries(&RETRY_WAITS, || {
        let mut bytes = Vec::with_capacity(capacity);
        let got = agent.get(url).call().and_then(|answer| {
            answer
                .into_body()
                .into_reader()
                .take(size + 1)
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
    if u64::try_from(bytes.len()).ok() != Some(size) {
        return Err("the file downloaded isn't the size the release lists".into());
    }
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

/// Whether `bytes` are the package a manifest lists: `size` bytes with SHA-256 `sha256`.
fn check_package(bytes: &[u8], size: u64, sha256: &str) -> Result<(), String> {
    if u64::try_from(bytes.len()).ok() != Some(size) {
        return Err("the package downloaded isn't the size its manifest lists".into());
    }
    let got: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != sha256 {
        return Err(
            "the package downloaded isn't the one its manifest lists (SHA-256 differs)".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use vault_sync_wire::releases::testing::{TestKey, verified};

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
    fn a_package_is_taken_only_as_the_manifest_lists_it() {
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

    /// The phone's package of a signed release: what is downloaded is checked against the
    /// manifest's SHA-256, so a package swapped on GitHub's side (same name and size, other
    /// bytes, and GitHub's digest of the new bytes) is refused.
    #[test]
    fn a_package_whose_sha256_differs_from_the_manifest_is_refused() {
        let key = TestKey::new();
        let name = releases::phone_package_name("1.2.3");
        let signed: &[u8] = b"PK the package the owner signed";
        let release = verified("1.2.3", &[(&name, signed)], &key);
        let package = release.phone_package().unwrap();
        assert!(check_package(signed, package.size, &package.sha256).is_ok());
        let swapped: &[u8] = b"PK another package, same size!!";
        assert_eq!(swapped.len(), signed.len());
        assert!(check_package(swapped, package.size, &package.sha256).is_err());
        // The extension's zip, missing from the release: nothing to take, said apart from a
        // refusal.
        assert_eq!(extension_package(&release), Err(PackageError::None));
    }
}
