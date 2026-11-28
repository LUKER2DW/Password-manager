//! Following the project's releases on GitHub (`serve` with `VAULT_SERVER_APP_UPDATES`, or
//! `vault-server fetch-app` once): when the newest release carries a newer phone app than the
//! one here, the server downloads the release's manifest and its signature, checks them
//! against the project's release keys (`releases::RELEASE_KEYS`, CRYPTO.md §9), downloads the
//! package, checks its size and SHA-256 against that manifest, and publishes it as
//! `publish-app` would, with the manifest and the signature kept unchanged beside it. The
//! phones that sync through it then offer the update, and check it all again themselves (this
//! server is trusted with nothing there): the manifest's signature, that it lists this very
//! package, and, before Android asks to install it, that it is this app, newer, signed with the
//! same certificate. The log also says when a newer server is out.
//!
//! What it sends: one request for the release list every [`EVERY`], two small ones for the
//! manifest and its signature, and one for a package when there is a new one; nothing about
//! the vaults or the devices. Off unless the owner sets it.

use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use vault_sync_wire::{
    self as wire, AppRelease,
    releases::{self, Release, SignedManifest, Verified},
};

use crate::Store;

/// How often the release list is asked for while serving.
pub const EVERY: Duration = Duration::from_secs(6 * 60 * 60);

/// What one look at the releases found.
#[derive(Debug)]
pub enum Looked {
    /// The phone app here is the newest there is (its version, or none published here yet and
    /// none in the release either).
    UpToDate(Option<String>),
    /// A newer phone app was downloaded, checked and published here.
    Published(AppRelease),
    /// The newest release has no phone app package that can be taken.
    NoPackage(String),
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        // github.com sends a file on to its file store.
        .max_redirects(4)
        .timeout_global(Some(timeout))
        .user_agent(concat!("vault-server/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// Asks GitHub for `repository`'s newest release and checks its manifest. Blocks.
pub fn latest(repository: &str) -> Result<Verified> {
    if !releases::is_repository(repository) {
        bail!("{repository:?} isn't a GitHub repository (owner/name)");
    }
    let mut response = agent(Duration::from_secs(30))
        .get(releases::latest_url(repository))
        .header("Accept", "application/vnd.github+json")
        .call()
        .context("asking GitHub for the newest release")?;
    let body = response
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_vec()
        .context("reading GitHub's answer")?;
    let release =
        Release::parse(&body).context("GitHub's newest release isn't one this server takes")?;
    let version = release.version.clone();
    let (manifest, signature) = release
        .manifest_assets()
        .with_context(|| format!("release {version}"))?;
    let manifest = fetch(&manifest.url, manifest.size, releases::MAX_MANIFEST_BYTES)
        .with_context(|| format!("downloading the manifest of release {version}"))?;
    let signature = fetch(
        &signature.url,
        signature.size,
        releases::MAX_SIGNATURE_BYTES,
    )
    .with_context(|| format!("downloading the signature of release {version}"))?;
    release
        .verify(&manifest, &signature, &releases::RELEASE_KEYS)
        .with_context(|| format!("release {version}"))
}

/// The file at `url`: `size` bytes, at most `max`. Blocks.
fn fetch(url: &str, size: u64, max: usize) -> Result<Vec<u8>> {
    let capacity = usize::try_from(size).context("too large")?;
    if capacity > max {
        bail!("the file is too large");
    }
    let response = agent(Duration::from_secs(15 * 60))
        .get(url)
        .call()
        .context("downloading")?;
    let mut bytes = Vec::with_capacity(capacity);
    response
        .into_body()
        .into_reader()
        .take(size + 1)
        .read_to_end(&mut bytes)
        .context("downloading")?;
    if bytes.len() != capacity {
        bail!("the file downloaded isn't the size the release lists");
    }
    Ok(bytes)
}

/// Whether `package` is `size` bytes with SHA-256 `sha256` (lowercase hex).
fn check_package(package: &[u8], size: u64, sha256: &str) -> Result<()> {
    if package.len() as u64 != size {
        bail!("the package isn't the size its release's manifest lists");
    }
    if wire::hex(&Sha256::digest(package)) != sha256 {
        bail!("the package isn't the one its release's manifest lists (SHA-256 differs)");
    }
    Ok(())
}

/// One look: the newest release's phone app published here when it is newer. Blocks.
pub fn look_once(data: &Path, repository: &str) -> Result<(Verified, Looked)> {
    let release = latest(repository)?;
    let store = Store::open(data)?;
    let here = store.app_release()?.map(|release| release.version);
    if here
        .as_deref()
        .is_some_and(|version| !release.is_newer_than(version))
    {
        return Ok((release, Looked::UpToDate(here)));
    }
    let Ok(package) = release.phone_package() else {
        let version = release.version().to_owned();
        return Ok((release, Looked::NoPackage(version)));
    };
    let bytes = fetch(&package.url, package.size, wire::MAX_APP_BYTES)
        .context("downloading the phone app")?;
    check_package(&bytes, package.size, &package.sha256)?;
    let published = store.publish_app(&bytes, release.version(), Some(release.signed()))?;
    Ok((release, Looked::Published(published)))
}

/// `publish-app --manifest`: the release's manifest at `path` and its signature beside it
/// (`manifest.json.minisig`), checked against the project's release keys, for `package` as
/// version `version`. The phones check them again.
pub fn signed_manifest_for(path: &Path, package: &[u8], version: &str) -> Result<SignedManifest> {
    signed_manifest_with(path, package, version, &releases::RELEASE_KEYS)
}

fn signed_manifest_with(
    path: &Path,
    package: &[u8],
    version: &str,
    keys: &[&str],
) -> Result<SignedManifest> {
    let read = |path: &Path, max: usize| -> Result<String> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        if bytes.len() > max {
            bail!("{} is too large", path.display());
        }
        String::from_utf8(bytes).with_context(|| format!("{} isn't text", path.display()))
    };
    let mut signature_path = path.as_os_str().to_owned();
    signature_path.push(".minisig");
    let signed = SignedManifest {
        manifest: read(path, releases::MAX_MANIFEST_BYTES)?,
        signature: read(Path::new(&signature_path), releases::MAX_SIGNATURE_BYTES)?,
    };
    let release = AppRelease {
        version: version.trim().to_owned(),
        sha256: wire::hex(&Sha256::digest(package)),
        size: package.len() as u64,
        manifest: Some(signed.manifest.clone()),
        signature: Some(signed.signature.clone()),
    };
    releases::verify_app_release(&release, keys).with_context(|| {
        format!(
            "{} doesn't vouch for this package as version {version}",
            path.display()
        )
    })?;
    Ok(signed)
}

/// Says in the log what [`look_once`] found, and whether a newer server is out.
pub fn report(found: &Result<(Verified, Looked)>) {
    match found {
        Ok((release, looked)) => {
            match looked {
                Looked::Published(app) => eprintln!(
                    "vault-server: the phone app {} is here now ({} bytes, SHA-256 {}); the \
                     phones offer it in Settings, Updates.",
                    app.version, app.size, app.sha256
                ),
                Looked::NoPackage(version) => eprintln!(
                    "vault-server: release {version} has no phone app package this server \
                     takes."
                ),
                Looked::UpToDate(_) => {}
            }
            if release.is_newer_than(env!("CARGO_PKG_VERSION")) {
                eprintln!(
                    "vault-server: version {} of the server is out ({}); this one is {}. With \
                     Docker: docker compose pull && docker compose up -d.",
                    release.version(),
                    release.page(),
                    env!("CARGO_PKG_VERSION")
                );
            }
        }
        Err(err) => eprintln!("vault-server: looking for updates failed: {err:#}"),
    }
}

/// While serving: a look a minute after the start, then every [`EVERY`].
pub async fn follow(data: PathBuf, repository: String) {
    tokio::time::sleep(Duration::from_secs(60)).await;
    loop {
        let (data, repository) = (data.clone(), repository.clone());
        let found = tokio::task::spawn_blocking(move || look_once(&data, &repository)).await;
        match found {
            Ok(found) => report(&found),
            Err(err) => eprintln!("vault-server: looking for updates failed: {err}"),
        }
        tokio::time::sleep(EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use vault_sync_wire::releases::testing::{TestKey, manifest_of};

    use super::*;

    /// `publish-app --manifest`: the release's own manifest for this very package, signed by a
    /// trusted key, or nothing is published.
    #[test]
    fn a_manifest_given_to_publish_app_is_checked_first() {
        let dir = tempfile::tempdir().unwrap();
        let key = TestKey::new();
        let package = b"PK\x03\x04 a test package";
        let name = releases::phone_package_name("1.2.3");
        let manifest = manifest_of("1.2.3", &[(&name, package)]);
        let path = dir.path().join("manifest.json");
        std::fs::write(&path, &manifest).unwrap();
        // No signature beside it.
        assert!(signed_manifest_with(&path, package, "1.2.3", &[&key.public()]).is_err());
        std::fs::write(
            dir.path().join("manifest.json.minisig"),
            key.sign_release(&manifest, "1.2.3"),
        )
        .unwrap();
        let signed = signed_manifest_with(&path, package, "1.2.3", &[&key.public()]).unwrap();
        assert_eq!(signed.manifest, manifest);
        // Another key, another package, another version.
        assert!(
            signed_manifest_with(&path, package, "1.2.3", &[&TestKey::new().public()]).is_err()
        );
        assert!(
            signed_manifest_with(&path, b"PK\x03\x04 another", "1.2.3", &[&key.public()]).is_err()
        );
        assert!(signed_manifest_with(&path, package, "1.2.4", &[&key.public()]).is_err());
        // Kept and handed on unchanged.
        let store = Store::open(dir.path()).unwrap();
        let published = store.publish_app(package, "1.2.3", Some(&signed)).unwrap();
        assert_eq!(published.manifest.as_deref(), Some(manifest.as_str()));
        assert_eq!(store.app_release().unwrap(), Some(published));
        assert!(
            check_package(
                package,
                package.len() as u64,
                &wire::hex(&Sha256::digest(package))
            )
            .is_ok()
        );
        assert!(check_package(package, package.len() as u64, &"0".repeat(64)).is_err());
    }
}
