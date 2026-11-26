//! Following the project's releases on GitHub (`serve` with `VAULT_SERVER_APP_UPDATES`, or
//! `vault-server fetch-app` once): when the newest release carries a newer phone app than the
//! one here, the server downloads it, checks its size and SHA-256 against what GitHub lists for
//! it, and publishes it as `publish-app` would. The phones that sync through it then offer the
//! update, and check it themselves before Android asks to install it (this app, newer, signed
//! with the same certificate). The log also says when a newer server is out.
//!
//! What it sends: one request for the release list every [`EVERY`], and one for a package when
//! there is a new one; nothing about the vaults or the devices. Off unless the owner sets it.

use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use vault_sync_wire::{
    self as wire, AppRelease,
    releases::{self, Release},
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
        // github.com sends a package on to its file store.
        .max_redirects(4)
        .timeout_global(Some(timeout))
        .user_agent(concat!("vault-server/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// Asks GitHub for `repository`'s newest release. Blocks.
pub fn latest(repository: &str) -> Result<Release> {
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
    Release::parse(&body).context("GitHub's newest release isn't one this server takes")
}

/// Downloads `asset` and checks it is what the release lists. Blocks.
fn download(asset: &releases::Asset) -> Result<Vec<u8>> {
    let expected = asset.sha256.as_deref().context("no SHA-256 listed")?;
    let size = usize::try_from(asset.size).context("too large")?;
    if size > wire::MAX_APP_BYTES {
        bail!("the package is too large");
    }
    let response = agent(Duration::from_secs(15 * 60))
        .get(&asset.url)
        .call()
        .context("downloading the phone app")?;
    let mut bytes = Vec::with_capacity(size);
    response
        .into_body()
        .into_reader()
        .take(asset.size + 1)
        .read_to_end(&mut bytes)
        .context("downloading the phone app")?;
    if bytes.len() != size {
        bail!("the package downloaded isn't the size GitHub lists");
    }
    let got: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != expected {
        bail!("the package downloaded isn't the one GitHub lists (SHA-256 differs)");
    }
    Ok(bytes)
}

/// One look: the newest release's phone app published here when it is newer. Blocks.
pub fn look_once(data: &Path, repository: &str) -> Result<(Release, Looked)> {
    let release = latest(repository)?;
    let store = Store::open(data)?;
    let here = store.app_release()?.map(|release| release.version);
    if here
        .as_deref()
        .is_some_and(|version| !release.is_newer_than(version))
    {
        return Ok((release, Looked::UpToDate(here)));
    }
    let Some(asset) = release.phone_package() else {
        let version = release.version.clone();
        return Ok((release, Looked::NoPackage(version)));
    };
    let package = download(asset)?;
    let published = store.publish_app(&package, &release.version)?;
    Ok((release, Looked::Published(published)))
}

/// Says in the log what [`look_once`] found, and whether a newer server is out.
pub fn report(found: &Result<(Release, Looked)>) {
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
                    release.version,
                    release.page,
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
