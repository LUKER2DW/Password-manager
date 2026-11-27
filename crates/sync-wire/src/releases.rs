//! The project's releases on GitHub: which version is the newest, where its page is, and the
//! phone app's package in it. Read by the sync server, which can follow them and hand the phone
//! app's updates to the phones that sync through it (`VAULT_SERVER_APP_UPDATES`), and by the
//! desktop app's "Check for updates" (Settings → About). Only the reading is here: whoever asks
//! does the fetching, over HTTPS, from [`latest_url`].
//!
//! What GitHub says is checked before it is used: a plain `vX.Y.Z` tag, a page and package
//! addresses on github.com, and a package's SHA-256 in the form GitHub lists it. A draft or a
//! pre-release is never taken.

use serde::Deserialize;

use crate::{MAX_APP_BYTES, parse_version};

/// The repository whose releases the apps follow.
pub const REPOSITORY: &str = "LUKER2DW/Password-manager";

/// Where GitHub answers with `repository`'s newest release (drafts and pre-releases left out).
pub fn latest_url(repository: &str) -> String {
    format!("https://api.github.com/repos/{repository}/releases/latest")
}

/// Whether `repository` reads as `owner/name`, as GitHub writes them.
pub fn is_repository(repository: &str) -> bool {
    let fits = |part: &str| {
        !part.is_empty()
            && part.len() <= 100
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            && part != "."
            && part != ".."
    };
    matches!(repository.split_once('/'), Some((owner, name)) if fits(owner) && fits(name))
}

/// The file name of the phone app's package in release `version`.
pub fn phone_package_name(version: &str) -> String {
    format!("vault-mobile-android-{version}.apk")
}

/// The file name of the browser extension's zip in release `version` (release.yml, job
/// `extension`).
pub fn extension_package_name(version: &str) -> String {
    format!("vault-extension-{version}.zip")
}

/// The largest extension zip taken (it is a few hundred kilobytes).
pub const MAX_EXTENSION_BYTES: usize = 16 * 1024 * 1024;

/// A release, as checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// `1.2.3` (the tag without its `v`).
    pub version: String,
    /// Its page on github.com.
    pub page: String,
    pub assets: Vec<Asset>,
}

/// A file of a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    /// SHA-256 (lowercase hex), when GitHub lists one.
    pub sha256: Option<String>,
    /// Where it is downloaded from (github.com, which redirects to its file store).
    pub url: String,
}

#[derive(Deserialize)]
struct RawRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<RawAsset>,
}

#[derive(Deserialize)]
struct RawAsset {
    name: String,
    size: u64,
    #[serde(default)]
    digest: Option<String>,
    browser_download_url: String,
}

const GITHUB: &str = "https://github.com/";

impl Release {
    /// Reads GitHub's answer for a release; `None` when it isn't one this project would make
    /// (a draft, a pre-release, a tag that isn't a version, addresses off github.com).
    pub fn parse(json: &[u8]) -> Option<Self> {
        let raw: RawRelease = serde_json::from_slice(json).ok()?;
        if raw.draft || raw.prerelease || !raw.html_url.starts_with(GITHUB) {
            return None;
        }
        let version = raw.tag_name.strip_prefix('v')?;
        parse_version(version)?;
        let assets = raw
            .assets
            .into_iter()
            .filter(|asset| asset.browser_download_url.starts_with(GITHUB))
            .map(|asset| Asset {
                sha256: asset.digest.as_deref().and_then(sha256_of_digest),
                name: asset.name,
                size: asset.size,
                url: asset.browser_download_url,
            })
            .collect();
        Some(Self {
            version: version.to_owned(),
            page: raw.html_url,
            assets,
        })
    }

    /// Whether this release comes after version `installed`.
    pub fn is_newer_than(&self, installed: &str) -> bool {
        crate::is_newer(&self.version, installed)
    }

    /// The phone app's package, when the release has one GitHub lists a SHA-256 for and that
    /// isn't larger than a server keeps.
    pub fn phone_package(&self) -> Option<&Asset> {
        let name = phone_package_name(&self.version);
        self.assets.iter().find(|asset| {
            asset.name == name
                && asset.sha256.is_some()
                && asset.size > 0
                && usize::try_from(asset.size).is_ok_and(|size| size <= MAX_APP_BYTES)
        })
    }

    /// The browser extension's zip, when the release has one GitHub lists a SHA-256 for and
    /// that isn't larger than an extension could be.
    pub fn extension_package(&self) -> Option<&Asset> {
        let name = extension_package_name(&self.version);
        self.assets.iter().find(|asset| {
            asset.name == name
                && asset.sha256.is_some()
                && asset.size > 0
                && usize::try_from(asset.size).is_ok_and(|size| size <= MAX_EXTENSION_BYTES)
        })
    }
}

/// `sha256:<64 hex>`, as GitHub lists an asset's digest, to lowercase hex.
fn sha256_of_digest(digest: &str) -> Option<String> {
    let hex = digest.strip_prefix("sha256:")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hex.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "35a3820da14470570821134cca00000000000000000000000000000000000000";

    fn answer(tag: &str, extra: &str) -> Vec<u8> {
        format!(
            r#"{{"tag_name":"{tag}","html_url":"https://github.com/o/r/releases/tag/{tag}",{extra}
            "assets":[
              {{"name":"vault-mobile-android-{v}.apk","size":2048,"digest":"sha256:{DIGEST}",
                "browser_download_url":"https://github.com/o/r/releases/download/{tag}/vault-mobile-android-{v}.apk"}},
              {{"name":"vault-desktop-{v}-windows-x64.exe","size":4096,"digest":null,
                "browser_download_url":"https://github.com/o/r/releases/download/{tag}/vault-desktop-{v}-windows-x64.exe"}},
              {{"name":"vault-extension-{v}.zip","size":300000,"digest":"sha256:{DIGEST}",
                "browser_download_url":"https://github.com/o/r/releases/download/{tag}/vault-extension-{v}.zip"}}
            ]}}"#,
            v = tag.trim_start_matches('v'),
        )
        .into_bytes()
    }

    #[test]
    fn a_release_is_read_with_its_phone_package() {
        let release = Release::parse(&answer("v0.4.3", "")).unwrap();
        assert_eq!(release.version, "0.4.3");
        // And the browser extension's zip, with its digest; none without one.
        let extension = release.extension_package().unwrap();
        assert_eq!(extension.size, 300_000);
        assert_eq!(extension.sha256.as_deref(), Some(DIGEST));
        let mut without = release.clone();
        without
            .assets
            .retain(|asset| asset.name != "vault-extension-0.4.3.zip");
        without.assets.push(Asset {
            name: "vault-extension-0.4.3.zip".into(),
            size: 300_000,
            sha256: None,
            url: "https://github.com/o/r/releases/download/v0.4.3/vault-extension-0.4.3.zip".into(),
        });
        assert!(without.extension_package().is_none());
        assert_eq!(release.page, "https://github.com/o/r/releases/tag/v0.4.3");
        let package = release.phone_package().unwrap();
        assert_eq!(package.size, 2048);
        assert_eq!(package.sha256.as_deref(), Some(DIGEST));
        assert!(release.is_newer_than("0.4.2"));
        assert!(!release.is_newer_than("0.4.3"));
        assert!(!release.is_newer_than("0.10.0"));
    }

    #[test]
    fn drafts_pre_releases_and_odd_tags_are_not_taken() {
        assert!(Release::parse(&answer("v0.4.3", r#""prerelease":true,"#)).is_none());
        assert!(Release::parse(&answer("v0.4.3", r#""draft":true,"#)).is_none());
        assert!(Release::parse(&answer("0.4.3", "")).is_none());
        assert!(Release::parse(&answer("v0.4", "")).is_none());
        assert!(Release::parse(&answer("android-v0.4.3", "")).is_none());
        assert!(Release::parse(b"not json").is_none());
    }

    #[test]
    fn a_package_off_github_or_without_its_digest_is_not_offered() {
        let elsewhere = String::from_utf8(answer("v0.4.3", "")).unwrap().replace(
            "https://github.com/o/r/releases/download/v0.4.3/vault-mobile-android",
            "https://example.com/vault-mobile-android",
        );
        let release = Release::parse(elsewhere.as_bytes()).unwrap();
        assert!(release.phone_package().is_none());

        let no_digest = String::from_utf8(answer("v0.4.3", ""))
            .unwrap()
            .replace(&format!("sha256:{DIGEST}"), "md5:abc");
        let release = Release::parse(no_digest.as_bytes()).unwrap();
        assert!(release.phone_package().is_none());
    }

    #[test]
    fn repositories_are_owner_and_name() {
        assert!(is_repository(REPOSITORY));
        assert!(is_repository("someone/vault.fork"));
        assert!(!is_repository("someone"));
        assert!(!is_repository("someone/vault/extra"));
        assert!(!is_repository("../x"));
        assert!(!is_repository("someone/.."));
        assert!(!is_repository("some one/vault"));
    }
}
