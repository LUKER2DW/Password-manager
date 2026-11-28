//! The project's releases on GitHub: which version is the newest, where its page is, and the
//! phone app's package and the browser extension's zip in it. Read by the sync server, which can
//! follow them and hand the phone app's updates to the phones that sync through it
//! (`VAULT_SERVER_APP_UPDATES`), by the phone, and by the desktop app's "Check for updates"
//! (Settings → About). Only the reading is here: whoever asks does the fetching, over HTTPS,
//! from [`latest_url`].
//!
//! What GitHub says is checked before it is used: a plain `vX.Y.Z` tag, a page and package
//! addresses on github.com. A draft or a pre-release is never taken.
//!
//! **A release is taken only with its manifest signed** (CRYPTO.md §9): `manifest.json` lists
//! every file of the release (its name, size and SHA-256), and `manifest.json.minisig` is its
//! signature, in minisign's format, by one of [`RELEASE_KEYS`]. The release workflow signs it
//! with the primary key, which only a run that publishes gets, after the maintainer's approval
//! (the `android-release` environment); the backup key never leaves the maintainer's computer.
//! The signed (trusted) comment names the version, `vault-release v<version>`, and the
//! manifest's version, that comment and the release's tag must all agree ([`Release::verify`]).
//! A file is taken only as the manifest lists it ([`Verified::phone_package`],
//! [`Verified::extension_package`]), and a version not newer than the one installed is never
//! offered. So a file swapped in a release, a release made by a push or a stolen token without
//! that approval, or a copy a sync server altered is refused; someone who holds the whole GitHub
//! account (the approval with it) or the maintainer's signing folder is not stopped here.

use serde::Deserialize;

use crate::{AppRelease, MAX_APP_BYTES, parse_version};

/// The repository whose releases the apps follow.
pub const REPOSITORY: &str = "LUKER2DW/Password-manager";

/// The public keys whose signature on a release manifest the apps take (minisign's form, the
/// second line of its `.pub` file): the primary, which signs every release in the release
/// workflow, and the backup, which stays on the maintainer's computer to replace the primary if
/// it ever leaks. One valid signature by either is enough. A change of keys is a release of its
/// own, signed by a key the apps already take (docs/CODE_SIGNING.md); the test
/// `the_trusted_keys_are_the_ones_pinned` names them by id, so none changes by accident.
pub const RELEASE_KEYS: [&str; 2] = [
    // Primary, key id E176CCB6F6ED2D5E.
    "RWReLe32tsx24bYUvenBoZVNm003L9xbTNGaaXtyh5kDyZpELASGbiQ2",
    // Backup, key id D1206EC499792B97.
    "RWSXK3mZxG4g0UHPMFIxmn8I8dgQY79re11UuU/brRlNNIkGS7O6GyNM",
];

/// The release's file that lists every other one.
pub const MANIFEST: &str = "manifest.json";
/// Its signature, in the form `minisign -Sm manifest.json` writes (tools/release makes it).
pub const MANIFEST_SIGNATURE: &str = "manifest.json.minisig";
/// The manifest's layout. Fields may be added to it without a new number (they are skipped
/// here); one that changes what a field means needs a new number, which this version refuses.
pub const MANIFEST_SCHEMA: u32 = 1;
/// The manifest's `project`.
pub const PROJECT: &str = "vault";
/// The largest manifest taken (it is a couple of kilobytes): small enough that a sync server's
/// answer holding it stays under what older phones read (64 KiB).
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;
/// The largest signature taken (minisign's is about 300 bytes).
pub const MAX_SIGNATURE_BYTES: usize = 1024;
/// The most files a manifest lists.
const MAX_FILES: usize = 64;

/// The signed comment a release's manifest carries: `vault-release v<version>`.
pub fn trusted_comment(version: &str) -> String {
    format!("vault-release v{version}")
}

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

/// The file name of the desktop app's program in every release (release.yml, job `windows`):
/// one name, without the version, so a link to the newest release's file stays the same.
pub const DESKTOP_EXE: &str = "vault-desktop.exe";

/// The largest desktop program taken (it is a few tens of megabytes).
pub const MAX_DESKTOP_BYTES: usize = 192 * 1024 * 1024;

/// A release, as GitHub describes it: not taken for anything until [`Release::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// `1.2.3` (the tag without its `v`).
    pub version: String,
    /// Its page on github.com.
    pub page: String,
    pub assets: Vec<Asset>,
}

/// A file of a release, as GitHub lists it.
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
        if version.trim() != version {
            return None;
        }
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

    /// The file named `name`, on github.com.
    pub fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|asset| asset.name == name)
    }

    /// The manifest and its signature, when the release has both (and neither is larger than
    /// either could be).
    pub fn manifest_assets(&self) -> Result<(&Asset, &Asset), ManifestError> {
        let manifest = self.asset(MANIFEST).ok_or(ManifestError::Missing)?;
        let signature = self
            .asset(MANIFEST_SIGNATURE)
            .ok_or(ManifestError::Missing)?;
        if !fits(manifest.size, MAX_MANIFEST_BYTES) || !fits(signature.size, MAX_SIGNATURE_BYTES) {
            return Err(ManifestError::TooLarge);
        }
        Ok((manifest, signature))
    }

    /// This release with its manifest `manifest` and signature `signature` (the bytes of
    /// [`MANIFEST`] and [`MANIFEST_SIGNATURE`]), checked with `keys` (the apps pass
    /// [`RELEASE_KEYS`]; tests, keys of their own): signed by one of them, the version the
    /// signed comment names and the manifest's both this release's.
    pub fn verify(
        self,
        manifest: &[u8],
        signature: &[u8],
        keys: &[&str],
    ) -> Result<Verified, ManifestError> {
        let checked = verify_manifest(manifest, signature, keys)?;
        if checked.version != self.version {
            return Err(ManifestError::OtherVersion {
                manifest: checked.version,
                release: self.version,
            });
        }
        // Both are text: verify_manifest read them as such.
        let signed = SignedManifest {
            manifest: String::from_utf8_lossy(manifest).into_owned(),
            signature: String::from_utf8_lossy(signature).into_owned(),
        };
        Ok(Verified {
            release: self,
            manifest: checked,
            signed,
        })
    }
}

fn fits(size: u64, max: usize) -> bool {
    size > 0 && usize::try_from(size).is_ok_and(|size| size <= max)
}

/// `sha256:<64 hex>`, as GitHub lists an asset's digest, to lowercase hex.
fn sha256_of_digest(digest: &str) -> Option<String> {
    let hex = digest.strip_prefix("sha256:")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hex.to_ascii_lowercase())
}

// ---- the manifest ----

/// A release's manifest, as signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// `1.2.3`.
    pub version: String,
    /// When the release was built (UTC, as release.yml writes it). Shown, not compared.
    pub date: String,
    /// The commit it was built from (hex).
    pub commit: String,
    /// SHA-256 (lowercase hex) of the certificate the phone app's package is signed with.
    pub android_certificate_sha256: String,
    pub files: Vec<ManifestFile>,
}

/// One file of a release, as its manifest lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFile {
    pub name: String,
    pub size: u64,
    /// Lowercase hex.
    pub sha256: String,
}

impl Manifest {
    /// The file named `name`.
    pub fn file(&self, name: &str) -> Option<&ManifestFile> {
        self.files.iter().find(|file| file.name == name)
    }
}

/// A manifest and its signature, exactly as the release has them: what a sync server keeps and
/// hands on, for the phone to check again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedManifest {
    pub manifest: String,
    pub signature: String,
}

#[derive(Deserialize)]
struct RawManifest {
    schema: u32,
    project: String,
    version: String,
    date: String,
    commit: String,
    android_certificate_sha256: String,
    files: Vec<RawFile>,
}

#[derive(Deserialize)]
struct RawFile {
    name: String,
    size: u64,
    sha256: String,
}

/// Why a release (or a server's update) wasn't taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// It has no manifest or no signature.
    Missing,
    /// The manifest or the signature is larger than either could be.
    TooLarge,
    /// The signature isn't one minisign writes (or one made the old way, without hashing first).
    Malformed,
    /// None of the trusted keys signed this manifest: another key did, or it was changed since.
    NotSigned,
    /// Signed, but not a manifest this version reads.
    NotAManifest(String),
    /// The signed comment doesn't name the manifest's version.
    Comment,
    /// The manifest is for another version than the release or the update says.
    OtherVersion { manifest: String, release: String },
    /// The release has no such file.
    NoFile(String),
    /// The file isn't in the manifest, or isn't what the manifest lists (its size or SHA-256).
    NotListed(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(
                f,
                "it has no signed manifest ({MANIFEST} and {MANIFEST_SIGNATURE})"
            ),
            Self::TooLarge => write!(f, "its manifest or signature is too large"),
            Self::Malformed => write!(f, "its manifest's signature can't be read"),
            Self::NotSigned => write!(
                f,
                "its manifest isn't signed by the project's release key (another key, or changed \
                 since)"
            ),
            Self::NotAManifest(why) => write!(f, "its manifest can't be read: {why}"),
            Self::Comment => write!(f, "its manifest's signature names another version"),
            Self::OtherVersion { manifest, release } => {
                write!(f, "its manifest is for version {manifest}, not {release}")
            }
            Self::NoFile(name) => write!(f, "it has no {name}"),
            Self::NotListed(name) => write!(f, "{name} isn't the file its manifest lists"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// Checks `manifest` (the bytes of a release's `manifest.json`) against `signature` (its
/// `manifest.json.minisig`) and `keys`: signed by any one of them (minisign's own verifier,
/// prehashed signatures only), its trusted comment `vault-release v<its version>`, and read
/// strictly. Only signed bytes are read.
pub fn verify_manifest(
    manifest: &[u8],
    signature: &[u8],
    keys: &[&str],
) -> Result<Manifest, ManifestError> {
    if manifest.len() > MAX_MANIFEST_BYTES || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(ManifestError::TooLarge);
    }
    let text = std::str::from_utf8(signature).map_err(|_| ManifestError::Malformed)?;
    let signature =
        minisign_verify::Signature::decode(text).map_err(|_| ManifestError::Malformed)?;
    let signed = keys.iter().any(|key| {
        minisign_verify::PublicKey::from_base64(key)
            .is_ok_and(|key| key.verify(manifest, &signature, false).is_ok())
    });
    if !signed {
        return Err(ManifestError::NotSigned);
    }
    let read = read_manifest(manifest)?;
    if signature.trusted_comment() != trusted_comment(&read.version) {
        return Err(ManifestError::Comment);
    }
    Ok(read)
}

fn read_manifest(bytes: &[u8]) -> Result<Manifest, ManifestError> {
    let bad = |why: &str| ManifestError::NotAManifest(why.to_owned());
    let raw: RawManifest = serde_json::from_slice(bytes)
        .map_err(|err| ManifestError::NotAManifest(err.to_string()))?;
    if raw.schema != MANIFEST_SCHEMA {
        return Err(ManifestError::NotAManifest(format!(
            "schema {} (this version reads {MANIFEST_SCHEMA})",
            raw.schema
        )));
    }
    if raw.project != PROJECT {
        return Err(bad("another project's"));
    }
    if parse_version(&raw.version).is_none() || raw.version.trim() != raw.version {
        return Err(bad("its version isn't one"));
    }
    if raw.date.is_empty() || raw.date.len() > 64 || !raw.date.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(bad("its date isn't one"));
    }
    if !matches!(raw.commit.len(), 40 | 64) || !is_lower_hex(&raw.commit) {
        return Err(bad("its commit isn't one"));
    }
    if !is_sha256(&raw.android_certificate_sha256) {
        return Err(bad("its certificate digest isn't one"));
    }
    if raw.files.is_empty() || raw.files.len() > MAX_FILES {
        return Err(bad("it lists no files, or too many"));
    }
    let mut files: Vec<ManifestFile> = Vec::with_capacity(raw.files.len());
    for file in raw.files {
        if !is_file_name(&file.name) || file.size == 0 || !is_sha256(&file.sha256) {
            return Err(ManifestError::NotAManifest(format!(
                "a file isn't listed as one: {:?}",
                file.name
            )));
        }
        if files.iter().any(|seen| seen.name == file.name) {
            return Err(ManifestError::NotAManifest(format!(
                "{} is listed twice",
                file.name
            )));
        }
        files.push(ManifestFile {
            name: file.name,
            size: file.size,
            sha256: file.sha256,
        });
    }
    Ok(Manifest {
        version: raw.version,
        date: raw.date,
        commit: raw.commit,
        android_certificate_sha256: raw.android_certificate_sha256,
        files,
    })
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && is_lower_hex(text)
}

/// A release file's name: letters, digits, `-`, `_` and `.`, not starting with `.`.
fn is_file_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

// ---- a release, checked ----

/// A release whose manifest is signed by a trusted key and names its version: the only kind
/// the apps offer or take files from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    release: Release,
    manifest: Manifest,
    signed: SignedManifest,
}

/// A file of a checked release, as its manifest lists it: what to download, and what it must
/// turn out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub size: u64,
    /// From the manifest (lowercase hex).
    pub sha256: String,
    /// Where it is downloaded from (github.com).
    pub url: String,
}

impl Verified {
    /// `1.2.3`.
    pub fn version(&self) -> &str {
        &self.release.version
    }

    /// Its page on github.com.
    pub fn page(&self) -> &str {
        &self.release.page
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The manifest and its signature as they were read, to hand on unchanged.
    pub fn signed(&self) -> &SignedManifest {
        &self.signed
    }

    /// Whether this release comes after version `installed`.
    pub fn is_newer_than(&self, installed: &str) -> bool {
        crate::is_newer(&self.release.version, installed)
    }

    /// The file `name` of this release (at most `max` bytes), as the manifest lists it: the
    /// release must have it, at the size the manifest gives, and when GitHub lists a SHA-256
    /// for it, the manifest's.
    pub fn package(&self, name: &str, max: usize) -> Result<Package, ManifestError> {
        let asset = self
            .release
            .asset(name)
            .ok_or_else(|| ManifestError::NoFile(name.to_owned()))?;
        let listed = self
            .manifest
            .file(name)
            .ok_or_else(|| ManifestError::NotListed(name.to_owned()))?;
        if asset.size != listed.size
            || asset
                .sha256
                .as_deref()
                .is_some_and(|sha256| sha256 != listed.sha256)
        {
            return Err(ManifestError::NotListed(name.to_owned()));
        }
        if !fits(listed.size, max) {
            return Err(ManifestError::TooLarge);
        }
        Ok(Package {
            name: name.to_owned(),
            size: listed.size,
            sha256: listed.sha256.clone(),
            url: asset.url.clone(),
        })
    }

    /// The phone app's package, as the manifest lists it.
    pub fn phone_package(&self) -> Result<Package, ManifestError> {
        self.package(&phone_package_name(self.version()), MAX_APP_BYTES)
    }

    /// The browser extension's zip, as the manifest lists it.
    pub fn extension_package(&self) -> Result<Package, ManifestError> {
        self.package(&extension_package_name(self.version()), MAX_EXTENSION_BYTES)
    }

    /// The desktop app's program, as the manifest lists it: what the desktop app replaces
    /// itself with.
    pub fn desktop_exe(&self) -> Result<Package, ManifestError> {
        self.package(DESKTOP_EXE, MAX_DESKTOP_BYTES)
    }
}

/// The manifest of a sync server's update (`AppRelease`), checked by the phone itself with
/// `keys` (the server is trusted with nothing here): present, signed by one of them, for the
/// update's version, and listing the phone's package at the update's size and SHA-256. The
/// package the server then sends is checked against those (`app_package`).
pub fn verify_app_release(release: &AppRelease, keys: &[&str]) -> Result<Manifest, ManifestError> {
    let (Some(manifest), Some(signature)) = (&release.manifest, &release.signature) else {
        return Err(ManifestError::Missing);
    };
    let checked = verify_manifest(manifest.as_bytes(), signature.as_bytes(), keys)?;
    if checked.version != release.version {
        return Err(ManifestError::OtherVersion {
            manifest: checked.version,
            release: release.version.clone(),
        });
    }
    let name = phone_package_name(&release.version);
    let listed = checked
        .file(&name)
        .ok_or_else(|| ManifestError::NotListed(name.clone()))?;
    if listed.size != release.size || listed.sha256 != release.sha256 {
        return Err(ManifestError::NotListed(name));
    }
    Ok(checked)
}

/// Release manifests signed with keys made for a test: for this crate's tests and, through the
/// `test-signing` feature, the apps'. It never adds a trusted key: what it signs is taken only
/// where a test passes [`TestKey::public`] in place of [`RELEASE_KEYS`].
#[cfg(any(test, feature = "test-signing"))]
pub mod testing {
    use sha2::{Digest, Sha256};

    use super::*;

    /// A minisign key pair made for one test (random, in memory, never written anywhere).
    pub struct TestKey(minisign::KeyPair);

    impl std::fmt::Debug for TestKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestKey({})", self.public())
        }
    }

    impl Default for TestKey {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TestKey {
        pub fn new() -> Self {
            Self(minisign::KeyPair::generate_unencrypted_keypair().expect("a test key"))
        }

        /// The public key, as [`RELEASE_KEYS`] holds them.
        pub fn public(&self) -> String {
            self.0.pk.to_base64()
        }

        /// `data` signed as `minisign -Sm` does, with trusted comment `comment`.
        pub fn sign(&self, data: &[u8], comment: &str) -> String {
            minisign::sign(
                Some(&self.0.pk),
                &self.0.sk,
                std::io::Cursor::new(data),
                Some(comment),
                Some("signature from a test key"),
            )
            .expect("signing with a test key")
            .into_string()
        }

        /// A manifest of `version` signed as the owner signs a release.
        pub fn sign_release(&self, manifest: &str, version: &str) -> String {
            self.sign(manifest.as_bytes(), &trusted_comment(version))
        }
    }

    /// Lowercase hex SHA-256.
    pub fn sha256(bytes: &[u8]) -> String {
        crate::hex(&Sha256::digest(bytes))
    }

    /// A manifest of `version` listing `files` (name, size, SHA-256) as release.yml writes one.
    pub fn manifest(version: &str, files: &[(&str, u64, &str)]) -> String {
        let files: Vec<serde_json::Value> = files
            .iter()
            .map(|(name, size, sha256)| {
                serde_json::json!({ "name": name, "size": size, "sha256": sha256 })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": MANIFEST_SCHEMA,
            "project": PROJECT,
            "version": version,
            "date": "2026-11-27T12:00:00Z",
            "commit": "0123456789abcdef0123456789abcdef01234567",
            "android_certificate_sha256": "ab".repeat(32),
            "files": files,
        }))
        .expect("a manifest")
    }

    /// A manifest of `version` listing `files` with their real sizes and SHA-256.
    pub fn manifest_of(version: &str, files: &[(&str, &[u8])]) -> String {
        let listed: Vec<(&str, u64, String)> = files
            .iter()
            .map(|(name, bytes)| (*name, bytes.len() as u64, sha256(bytes)))
            .collect();
        let listed: Vec<(&str, u64, &str)> = listed
            .iter()
            .map(|(name, size, sha256)| (*name, *size, sha256.as_str()))
            .collect();
        manifest(version, &listed)
    }

    /// A release of `version` on github.com with `files`, its manifest signed by `key` and
    /// checked with it: what `vault_platform::updates::latest` hands back for a real one.
    pub fn verified(version: &str, files: &[(&str, &[u8])], key: &TestKey) -> Verified {
        let manifest = manifest_of(version, files);
        let signature = key.sign_release(&manifest, version);
        let tag = format!("v{version}");
        let mut assets: Vec<Asset> = files
            .iter()
            .map(|(name, bytes)| Asset {
                name: (*name).to_owned(),
                size: bytes.len() as u64,
                sha256: Some(sha256(bytes)),
                url: format!("https://github.com/o/r/releases/download/{tag}/{name}"),
            })
            .collect();
        for (name, bytes) in [(MANIFEST, &manifest), (MANIFEST_SIGNATURE, &signature)] {
            assets.push(Asset {
                name: name.to_owned(),
                size: bytes.len() as u64,
                sha256: Some(sha256(bytes.as_bytes())),
                url: format!("https://github.com/o/r/releases/download/{tag}/{name}"),
            });
        }
        let release = Release {
            version: version.to_owned(),
            page: format!("https://github.com/o/r/releases/tag/{tag}"),
            assets,
        };
        release
            .verify(manifest.as_bytes(), signature.as_bytes(), &[&key.public()])
            .expect("a release signed with its test key")
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::*, *};

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
                "browser_download_url":"https://github.com/o/r/releases/download/{tag}/vault-extension-{v}.zip"}},
              {{"name":"manifest.json","size":900,"digest":null,
                "browser_download_url":"https://github.com/o/r/releases/download/{tag}/manifest.json"}},
              {{"name":"manifest.json.minisig","size":300,"digest":null,
                "browser_download_url":"https://github.com/o/r/releases/download/{tag}/manifest.json.minisig"}}
            ]}}"#,
            v = tag.trim_start_matches('v'),
        )
        .into_bytes()
    }

    /// The manifest of `answer("v0.4.3")`'s files, and its signature by `key`.
    fn signed_answer(key: &TestKey, version: &str) -> (String, String) {
        let manifest = manifest(
            version,
            &[
                (&phone_package_name(version), 2048, DIGEST),
                (
                    &format!("vault-desktop-{version}-windows-x64.exe"),
                    4096,
                    &"cd".repeat(32),
                ),
                (&extension_package_name(version), 300_000, DIGEST),
            ],
        );
        let signature = key.sign_release(&manifest, version);
        (manifest, signature)
    }

    #[test]
    fn a_release_is_read_as_github_lists_it() {
        let release = Release::parse(&answer("v0.4.3", "")).unwrap();
        assert_eq!(release.version, "0.4.3");
        assert_eq!(release.page, "https://github.com/o/r/releases/tag/v0.4.3");
        let package = release.asset("vault-mobile-android-0.4.3.apk").unwrap();
        assert_eq!(
            (package.size, package.sha256.as_deref()),
            (2048, Some(DIGEST))
        );
        assert_eq!(
            release
                .asset("vault-desktop-0.4.3-windows-x64.exe")
                .unwrap()
                .sha256,
            None
        );
        let (manifest, signature) = release.manifest_assets().unwrap();
        assert_eq!((manifest.size, signature.size), (900, 300));
    }

    #[test]
    fn drafts_pre_releases_and_odd_tags_are_not_taken() {
        assert!(Release::parse(&answer("v0.4.3", r#""prerelease":true,"#)).is_none());
        assert!(Release::parse(&answer("v0.4.3", r#""draft":true,"#)).is_none());
        assert!(Release::parse(&answer("0.4.3", "")).is_none());
        assert!(Release::parse(&answer("v0.4", "")).is_none());
        assert!(Release::parse(&answer("android-v0.4.3", "")).is_none());
        assert!(Release::parse(&answer("v 0.4.3", "")).is_none());
        assert!(Release::parse(b"not json").is_none());
    }

    /// A release signed by a trusted key is taken, with its files as the manifest lists them.
    #[test]
    fn a_valid_manifest_is_taken_with_its_files() {
        let key = TestKey::new();
        let (manifest, signature) = signed_answer(&key, "0.4.3");
        let release = Release::parse(&answer("v0.4.3", "")).unwrap();
        let checked = release
            .verify(manifest.as_bytes(), signature.as_bytes(), &[&key.public()])
            .unwrap();
        assert_eq!(checked.version(), "0.4.3");
        assert_eq!(checked.page(), "https://github.com/o/r/releases/tag/v0.4.3");
        assert_eq!(checked.manifest().files.len(), 3);
        assert_eq!(checked.signed().manifest, manifest);
        assert_eq!(checked.signed().signature, signature);
        let phone = checked.phone_package().unwrap();
        assert_eq!((phone.size, phone.sha256.as_str()), (2048, DIGEST));
        assert_eq!(
            phone.url,
            "https://github.com/o/r/releases/download/v0.4.3/vault-mobile-android-0.4.3.apk"
        );
        assert_eq!(checked.extension_package().unwrap().size, 300_000);
        assert!(checked.is_newer_than("0.4.2"));
        assert!(
            !checked.is_newer_than("0.4.3"),
            "the same version isn't newer"
        );
        assert!(!checked.is_newer_than("0.10.0"), "an older one never is");

        // Either of two trusted keys will do.
        let other = TestKey::new();
        let release = Release::parse(&answer("v0.4.3", "")).unwrap();
        assert!(
            release
                .verify(
                    manifest.as_bytes(),
                    signature.as_bytes(),
                    &[&other.public(), &key.public()]
                )
                .is_ok()
        );
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let (key, stranger) = (TestKey::new(), TestKey::new());
        let (manifest, signature) = signed_answer(&stranger, "0.4.3");
        let release = Release::parse(&answer("v0.4.3", "")).unwrap();
        assert_eq!(
            release.verify(manifest.as_bytes(), signature.as_bytes(), &[&key.public()]),
            Err(ManifestError::NotSigned)
        );
        // No key at all, or one that isn't a key: nothing is trusted.
        assert_eq!(
            verify_manifest(manifest.as_bytes(), signature.as_bytes(), &[]),
            Err(ManifestError::NotSigned)
        );
        assert_eq!(
            verify_manifest(manifest.as_bytes(), signature.as_bytes(), &["not a key"]),
            Err(ManifestError::NotSigned)
        );
    }

    #[test]
    fn an_altered_manifest_is_refused() {
        let key = TestKey::new();
        let (manifest, signature) = signed_answer(&key, "0.4.3");
        let keys = [key.public()];
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        // Another package digest, one byte of whitespace more, a file left out.
        for altered in [
            manifest.replacen(DIGEST, &"0".repeat(64), 1),
            format!("{manifest} "),
            manifest.replace("\"size\": 4096", "\"size\": 4097"),
        ] {
            assert_ne!(altered, manifest);
            assert_eq!(
                verify_manifest(altered.as_bytes(), signature.as_bytes(), &keys),
                Err(ManifestError::NotSigned)
            );
        }
        // A signature that isn't minisign's, cut short, or over the size limits.
        assert_eq!(
            verify_manifest(manifest.as_bytes(), b"not a signature", &keys),
            Err(ManifestError::Malformed)
        );
        let cut = signature.lines().take(2).collect::<Vec<_>>().join("\n");
        assert_eq!(
            verify_manifest(manifest.as_bytes(), cut.as_bytes(), &keys),
            Err(ManifestError::Malformed)
        );
        assert_eq!(
            verify_manifest(
                &vec![b' '; MAX_MANIFEST_BYTES + 1],
                signature.as_bytes(),
                &keys
            ),
            Err(ManifestError::TooLarge)
        );
    }

    #[test]
    fn a_changed_trusted_comment_is_refused() {
        let key = TestKey::new();
        let (manifest, signature) = signed_answer(&key, "0.4.3");
        let keys = [key.public()];
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        // Rewritten after signing: the global signature no longer covers it.
        let rewritten = signature.replace("vault-release v0.4.3", "vault-release v0.4.4");
        assert_ne!(rewritten, signature);
        assert_eq!(
            verify_manifest(manifest.as_bytes(), rewritten.as_bytes(), &keys),
            Err(ManifestError::NotSigned)
        );
        // Signed so, but naming another version, or none (minisign's default comment).
        for comment in [
            "vault-release v0.4.4",
            "timestamp:1764244800\tfile:manifest.json",
            "",
        ] {
            let other = key.sign(manifest.as_bytes(), comment);
            assert_eq!(
                verify_manifest(manifest.as_bytes(), other.as_bytes(), &keys),
                Err(ManifestError::Comment),
                "{comment}"
            );
        }
    }

    /// A manifest signed for one version, handed out as another release (an old one replayed
    /// under a new tag, or the other way round), is refused; so is a version not newer.
    #[test]
    fn a_lower_or_other_version_is_refused() {
        let key = TestKey::new();
        let (old_manifest, old_signature) = signed_answer(&key, "0.4.2");
        let release = Release::parse(&answer("v0.4.3", "")).unwrap();
        assert_eq!(
            release.verify(
                old_manifest.as_bytes(),
                old_signature.as_bytes(),
                &[&key.public()]
            ),
            Err(ManifestError::OtherVersion {
                manifest: "0.4.2".into(),
                release: "0.4.3".into()
            })
        );
        // Properly signed, but older than what is installed: never offered.
        let release = Release::parse(&answer("v0.4.2", "")).unwrap();
        let old = release
            .verify(
                old_manifest.as_bytes(),
                old_signature.as_bytes(),
                &[&key.public()],
            )
            .unwrap();
        assert!(!old.is_newer_than("0.4.3"));
        assert!(!old.is_newer_than("0.4.2"));
    }

    #[test]
    fn a_file_not_in_the_manifest_is_not_taken() {
        let key = TestKey::new();
        // The manifest leaves the extension's zip out.
        let manifest = manifest("0.4.3", &[(&phone_package_name("0.4.3"), 2048, DIGEST)]);
        let signature = key.sign_release(&manifest, "0.4.3");
        let checked = Release::parse(&answer("v0.4.3", ""))
            .unwrap()
            .verify(manifest.as_bytes(), signature.as_bytes(), &[&key.public()])
            .unwrap();
        assert!(checked.phone_package().is_ok());
        assert_eq!(
            checked.extension_package(),
            Err(ManifestError::NotListed("vault-extension-0.4.3.zip".into()))
        );
        assert_eq!(
            checked.package("vault-desktop.exe", 1 << 20),
            Err(ManifestError::NoFile("vault-desktop.exe".into())),
            "a file the release doesn't have"
        );
    }

    /// GitHub's size or digest for a file that differs from the manifest's: not taken.
    #[test]
    fn a_file_github_lists_otherwise_is_not_taken() {
        let key = TestKey::new();
        let (manifest, signature) = signed_answer(&key, "0.4.3");
        let other_digest = String::from_utf8(answer("v0.4.3", "")).unwrap().replacen(
            &format!("sha256:{DIGEST}"),
            &format!("sha256:{}", "1".repeat(64)),
            1,
        );
        let checked = Release::parse(other_digest.as_bytes())
            .unwrap()
            .verify(manifest.as_bytes(), signature.as_bytes(), &[&key.public()])
            .unwrap();
        assert_eq!(
            checked.phone_package(),
            Err(ManifestError::NotListed(
                "vault-mobile-android-0.4.3.apk".into()
            ))
        );
        let other_size = String::from_utf8(answer("v0.4.3", ""))
            .unwrap()
            .replace(r#""size":300000"#, r#""size":300001"#);
        let checked = Release::parse(other_size.as_bytes())
            .unwrap()
            .verify(manifest.as_bytes(), signature.as_bytes(), &[&key.public()])
            .unwrap();
        assert!(checked.extension_package().is_err());
        // Off github.com, a file isn't part of the release at all.
        let elsewhere = String::from_utf8(answer("v0.4.3", "")).unwrap().replace(
            "https://github.com/o/r/releases/download/v0.4.3/vault-mobile-android",
            "https://example.com/vault-mobile-android",
        );
        let checked = Release::parse(elsewhere.as_bytes())
            .unwrap()
            .verify(manifest.as_bytes(), signature.as_bytes(), &[&key.public()])
            .unwrap();
        assert!(matches!(
            checked.phone_package(),
            Err(ManifestError::NoFile(_))
        ));
    }

    #[test]
    fn a_release_without_its_manifest_is_not_taken() {
        let only_files = String::from_utf8(answer("v0.4.3", "")).unwrap().replace(
            "\"name\":\"manifest.json.minisig\"",
            "\"name\":\"notes.txt\"",
        );
        let release = Release::parse(only_files.as_bytes()).unwrap();
        assert_eq!(release.manifest_assets(), Err(ManifestError::Missing));
        let large = String::from_utf8(answer("v0.4.3", ""))
            .unwrap()
            .replace(r#""size":900"#, r#""size":900000"#);
        let release = Release::parse(large.as_bytes()).unwrap();
        assert_eq!(release.manifest_assets(), Err(ManifestError::TooLarge));
    }

    /// Signed, but not laid out as this version reads a manifest: refused.
    #[test]
    fn a_manifest_is_read_strictly() {
        let key = TestKey::new();
        let keys = [key.public()];
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        let good = manifest("0.4.3", &[("a.zip", 1, DIGEST)]);
        let check = |text: &str| {
            verify_manifest(
                text.as_bytes(),
                key.sign_release(text, "0.4.3").as_bytes(),
                &keys,
            )
        };
        assert!(check(&good).is_ok());
        // A field added later is skipped.
        assert!(check(&good.replacen('{', r#"{"notes": "more", "#, 1)).is_ok());
        for bad in [
            good.replace("\"schema\": 1", "\"schema\": 2"),
            good.replace("\"project\": \"vault\"", "\"project\": \"other\""),
            good.replace("\"a.zip\"", "\"../a.zip\""),
            good.replace("\"a.zip\"", "\".hidden\""),
            good.replace("\"size\": 1", "\"size\": 0"),
            good.replace(DIGEST, &DIGEST.to_uppercase()),
            good.replace("0123456789abcdef0123456789abcdef01234567", "main"),
            good.replace(&"ab".repeat(32), "none"),
            good.replace("\"files\": [", "\"files\": [{\"name\": \"a.zip\", \"size\": 1, \"sha256\": \"35a3820da14470570821134cca00000000000000000000000000000000000000\"},"),
            good.replace("\"version\": \"0.4.3\"", "\"version\": \"0.4.3\", \"version\": \"0.4.3\""),
            "[]".to_owned(),
        ] {
            assert!(
                matches!(check(&bad), Err(ManifestError::NotAManifest(_))),
                "{bad}"
            );
        }
    }

    /// A sync server's update: taken only with the release's own manifest and signature,
    /// listing the package the server offers.
    #[test]
    fn a_servers_update_is_checked_against_its_manifest() {
        let key = TestKey::new();
        let package = b"PK a test package";
        let name = phone_package_name("0.5.0");
        let manifest = manifest_of("0.5.0", &[(&name, package)]);
        let signature = key.sign_release(&manifest, "0.5.0");
        let keys = [key.public()];
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        let release = AppRelease {
            version: "0.5.0".into(),
            sha256: sha256(package),
            size: package.len() as u64,
            manifest: Some(manifest.clone()),
            signature: Some(signature.clone()),
        };
        assert!(verify_app_release(&release, &keys).is_ok());
        // Without them (a server older than this, or its owner's own build), never.
        let bare = AppRelease {
            manifest: None,
            signature: None,
            ..release.clone()
        };
        assert_eq!(
            verify_app_release(&bare, &keys),
            Err(ManifestError::Missing)
        );
        // Another package than the manifest lists, another version, a changed manifest.
        let other_package = AppRelease {
            sha256: "0".repeat(64),
            ..release.clone()
        };
        assert_eq!(
            verify_app_release(&other_package, &keys),
            Err(ManifestError::NotListed(name))
        );
        let other_version = AppRelease {
            version: "0.6.0".into(),
            ..release.clone()
        };
        assert!(matches!(
            verify_app_release(&other_version, &keys),
            Err(ManifestError::OtherVersion { .. })
        ));
        let changed = AppRelease {
            manifest: Some(manifest.replace("0.5.0", "0.6.0")),
            version: "0.6.0".into(),
            ..release.clone()
        };
        assert_eq!(
            verify_app_release(&changed, &keys),
            Err(ManifestError::NotSigned)
        );
        // An older phone reads the same answer, without the two fields it doesn't know.
        let json = serde_json::to_string(&release).unwrap();
        #[derive(Deserialize)]
        struct Older {
            version: String,
            sha256: String,
            size: u64,
        }
        let older: Older = serde_json::from_str(&json).unwrap();
        assert_eq!(
            (older.version, older.sha256, older.size),
            (
                release.version.clone(),
                release.sha256.clone(),
                release.size
            )
        );
        // And one from an older server, without them, reads as having none.
        let from_older: AppRelease =
            serde_json::from_str(r#"{"version":"0.5.0","sha256":"00","size":1}"#).unwrap();
        assert_eq!((from_older.manifest, from_older.signature), (None, None));
    }

    /// The keys the apps trust, by id (the 8 bytes after the algorithm, as minisign prints
    /// them): changing one fails here, so it can only be done on purpose, with this test.
    #[test]
    fn the_trusted_keys_are_the_ones_pinned() {
        const PINNED: [&str; 2] = ["E176CCB6F6ED2D5E", "D1206EC499792B97"];
        let ids: Vec<String> = RELEASE_KEYS
            .iter()
            .map(|key| {
                assert!(
                    minisign_verify::PublicKey::from_base64(key).is_ok(),
                    "{key}"
                );
                let bytes = minisign::PublicKey::from_base64(key).unwrap();
                let id: [u8; 8] = bytes.keynum().try_into().unwrap();
                format!("{:016X}", u64::from_le_bytes(id))
            })
            .collect();
        assert_eq!(ids, PINNED);
        assert_ne!(RELEASE_KEYS[0], RELEASE_KEYS[1], "two keys, kept apart");
    }

    /// The desktop program is taken only as the signed manifest lists it: present in the
    /// release, listed, at the listed size, and never larger than a program could be.
    #[test]
    fn the_desktop_program_is_taken_only_as_listed() {
        let key = TestKey::new();
        let exe: &[u8] = b"MZ a test program";
        let release = verified("2.0.0", &[(DESKTOP_EXE, exe)], &key);
        let package = release.desktop_exe().unwrap();
        assert_eq!(package.name, DESKTOP_EXE);
        assert_eq!(package.size, exe.len() as u64);
        assert_eq!(package.sha256, sha256(exe));
        assert!(package.url.starts_with("https://github.com/"));

        // Not in the release at all.
        let other = verified("2.0.0", &[("vault.exe", exe)], &key);
        assert_eq!(
            other.desktop_exe(),
            Err(ManifestError::NoFile(DESKTOP_EXE.into()))
        );

        // In the release but not in its manifest: the asset added after the signing.
        let mut unlisted = verified("2.0.0", &[("vault.exe", exe)], &key);
        unlisted.release.assets.push(Asset {
            name: DESKTOP_EXE.into(),
            size: exe.len() as u64,
            sha256: None,
            url: "https://github.com/o/r/releases/download/v2.0.0/vault-desktop.exe".into(),
        });
        assert_eq!(
            unlisted.desktop_exe(),
            Err(ManifestError::NotListed(DESKTOP_EXE.into()))
        );

        // Another size on GitHub than the manifest lists, or GitHub's digest of other bytes.
        let mut resized = release.clone();
        resized
            .release
            .assets
            .iter_mut()
            .find(|asset| asset.name == DESKTOP_EXE)
            .unwrap()
            .size += 1;
        assert_eq!(
            resized.desktop_exe(),
            Err(ManifestError::NotListed(DESKTOP_EXE.into()))
        );
        let mut swapped = release.clone();
        swapped
            .release
            .assets
            .iter_mut()
            .find(|asset| asset.name == DESKTOP_EXE)
            .unwrap()
            .sha256 = Some(sha256(b"MZ another program"));
        assert_eq!(
            swapped.desktop_exe(),
            Err(ManifestError::NotListed(DESKTOP_EXE.into()))
        );
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
