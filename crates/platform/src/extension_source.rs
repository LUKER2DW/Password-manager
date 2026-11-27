//! Where the browser extension's files come from, before the app writes them into the folder the
//! browser loads (`extension_folder`):
//! - by default, the newest GitHub release of the project: its `vault-extension-<version>.zip`,
//!   downloaded when the app looks for its own updates (`updates::extension_package`), taken only
//!   when its SHA-256 is the one the release list gives, read strictly ([`Extension::from_zip`])
//!   and kept next to the folder (`browser-extension-release.zip`) with that digest;
//! - the copy built into the desktop app, whenever it is newer than the release kept (or none
//!   was downloaded yet, or there is no network);
//! - instead of both, a folder of the person's (someone who changes the extension), read with
//!   the same rules ([`Extension::from_folder`]) at each check, so the app follows their changes.
//!
//! The choice, and the release kept, are in `browser-extension.json` in the app's directory.

use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{files::is_link, paths};

/// The person's choice and the release kept, in the app's directory.
const CHOICE: &str = "browser-extension.json";
/// The release's zip, as downloaded and checked.
const RELEASE_ZIP: &str = "browser-extension-release.zip";
/// Largest zip taken, and what may come out of it (or out of a folder of the person's): the
/// extension is a few hundred kilobytes.
pub const MAX_ZIP_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILES: usize = 500;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;

/// One reader or writer of these files at a time in this process.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// The extension's files (paths relative to its folder, with `/`) and the version its
/// `manifest.json` names.
#[derive(Clone, PartialEq, Eq)]
pub struct Extension {
    pub version: String,
    pub files: Vec<(String, Vec<u8>)>,
}

impl std::fmt::Debug for Extension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extension")
            .field("version", &self.version)
            .field("files", &self.files.len())
            .finish()
    }
}

impl Extension {
    /// The copy built into an app (its files as `include_bytes!` gives them).
    pub fn built_in(version: &str, files: &[(&str, &[u8])]) -> Self {
        Self {
            version: version.to_owned(),
            files: files
                .iter()
                .map(|&(name, bytes)| (name.to_owned(), bytes.to_vec()))
                .collect(),
        }
    }

    /// The extension in a release's zip. Refused: an archive over the size limits, encrypted,
    /// in ZIP64 form or compressed other than stored or deflated; an entry that is a link, whose
    /// name leaves the folder (`..`, a drive, a leading `/`, `\`) or comes twice, or whose
    /// contents don't match its CRC or size; no `manifest.json` with a version.
    pub fn from_zip(zip: &[u8]) -> Result<Self> {
        if zip.len() > MAX_ZIP_BYTES {
            bail!("the archive is larger than {MAX_ZIP_BYTES} bytes");
        }
        Self::with_files(unzip(zip)?)
    }

    /// The extension in a folder of the person's: its files (hidden ones, starting with `.`,
    /// left out: `.git` and the like), within the same limits. A link anywhere in it is refused.
    pub fn from_folder(dir: &Path) -> Result<Self> {
        let meta = fs::symlink_metadata(dir).with_context(|| format!("{}", dir.display()))?;
        if is_link(&meta) || !meta.is_dir() {
            bail!("{} is not a folder", dir.display());
        }
        let mut files = Vec::new();
        let mut total = 0;
        read_folder(dir, "", &mut files, &mut total)?;
        Self::with_files(files)
    }

    fn with_files(mut files: Vec<(String, Vec<u8>)>) -> Result<Self> {
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let manifest = files
            .iter()
            .find(|(name, _)| name == "manifest.json")
            .context("there is no manifest.json at its top")?;
        let version = version_of(&manifest.1)?;
        Ok(Self { version, files })
    }

    /// SHA-256 over every name and file (in order, each with its length): what the folder is
    /// meant to hold, as hex.
    pub fn digest(&self) -> String {
        let mut hash = Sha256::new();
        for (name, bytes) in &self.files {
            hash.update((name.len() as u64).to_le_bytes());
            hash.update(name.as_bytes());
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        hex(&hash.finalize())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `version` of a `manifest.json`: one to four numbers, as browsers take it.
pub fn version_of(manifest: &[u8]) -> Result<String> {
    let manifest: serde_json::Value =
        serde_json::from_slice(manifest).context("its manifest.json is not JSON")?;
    let version = manifest["version"]
        .as_str()
        .context("its manifest.json names no version")?;
    if parts(version).is_none() {
        bail!("its manifest.json names no version a browser takes: {version}");
    }
    Ok(version.to_owned())
}

fn parts(version: &str) -> Option<Vec<u32>> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    parts
        .iter()
        .map(|part| {
            let fits =
                !part.is_empty() && part.len() <= 5 && part.bytes().all(|b| b.is_ascii_digit());
            fits.then(|| part.parse::<u32>().ok().filter(|&n| n <= 65535))
                .flatten()
        })
        .collect()
}

/// Whether version `a` is newer than `b` (numbers compared one by one, a missing one is 0; a
/// version that isn't one is never newer).
pub fn newer(a: &str, b: &str) -> bool {
    let (Some(a), Some(b)) = (parts(a), parts(b)) else {
        return false;
    };
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x > y;
        }
    }
    false
}

/// A name inside the extension: plain parts only, nothing that leaves its folder.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.contains(['\\', ':', '\0'])
                && !part.chars().any(char::is_control)
        })
}

// ---- the release's zip ----

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// Reads every file of a zip through its central directory.
fn unzip(zip: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    const END: u32 = 0x0605_4b50;
    const CENTRAL: u32 = 0x0201_4b50;
    const LOCAL: u32 = 0x0403_4b50;
    const UNIX_KIND: u32 = 0o170_000;
    const UNIX_FILE: u32 = 0o100_000;
    let short = || anyhow::anyhow!("the archive is cut short or malformed");
    // The end record: 22 bytes, then a comment that runs to the end of the archive.
    let end = (0..=zip.len().saturating_sub(22))
        .rev()
        .take(65_536)
        .find(|&at| {
            u32_at(zip, at) == Some(END)
                && u16_at(zip, at + 20)
                    .is_some_and(|comment| at + 22 + usize::from(comment) == zip.len())
        })
        .context("not a zip archive")?;
    let count = usize::from(u16_at(zip, end + 10).ok_or_else(short)?);
    let directory_size = u32_at(zip, end + 12).ok_or_else(short)? as usize;
    let directory = u32_at(zip, end + 16).ok_or_else(short)? as usize;
    if count == 0xFFFF || directory == 0xFFFF_FFFF || u16_at(zip, end + 4) != Some(0) {
        bail!("a ZIP64 or split archive is not taken");
    }
    if count > MAX_FILES {
        bail!("the archive holds more than {MAX_FILES} entries");
    }
    if directory
        .checked_add(directory_size)
        .is_none_or(|stop| stop > end)
    {
        return Err(short());
    }
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    let mut total = 0u64;
    let mut at = directory;
    for _ in 0..count {
        if u32_at(zip, at) != Some(CENTRAL) {
            return Err(short());
        }
        let flags = u16_at(zip, at + 8).ok_or_else(short)?;
        let method = u16_at(zip, at + 10).ok_or_else(short)?;
        let crc = u32_at(zip, at + 16).ok_or_else(short)?;
        let packed = u32_at(zip, at + 20).ok_or_else(short)?;
        let size = u32_at(zip, at + 24).ok_or_else(short)?;
        let name_len = usize::from(u16_at(zip, at + 28).ok_or_else(short)?);
        let extra_len = usize::from(u16_at(zip, at + 30).ok_or_else(short)?);
        let comment_len = usize::from(u16_at(zip, at + 32).ok_or_else(short)?);
        let made_by = u16_at(zip, at + 4).ok_or_else(short)? >> 8;
        let attributes = u32_at(zip, at + 38).ok_or_else(short)?;
        let local = u32_at(zip, at + 42).ok_or_else(short)? as usize;
        let name_bytes = zip.get(at + 46..at + 46 + name_len).ok_or_else(short)?;
        at += 46 + name_len + extra_len + comment_len;
        let name = std::str::from_utf8(name_bytes).context("an entry's name is not UTF-8")?;
        if flags & 1 != 0 {
            bail!("{name} is encrypted");
        }
        if packed == u32::MAX || size == u32::MAX {
            bail!("a ZIP64 entry is not taken");
        }
        // Made on Unix (3): the mode is in the top half; only plain files and folders.
        let mode = attributes >> 16;
        if made_by == 3
            && mode != 0
            && mode & UNIX_KIND != UNIX_FILE
            && mode & UNIX_KIND != 0o040_000
        {
            bail!("{name} is a link or a special file");
        }
        if let Some(folder) = name.strip_suffix('/') {
            if !plain_name(folder) || size != 0 {
                bail!("not a folder inside the extension: {name}");
            }
            continue;
        }
        if !plain_name(name) {
            bail!("not a path inside the extension: {name}");
        }
        if !seen.insert(name.to_lowercase()) {
            bail!("{name} comes twice");
        }
        total += u64::from(size);
        if u64::from(size) > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES {
            bail!("the archive unpacks to more than the extension could be");
        }
        // The entry's own header, which must name it the same way.
        if u32_at(zip, local) != Some(LOCAL) {
            return Err(short());
        }
        let local_name = usize::from(u16_at(zip, local + 26).ok_or_else(short)?);
        let local_extra = usize::from(u16_at(zip, local + 28).ok_or_else(short)?);
        if zip.get(local + 30..local + 30 + local_name) != Some(name_bytes) {
            bail!("{name} is named otherwise in its own header");
        }
        let start = local + 30 + local_name + local_extra;
        let data = zip
            .get(start..start.checked_add(packed as usize).ok_or_else(short)?)
            .ok_or_else(short)?;
        let mut bytes = Vec::with_capacity(size as usize);
        match method {
            0 => bytes.extend_from_slice(data),
            8 => {
                flate2::read::DeflateDecoder::new(data)
                    .take(u64::from(size) + 1)
                    .read_to_end(&mut bytes)
                    .with_context(|| format!("{name} doesn't unpack"))?;
            }
            other => bail!("{name} is compressed in a way not taken ({other})"),
        }
        if bytes.len() != size as usize || crc32fast::hash(&bytes) != crc {
            bail!("{name} doesn't match its size or checksum");
        }
        files.push((name.to_owned(), bytes));
    }
    Ok(files)
}

// ---- a folder of the person's ----

fn read_folder(
    dir: &Path,
    base: &str,
    files: &mut Vec<(String, Vec<u8>)>,
    total: &mut u64,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            bail!("a name in {} isn't Unicode", dir.display());
        };
        if name.starts_with('.') {
            continue;
        }
        let relative = if base.is_empty() {
            name.clone()
        } else {
            format!("{base}/{name}")
        };
        if !plain_name(&relative) {
            bail!("not a name the extension can have: {relative}");
        }
        let meta = fs::symlink_metadata(entry.path())?;
        if is_link(&meta) {
            bail!("{relative} is a link");
        }
        if meta.is_dir() {
            read_folder(&entry.path(), &relative, files, total)?;
        } else if meta.is_file() {
            *total += meta.len();
            if files.len() >= MAX_FILES || meta.len() > MAX_FILE_BYTES || *total > MAX_TOTAL_BYTES {
                bail!("the folder holds more than the extension could be");
            }
            let mut bytes = Vec::new();
            fs::File::open(entry.path())?
                .take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .with_context(|| format!("reading {relative}"))?;
            files.push((relative, bytes));
        }
    }
    Ok(())
}

// ---- the choice and the release kept ----

/// What the app takes the extension from, and the release it keeps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Choice {
    /// A folder of the person's, instead of GitHub's releases.
    #[serde(default)]
    pub folder: Option<PathBuf>,
    /// The release whose zip is kept, as checked when it was downloaded.
    #[serde(default)]
    pub release: Option<KeptRelease>,
}

/// A release's zip, kept: its version and the SHA-256 GitHub listed for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeptRelease {
    pub version: String,
    pub sha256: String,
}

/// The choice (the default, GitHub's releases with none kept, when there is none yet or it
/// can't be read).
pub fn choice() -> Choice {
    let Ok(app_dir) = paths::app_dir() else {
        return Choice::default();
    };
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    choice_in(&app_dir)
}

fn choice_in(app_dir: &Path) -> Choice {
    let path = app_dir.join(CHOICE);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() && !is_link(&meta) && meta.len() <= 64 * 1024 => fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default(),
        _ => Choice::default(),
    }
}

fn save_choice_in(app_dir: &Path, choice: &Choice) -> Result<()> {
    fs::create_dir_all(app_dir)?;
    crate::extension_folder::put(&app_dir.join(CHOICE), &serde_json::to_vec(choice)?)
}

/// Takes the extension from the person's folder `folder` (checked first), or, with `None`,
/// from GitHub's releases again.
pub fn set_folder(folder: Option<&Path>) -> Result<()> {
    if let Some(folder) = folder {
        Extension::from_folder(folder)?;
    }
    let app_dir = paths::app_dir()?;
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let mut choice = choice_in(&app_dir);
    choice.folder = folder.map(Path::to_path_buf);
    save_choice_in(&app_dir, &choice)
}

/// Keeps a release's zip, downloaded for `version` with the SHA-256 GitHub listed: taken only
/// when the bytes have that very digest and hold the extension of that version. What it holds.
pub fn keep_release(version: &str, sha256: &str, zip: &[u8]) -> Result<Extension> {
    keep_release_in(&paths::app_dir()?, version, sha256, zip)
}

fn keep_release_in(app_dir: &Path, version: &str, sha256: &str, zip: &[u8]) -> Result<Extension> {
    if hex(&Sha256::digest(zip)) != sha256.to_ascii_lowercase() {
        bail!("the file downloaded isn't the one GitHub lists (SHA-256 differs)");
    }
    let extension = Extension::from_zip(zip)?;
    if extension.version != version {
        bail!(
            "the release {version} holds the extension {}",
            extension.version
        );
    }
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    fs::create_dir_all(app_dir)?;
    crate::extension_folder::put(&app_dir.join(RELEASE_ZIP), zip)?;
    let mut choice = choice_in(app_dir);
    choice.release = Some(KeptRelease {
        version: version.to_owned(),
        sha256: sha256.to_ascii_lowercase(),
    });
    save_choice_in(app_dir, &choice)?;
    Ok(extension)
}

/// The release kept, read again and checked against the digest recorded when it was
/// downloaded. `None` when there is none, or it doesn't check out (it is then forgotten).
pub fn kept_release() -> Option<Extension> {
    let app_dir = paths::app_dir().ok()?;
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    kept_release_in(&app_dir)
}

fn kept_release_in(app_dir: &Path) -> Option<Extension> {
    let mut choice = choice_in(app_dir);
    let kept = choice.release.clone()?;
    let path = app_dir.join(RELEASE_ZIP);
    let read = || -> Option<Extension> {
        let meta = fs::symlink_metadata(&path).ok()?;
        if is_link(&meta) || !meta.is_file() || meta.len() > MAX_ZIP_BYTES as u64 {
            return None;
        }
        let zip = fs::read(&path).ok()?;
        (hex(&Sha256::digest(&zip)) == kept.sha256)
            .then(|| Extension::from_zip(&zip).ok())
            .flatten()
            .filter(|extension| extension.version == kept.version)
    };
    let extension = read();
    if extension.is_none() {
        choice.release = None;
        let _ = save_choice_in(app_dir, &choice);
        let _ = fs::remove_file(&path);
    }
    extension
}

/// Where the extension the app writes now comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The copy built into the app.
    BuiltIn,
    /// A GitHub release's zip, kept.
    Release,
    /// The person's folder.
    Folder,
}

/// The extension the app writes now: the person's folder when they chose one (an error when
/// it can't be read: nothing else is taken in its place), else the newer of the release kept
/// and `built_in`.
pub fn current(built_in: &Extension) -> Result<(Extension, Origin)> {
    let choice = choice();
    if let Some(folder) = &choice.folder {
        return Extension::from_folder(folder)
            .with_context(|| format!("the folder {}", folder.display()))
            .map(|extension| (extension, Origin::Folder));
    }
    Ok(match kept_release() {
        Some(release) if newer(&release.version, &built_in.version) => (release, Origin::Release),
        _ => (built_in.clone(), Origin::BuiltIn),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;

    use super::*;

    /// A zip of `files` as the release's is made: each entry deflated when `deflate`, plain
    /// otherwise; `mode` is the Unix mode recorded (0: none).
    pub(crate) fn zip_of(files: &[(&str, &[u8])], deflate: bool, mode: u32) -> Vec<u8> {
        let mut zip = Vec::new();
        let mut directory = Vec::new();
        for (name, bytes) in files {
            let packed = if deflate {
                let mut encoder =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(bytes).unwrap();
                encoder.finish().unwrap()
            } else {
                bytes.to_vec()
            };
            let crc = crc32fast::hash(bytes);
            let method: u16 = if deflate { 8 } else { 0 };
            let offset = zip.len() as u32;
            zip.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            zip.extend_from_slice(&[20, 0, 0, 0]);
            zip.extend_from_slice(&method.to_le_bytes());
            zip.extend_from_slice(&[0; 4]);
            zip.extend_from_slice(&crc.to_le_bytes());
            zip.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            zip.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
            zip.extend_from_slice(&[0, 0]);
            zip.extend_from_slice(name.as_bytes());
            zip.extend_from_slice(&packed);
            directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            directory.extend_from_slice(&[20, if mode == 0 { 0 } else { 3 }, 20, 0, 0, 0]);
            directory.extend_from_slice(&method.to_le_bytes());
            directory.extend_from_slice(&[0; 4]);
            directory.extend_from_slice(&crc.to_le_bytes());
            directory.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
            directory.extend_from_slice(&[0; 8]);
            directory.extend_from_slice(&(mode << 16).to_le_bytes());
            directory.extend_from_slice(&offset.to_le_bytes());
            directory.extend_from_slice(name.as_bytes());
        }
        let at = zip.len() as u32;
        zip.extend_from_slice(&directory);
        zip.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        zip.extend_from_slice(&[0; 4]);
        zip.extend_from_slice(&(files.len() as u16).to_le_bytes());
        zip.extend_from_slice(&(files.len() as u16).to_le_bytes());
        zip.extend_from_slice(&(directory.len() as u32).to_le_bytes());
        zip.extend_from_slice(&at.to_le_bytes());
        zip.extend_from_slice(&[0, 0]);
        zip
    }

    const MANIFEST: &[u8] = br#"{"manifest_version":3,"version":"1.2.4"}"#;

    fn files() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("manifest.json", MANIFEST),
            ("background.js", b"// the worker\n"),
            ("_locales/en/messages.json", b"{}"),
        ]
    }

    #[test]
    fn a_release_zip_is_read_whole_deflated_or_stored() {
        for deflate in [true, false] {
            let extension = Extension::from_zip(&zip_of(&files(), deflate, 0o100_644)).unwrap();
            assert_eq!(extension.version, "1.2.4");
            assert_eq!(extension.files.len(), 3);
            assert_eq!(extension.files[0].0, "_locales/en/messages.json");
            assert!(
                extension
                    .files
                    .contains(&("background.js".to_owned(), b"// the worker\n".to_vec()))
            );
        }
    }

    #[test]
    fn a_zip_that_could_reach_outside_or_lie_is_refused() {
        let with = |name: &'static str| {
            let mut files = files();
            files.push((name, b"x"));
            Extension::from_zip(&zip_of(&files, true, 0))
        };
        for bad in [
            "../outside.js",
            "/root.js",
            "a/../../b.js",
            r"a\..\b.js",
            "c:/x.js",
            "a//b.js",
            "background.js",
        ] {
            assert!(with(bad).is_err(), "{bad}");
        }
        // A link (Unix mode 120000), whatever it points at.
        assert!(Extension::from_zip(&zip_of(&files(), false, 0o120_777)).is_err());
        // A byte changed after the checksum was made.
        let mut zip = zip_of(&files(), false, 0);
        let at = zip
            .windows(14)
            .position(|w| w == b"// the worker\n")
            .unwrap();
        zip[at] = b'X';
        assert!(Extension::from_zip(&zip).is_err());
        // No manifest, or one without a version a browser takes.
        assert!(Extension::from_zip(&zip_of(&[("a.js", b"x")], true, 0)).is_err());
        let odd: &[(&str, &[u8])] = &[("manifest.json", br#"{"version":"1.2.3.4.5"}"#)];
        assert!(Extension::from_zip(&zip_of(odd, true, 0)).is_err());
        // Cut short, or not a zip at all.
        let zip = zip_of(&files(), true, 0);
        assert!(Extension::from_zip(&zip[..zip.len() - 30]).is_err());
        assert!(Extension::from_zip(b"PK not really").is_err());
        assert!(Extension::from_zip(&vec![0; MAX_ZIP_BYTES + 1]).is_err());
    }

    #[test]
    fn versions_are_compared_as_numbers() {
        assert!(newer("0.4.10", "0.4.9"));
        assert!(newer("0.5", "0.4.9"));
        assert!(!newer("0.4.8", "0.4.8.0"));
        assert!(!newer("0.4.7", "0.4.8"));
        for bad in ["", "1.2.3-beta", "1..2", "1.2.3.4.5", "99999"] {
            assert!(!newer(bad, "0.0.1"), "{bad}");
        }
        assert!(newer("1.2.3.4", "1.2.3"));
    }

    #[test]
    fn a_release_is_kept_only_with_the_digest_github_lists() {
        let home = tempfile::tempdir().unwrap();
        let zip = zip_of(&files(), true, 0);
        let sha256 = hex(&Sha256::digest(&zip));
        // Another digest, or another version than the release's: nothing kept.
        let other = format!("{}0", &sha256[..63]);
        assert!(keep_release_in(home.path(), "1.2.4", &other, &zip).is_err());
        assert!(keep_release_in(home.path(), "1.2.5", &sha256, &zip).is_err());
        assert_eq!(kept_release_in(home.path()), None);
        assert!(!home.path().join(RELEASE_ZIP).exists());
        // Its own: kept, and read back.
        let kept = keep_release_in(home.path(), "1.2.4", &sha256.to_uppercase(), &zip).unwrap();
        assert_eq!(kept.version, "1.2.4");
        assert_eq!(kept_release_in(home.path()), Some(kept));
        // Changed on disk since: forgotten.
        let mut changed = zip.clone();
        changed.push(0);
        fs::write(home.path().join(RELEASE_ZIP), &changed).unwrap();
        assert_eq!(kept_release_in(home.path()), None);
        assert_eq!(choice_in(home.path()).release, None);
    }

    #[test]
    fn a_folder_of_the_persons_is_read_with_the_same_rules() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in files() {
            let path = dir.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        fs::create_dir_all(dir.path().join(".git/objects")).unwrap();
        fs::write(dir.path().join(".git/HEAD"), b"ref").unwrap();
        let extension = Extension::from_folder(dir.path()).unwrap();
        assert_eq!(extension.version, "1.2.4");
        assert_eq!(extension.files.len(), 3, "hidden ones left out");
        assert_eq!(
            extension.digest(),
            Extension::from_zip(&zip_of(&files(), true, 0))
                .unwrap()
                .digest(),
            "the same files, wherever they come from"
        );
        fs::remove_file(dir.path().join("manifest.json")).unwrap();
        assert!(Extension::from_folder(dir.path()).is_err(), "no manifest");
        assert!(Extension::from_folder(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn the_choice_is_kept_and_a_broken_one_is_the_default() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(choice_in(home.path()), Choice::default());
        let choice = Choice {
            folder: Some(PathBuf::from("extension-test-folder")),
            release: None,
        };
        save_choice_in(home.path(), &choice).unwrap();
        assert_eq!(choice_in(home.path()), choice);
        fs::write(home.path().join(CHOICE), b"{ not json").unwrap();
        assert_eq!(choice_in(home.path()), Choice::default());
    }
}
