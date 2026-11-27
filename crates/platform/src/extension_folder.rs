//! The browser extension's own folder: the files the desktop app carries, written where a
//! browser loads them from ("Load unpacked" in Chrome, Edge and the other Chromium browsers, a
//! temporary add-on in Firefox), and kept exactly as the app carries them.
//!
//! An extension loaded that way runs whatever its folder holds, read again whenever the browser
//! starts or the extension reloads itself (`chrome.runtime.reload()`, which is how it takes a
//! new version: `apps/extension/update.js`). So the folder is the app's alone:
//! - made by the app, under its own directory ([`folder`]);
//! - each file written whole, as a new file renamed over the old one, and never through a link:
//!   a link or junction in the folder's place, or in a file's, is removed first (never what it
//!   points at), so a write can't be sent somewhere else;
//! - anything in it that isn't one of the extension's files is removed;
//! - checked while the browser link runs ([`keep`]): a file that differs from the app's copy is
//!   put back. When the folder already held this version, that difference is another program
//!   changing the code that runs inside the browser, and [`Kept::tampered`] says so; after a new
//!   version of the app the differences are the update itself.
//!
//! A small file next to the folder (`browser-extension.version`) names the version written,
//! and says the app made the folder: without it, or once the person deleted the folder, the
//! link's checks leave it alone.
//!
//! This doesn't stop a program running as the same Windows user: it can change the files
//! between two checks, change the browser itself, or load an extension of its own. See
//! docs/THREAT_MODEL.md.

use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use anyhow::{Context, Result, bail};

use crate::{extension_source::Extension, files::is_link, paths};

/// The folder's name in the app's directory.
pub const FOLDER: &str = "browser-extension";
/// The file that names the version written into the folder, next to it.
const MARKER: &str = "browser-extension.version";
/// What a file is first written as, in its own folder, before it is renamed into place.
const NEW: &str = ".vault-new";
/// Files Windows' Explorer may leave in a folder the person opened (its view, thumbnails):
/// removed like anything else, but no one's attempt to change the extension (they run nothing).
const EXPLORER: [&str; 2] = ["desktop.ini", "thumbs.db"];

/// `<app dir>/browser-extension`: where the browser loads the extension from.
pub fn folder() -> Result<PathBuf> {
    Ok(paths::app_dir()?.join(FOLDER))
}

/// What one pass over the folder found, and put right. Paths are relative to the folder, with
/// `/` between their parts ("" is the folder itself).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// The extension's files (or folders) that were there with other contents, or with
    /// something else in their place (a link, a folder): written again.
    pub changed: Vec<String>,
    /// Its files that were missing: written.
    pub missing: Vec<String>,
    /// What the folder held that isn't the extension's: removed.
    pub extra: Vec<String>,
}

impl Report {
    /// Whether anything in the folder was other than the app wrote: a file changed, or added.
    /// (A missing file runs nothing.)
    pub fn differed(&self) -> bool {
        !self.changed.is_empty() || !self.extra.is_empty()
    }
}

/// What [`install`] or [`keep`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The folder, as the browser is to be pointed at it.
    pub path: PathBuf,
    pub report: Report,
    /// The folder held these very files already, and something in it had been changed or
    /// added since: another program changed the extension's code. It is put back now.
    pub tampered: bool,
}

/// Writes `extension` into [`folder`], putting right whatever differs. Used when the person
/// adds the extension to a browser.
pub fn install(extension: &Extension) -> Result<Kept> {
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    install_in(&paths::app_dir()?, extension)
}

/// [`install`], only when the app wrote the folder before and it is still there (its checks
/// while the browser link runs). `None` when there is nothing of the app's to keep.
pub fn keep(extension: &Extension) -> Result<Option<Kept>> {
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    keep_in(&paths::app_dir()?, extension)
}

/// The version written into the folder last, when the app wrote it.
pub fn written() -> Option<String> {
    let marker = read_marker(&paths::app_dir().ok()?.join(MARKER))?;
    Some(marker.0)
}

/// One pass over the folder at a time in this process (the link's checks run on threads of
/// their own, while the person may be adding the extension to a browser).
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn install_in(app_dir: &Path, extension: &Extension) -> Result<Kept> {
    fs::create_dir_all(app_dir).with_context(|| format!("creating {}", app_dir.display()))?;
    let marker = app_dir.join(MARKER);
    let before = read_marker(&marker);
    let dir = app_dir.join(FOLDER);
    let report = write(&dir, &extension.files)?;
    // The same files as written last: what differed is someone else's doing. Other files (a
    // new version, another source, the person's own changes to their folder) are the update.
    let digest = extension.digest();
    let same = before
        .as_ref()
        .is_some_and(|(_, written)| *written == digest);
    if !same {
        put(
            &marker,
            format!("{}\n{digest}\n", extension.version).as_bytes(),
        )
        .with_context(|| format!("writing {}", marker.display()))?;
    }
    Ok(Kept {
        path: dir,
        tampered: same && report.differed(),
        report,
    })
}

fn keep_in(app_dir: &Path, extension: &Extension) -> Result<Option<Kept>> {
    let marker = app_dir.join(MARKER);
    if read_marker(&marker).is_none() {
        return Ok(None);
    }
    match fs::symlink_metadata(app_dir.join(FOLDER)) {
        Ok(_) => install_in(app_dir, extension).map(Some),
        // Deleted: the person took the extension out of the app's hands.
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let _ = fs::remove_file(&marker);
            Ok(None)
        }
        Err(err) => Err(err).context("looking at the extension's folder"),
    }
}

/// Makes `dir` hold exactly `files`: each one written when it is missing or differs, anything
/// else removed, no link followed. What it found is in the [`Report`].
pub fn write(dir: &Path, files: &[(String, Vec<u8>)]) -> Result<Report> {
    let mut report = Report::default();
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    if real_dir(dir).with_context(|| format!("creating {}", dir.display()))? {
        report.changed.push(String::new());
    }
    let mut wanted_files = HashSet::new();
    let mut wanted_dirs = HashSet::new();
    for (name, bytes) in files {
        let (name, bytes) = (name.as_str(), bytes.as_slice());
        let parts = parts_of(name)?;
        let mut at = dir.to_path_buf();
        for (depth, part) in parts[..parts.len() - 1].iter().enumerate() {
            at.push(part);
            let relative = parts[..=depth].join("/");
            if wanted_dirs.insert(folded(&relative)) && real_dir(&at)? {
                report.changed.push(relative);
            }
        }
        wanted_files.insert(folded(name));
        let path = dir.join(parts.join(std::path::MAIN_SEPARATOR_STR));
        match fs::symlink_metadata(&path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                put(&path, bytes)?;
                report.missing.push(name.to_owned());
            }
            Err(err) => return Err(err).with_context(|| format!("looking at {name}")),
            Ok(meta) if meta.is_file() && !is_link(&meta) => {
                if !holds(&path, bytes).with_context(|| format!("reading {name}"))? {
                    writable(&path, &meta);
                    put(&path, bytes)?;
                    report.changed.push(name.to_owned());
                }
            }
            Ok(meta) => {
                remove(&path, &meta).with_context(|| format!("removing what was at {name}"))?;
                put(&path, bytes)?;
                report.changed.push(name.to_owned());
            }
        }
    }
    sweep(dir, "", &wanted_files, &wanted_dirs, &mut report)?;
    Ok(report)
}

/// The parts of one of the extension's paths: plain names only.
fn parts_of(name: &str) -> Result<Vec<&str>> {
    let parts: Vec<&str> = name.split('/').collect();
    let plain = |part: &&str| {
        !part.is_empty()
            && *part != "."
            && *part != ".."
            && !part.contains(['\\', ':', '\0'])
            && !part.ends_with(NEW)
    };
    if !parts.iter().all(plain) {
        bail!("not a path inside the extension: {name}");
    }
    Ok(parts)
}

/// A name as the file system compares it: Windows doesn't tell `a` from `A`.
fn folded(name: &str) -> String {
    if cfg!(windows) {
        name.to_lowercase()
    } else {
        name.to_owned()
    }
}

/// Makes `path` a real folder; whether something else was in its place (removed first).
fn real_dir(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !is_link(&meta) => Ok(false),
        Ok(meta) => {
            remove(path, &meta)?;
            fs::create_dir(path)?;
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            Ok(false)
        }
        Err(err) => Err(err.into()),
    }
}

/// Removes what is at `path` without following it: a link goes, never what it points at; a
/// folder goes with all it holds (`remove_dir_all` doesn't follow the links inside either).
fn remove(path: &Path, meta: &fs::Metadata) -> io::Result<()> {
    if is_link(meta) {
        // A link to a folder (a junction, a folder's symbolic link) is removed as a folder on
        // Windows; a link to a file, as a file.
        return fs::remove_file(path).or_else(|_| fs::remove_dir(path));
    }
    if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        writable(path, meta);
        fs::remove_file(path)
    }
}

/// Takes a file's read-only mark off: on Windows it stops the file being replaced or removed,
/// and another program could set it on a file it changed, so that it stays. (The attribute
/// only: no one gains access by it.)
#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn writable(path: &Path, meta: &fs::Metadata) {
    if !is_link(meta) && meta.is_file() && meta.permissions().readonly() {
        let mut permissions = meta.permissions();
        permissions.set_readonly(false);
        let _ = fs::set_permissions(path, permissions);
    }
}

/// Elsewhere a read-only file is still replaced and removed (the folder's own rights count).
#[cfg(not(windows))]
fn writable(_: &Path, _: &fs::Metadata) {}

/// Whether the file at `path` holds exactly `bytes` (read up to one byte past them).
fn holds(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let mut found = Vec::with_capacity(bytes.len() + 1);
    fs::File::open(path)?
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut found)?;
    Ok(found == bytes)
}

/// Writes `bytes` to `path` whole: a new file next to it, flushed, then renamed over it (the
/// name only: a link there is replaced, not written through).
pub(crate) fn put(path: &Path, bytes: &[u8]) -> Result<()> {
    let name = path
        .file_name()
        .context("a file without a name")?
        .to_string_lossy();
    let new = path.with_file_name(format!("{name}{NEW}"));
    if let Ok(meta) = fs::symlink_metadata(&new) {
        // Left by a write that stopped halfway (or put there): only that name goes.
        remove(&new, &meta).with_context(|| format!("removing {}", new.display()))?;
    }
    let written = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&new)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&new, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&new);
    }
    written.with_context(|| format!("writing {}", path.display()))
}

/// Removes from `dir` (at `base` inside the extension's folder) what isn't one of the wanted
/// files or folders, and goes down into the wanted folders.
fn sweep(
    dir: &Path,
    base: &str,
    wanted_files: &HashSet<String>,
    wanted_dirs: &HashSet<String>,
    report: &mut Report,
) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let relative = if base.is_empty() {
            name.clone()
        } else {
            format!("{base}/{name}")
        };
        let meta = fs::symlink_metadata(&path)?;
        let link = is_link(&meta);
        if !link && meta.is_dir() && wanted_dirs.contains(&folded(&relative)) {
            sweep(&path, &relative, wanted_files, wanted_dirs, report)?;
            continue;
        }
        if !link && meta.is_file() && wanted_files.contains(&folded(&relative)) {
            continue;
        }
        remove(&path, &meta).with_context(|| format!("removing {relative}"))?;
        // A file of a write that stopped halfway is no one else's doing, nor is Explorer's.
        let inert = !link && meta.is_file() && EXPLORER.contains(&name.to_lowercase().as_str());
        if !name.ends_with(NEW) && !inert {
            report.extra.push(relative);
        }
    }
    Ok(())
}

/// The version and digest the marker names, when it is a file of its own (not a link) and
/// reads as one.
fn read_marker(path: &Path) -> Option<(String, String)> {
    let meta = fs::symlink_metadata(path).ok()?;
    if is_link(&meta) || !meta.is_file() || meta.len() > 256 {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let mut lines = text.lines().map(str::trim);
    let version = lines.next().filter(|version| !version.is_empty())?;
    Some((
        version.to_owned(),
        lines.next().unwrap_or_default().to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(version: &str, files: &[(&str, &[u8])]) -> Extension {
        Extension::built_in(version, files)
    }

    const FILES: &[(&str, &[u8])] = &[
        ("manifest.json", br#"{"version":"1.2.3"}"#),
        ("background.js", b"// the worker\n"),
        ("_locales/en/messages.json", b"{}"),
        ("icons/icon16.png", &[0x89, b'P', b'N', b'G']),
    ];

    fn names(dir: &Path) -> Vec<String> {
        let mut found = Vec::new();
        fn walk(dir: &Path, base: &str, found: &mut Vec<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().into_owned();
                let relative = if base.is_empty() {
                    name
                } else {
                    format!("{base}/{name}")
                };
                if entry.file_type().unwrap().is_dir() {
                    walk(&entry.path(), &relative, found);
                } else {
                    found.push(relative);
                }
            }
        }
        walk(dir, "", &mut found);
        found.sort();
        found
    }

    fn sorted(names: &[&str]) -> Vec<String> {
        let mut names: Vec<String> = names.iter().map(|&name| name.to_owned()).collect();
        names.sort();
        names
    }

    #[test]
    fn every_file_is_written_and_a_second_pass_finds_nothing() {
        let home = tempfile::tempdir().unwrap();
        let kept = install_in(home.path(), &ext("1.2.3", FILES)).unwrap();
        assert_eq!(kept.path, home.path().join(FOLDER));
        assert!(!kept.tampered);
        assert_eq!(
            kept.report.missing,
            FILES.iter().map(|(name, _)| *name).collect::<Vec<_>>()
        );
        assert!(!kept.report.differed());
        assert_eq!(
            names(&kept.path),
            sorted(&FILES.iter().map(|(name, _)| *name).collect::<Vec<_>>())
        );
        for (name, bytes) in FILES {
            assert_eq!(fs::read(kept.path.join(name)).unwrap(), *bytes, "{name}");
        }
        assert_eq!(
            read_marker(&home.path().join(MARKER))
                .map(|marker| marker.0)
                .as_deref(),
            Some("1.2.3")
        );
        let again = keep_in(home.path(), &ext("1.2.3", FILES)).unwrap().unwrap();
        assert_eq!(again.report, Report::default());
        assert!(!again.tampered);
    }

    #[test]
    fn a_changed_or_added_file_is_put_right_and_told_for_the_same_version() {
        let home = tempfile::tempdir().unwrap();
        let dir = install_in(home.path(), &ext("1.2.3", FILES)).unwrap().path;
        fs::write(dir.join("background.js"), b"stealPasswords();").unwrap();
        fs::write(dir.join("evil.js"), b"stealPasswords();").unwrap();
        fs::create_dir_all(dir.join("_locales/xx")).unwrap();
        fs::write(dir.join("_locales/xx/messages.json"), b"{}").unwrap();
        fs::remove_file(dir.join("icons/icon16.png")).unwrap();
        let kept = keep_in(home.path(), &ext("1.2.3", FILES)).unwrap().unwrap();
        assert!(kept.tampered);
        assert_eq!(kept.report.changed, ["background.js"]);
        assert_eq!(kept.report.missing, ["icons/icon16.png"]);
        let mut extra = kept.report.extra.clone();
        extra.sort();
        assert_eq!(extra, ["_locales/xx", "evil.js"]);
        assert_eq!(
            names(&dir),
            sorted(&FILES.iter().map(|(name, _)| *name).collect::<Vec<_>>())
        );
        assert_eq!(
            fs::read(dir.join("background.js")).unwrap(),
            b"// the worker\n"
        );
        // Marked read-only so that it stays: put back all the same, and so is an added one.
        fs::write(dir.join("background.js"), b"stealPasswords();").unwrap();
        fs::write(dir.join("evil.js"), b"stealPasswords();").unwrap();
        for name in ["background.js", "evil.js"] {
            let mut permissions = fs::metadata(dir.join(name)).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(dir.join(name), permissions).unwrap();
        }
        let kept = keep_in(home.path(), &ext("1.2.3", FILES)).unwrap().unwrap();
        assert!(kept.tampered);
        assert_eq!(kept.report.changed, ["background.js"]);
        assert_eq!(kept.report.extra, ["evil.js"]);
        assert_eq!(
            fs::read(dir.join("background.js")).unwrap(),
            b"// the worker\n"
        );
        assert!(!dir.join("evil.js").exists());
        // Only missing files: nothing ran that the app didn't write.
        fs::remove_file(dir.join("background.js")).unwrap();
        let kept = keep_in(home.path(), &ext("1.2.3", FILES)).unwrap().unwrap();
        assert!(!kept.tampered);
        assert_eq!(kept.report.missing, ["background.js"]);
    }

    #[test]
    fn a_new_version_is_written_over_the_old_one_without_a_word() {
        let home = tempfile::tempdir().unwrap();
        let dir = install_in(home.path(), &ext("1.2.3", FILES)).unwrap().path;
        fs::write(dir.join("removed-in-1.2.4.js"), b"old").unwrap();
        let newer: &[(&str, &[u8])] = &[
            ("manifest.json", br#"{"version":"1.2.4"}"#),
            ("background.js", b"// the worker, newer\n"),
            ("_locales/en/messages.json", b"{}"),
            ("icons/icon16.png", &[0x89, b'P', b'N', b'G']),
        ];
        let kept = keep_in(home.path(), &ext("1.2.4", newer)).unwrap().unwrap();
        assert!(!kept.tampered, "the differences are the update");
        assert_eq!(kept.report.changed, ["manifest.json", "background.js"]);
        assert_eq!(kept.report.extra, ["removed-in-1.2.4.js"]);
        assert_eq!(
            fs::read(dir.join("manifest.json")).unwrap(),
            br#"{"version":"1.2.4"}"#
        );
        assert_eq!(
            read_marker(&home.path().join(MARKER))
                .map(|marker| marker.0)
                .as_deref(),
            Some("1.2.4")
        );
    }

    #[test]
    fn nothing_is_kept_that_the_app_never_wrote_or_the_person_deleted() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(keep_in(home.path(), &ext("1.2.3", FILES)).unwrap(), None);
        assert!(!home.path().join(FOLDER).exists());
        let dir = install_in(home.path(), &ext("1.2.3", FILES)).unwrap().path;
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(keep_in(home.path(), &ext("1.2.3", FILES)).unwrap(), None);
        assert!(!dir.exists());
        assert!(!home.path().join(MARKER).exists(), "forgotten");
    }

    #[test]
    fn a_write_left_halfway_or_explorers_files_are_cleared_without_a_word() {
        let home = tempfile::tempdir().unwrap();
        let dir = install_in(home.path(), &ext("1.2.3", FILES)).unwrap().path;
        fs::write(dir.join(format!("background.js{NEW}")), b"half").unwrap();
        // Explorer's view of the folder, opened by the person.
        fs::write(dir.join("desktop.ini"), b"[ViewState]").unwrap();
        fs::write(dir.join("icons/Thumbs.db"), b"thumbnails").unwrap();
        let kept = keep_in(home.path(), &ext("1.2.3", FILES)).unwrap().unwrap();
        assert!(!kept.tampered);
        assert!(!dir.join(format!("background.js{NEW}")).exists());
        assert!(!dir.join("desktop.ini").exists() && !dir.join("icons/Thumbs.db").exists());
    }

    #[test]
    fn only_plain_paths_inside_the_folder_are_written() {
        let home = tempfile::tempdir().unwrap();
        for bad in [
            "../outside.js",
            "/root.js",
            "a//b.js",
            r"a\b.js",
            "c:x.js",
            "",
        ] {
            assert!(
                write(
                    &home.path().join(FOLDER),
                    &[(bad.to_owned(), b"x".to_vec())]
                )
                .is_err(),
                "{bad}"
            );
        }
        assert!(!home.path().join("outside.js").exists());
    }

    /// Makes `link` point at the folder `target`: a symbolic link, or on Windows without the
    /// right to make one, a junction.
    #[cfg(windows)]
    fn link_dir(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
            || std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .is_ok_and(|out| out.status.success())
    }

    #[cfg(unix)]
    fn link_dir(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[test]
    fn a_link_in_the_folders_place_or_a_files_is_replaced_not_followed() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        fs::write(elsewhere.path().join("manifest.json"), b"someone else's").unwrap();
        let dir = home.path().join(FOLDER);
        if !link_dir(elsewhere.path(), &dir) {
            eprintln!("no link could be made here: skipped");
            return;
        }
        // Planted before this version was written: replaced, nothing written through it.
        put(
            &home.path().join(MARKER),
            format!(
                "1.2.3
{}
",
                ext("1.2.3", FILES).digest()
            )
            .as_bytes(),
        )
        .unwrap();
        let kept = install_in(home.path(), &ext("1.2.3", FILES)).unwrap();
        assert!(kept.tampered);
        assert_eq!(kept.report.changed, [""]);
        assert_eq!(
            fs::read(elsewhere.path().join("manifest.json")).unwrap(),
            b"someone else's"
        );
        assert_eq!(names(elsewhere.path()), ["manifest.json"]);
        let meta = fs::symlink_metadata(&dir).unwrap();
        assert!(meta.is_dir() && !is_link(&meta));
        // A link in a folder's place inside it: the same.
        fs::remove_dir_all(dir.join("icons")).unwrap();
        assert!(link_dir(elsewhere.path(), &dir.join("icons")));
        let kept = keep_in(home.path(), &ext("1.2.3", FILES)).unwrap().unwrap();
        assert!(kept.tampered);
        assert_eq!(kept.report.changed, ["icons"]);
        assert_eq!(names(elsewhere.path()), ["manifest.json"]);
        assert_eq!(
            fs::read(dir.join("icons/icon16.png")).unwrap(),
            [0x89, b'P', b'N', b'G']
        );
        // A link added as an extra: removed, its target left.
        assert!(link_dir(elsewhere.path(), &dir.join("more")));
        let kept = keep_in(home.path(), &ext("1.2.3", FILES)).unwrap().unwrap();
        assert_eq!(kept.report.extra, ["more"]);
        assert!(!dir.join("more").exists());
        assert_eq!(names(elsewhere.path()), ["manifest.json"]);
    }
}
