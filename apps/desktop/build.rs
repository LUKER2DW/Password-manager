//! Puts the app's icon into the Windows executable (`assets/app.rc` → `assets/app.ico`), so
//! Explorer, the taskbar and system prompts such as Windows Hello show it. The window's own
//! icon is set by the UI at run time.
//!
//! Also builds the browser extension's files into the app (`$OUT_DIR/extension_files.rs`,
//! read by `src/controller/extension.rs`): what the release's zip holds (`.github/workflows/
//! release.yml`, job `extension`), that is everything in `apps/extension` except its tests
//! (`test/`), `package.json` and `README.md`, here without hidden files and editor leftovers
//! too. The app writes them into a folder of its own, which the browser loads.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

fn main() {
    println!("cargo:rerun-if-changed=assets/app.rc");
    println!("cargo:rerun-if-changed=assets/app.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("assets/app.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("the app's icon resource could not be compiled");
    }
    extension_files();
}

/// Writes `extension_files.rs`: `FILES`, each `(path, bytes)` with `/` between the parts and
/// in a fixed order, and `VERSION`, the `version` of its `manifest.json`.
fn extension_files() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let extension = manifest_dir
        .parent()
        .expect("apps/desktop has a parent")
        .join("extension");
    // A folder here is looked at whole: any file changed, added or removed in it.
    println!("cargo:rerun-if-changed=../extension");
    let mut files = Vec::new();
    collect(&extension, "", &mut files);
    files.sort();
    assert!(
        files.iter().any(|(name, _)| name == "manifest.json"),
        "apps/extension/manifest.json is missing"
    );
    let manifest = std::fs::read(extension.join("manifest.json")).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest).expect("apps/extension/manifest.json is not JSON");
    let version = manifest["version"]
        .as_str()
        .expect("apps/extension/manifest.json has no version");
    let mut code = String::from(
        "/// The extension's files (`apps/extension`, as the release's zip holds them).\n\
         pub(crate) const FILES: &[(&str, &[u8])] = &[\n",
    );
    for (name, path) in &files {
        let path = path.to_str().expect("a path that isn't Unicode");
        writeln!(code, "    ({name:?}, include_bytes!({path:?})),").unwrap();
    }
    code.push_str("];\n");
    writeln!(
        code,
        "/// The `version` in its `manifest.json`.\npub(crate) const VERSION: &str = {version:?};"
    )
    .unwrap();
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("extension_files.rs");
    std::fs::write(out, code).unwrap();
}

/// The files under `dir` (at `base` inside the extension) that the browser loads.
fn collect(dir: &Path, base: &str, files: &mut Vec<(String, PathBuf)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let relative = if base.is_empty() {
            name.clone()
        } else {
            format!("{base}/{name}")
        };
        // Not shipped (release.yml), hidden, or an editor's copy.
        if matches!(relative.as_str(), "test" | "package.json" | "README.md")
            || name.starts_with('.')
            || name.ends_with('~')
        {
            continue;
        }
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            collect(&entry.path(), &relative, files);
        } else if kind.is_file() {
            files.push((relative, entry.path()));
        }
    }
}
