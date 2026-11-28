// The version information of a Windows program (Explorer: Properties → Details), the same in
// every program the project releases: the product's name, the project as its company and the
// release's version (the package's `version`, which release.yml keeps equal in every app). Code
// signing checks it too (docs/CODE_SIGNING.md). Included by the build scripts of the desktop
// app, the CLI and the server (`include!("../windows-version-info.rs")`), each with its own
// description and file name.

/// Compiles the version information (and `more`, further resource lines such as an icon) into
/// the program being built, when it is built for Windows.
fn windows_version_info(description: &str, file_name: &str, licence: &str, more: &str) {
    println!("cargo:rerun-if-changed=../windows-version-info.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = std::env::var("CARGO_PKG_VERSION").expect("cargo sets the version");
    let numbers: Vec<u16> = version
        .split('.')
        .map(|part| part.parse().expect("a version of three numbers"))
        .collect();
    assert_eq!(numbers.len(), 3, "a version of three numbers: {version}");
    let (major, minor, patch) = (numbers[0], numbers[1], numbers[2]);
    let quoted = |text: &str| {
        assert!(!text.contains(['"', '\\', '\n']), "{text}");
        format!("\"{text}\"")
    };
    // VS_VERSION_INFO (1); FILEOS VOS_NT_WINDOWS32, FILETYPE VFT_APP; US English, Unicode.
    let resource = format!(
        "{more}
1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEFLAGSMASK 0x3F
FILEFLAGS 0x0
FILEOS 0x40004
FILETYPE 0x1
FILESUBTYPE 0x0
BEGIN
    BLOCK \"StringFileInfo\"
    BEGIN
        BLOCK \"040904B0\"
        BEGIN
            VALUE \"CompanyName\", {company}
            VALUE \"FileDescription\", {description}
            VALUE \"FileVersion\", {version_text}
            VALUE \"InternalName\", {internal}
            VALUE \"LegalCopyright\", {licence}
            VALUE \"OriginalFilename\", {file_name}
            VALUE \"ProductName\", {product}
            VALUE \"ProductVersion\", {version_text}
        END
    END
    BLOCK \"VarFileInfo\"
    BEGIN
        VALUE \"Translation\", 0x409, 1200
    END
END
",
        company = quoted("Vault"),
        product = quoted("Vault"),
        description = quoted(description),
        version_text = quoted(&version),
        internal = quoted(file_name.trim_end_matches(".exe")),
        licence = quoted(licence),
        file_name = quoted(file_name),
    );
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"))
        .join("version-info.rc");
    std::fs::write(&out, resource).expect("writing version-info.rc");
    embed_resource::compile(&out, embed_resource::NONE)
        .manifest_optional()
        .expect("the program's version information could not be compiled");
}

/// An `ICON` line for the resource: `path` written as the resource compiler reads it.
#[allow(dead_code)]
fn icon_line(path: &std::path::Path) -> String {
    let text = path.to_str().expect("a path that is Unicode");
    assert!(!text.contains('"'), "{text}");
    format!("1 ICON \"{}\"", text.replace('\\', "\\\\"))
}
