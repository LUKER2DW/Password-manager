//! Puts the program's version information into the Windows executable
//! (`../windows-version-info.rs`: product, company, version), as in every program the project
//! releases. Nothing on Linux.

include!("../windows-version-info.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    windows_version_info(
        "Vault sync server",
        "vault-server-windows-x64.exe",
        "AGPL-3.0-or-later",
        "",
    );
}
