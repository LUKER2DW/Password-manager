//! Puts the app's icon into the Windows executable (`assets/app.rc` → `assets/app.ico`), so
//! Explorer, the taskbar and system prompts such as Windows Hello show it. The window's own
//! icon is set by the UI at run time.

fn main() {
    println!("cargo:rerun-if-changed=assets/app.rc");
    println!("cargo:rerun-if-changed=assets/app.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("assets/app.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("the app's icon resource could not be compiled");
    }
}
