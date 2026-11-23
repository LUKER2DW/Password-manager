fn main() {
    // The Brazilian Portuguese catalogue (gettext, see translations/README.md) is compiled into
    // the app; `src/i18n.rs` picks it at run time.
    let config =
        slint_build::CompilerConfiguration::new().with_bundled_translations("translations");
    slint_build::compile_with_config("ui/app.slint", config)
        .expect("failed to compile the Slint UI");
}
