fn main() {
    // The translations (gettext catalogues, see ../translations/README.md) are compiled into
    // the app; `src/i18n.rs` picks one at run time.
    let config =
        slint_build::CompilerConfiguration::new().with_bundled_translations("../translations");
    slint_build::compile_with_config("app.slint", config).expect("failed to compile the Slint UI");
}
