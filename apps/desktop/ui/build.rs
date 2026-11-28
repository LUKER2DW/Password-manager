fn main() {
    // The translations (gettext catalogues, see ../translations/README.md) are compiled into
    // the app; `src/i18n.rs` picks one at run time.
    //
    // The Slint compiler works through the whole UI recursively, and a release build of these
    // files overflowed the 1 MB stack Windows gives the main thread (STATUS_STACK_OVERFLOW), so
    // it runs on a thread with a stack of its own.
    let worker = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(|| {
            let config = slint_build::CompilerConfiguration::new()
                .with_bundled_translations("../translations");
            slint_build::compile_with_config("app.slint", config)
                .expect("failed to compile the Slint UI");
        })
        .expect("a thread for the Slint compiler");
    worker.join().expect("the Slint compiler");
}
