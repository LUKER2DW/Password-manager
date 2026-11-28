fn main() {
    // The Brazilian Portuguese catalogue (gettext, see translations/README.md) is compiled into
    // the app; `src/i18n.rs` picks it at run time.
    //
    // The Slint compiler runs on a thread with a stack of its own: the release build overflowed
    // the 1 MB stack of the main thread (see apps/desktop/ui/build.rs).
    let worker = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(|| {
            let config =
                slint_build::CompilerConfiguration::new().with_bundled_translations("translations");
            slint_build::compile_with_config("ui/app.slint", config)
                .expect("failed to compile the Slint UI");
        })
        .expect("a thread for the Slint compiler");
    worker.join().expect("the Slint compiler");
}
