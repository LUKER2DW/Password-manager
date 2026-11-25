# Fuzzing

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for what the apps read from
outside: a vault file's header, files brought in by import, and sync invite lines. They are
kept out of the workspace (libFuzzer needs a nightly toolchain); the property tests in
`crates/core/tests/sync.rs` cover the merge.

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run vault_file
cargo +nightly fuzz run import
cargo +nightly fuzz run invite_link
```

A crash is saved under `fuzz/artifacts/` (git-ignored); turn it into a regression test in the
crate it belongs to.
