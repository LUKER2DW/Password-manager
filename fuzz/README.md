# Fuzzing

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for what the apps read from
someone else: a vault file or a copy of it from a sync place, what a sync server is sent and
what it answers, the browser extension's messages, the extension's release zip, files brought
in by import, invite lines, one-time code links and the picture that holds recovery part C.
They are kept out of the workspace (libFuzzer needs a nightly toolchain); the property tests in
`crates/core/tests/sync.rs` cover the merge itself.

| Target | Reads | Seeds |
|---|---|---|
| `vault_file` | a vault file's public header (`Vault::inspect`) | `crates/core/tests/fixtures/` |
| `sync_copy` | a copy from a sync place, checked and merged into the open v10 fixture (`check_copy`, `merge_from`): nothing is taken from it | `crates/core/tests/fixtures/` |
| `sync_requests` | what a server reads: an enrollment's body, a signed request's headers (`vault_sync_wire`, as `vault-server` reads them) | `seeds/sync_requests/` |
| `sync_answers` | what a device reads back: a server's JSON answers, a WebDAV listing, GitHub's release list, versions | `seeds/sync_answers/` |
| `invite_link` | a `vaultsync:` invite line | `seeds/invite_link/` |
| `import` | a JSON, CSV, KeePass (KDBX) or sealed export file (the first byte picks) | `seeds/import/` |
| `browser_link` | the extension's envelope, sealed request and proof, the request JSON, page addresses (`vault_browser`) | `seeds/browser_link/` |
| `extension_zip` | the extension's zip from a release (`Extension::from_zip`) | `seeds/extension_zip/` |
| `otpauth` | an `otpauth://` link or a Base32 secret (`Totp::parse`) | `seeds/otpauth/` |
| `part_picture` | a picture said to hold recovery part C (`part_picture::read`) | `seeds/part_picture/` |

The seeds are small inputs made for this, with obvious test values only. `corpus/` (what a run
grows) and `artifacts/` (what it found) are git-ignored.

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run --debug-assertions sync_copy corpus/sync_copy ../crates/core/tests/fixtures
cargo +nightly fuzz run --debug-assertions browser_link corpus/browser_link seeds/browser_link
```

A finding is saved under `artifacts/<target>/`; turn it into a regression test in the crate it
belongs to (`crates/platform/src/part_picture.rs` has one), then fix it.

**On a schedule:** `.github/workflows/fuzz.yml` runs every target for five minutes each day
(and on demand), on Linux with AddressSanitizer and debug assertions; a finding fails the job
and is kept as the run's artifact.

**On Windows** cargo-fuzz builds, but rustup ships no AddressSanitizer runtime for MSVC, and
without it the coverage sections' bounds are missing at link time. Run with `-s none`, and link
an object that defines them (what compiler-rt's `sanitizer_coverage_win_sections.cpp` does),
compiled once with MSVC's `cl /c /Zl /MD /GS- sancov_win.c`:

```c
#pragma section(".SCOV$CA", read, write)
__declspec(allocate(".SCOV$CA")) unsigned long long __start___sancov_cntrs = 0;
#pragma section(".SCOV$CZ", read, write)
__declspec(allocate(".SCOV$CZ")) __declspec(align(1)) unsigned char __stop___sancov_cntrs = 0;
#pragma section(".SCOV$GA", read, write)
__declspec(allocate(".SCOV$GA")) unsigned long long __start___sancov_guards = 0;
#pragma section(".SCOV$GZ", read, write)
__declspec(allocate(".SCOV$GZ")) __declspec(align(1)) unsigned char __stop___sancov_guards = 0;
#pragma comment(linker, "/MERGE:.SCOV=.data")
#pragma section(".SCOVP$A", read)
__declspec(allocate(".SCOVP$A")) unsigned long long __start___sancov_pcs = 0;
#pragma section(".SCOVP$Z", read)
__declspec(allocate(".SCOVP$Z")) __declspec(align(1)) unsigned char __stop___sancov_pcs = 0;
#pragma comment(linker, "/MERGE:.SCOVP=.rdata")
```

```powershell
$env:RUSTFLAGS = "-Clink-arg=C:\path\to\sancov_win.obj"
cargo +nightly fuzz run -s none --debug-assertions otpauth corpus/otpauth seeds/otpauth
```

Without a sanitizer a crash in `unsafe` or C code may go unnoticed there; panics, aborts,
timeouts and memory limits are still caught. A process that aborts (an allocation that fails)
leaves no artifact on Windows: rerun the input on Linux, or rebuild it in a test.
