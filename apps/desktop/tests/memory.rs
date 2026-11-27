//! The memory test (Windows): a running copy of the app opens a vault, shows a guarded item's
//! secrets and locks; its whole memory is read from outside before and after the lock. After
//! it nothing of the vault's secrets may be left; before it, the vault key and the guard key
//! may not be found either (they are kept encrypted between uses, `vault_core::memory`).
//!
//! The copy is this test again, as a process of its own (`CHILD` set), started like the app
//! (the release build's process protection and the key shield on) and driven through the
//! window's own callbacks with Slint's testing backend. This process keeps the handle Windows
//! gave it when it started the copy, which still reads its memory after the copy closed itself
//! to other programs (`vault_platform::process::protect_memory`), and searches it with
//! `VirtualQueryEx` and `ReadProcessMemory`: no dump file, nothing written to disk.
//!
//! What is looked for: the master password, the Secret Key (its bytes and its text), the
//! vault key, the item guard key, and the item's password, one-time code secret (text and
//! bytes) and notes; text in UTF-8 and UTF-16 (what Windows and the UI convert to). Every
//! 16-byte piece of each is looked for, not only the whole value: the heap writes its own
//! bookkeeping over the first bytes of a freed block and leaves the rest. All of them are
//! made here at run time (a literal would be in the test's own image) and the copy gets the
//! master password and the PIN through its standard input, read past the standard library's
//! buffer (the environment and the command line stay in its memory).
//!
//! Slint's testing backend draws nothing and serves no UI Automation: copies made by the
//! renderer (Skia) or a screen reader's requests aren't covered here.

#![cfg(windows)]

use std::{
    ffi::c_void,
    io::{BufRead, BufReader, Read, Write},
    os::windows::io::AsRawHandle,
    path::PathBuf,
    process::{ChildStdin, Command, Stdio},
};

use aho_corasick::AhoCorasick;
use slint::ComponentHandle;
use vault_core::{
    GuardCheck, ItemData, ItemKind, KdfParams, SecretKey, Vault,
    generator::{PasswordOptions, generate_password},
    memory_test,
};
use vault_desktop::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::{AppWindow, Screen, Secrets},
};
use vault_platform::secret_store;
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{
            MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READWRITE, PAGE_WRITECOPY,
            VirtualQueryEx,
        },
        Threading::GetCurrentThreadStackLimits,
    },
};
use zeroize::Zeroizing;

/// Set in the copy of this test that plays the app.
const CHILD: &str = "VAULT_MEMORY_TEST_CHILD";
/// The vault file the copy opens.
const FILE: &str = "VAULT_MEMORY_TEST_FILE";
/// The length of the pieces looked for.
const PIECE: usize = 16;

/// Secret fields of the window (`controller::field`): the master password on the lock
/// screen, and the item lock's PIN or password.
const MASTER_FIELD: i32 = 0;
const ITEM_LOCK_FIELD: i32 = 11;

#[test]
fn secrets_leave_memory_when_the_vault_locks() {
    if std::env::var_os(CHILD).is_some() {
        play_the_app();
    } else {
        look_into_the_app();
    }
}

// ---- the copy that plays the app ----

fn play_the_app() {
    // As the app starts (apps/desktop/src/main.rs, release build).
    vault_platform::process::restrict_dll_search();
    assert!(vault_platform::process::protect_memory());
    vault_platform::process::apply_mitigations();
    assert!(vault_platform::secure_memory::install_key_shield());

    let told = read_message();
    let text = std::str::from_utf8(&told).unwrap();
    let (master, pin) = text.trim_end().split_once('\t').unwrap();

    i_slint_backend_testing::init_no_event_loop();
    let app = AppWindow::new().unwrap();
    apply_sketches(&app);
    let path = PathBuf::from(std::env::var_os(FILE).unwrap());
    let _controller = Controller::install(&app, path, Runner::Inline, None).unwrap();

    type_into(&app, MASTER_FIELD, master);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault, "unlocked");
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert!(app.get_detail_locked(), "the item waits for its PIN");
    type_into(&app, ITEM_LOCK_FIELD, pin);
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked(), "the PIN opened it");
    app.invoke_reveal();
    assert!(!app.get_revealed_password().is_empty(), "password shown");
    assert!(!app.get_totp_code().is_empty(), "one-time code shown");
    assert!(!app.get_detail_notes().is_empty(), "notes shown");
    drop(told);

    // Where this thread's stack is, so what is found there can be told apart.
    let (mut low, mut high) = (0usize, 0usize);
    // SAFETY: two writable `usize`s for the bounds of this thread's own stack.
    #[allow(unsafe_code)]
    unsafe {
        GetCurrentThreadStackLimits(&raw mut low, &raw mut high);
    }
    say(&format!("open {low} {high}"));
    wait_for("lock");
    app.invoke_lock();
    assert_eq!(app.get_screen(), Screen::Unlock, "locked");
    say("locked");
    wait_for("quit");
}

fn type_into(app: &AppWindow, field: i32, text: &str) {
    let secrets = app.global::<Secrets>();
    secrets.invoke_clear(field);
    for c in text.chars() {
        secrets.invoke_insert(field, c.to_string().into());
    }
}

/// One line from standard input, read straight into a buffer wiped when dropped: a read
/// larger than the standard library's own buffer bypasses it, so no copy stays there.
fn read_message() -> Zeroizing<Vec<u8>> {
    let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut filled = 0;
    let mut input = std::io::stdin();
    while !buffer[..filled].contains(&b'\n') {
        let read = input.read(&mut buffer[filled..]).unwrap();
        assert!(read > 0, "standard input ended");
        filled += read;
    }
    buffer.truncate(filled);
    buffer
}

fn say(words: &str) {
    println!("memory-test: {words}");
    std::io::stdout().flush().unwrap();
}

fn wait_for(word: &str) {
    let message = read_message();
    assert_eq!(std::str::from_utf8(&message).unwrap().trim_end(), word);
}

// ---- this process: the vault, the copy, its memory ----

/// A value looked for: which secret, in which form.
struct Wanted {
    secret: &'static str,
    form: &'static str,
    bytes: Vec<u8>,
}

impl Wanted {
    /// `text` in UTF-8 and in UTF-16.
    fn text(secret: &'static str, text: &str) -> Vec<Self> {
        vec![
            Self {
                secret,
                form: "UTF-8",
                bytes: text.as_bytes().to_vec(),
            },
            Self {
                secret,
                form: "UTF-16",
                bytes: text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            },
        ]
    }

    fn bytes(secret: &'static str, bytes: &[u8]) -> Vec<Self> {
        vec![Self {
            secret,
            form: "bytes",
            bytes: bytes.to_vec(),
        }]
    }
}

/// Random text from the app's own generator: letters and digits only, so a piece of it
/// can't be found anywhere by chance.
fn random_text(length: usize, letters: bool) -> String {
    let options = PasswordOptions {
        length,
        lowercase: letters,
        uppercase: letters,
        digits: true,
        symbols: false,
        ..PasswordOptions::default()
    };
    generate_password(&options).unwrap().to_string()
}

/// RFC 4648 Base32, as one-time code secrets are written.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    for chunk in bytes.chunks(5) {
        let mut block = [0u8; 5];
        block[..chunk.len()].copy_from_slice(chunk);
        let bits = block.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        for i in 0..(chunk.len() * 8).div_ceil(5) {
            out.push(char::from(ALPHABET[((bits >> (35 - i * 5)) & 31) as usize]));
        }
    }
    out
}

fn send(input: &mut ChildStdin, line: &str) {
    input.write_all(line.as_bytes()).unwrap();
    input.write_all(b"\n").unwrap();
    input.flush().unwrap();
}

/// Removes the test vault's Secret Key from the OS credential store, even if the test fails.
struct ForgetOnDrop(String);

impl Drop for ForgetOnDrop {
    fn drop(&mut self) {
        let _ = secret_store::forget(&self.0);
    }
}

fn look_into_the_app() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.vault");

    let master = random_text(28, true);
    let pin = random_text(8, false);
    let password = random_text(32, true);
    let notes = format!("notes {}", random_text(40, true));
    let totp_bytes = random_text(20, true).into_bytes();
    let totp = base32(&totp_bytes);
    let secret_key = SecretKey::generate().unwrap();

    let mut vault =
        Vault::create(&master, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    let mut item = ItemData::new(ItemKind::Login, "Memory test");
    item.username = "memory-test@example.com".into();
    item.password = password.clone();
    item.totp = totp.clone();
    item.notes = notes.clone();
    vault.add_item(&item).unwrap();
    vault
        .set_item_guard(true, GuardCheck::Pin, Some(&pin), Some(&master))
        .unwrap();
    std::fs::write(&path, vault.to_bytes().unwrap()).unwrap();
    let _forget = ForgetOnDrop(vault.id_hex());
    // As on a device the vault was made on: its Secret Key in the credential store.
    secret_store::store(&vault.id_hex(), &secret_key).unwrap();

    let wanted: Vec<Wanted> = [
        Wanted::text("master password", &master),
        Wanted::bytes("Secret Key", &*memory_test::secret_key(&secret_key)),
        Wanted::text("Secret Key", &secret_key.to_display_string()),
        Wanted::bytes("vault key", &*memory_test::vault_key(&vault)),
        Wanted::bytes("guard key", &*memory_test::guard_key(&vault).unwrap()),
        Wanted::text("item password", &password),
        Wanted::text("one-time code secret", &totp),
        Wanted::bytes("one-time code secret", &totp_bytes),
        Wanted::text("notes", &notes),
    ]
    .into_iter()
    .flatten()
    .collect();
    drop(vault);

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "secrets_leave_memory_when_the_vault_locks",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env(FILE, &path)
        .env("VAULT_HOME", dir.path().join("home"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    // What the copy says after `word`, once it says it.
    let mut expect = |word: &str| -> String {
        let mut said = String::new();
        loop {
            let mut line = String::new();
            if output.read_line(&mut line).unwrap() == 0 {
                panic!("the app's copy ended before saying {word:?}: {said}");
            }
            // The test harness may have started the line ("test name ... ").
            if let Some((_, rest)) = line.split_once(&format!("memory-test: {word}")) {
                return rest.trim().to_owned();
            }
            said.push_str(&line);
        }
    };

    send(&mut input, &format!("{master}\t{pin}"));
    let stack = expect("open");
    let (low, high) = stack.split_once(' ').unwrap();
    let stack = low.parse::<usize>().unwrap()..high.parse::<usize>().unwrap();
    let handle = child.as_raw_handle();
    let open = search(handle, &wanted);
    send(&mut input, "lock");
    expect("locked");
    let locked = search(handle, &wanted);
    send(&mut input, "quit");
    let ended = child.wait().unwrap();

    println!(
        "{:<36} {:>5} {:>7}",
        "found in the app's memory", "open", "locked"
    );
    let mut left = Vec::new();
    let mut open_keys = Vec::new();
    for (index, value) in wanted.iter().enumerate() {
        let name = format!("{} ({})", value.secret, value.form);
        println!(
            "{name:<36} {:>5} {:>7}",
            open[index].len(),
            locked[index].len()
        );
        for &at in &locked[index] {
            let place = if stack.contains(&at) {
                "the UI thread's stack"
            } else {
                "the heap or other memory"
            };
            println!("    after the lock at {at:#x}: {place}");
            left.push((name.clone(), place));
        }
        // The keys are encrypted between uses (the key shield), even while the vault is open.
        if matches!(value.secret, "vault key" | "guard key") && !open[index].is_empty() {
            open_keys.push(name.clone());
        }
    }
    assert!(ended.success(), "the app's copy did what it was asked");
    assert!(
        wanted
            .iter()
            .zip(&open)
            .any(|(value, places)| value.secret == "item password" && !places.is_empty()),
        "the shown password is found while the vault is open (else the search proves nothing)"
    );
    assert!(left.is_empty(), "left in memory after the lock: {left:?}");
    assert!(
        open_keys.is_empty(),
        "in the clear while the vault is open: {open_keys:?}"
    );
}

/// Searches the whole memory of the process behind `process` for every piece of each wanted
/// value. Answers, for each, where it was found: pieces of one value close together are one
/// place.
fn search(process: HANDLE, wanted: &[Wanted]) -> Vec<Vec<usize>> {
    // Every piece of every value, as one set of patterns, remembering whose it is.
    let mut patterns: Vec<&[u8]> = Vec::new();
    let mut owner: Vec<usize> = Vec::new();
    for (index, value) in wanted.iter().enumerate() {
        if value.bytes.len() <= PIECE {
            patterns.push(&value.bytes);
            owner.push(index);
        } else {
            for piece in value.bytes.windows(PIECE) {
                patterns.push(piece);
                owner.push(index);
            }
        }
    }
    let matcher = AhoCorasick::new(&patterns).unwrap();
    let mut hits: Vec<Vec<usize>> = vec![Vec::new(); wanted.len()];
    let mut scanned = 0usize;
    each_region(process, |address, bytes| {
        scanned += bytes.len();
        for found in matcher.find_overlapping_iter(bytes) {
            hits[owner[found.pattern().as_usize()]].push(address + found.start());
        }
    });
    assert!(
        scanned > 1 << 20,
        "the app's memory was read ({scanned} bytes)"
    );

    hits.into_iter()
        .zip(wanted)
        .map(|(mut at, value)| {
            at.sort_unstable();
            at.dedup();
            let mut places: Vec<usize> = Vec::new();
            let mut last: Option<usize> = None;
            for address in at {
                if last.is_none_or(|last| address > last + value.bytes.len()) {
                    places.push(address);
                }
                last = Some(address);
            }
            places
        })
        .collect()
}

/// Hands `each` the contents of every readable region of the process's memory, with its
/// address, in pieces of a few megabytes that overlap so nothing is cut in two. Code and
/// constants of the program's own files (read-only image pages) are skipped: nothing made
/// at run time is there.
fn each_region(process: HANDLE, mut each: impl FnMut(usize, &[u8])) {
    const STEP: usize = 4 << 20;
    const OVERLAP: usize = 4096;
    let mut buffer = vec![0u8; STEP + OVERLAP];
    let mut address = 0usize;
    loop {
        // SAFETY: `info` is a plain struct of the size passed; `process` is a live handle with
        // every right (the one CreateProcess gave this process).
        #[allow(unsafe_code)]
        let info = unsafe {
            let mut info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let size = VirtualQueryEx(
                process,
                address as *const c_void,
                &raw mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if size == 0 {
                break;
            }
            info
        };
        let (base, length) = (info.BaseAddress as usize, info.RegionSize);
        let writable = info.Protect
            & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            != 0;
        let readable = info.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0 && info.Protect != 0;
        if info.State == MEM_COMMIT && readable && (info.Type != MEM_IMAGE || writable) {
            let mut offset = 0;
            while offset < length {
                let wanted = (length - offset).min(STEP + OVERLAP);
                let mut read = 0usize;
                // SAFETY: `buffer` holds at least `wanted` bytes; Windows writes at most that
                // and says how many in `read`.
                #[allow(unsafe_code)]
                unsafe {
                    ReadProcessMemory(
                        process,
                        (base + offset) as *const c_void,
                        buffer.as_mut_ptr().cast(),
                        wanted,
                        &raw mut read,
                    );
                }
                if read > 0 {
                    each(base + offset, &buffer[..read]);
                }
                offset += STEP;
            }
        }
        match base.checked_add(length) {
            Some(next) if next > address => address = next,
            _ => break,
        }
    }
}
