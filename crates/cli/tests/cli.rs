//! End-to-end test of the `vault` binary in script mode (`--password-stdin`).
//!
//! Uses a temporary vault and `VAULT_HOME`, plus the real OS credential store for the Secret
//! Key (cleaned up with `vault forget`). Windows-only for now: Linux CI has no Secret Service.

#![cfg(windows)]

use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

const MASTER: &str = "e2e test master passphrase";
const NEW_MASTER: &str = "e2e test second passphrase";

struct Env {
    _dir: tempfile::TempDir,
    vault: std::path::PathBuf,
    home: std::path::PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            vault: dir.path().join("test.vault"),
            home: dir.path().join("home"),
            _dir: dir,
        }
    }

    /// Runs `vault <args>` feeding `stdin_lines`, one per prompt. One at a time across the
    /// tests: the OS credential store, shared by all of them, can miss a key written a moment
    /// before by another process while several write at once.
    fn run(&self, args: &[&str], stdin_lines: &[&str]) -> Output {
        static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
            .args(["--vault", self.vault.to_str().unwrap(), "--password-stdin"])
            .args(args)
            .env("VAULT_HOME", &self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        for line in stdin_lines {
            writeln!(stdin, "{line}").unwrap();
        }
        drop(stdin);
        child.wait_with_output().unwrap()
    }

    fn ok(&self, args: &[&str], stdin_lines: &[&str]) -> String {
        let output = self.run(args, stdin_lines);
        assert!(
            output.status.success(),
            "`vault {}` failed:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn fails(&self, args: &[&str], stdin_lines: &[&str]) -> String {
        let output = self.run(args, stdin_lines);
        assert!(
            !output.status.success(),
            "`vault {}` should have failed",
            args.join(" ")
        );
        String::from_utf8(output.stderr).unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // Remove the Secret Key (and a sync server key) from the OS credential store even if
        // the test failed.
        if self.vault.exists() {
            let _ = self.run(&["sync", "--stop"], &[]);
            let _ = self.run(&["forget"], &[]);
        }
    }
}

fn kit_value(kit: &str, label: &str) -> String {
    kit.lines()
        .find_map(|line| line.trim().strip_prefix(label))
        .unwrap_or_else(|| panic!("{label} not in output:\n{kit}"))
        .trim()
        .to_owned()
}

#[test]
fn full_lifecycle() {
    let env = Env::new();

    // init (fast KDF settings to keep the test quick; still above the format floor)
    let kit = env.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    let secret_key = kit_value(&kit, "Secret Key:");
    let parts = ["Part A:", "Part B:", "Part C:"].map(|label| kit_value(&kit, label));
    assert!(secret_key.starts_with("S0-") && parts[0].starts_with("A0-"));
    assert!(parts[1].starts_with("B0-") && parts[2].starts_with("C0-"));
    env.fails(&["init"], &[MASTER]); // never overwrites

    let short = env.run(
        &[
            "--vault",
            &env.vault.with_extension("x").to_string_lossy(),
            "init",
        ],
        &["too short"],
    );
    assert!(
        !short.status.success(),
        "short master passwords are refused"
    );

    // add items
    env.ok(
        &[
            "add",
            "GitHub",
            "-u",
            "octocat",
            "--url",
            "https://github.com",
            "--totp",
            "JBSWY3DPEHPK3PXP",
            "--favorite",
        ],
        &[MASTER, "gh-item-password-1"],
    );
    let added = env.ok(
        &["add", "Bank", "-u", "me", "--generate", "--length", "32"],
        &[MASTER],
    );
    assert!(added.contains("32-character password was generated"));

    // list and search
    let list = env.ok(&["list"], &[MASTER]);
    assert!(list.contains("GitHub") && list.contains("Bank") && list.contains("2 item(s)"));
    assert!(env.ok(&["list", "git"], &[MASTER]).contains("1 item(s)"));

    // show: hidden by default, revealed on request
    let hidden = env.ok(&["show", "github"], &[MASTER]);
    assert!(!hidden.contains("gh-item-password-1") && hidden.contains("octocat"));
    assert!(
        env.ok(&["show", "GitHub", "--reveal"], &[MASTER])
            .contains("gh-item-password-1")
    );

    // totp
    let code = env.ok(&["totp", "GitHub"], &[MASTER]);
    assert!(code.split_whitespace().next().unwrap().len() == 6, "{code}");

    // wrong password is rejected with a clear message
    assert!(
        env.fails(&["list"], &["not the password"])
            .contains("wrong master password or Secret Key")
    );

    // keep an old copy, edit, then try to open the old copy (rollback)
    let old_copy = env.vault.with_extension("old");
    std::fs::copy(&env.vault, &old_copy).unwrap();
    env.ok(
        &["edit", "GitHub", "-u", "hubot", "--favorite", "false"],
        &[MASTER],
    );
    assert!(env.ok(&["show", "GitHub"], &[MASTER]).contains("hubot"));
    let newest_copy = env.vault.with_extension("newest");
    std::fs::copy(&env.vault, &newest_copy).unwrap();
    std::fs::copy(&old_copy, &env.vault).unwrap();
    assert!(
        env.fails(&["list"], &[MASTER])
            .contains("OLDER than one this device has already seen")
    );
    env.ok(&["--allow-rollback", "list"], &[MASTER]);
    std::fs::copy(&newest_copy, &env.vault).unwrap();

    // new device: forget the Secret Key, then type it from the kit
    env.ok(&["forget"], &[]);
    assert!(
        env.ok(&["info"], &[])
            .contains("does not have the Secret Key")
    );
    env.fails(&["list"], &["S0-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA", MASTER]);
    assert!(
        env.ok(&["list"], &[&secret_key, MASTER])
            .contains("2 item(s)")
    );
    assert!(env.ok(&["info"], &[]).contains("has the Secret Key"));

    // new device without the Secret Key: two recovery parts bring it back, once
    env.ok(&["forget"], &[]);
    assert!(
        env.ok(&["list"], &[&parts[2], &parts[0], MASTER])
            .contains("2 item(s)")
    );
    assert!(env.ok(&["info"], &[]).contains("has the Secret Key"));
    env.fails(&["recover"], &[&parts[1], &parts[2], &parts[0], NEW_MASTER]);
    let kit = env.ok(&["kit", "--new-parts"], &[MASTER]);
    let parts = ["Part A:", "Part B:", "Part C:"].map(|label| kit_value(&kit, label));

    // forgot the password: recover with all three parts → new password + new Secret Key,
    // and new parts in place of the used ones
    let new_kit = env.ok(&["recover"], &[&parts[1], &parts[2], &parts[0], NEW_MASTER]);
    let newest = kit_value(&new_kit, "Part A:");
    assert!(newest.starts_with("A0-") && newest != parts[0]);
    let new_secret_key = kit_value(&new_kit, "Secret Key:");
    assert_ne!(new_secret_key, secret_key);
    env.fails(&["list"], &[MASTER]);
    assert!(env.ok(&["list"], &[NEW_MASTER]).contains("2 item(s)"));

    // delete
    env.fails(&["rm", "Bank"], &[NEW_MASTER, "wrong title"]);
    env.ok(&["rm", "Bank"], &[NEW_MASTER, "Bank"]);
    assert!(env.ok(&["list"], &[NEW_MASTER]).contains("1 item(s)"));

    // change master password
    env.ok(&["passwd"], &[NEW_MASTER, MASTER]);
    assert!(env.ok(&["list"], &[MASTER]).contains("GitHub"));

    // the file never contains plaintext
    let bytes = std::fs::read(&env.vault).unwrap();
    for needle in [
        "GitHub",
        "octocat",
        "hubot",
        "gh-item-password-1",
        "github.com",
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} leaked"
        );
    }
}

#[test]
fn import_browser_csv() {
    let env = Env::new();
    env.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    let csv = env.vault.with_file_name("chrome-export.csv");
    std::fs::write(
        &csv,
        "name,url,username,password,note\n\
         Shop,https://shop.example,me,shop-pass-1,\n\
         ,https://www.forum.example/login,me2,forum-pass-2,old account\n",
    )
    .unwrap();
    let csv_arg = csv.to_str().unwrap();

    let dry = env.ok(&["import", csv_arg, "--dry-run"], &[MASTER]);
    assert!(dry.contains("2 item(s) would be imported"), "{dry}");
    assert!(env.ok(&["list"], &[MASTER]).contains("(no items)"));

    let first = env.ok(&["import", csv_arg], &[MASTER]);
    assert!(
        first.contains("Imported 2 item(s)") && first.contains("PLAIN TEXT"),
        "{first}"
    );
    let again = env.ok(&["import", csv_arg, "--delete-source"], &[MASTER]);
    assert!(
        again.contains("Imported 0 item(s)") && again.contains("skipped 2 duplicate(s)"),
        "{again}"
    );
    assert!(!csv.exists(), "--delete-source removes the export");

    let list = env.ok(&["list"], &[MASTER]);
    assert!(
        list.contains("Shop") && list.contains("forum.example"),
        "{list}"
    );
    assert!(
        env.ok(&["show", "forum", "--reveal"], &[MASTER])
            .contains("forum-pass-2")
    );
}

#[test]
fn passphrases() {
    let env = Env::new();
    let phrase = env.ok(&["generate", "--words", "7", "--separator", "."], &[]);
    assert!(
        phrase.trim().split('.').filter(|w| !w.is_empty()).count() >= 7,
        "{phrase}"
    );
    let output = env.run(&["generate", "--words", "2"], &[]);
    assert!(!output.status.success(), "fewer than 3 words is refused");
}

#[test]
fn generate_needs_no_vault() {
    let env = Env::new();
    let password = env.ok(&["generate", "--length", "40", "--no-symbols"], &[]);
    let password = password.trim();
    assert_eq!(password.len(), 40);
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn keyfile_as_a_third_factor() {
    let env = Env::new();
    env.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    env.ok(&["add", "Site", "--username", "me"], &[MASTER, "site-pw-1"]);
    let keyfile = env.vault.with_file_name("test.keyfile");
    let keyfile_arg = keyfile.to_str().unwrap();

    let out = env.ok(&["keyfile", "create", keyfile_arg], &[MASTER]);
    assert!(out.contains("Keyfile written"));
    assert!(keyfile.is_file());
    assert!(env.ok(&["info"], &[]).contains("Keyfile:        needed"));
    // Never overwritten.
    env.fails(&["keyfile", "create", keyfile_arg], &[MASTER]);

    // The location is remembered on this device, so nothing extra to type...
    assert!(env.ok(&["list"], &[MASTER]).contains("Site"));
    // ...but without the file the vault stays shut, with or without the right password.
    let moved = keyfile.with_extension("moved");
    std::fs::rename(&keyfile, &moved).unwrap();
    env.fails(&["list"], &[MASTER]);
    let wrong = keyfile.with_extension("wrong");
    std::fs::write(&wrong, "vault-keyfile-v1 0000000000000000\n").unwrap();
    let err = env.fails(
        &["--vault-keyfile", wrong.to_str().unwrap(), "list"],
        &[MASTER],
    );
    assert!(err.contains("wrong master password"), "{err}");
    let moved_arg = moved.to_str().unwrap();
    assert!(
        env.ok(&["--vault-keyfile", moved_arg, "list"], &[MASTER])
            .contains("Site")
    );

    // Changing the master password keeps the keyfile; removing it goes back to two factors.
    env.ok(&["passwd"], &[MASTER, NEW_MASTER, NEW_MASTER]);
    assert!(env.ok(&["list"], &[NEW_MASTER]).contains("Site"));
    env.ok(&["keyfile", "remove"], &[NEW_MASTER]);
    assert!(env.ok(&["info"], &[]).contains("Keyfile:        not used"));
    std::fs::remove_file(&moved).unwrap();
    assert!(env.ok(&["list"], &[NEW_MASTER]).contains("Site"));
}

#[test]
fn two_devices_sync_through_a_folder() {
    let desktop = Env::new();
    desktop.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    desktop.ok(
        &[
            "add",
            "Desktop item",
            "-u",
            "d",
            "--url",
            "https://d.example",
        ],
        &[MASTER, "desktop-item-password"],
    );
    // The phone (another device: its own state folder) starts from a copy of the file. The
    // Secret Key comes from the same credential store here.
    let phone = Env::new();
    std::fs::copy(&desktop.vault, &phone.vault).unwrap();
    let folder = tempfile::tempdir().unwrap();
    let folder_arg = folder.path().to_str().unwrap();

    desktop.fails(&["sync"], &[MASTER]); // no folder yet
    let first = desktop.ok(&["sync", folder_arg], &[MASTER]);
    assert!(first.contains("Synced with 0 other device(s)"), "{first}");
    let joined = phone.ok(&["sync", folder_arg], &[MASTER]);
    assert!(joined.contains("Synced with 1 other device(s)"), "{joined}");

    phone.ok(
        &["add", "Phone item", "-u", "p", "--url", "https://p.example"],
        &[MASTER, "phone-item-password"],
    );
    phone.ok(&["sync"], &[MASTER]);
    let back = desktop.ok(&["sync"], &[MASTER]);
    assert!(back.contains("1 added"), "{back}");
    let list = desktop.ok(&["list"], &[MASTER]);
    assert!(
        list.contains("Phone item") && list.contains("Desktop item"),
        "{list}"
    );

    // A deletion goes round too.
    desktop.ok(&["rm", "Phone item", "--yes"], &[MASTER]);
    desktop.ok(&["sync"], &[MASTER]);
    let gone = phone.ok(&["sync"], &[MASTER]);
    assert!(gone.contains("1 removed"), "{gone}");
    assert!(!phone.ok(&["list"], &[MASTER]).contains("Phone item"));

    // Only one sealed copy per device in the folder, nothing in clear.
    let devices = std::fs::read_dir(folder.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("devices");
    let mut copies: Vec<String> = std::fs::read_dir(&devices)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    copies.sort();
    assert_eq!(copies.len(), 2, "{copies:?}");
    for name in &copies {
        let bytes = std::fs::read(devices.join(name)).unwrap();
        assert!(bytes.starts_with(b"PMVAULT\0"));
        assert!(
            !bytes
                .windows(13)
                .any(|w| w == b"Desktop item\0"[..13].as_ref())
        );
    }

    phone.ok(&["sync", "--stop"], &[]);
    phone.fails(&["sync"], &[MASTER]);
}

/// A vault-server on a free local port, for as long as it lives.
struct Server {
    url: String,
    data: tempfile::TempDir,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn start() -> Self {
        let data = tempfile::tempdir().unwrap();
        let root = data.path().to_owned();
        let (ready, address) = std::sync::mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready.send(listener.local_addr().unwrap()).unwrap();
                vault_server::serve(&root, listener, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
            });
        });
        let address: std::net::SocketAddr = address.recv().unwrap();
        Self {
            url: format!("http://{address}"),
            data,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    fn invite(&self) -> String {
        vault_server::admin_invite(self.data.path(), 1).unwrap().0
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn two_devices_sync_through_a_server() {
    let server = Server::start();
    let desktop = Env::new();
    desktop.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    desktop.ok(
        &[
            "add",
            "Desktop item",
            "-u",
            "d",
            "--url",
            "https://d.example",
        ],
        &[MASTER, "desktop-item-password"],
    );
    let phone = Env::new();
    std::fs::copy(&desktop.vault, &phone.vault).unwrap();

    // Without an invite the server is refused; with the admin's invite the desktop joins.
    let refused = desktop.fails(&["sync", "--server", &server.url], &[MASTER]);
    assert!(refused.contains("--invite"), "{refused}");
    let first = desktop.ok(
        &[
            "sync",
            "--server",
            &server.url,
            "--invite",
            &server.invite(),
        ],
        &[MASTER],
    );
    assert!(first.contains("joined the server"), "{first}");
    assert!(first.contains("Synced with 0 other device(s)"), "{first}");

    // The desktop invites the phone; the phone joins with that line.
    let link = desktop.ok(&["sync", "--add-device"], &[]);
    let link = link.lines().next().unwrap().trim().to_owned();
    assert!(link.starts_with("vaultsync:1?"), "{link}");
    let joined = phone.ok(&["sync", "--join", &link], &[MASTER]);
    assert!(joined.contains("Synced with 1 other device(s)"), "{joined}");
    // The same invite doesn't work twice.
    let other = Env::new();
    std::fs::copy(&desktop.vault, &other.vault).unwrap();
    let used = other.fails(&["sync", "--join", &link], &[MASTER]);
    assert!(used.contains("invite"), "{used}");

    phone.ok(
        &["add", "Phone item", "-u", "p", "--url", "https://p.example"],
        &[MASTER, "phone-item-password"],
    );
    phone.ok(&["sync"], &[MASTER]);
    let back = desktop.ok(&["sync"], &[MASTER]);
    assert!(back.contains("1 added"), "{back}");
    assert!(desktop.ok(&["list"], &[MASTER]).contains("Phone item"));

    // Both devices are listed; the phone is removed and gets nothing new afterwards.
    let devices = desktop.ok(&["sync", "--devices"], &[MASTER]);
    assert_eq!(devices.lines().count(), 3, "{devices}");
    let phone_id = devices
        .lines()
        .skip(1)
        .find(|l| !l.contains("(this device)"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap()
        .to_owned();
    let removed = desktop.ok(&["sync", "--remove", &phone_id], &[MASTER]);
    assert!(removed.contains("Removed"), "{removed}");
    let after = phone.fails(&["sync"], &[MASTER]);
    assert!(after.contains("isn't allowed in"), "{after}");
}
