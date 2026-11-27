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
/// The item lock's PIN in these tests.
const ITEM_PIN: &str = "4821";

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

    // show: hidden by default, revealed on request; the current one-time code too
    let totp_line = |shown: &str| {
        shown
            .lines()
            .find(|line| line.trim_start().starts_with("totp:"))
            .unwrap_or_else(|| panic!("no totp line:\n{shown}"))
            .to_owned()
    };
    let hidden = env.ok(&["show", "github"], &[MASTER]);
    assert!(!hidden.contains("gh-item-password-1") && hidden.contains("octocat"));
    assert!(
        !totp_line(&hidden).chars().any(|c| c.is_ascii_digit()),
        "{hidden}"
    );
    let revealed = env.ok(&["show", "GitHub", "--reveal"], &[MASTER]);
    assert!(revealed.contains("gh-item-password-1"));
    assert!(
        totp_line(&revealed)
            .chars()
            .filter(char::is_ascii_digit)
            .count()
            >= 6,
        "{revealed}"
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
    let backup = vault_core::storage::backup_path(&env.vault);
    let (before, backup_before) = (
        std::fs::read(&env.vault).unwrap(),
        std::fs::read(&backup).unwrap(),
    );
    let again = env.ok(&["import", csv_arg, "--delete-source"], &[MASTER]);
    assert!(
        again.contains("Imported 0 item(s)") && again.contains("skipped 2 duplicate(s)"),
        "{again}"
    );
    assert!(!csv.exists(), "--delete-source removes the export");
    // Nothing new: the vault isn't written again (nor its previous copy replaced).
    assert_eq!(std::fs::read(&env.vault).unwrap(), before);
    assert_eq!(std::fs::read(&backup).unwrap(), backup_before);

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

/// Opens the test vault in this process, as the app would, with the master password and the
/// Secret Key from the kit.
fn open_here(env: &Env, secret_key: &str) -> vault_core::Vault {
    let secret_key = vault_core::SecretKey::parse(secret_key).unwrap();
    let bytes = std::fs::read(&env.vault).unwrap();
    vault_core::Vault::open(
        &bytes,
        vault_core::Unlock::Password {
            password: MASTER,
            secret_key: &secret_key,
        },
    )
    .unwrap()
}

/// Saves the vault from this process (another writer than the command under test).
fn save_here(env: &Env, vault: &mut vault_core::Vault) -> Vec<u8> {
    let bytes = vault.to_bytes().unwrap();
    vault_core::storage::write_atomic(&env.vault, &bytes).unwrap();
    bytes
}

/// A one-time-code secret can be typed at a prompt instead of on the command line, where it
/// would stay in the shell's history.
#[test]
fn a_totp_secret_can_be_typed_at_a_prompt() {
    let env = Env::new();
    env.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    env.ok(
        &["add", "Mail", "-u", "me", "--totp", "-"],
        &[MASTER, "JBSWY3DPEHPK3PXP", "mail-item-password"],
    );
    let code = env.ok(&["totp", "Mail"], &[MASTER]);
    assert!(
        code.chars().filter(char::is_ascii_digit).count() >= 6,
        "{code}"
    );
    // Nothing typed (Enter to back out): refused, and the secret stays.
    let before = std::fs::read(&env.vault).unwrap();
    let refused = env.fails(&["edit", "Mail", "--totp", "-"], &[MASTER, ""]);
    assert!(refused.contains("nothing was changed"), "{refused}");
    assert!(std::fs::read(&env.vault).unwrap() == before, "written");
    assert!(
        env.ok(&["totp", "Mail"], &[MASTER])
            .chars()
            .any(|c| c.is_ascii_digit())
    );
    // Changed the same way; a wrong one is refused and nothing changes.
    env.fails(&["edit", "Mail", "--totp", "-"], &[MASTER, "not base32 !"]);
    env.ok(
        &["edit", "Mail", "--totp", "-"],
        &[MASTER, "GEZDGNBVGY3TQOJQ"],
    );
    let shown = env.ok(&["show", "Mail"], &[MASTER]);
    assert!(!shown.contains("GEZDGNBVGY3TQOJQ"), "{shown}");
    assert!(
        env.ok(&["totp", "Mail"], &[MASTER])
            .chars()
            .any(|c| c.is_ascii_digit())
    );
}

#[test]
fn deleting_an_item_behind_the_item_lock_asks_for_it() {
    let env = Env::new();
    let kit = env.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    env.ok(
        &["add", "Locked item", "-u", "me"],
        &[MASTER, "locked-item-password"],
    );
    // The item lock (a PIN over every item) is set up in the app: the CLI has no command
    // for it.
    let mut vault = open_here(&env, &kit_value(&kit, "Secret Key:"));
    vault
        .set_item_guard(
            true,
            vault_core::GuardCheck::Pin,
            Some(ITEM_PIN),
            Some(MASTER),
        )
        .unwrap();
    let before = save_here(&env, &mut vault);
    let untouched = || {
        assert!(
            std::fs::read(&env.vault).unwrap() == before,
            "the vault was written: an item removed, or its tombstone"
        );
    };

    // A wrong PIN three times: the title isn't even asked, and nothing is written.
    let refused = env.fails(
        &["rm", "Locked item"],
        &[MASTER, "0000", "1111", "2222", "Locked item"],
    );
    assert!(refused.contains("wrong three times"), "{refused}");
    untouched();
    let refused = env.fails(
        &["rm", "Locked item", "--yes"],
        &[MASTER, "0000", "1111", "2222"],
    );
    assert!(refused.contains("wrong three times"), "{refused}");
    untouched();
    // The title where the PIN is asked doesn't pass either.
    env.fails(&["rm", "Locked item"], &[MASTER, "Locked item"]);
    untouched();
    assert!(env.ok(&["list"], &[MASTER]).contains("Locked item"));

    // The PIN, then the title: deleted.
    env.ok(&["rm", "Locked item"], &[MASTER, ITEM_PIN, "Locked item"]);
    assert!(env.ok(&["list"], &[MASTER]).contains("(no items)"));
}

#[test]
fn a_v5_item_lock_is_asked_for_too() {
    // Test values of the format v5 fixture (crates/core/tests/format_v5.rs).
    const V5_PASSWORD: &str = "fixture password v5 ✓ çãé";
    const V5_PIN: &str = "4821";
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/core/tests/fixtures");
    let env = Env::new();
    std::fs::copy(fixtures.join("vault-v5.bin"), &env.vault).unwrap();
    let keyfile = env.vault.with_file_name("test.keyfile");
    std::fs::copy(fixtures.join("vault-v5.keyfile"), &keyfile).unwrap();
    let credentials = std::fs::read_to_string(fixtures.join("vault-v5.credentials.txt")).unwrap();
    let secret_key = kit_value(&credentials, "secret_key =");
    let with_keyfile = |args: &[&'static str]| {
        let mut all = vec!["--vault-keyfile", keyfile.to_str().unwrap()];
        all.extend_from_slice(args);
        all
    };
    env.ok(&["forget"], &[]); // left over from an interrupted run
    let before = std::fs::read(&env.vault).unwrap();

    // A v5 lock only keeps a hash of its PIN, nothing encrypted under it yet: it is asked
    // for all the same, before secrets show and before a deletion.
    let shown = env.run(
        &with_keyfile(&["show", "Fixture Login", "--reveal"]),
        &[&secret_key, V5_PASSWORD, "0000", "1111", "2222"],
    );
    assert!(!shown.status.success());
    assert!(!String::from_utf8_lossy(&shown.stdout).contains("Fixture-P@ss-123"));
    let refused = env.fails(
        &with_keyfile(&["rm", "Fixture Login", "--yes"]),
        &[V5_PASSWORD, "0000", "1111", "2222"],
    );
    assert!(refused.contains("wrong three times"), "{refused}");
    assert!(std::fs::read(&env.vault).unwrap() == before, "written");

    // The PIN: deleted, and the lock now encrypts (the file is written in today's format).
    env.ok(
        &with_keyfile(&["rm", "Fixture Login", "--yes"]),
        &[V5_PASSWORD, V5_PIN],
    );
    let list = env.ok(&with_keyfile(&["list"]), &[V5_PASSWORD]);
    assert!(
        !list.contains("Fixture Login") && list.contains("1 item(s)"),
        "{list}"
    );
}

/// Renewing the vault key on one device: the old Secret Key opens nothing new, the other
/// device asks once for the new one (`sync --take-new-key`) and keeps what it changed.
/// Both "devices" share this computer's credential store, so the phone forgets the key first
/// to stand for a phone that still has the old one.
#[test]
fn a_renewed_vault_key_goes_round_through_a_folder() {
    let desktop = Env::new();
    let kit = desktop.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    let old_key = kit_value(&kit, "Secret Key:");
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
    let folder = tempfile::tempdir().unwrap();
    let folder_arg = folder.path().to_str().unwrap();
    desktop.ok(&["sync", folder_arg], &[MASTER]);
    phone.ok(&["sync", folder_arg], &[MASTER]);

    // Asked to confirm; anything but RENEW changes nothing.
    let before = std::fs::read(&desktop.vault).unwrap();
    desktop.fails(&["renew-key"], &[MASTER, "no"]);
    assert!(std::fs::read(&desktop.vault).unwrap() == before);
    let renewed = desktop.ok(&["renew-key"], &[MASTER, "RENEW"]);
    let new_key = kit_value(&renewed, "Secret Key:");
    assert_ne!(new_key, old_key);
    assert!(
        kit_value(&renewed, "Part A:").starts_with("A0-"),
        "{renewed}"
    );
    let sent = desktop.ok(&["sync"], &[MASTER]);
    assert!(sent.contains("still use the vault's former key"), "{sent}");

    // The phone, still on the old key, is told; a wrong key takes nothing.
    phone.ok(&["forget"], &[]);
    let told = phone.ok(&["sync"], &[&old_key, MASTER]);
    assert!(told.contains("--take-new-key"), "{told}");
    phone.ok(
        &["add", "Phone item", "-u", "p", "--url", "https://p.example"],
        &[MASTER, "phone-item-password"],
    );
    let wrong = phone.fails(&["sync", "--take-new-key"], &[MASTER, &old_key]);
    assert!(wrong.contains("opens none"), "{wrong}");
    let taken = phone.ok(&["sync", "--take-new-key"], &[MASTER, &new_key]);
    assert!(taken.contains("took the renewed vault key"), "{taken}");
    assert!(taken.contains("Synced with 1 other device(s)"), "{taken}");
    let list = phone.ok(&["list"], &[MASTER]);
    assert!(
        list.contains("Desktop item") && list.contains("Phone item"),
        "{list}"
    );

    // The desktop gets the phone's item; nothing is left on the old key.
    let back = desktop.ok(&["sync"], &[MASTER]);
    assert!(back.contains("1 added"), "{back}");
    assert!(
        !back.contains("former key") && !back.contains("can't be opened"),
        "{back}"
    );

    // The old Secret Key opens neither copy any more.
    let stray = Env::new();
    std::fs::copy(&desktop.vault, &stray.vault).unwrap();
    let refused = stray.fails(&["list"], &[&old_key, MASTER]);
    assert!(!refused.is_empty());
    stray.ok(&["forget"], &[]);
    // That forget was this vault's key on this computer: put it back for the cleanup.
    desktop.ok(&["list"], &[&new_key, MASTER]);
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
        vault_server::admin_invite(self.data.path(), 1, None)
            .unwrap()
            .0
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

// ---- A hostile sync place (THREAT_MODEL A2, SYNC.md §4.1, §9) ----

/// The one folder in `dir` (a sync folder's vault, a server's vault).
fn the_one_folder_in(dir: &std::path::Path) -> std::path::PathBuf {
    let mut entries = std::fs::read_dir(dir).unwrap();
    let only = entries.next().unwrap().unwrap().path();
    assert!(entries.next().is_none());
    only
}

fn names_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Runs `vault sync`, checks whether it ended well, and returns all it said.
fn sync_says(env: &Env, ends_well: bool) -> String {
    let output = env.run(&["sync"], &[MASTER]);
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.success(), ends_well, "{said}");
    said
}

/// What another program can leave where the phone's copy goes in a shared folder: the copy
/// with one byte altered, cut short, empty, garbage, another vault's, one bigger than any
/// vault, the phone's copy under another device's name, and an older copy once a newer one was
/// taken. `vault sync` on the desktop takes none of it: the vault file stays as it was, byte
/// for byte, and each is said. The phone's real copy goes in, and a later round works.
#[test]
fn a_hostile_sync_folder_changes_nothing_here() {
    let desktop = Env::new();
    desktop.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    let phone = Env::new();
    std::fs::copy(&desktop.vault, &phone.vault).unwrap();
    let folder = tempfile::tempdir().unwrap();
    let folder_arg = folder.path().to_str().unwrap();
    desktop.ok(&["sync", folder_arg], &[MASTER]);
    let devices = the_one_folder_in(folder.path()).join("devices");
    let desktop_copy = names_in(&devices).remove(0);
    phone.ok(&["sync", folder_arg], &[MASTER]);
    let phone_copy = names_in(&devices)
        .into_iter()
        .find(|name| *name != desktop_copy)
        .unwrap();
    let phone_path = devices.join(&phone_copy);
    let older = std::fs::read(&phone_path).unwrap();
    desktop.ok(&["sync"], &[MASTER]);
    phone.ok(
        &["add", "Phone item", "-u", "p", "--url", "https://p.example"],
        &[MASTER, "phone-item-password"],
    );
    phone.ok(&["sync"], &[MASTER]);
    let newer = std::fs::read(&phone_path).unwrap();
    let stranger = Env::new();
    stranger.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    let strangers = std::fs::read(&stranger.vault).unwrap();

    let before = std::fs::read(&desktop.vault).unwrap();
    let mut altered = newer.clone();
    let middle = altered.len() / 2;
    altered[middle] ^= 0x01;
    const REFUSED: &str = "Not used: the copy of device";
    const UNOPENED: &str = "can't be opened with this vault's key";
    let cases: Vec<(&str, Vec<u8>, &[&str])> = vec![
        ("one byte altered", altered, &[UNOPENED]),
        (
            "cut short",
            newer[..newer.len() / 2].to_vec(),
            &[REFUSED, UNOPENED],
        ),
        ("empty", Vec::new(), &[REFUSED]),
        ("garbage", b"not a vault at all ".repeat(200), &[REFUSED]),
        ("another vault's", strangers, &["belongs to another vault"]),
    ];
    for (what, bytes, said) in cases {
        std::fs::write(&phone_path, &bytes).unwrap();
        let told = sync_says(&desktop, true);
        assert!(said.iter().any(|s| told.contains(s)), "{what}: {told}");
        assert_eq!(
            std::fs::read(&desktop.vault).unwrap(),
            before,
            "{what}: the vault file changed"
        );
    }
    // Bigger than any vault: not read at all.
    std::fs::File::create(&phone_path)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    let told = sync_says(&desktop, true);
    assert!(
        told.contains("Couldn't read the copy of device") && told.contains("too big"),
        "{told}"
    );
    assert_eq!(std::fs::read(&desktop.vault).unwrap(), before);
    // The phone's real copy under another device's name.
    std::fs::remove_file(&phone_path).unwrap();
    let elsewhere = devices.join(format!("{}.vault", "ab".repeat(16)));
    std::fs::write(&elsewhere, &newer).unwrap();
    let told = sync_says(&desktop, true);
    assert!(
        told.contains("found under the name of a device that didn't write it"),
        "{told}"
    );
    assert_eq!(std::fs::read(&desktop.vault).unwrap(), before);
    std::fs::remove_file(&elsewhere).unwrap();
    assert!(!desktop.ok(&["list"], &[MASTER]).contains("Phone item"));

    // The real copy where it belongs: taken.
    std::fs::write(&phone_path, &newer).unwrap();
    assert!(sync_says(&desktop, true).contains("1 added"));
    assert!(desktop.ok(&["list"], &[MASTER]).contains("Phone item"));
    // The older one put back: a rollback, said, and nothing changes.
    let before = std::fs::read(&desktop.vault).unwrap();
    std::fs::write(&phone_path, &older).unwrap();
    let told = sync_says(&desktop, true);
    assert!(told.contains("older than one already seen"), "{told}");
    assert_eq!(std::fs::read(&desktop.vault).unwrap(), before);
    // A later honest round from the phone still goes in.
    phone.ok(
        &[
            "add",
            "Later item",
            "-u",
            "p",
            "--url",
            "https://later.example",
        ],
        &[MASTER, "later-item-password"],
    );
    phone.ok(&["sync"], &[MASTER]);
    assert!(sync_says(&desktop, true).contains("1 added"));
    assert!(desktop.ok(&["list"], &[MASTER]).contains("Later item"));
}

/// The real vault-server, its data folder changed by whoever runs it: the phone's stored copy
/// altered, replaced by the desktop's own, or by the phone's older one. The desktop takes none
/// of it and says so, then takes the real copy.
#[test]
fn a_tampered_server_store_changes_nothing_here() {
    let server = Server::start();
    let desktop = Env::new();
    desktop.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    let phone = Env::new();
    std::fs::copy(&desktop.vault, &phone.vault).unwrap();
    desktop.ok(
        &[
            "sync",
            "--server",
            &server.url,
            "--invite",
            &server.invite(),
        ],
        &[MASTER],
    );
    let link = desktop.ok(&["sync", "--add-device"], &[]);
    let link = link.lines().next().unwrap().trim().to_owned();
    phone.ok(&["sync", "--join", &link], &[MASTER]);
    desktop.ok(&["sync"], &[MASTER]);
    let copies = the_one_folder_in(&server.data.path().join("vaults")).join("copies");
    let devices = desktop.ok(&["sync", "--devices"], &[MASTER]);
    let desktop_id = devices
        .lines()
        .find(|l| l.contains("(this device)"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap()
        .to_owned();
    let (desktop_copy, phone_copy) = match names_in(&copies).as_slice() {
        [a, b] if a.starts_with(&desktop_id) => (copies.join(a), copies.join(b)),
        [a, b] => (copies.join(b), copies.join(a)),
        other => panic!("{other:?}"),
    };
    let older = std::fs::read(&phone_copy).unwrap();
    phone.ok(
        &["add", "Phone item", "-u", "p", "--url", "https://p.example"],
        &[MASTER, "phone-item-password"],
    );
    phone.ok(&["sync"], &[MASTER]);
    let newer = std::fs::read(&phone_copy).unwrap();

    let before = std::fs::read(&desktop.vault).unwrap();
    let mut altered = newer.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0x80;
    let desktops_own = std::fs::read(&desktop_copy).unwrap();
    for (what, bytes, said) in [
        ("altered", altered, "can't be opened with this vault's key"),
        (
            "the desktop's own copy",
            desktops_own,
            "found under the name of a device that didn't write it",
        ),
    ] {
        std::fs::write(&phone_copy, &bytes).unwrap();
        let told = sync_says(&desktop, true);
        assert!(told.contains(said), "{what}: {told}");
        assert_eq!(std::fs::read(&desktop.vault).unwrap(), before, "{what}");
    }
    std::fs::write(&phone_copy, &newer).unwrap();
    assert!(sync_says(&desktop, true).contains("1 added"));
    let before = std::fs::read(&desktop.vault).unwrap();
    std::fs::write(&phone_copy, &older).unwrap();
    let told = sync_says(&desktop, true);
    assert!(told.contains("older than one already seen"), "{told}");
    assert_eq!(std::fs::read(&desktop.vault).unwrap(), before);
}

/// What the lying server answers a request (method, path): status, extra headers, body.
type LiarAnswer = (u16, Vec<(String, String)>, Vec<u8>);
type LiarScript = dyn Fn(&str, &str) -> LiarAnswer + Send + Sync;

/// A server of someone else's making on this computer, one connection per request, answering
/// each as its script says.
struct Liar {
    url: String,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Liar {
    fn start(answer: std::sync::Arc<LiarScript>) -> Self {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let Ok((mut stream, _)) = listener.accept() else {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    };
                    let (method, path) = read_head_and_body(&mut stream);
                    let (status, headers, body) = answer(&method, &path);
                    let mut out = format!(
                        "HTTP/1.1 {status} Liar\r\ncontent-length: {}\r\nconnection: close\r\n",
                        body.len()
                    );
                    for (name, value) in headers {
                        out.push_str(&format!("{name}: {value}\r\n"));
                    }
                    out.push_str("\r\n");
                    let _ = stream.write_all(out.as_bytes());
                    let _ = stream.write_all(&body);
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let _ = std::io::copy(&mut stream, &mut std::io::sink());
                }
            })
        };
        Self {
            url,
            stop,
            thread: Some(thread),
        }
    }
}

/// Reads one request to its end; returns its method and path.
fn read_head_and_body(stream: &mut std::net::TcpStream) -> (String, String) {
    use std::io::Read;
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut piece = [0u8; 64 * 1024];
    let end = loop {
        if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut piece) {
            Ok(read) if read > 0 => bytes.extend_from_slice(&piece[..read]),
            _ => return (String::new(), String::new()),
        }
    };
    let head = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    let mut body = bytes.len() - end;
    while body < length {
        match stream.read(&mut piece) {
            Ok(read) if read > 0 => body += read,
            _ => break,
        }
    }
    let mut first = head.lines().next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_uppercase();
    (method, first.next().unwrap_or_default().to_owned())
}

impl Drop for Liar {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A server that lies in its answers: it takes the enrollment, then answers a listing that
/// can't be read, sends the device elsewhere, hands over a copy that isn't one, refuses this
/// device's copy. `vault sync` fails or says what it didn't use, and the vault file stays as
/// it was each time.
#[test]
fn a_lying_server_changes_nothing_here() {
    use std::sync::{Arc, Mutex};
    let desktop = Env::new();
    desktop.ok(
        &["init", "--kdf-target-ms", "50", "--kdf-memory-mib", "64"],
        &[MASTER],
    );
    // Synced through a folder once, so this device is in the vault's list already and a round
    // has nothing of its own to save.
    let folder = tempfile::tempdir().unwrap();
    desktop.ok(&["sync", folder.path().to_str().unwrap()], &[MASTER]);

    let mode: Arc<Mutex<&'static str>> = Arc::new(Mutex::new("honest"));
    let liar = {
        let mode = mode.clone();
        let phone = "cd".repeat(16);
        Liar::start(Arc::new(move |method: &str, path: &str| -> LiarAnswer {
            let ok = |body: &str| (200, Vec::new(), body.as_bytes().to_vec());
            let mode = *mode.lock().unwrap();
            match (mode, method, path) {
                (_, "POST", "/v1/enroll") => ok(r#"{"vault":"x","device":"y"}"#),
                ("garbage", _, _) => ok("<html>not what was asked</html>"),
                ("redirect", _, _) => (
                    302,
                    vec![("location".into(), "http://127.0.0.1:9/v1".into())],
                    Vec::new(),
                ),
                ("not a copy", "GET", p) if p.ends_with("/devices") => ok(&format!(
                    r#"{{"copies":[{{"device":"{phone}","tag":"t","size":5}}],"seq":1}}"#
                )),
                ("not a copy", "GET", _) => ok("<html>a page, not a vault</html>"),
                (_, "GET", p) if p.ends_with("/devices") => ok(r#"{"copies":[],"seq":1}"#),
                ("refuses", "PUT", _) => (500, Vec::new(), b"{}".to_vec()),
                (_, "PUT", _) => (204, Vec::new(), Vec::new()),
                _ => (404, Vec::new(), Vec::new()),
            }
        }))
    };
    let joined = desktop.ok(
        &["sync", "--server", &liar.url, "--invite", &"ab".repeat(16)],
        &[MASTER],
    );
    assert!(joined.contains("joined the server"), "{joined}");
    let before = std::fs::read(&desktop.vault).unwrap();
    for (what, ends_well, said) in [
        ("garbage", false, "can't be read"),
        ("redirect", false, "another address"),
        (
            "not a copy",
            true,
            "Not used: the copy of device cdcdcdcd: not a vault file",
        ),
    ] {
        *mode.lock().unwrap() = what;
        let told = sync_says(&desktop, ends_well);
        assert!(told.contains(said), "{what}: {told}");
        assert_eq!(std::fs::read(&desktop.vault).unwrap(), before, "{what}");
    }
    // A change of this device's own, then a server that refuses its copy: the change stays
    // here, and the command says the copy didn't go.
    *mode.lock().unwrap() = "honest";
    desktop.ok(
        &["add", "Here", "-u", "h", "--url", "https://here.example"],
        &[MASTER, "here-item-password"],
    );
    let before = std::fs::read(&desktop.vault).unwrap();
    *mode.lock().unwrap() = "refuses";
    let told = sync_says(&desktop, false);
    assert!(told.contains("answered 500"), "{told}");
    assert_eq!(std::fs::read(&desktop.vault).unwrap(), before);
    assert!(desktop.ok(&["list"], &[MASTER]).contains("Here"));
    // The server takes it again: the next round sends the copy.
    *mode.lock().unwrap() = "honest";
    sync_says(&desktop, true);
}
