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

    /// Runs `vault <args>` feeding `stdin_lines`, one per prompt.
    fn run(&self, args: &[&str], stdin_lines: &[&str]) -> Output {
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
        // Remove the Secret Key from the OS credential store even if the test failed.
        if self.vault.exists() {
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
    let recovery_key = kit_value(&kit, "Recovery Key:");
    assert!(secret_key.starts_with("S0-") && recovery_key.starts_with("R0-"));
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

    // lost everything: recover with the Recovery Key → new password + new Secret Key
    let new_kit = env.ok(&["recover"], &[&recovery_key, NEW_MASTER]);
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
