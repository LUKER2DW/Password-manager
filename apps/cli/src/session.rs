//! Locating, unlocking and saving the vault. Device integration lives in `vault-platform`.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use vault_core::{Error as CoreError, Keyfile, SecretKey, Unlock, Vault, storage};
use vault_platform::{
    DeviceState, RollbackStatus, VersionStatus,
    device::{self, Clock, unlock_attempts},
    keyfile, paths,
    secret_store::{self, Kept, Loaded},
};
use zeroize::Zeroizing;

use crate::prompt::Prompter;

pub fn default_vault_path() -> Result<PathBuf> {
    paths::default_vault_path()
}

/// `2:05` for 125 seconds.
fn minutes_seconds(seconds: i64) -> String {
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

/// `2026-11-26 14:02`, `offset_minutes` away from UTC (as the apps show it).
fn date_time(unix: i64, offset_minutes: i32) -> String {
    let local = unix + i64::from(offset_minutes) * 60;
    let days = local.div_euclid(86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let minutes = local.rem_euclid(86_400) / 60;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}",
        minutes / 60,
        minutes % 60
    )
}

/// Turns core errors into messages a person can act on.
pub fn explain(error: CoreError) -> anyhow::Error {
    match error {
        CoreError::DecryptionFailed => {
            anyhow!("wrong master password or Secret Key, or the vault file was modified")
        }
        CoreError::KeyChecksumMismatch => anyhow!("that key has a typo (checksum mismatch)"),
        CoreError::InvalidKeyFormat => anyhow!("that does not look like a valid key"),
        CoreError::KeyfileRequired => anyhow!(
            "this vault also needs its keyfile: pass --vault-keyfile <PATH> (or set VAULT_KEYFILE)"
        ),
        other => anyhow!(other),
    }
}

pub fn store_secret_key(vault_id: &str, key: &SecretKey) -> Result<()> {
    secret_store::store(vault_id, key)
}

pub fn forget_secret_key(vault_id: &str) -> Result<bool> {
    secret_store::forget(vault_id)
}

/// What the CLI says once it kept the Secret Key.
pub fn kept_message(kept: Option<Kept>) -> &'static str {
    match kept {
        Some(Kept::Chip) => {
            "Secret Key kept on this computer, under a key in its security chip (TPM)."
        }
        Some(Kept::System) => {
            "Secret Key saved in this device's credential store (no security chip to keep it)."
        }
        None => "This device didn't keep the Secret Key.",
    }
}

/// What the CLI says when a newer version of the apps (`highest`) opened the vault on this
/// computer before the one running: an old copy may have been put back in its place.
pub fn older_version_message(running: &str, highest: &str) -> String {
    format!(
        "this is vault {running}, but vault {highest} has already opened this vault on this          computer. If you didn't go back to an older version yourself, someone may have put          back an old one with a known fault. Get the newest from the project's releases on          GitHub (the desktop app: Settings → About → Check for updates)."
    )
}

pub fn record_new_vault(vault: &Vault) -> Result<()> {
    device::record_revision(&vault.id_hex(), vault.revision())
}

/// An unlocked vault bound to its file.
pub struct Session {
    pub path: PathBuf,
    pub vault: Vault,
    pub secret_key: SecretKey,
    /// The keyfile the vault was opened with, when it uses one.
    pub keyfile: Option<Keyfile>,
    /// The master password just typed, kept (wiped on drop) for commands that rewrite the
    /// password lock without changing the password.
    pub password: Zeroizing<String>,
    /// The file as it was read or last written, to refuse a save over someone else's changes.
    file_hash: [u8; 32],
}

impl Session {
    /// Unlocks with master password + Secret Key (from the OS store, or typed from the kit),
    /// plus the keyfile when the vault uses one (`keyfile_path`, else where it was last found).
    pub fn unlock(
        path: &Path,
        prompter: &mut Prompter,
        allow_rollback: bool,
        keyfile_path: Option<&Path>,
    ) -> Result<Self> {
        let bytes = read_vault_file(path)?;
        let info = Vault::inspect(&bytes).map_err(explain)?;
        // Too many failed tries in a row on this device: the next one waits, as in the apps
        // (the same count, in the device state).
        let wait = unlock_attempts::wait(&info.id_hex, Clock::read());
        if wait > 0 {
            bail!(
                "too many failed tries in a row to unlock this vault on this device: to slow \
                 down guessing, the next one can start in {}",
                minutes_seconds(wait)
            );
        }
        let keyfile = if info.needs_keyfile {
            let path = keyfile_path
                .map(Path::to_owned)
                .or_else(|| keyfile::remembered_path(&info.id_hex))
                .ok_or_else(|| explain(CoreError::KeyfileRequired))?;
            let key = keyfile::read(&path)?;
            Some((key, path))
        } else {
            None
        };

        let mut used_parts = false;
        let (secret_key, typed) = match secret_store::load_checked(&info.id_hex) {
            Ok(Loaded::Key(key)) => (key, false),
            kept => {
                // None kept that opens here (CRYPTO.md §2.2.1): the kit's is asked for.
                match kept {
                    Ok(Loaded::ChipLost) => eprintln!(
                        "This computer's security chip (TPM) no longer opens the Secret Key it \
                         kept for this vault: the chip was cleared, replaced or turned off."
                    ),
                    Ok(Loaded::Conflict) => eprintln!(
                        "Two different Secret Keys are kept for this vault on this computer (an \
                         older version saved one): type the one from your newest kit."
                    ),
                    Err(err) => eprintln!(
                        "warning: the Secret Key kept on this computer couldn't be read ({err:#})."
                    ),
                    Ok(_) => {
                        eprintln!("This device does not know the Secret Key for this vault yet.");
                    }
                }
                let text = prompter
                    .secret("Secret Key (from your emergency kit), or one of two recovery parts")?;
                match vault_core::RecoveryPart::parse(&text) {
                    // Two recovery parts bring the Secret Key back.
                    Ok(first) => {
                        let second = vault_core::RecoveryPart::parse(
                            &prompter.secret("Another recovery part")?,
                        )
                        .map_err(explain)?;
                        let key =
                            Vault::recover_secret_key(&bytes, &first, &second).map_err(explain)?;
                        used_parts = true;
                        (key, true)
                    }
                    Err(_) => (SecretKey::parse(&text).map_err(explain)?, true),
                }
            }
        };
        let password = prompter.secret("Master password")?;
        let unlock = match &keyfile {
            Some((keyfile, _)) => Unlock::PasswordAndKeyfile {
                password: &password,
                secret_key: &secret_key,
                keyfile,
            },
            None => Unlock::Password {
                password: &password,
                secret_key: &secret_key,
            },
        };
        let mut vault = match Vault::open(&bytes, unlock) {
            Ok(vault) => vault,
            Err(CoreError::DecryptionFailed) => {
                let clock = Clock::read();
                let attempts = unlock_attempts::failed(&info.id_hex, clock);
                let wait = attempts.wait_left(clock.now, clock.uptime);
                if wait > 0 {
                    eprintln!(
                        "{} failed tries in a row on this device: the next one can start in {}.",
                        attempts.failed,
                        minutes_seconds(wait)
                    );
                }
                return Err(explain(CoreError::DecryptionFailed));
            }
            Err(err) => return Err(explain(err)),
        };
        let before = unlock_attempts::succeeded(&info.id_hex);
        if !before.is_clear() {
            let since = date_time(
                before.first_at,
                vault_platform::locale::utc_offset_minutes(),
            );
            eprintln!(
                "{} failed {} to unlock this vault on this device since {since}. If {} yours, \
                 someone may be guessing your master password.",
                before.failed,
                if before.failed == 1 { "try" } else { "tries" },
                if before.failed == 1 {
                    "it wasn't"
                } else {
                    "they weren't"
                }
            );
        }
        if let Some((_, path)) = &keyfile {
            // It worked: next time the path needn't be typed.
            let _ = keyfile::remember_path(&info.id_hex, Some(path));
        }

        let mut state = DeviceState::load()?;
        if let RollbackStatus::Older {
            revision,
            highest_seen,
        } = state.check_rollback(&info.id_hex, vault.revision())
        {
            let message = format!(
                "this vault file is OLDER than one this device has already seen \
                 (revision {revision} < {highest_seen}). Someone may have replaced it with an old copy."
            );
            if !allow_rollback {
                bail!(
                    "{message}\nIf you restored a backup on purpose, re-run with --allow-rollback."
                );
            }
            eprintln!("warning: {message}");
        }
        state.record_revision(&info.id_hex, vault.revision());
        // A newer version of the apps opened this vault here before: this one may be an old
        // copy put back with a fault fixed since. Said, never refused.
        if let VersionStatus::Older { running, highest } =
            state.note_version(&info.id_hex, env!("CARGO_PKG_VERSION"))
        {
            eprintln!("warning: {}", older_version_message(&running, &highest));
        }

        let keep_secret_key = || -> Result<()> {
            secret_store::store(&info.id_hex, &secret_key)?;
            eprintln!("{}", kept_message(secret_store::kept(&info.id_hex)?));
            Ok(())
        };
        let mut file_hash = storage::fingerprint(&bytes);
        if used_parts {
            // Recovery parts work once: the two just typed stop working. That is written
            // first, and only over the file they were checked against, before this device
            // keeps the Secret Key they brought back: a device that kept it would never ask
            // for the parts again, and they would go on working.
            file_hash = retire_parts(path, &mut vault, &bytes, keep_secret_key)?;
            state.record_revision(&info.id_hex, vault.revision());
            eprintln!(
                "The two recovery parts you typed no longer work. Make a new kit: vault kit --new-parts"
            );
        } else {
            // Kept in the strongest form this computer has: a key typed from the kit, or one
            // kept the older way moved under the security chip, checked before the old one
            // goes. The first time the chip makes its key, which takes a second or two.
            let before = secret_store::kept(&info.id_hex).ok().flatten();
            match secret_store::settle(&info.id_hex, &secret_key) {
                Ok(now) if typed || before != Some(now) => eprintln!("{}", kept_message(Some(now))),
                Ok(_) => {}
                Err(err) if typed => return Err(err),
                Err(err) => eprintln!("warning: {err:#}"),
            }
        }
        state.save()?;

        Ok(Self {
            path: path.to_owned(),
            vault,
            secret_key,
            keyfile: keyfile.map(|(key, _)| key),
            password,
            file_hash,
        })
    }

    /// Whether the item lock asks for its PIN or password before anything else: one that
    /// encrypts and isn't open, or one from format v5 that only holds a hash of it (the
    /// first right answer turns that into encryption).
    fn lock_closed(&self) -> bool {
        let guard = self.vault.item_guard();
        (guard.encrypts() || guard.is_legacy()) && !self.vault.secrets_open()
    }

    /// Opens the secrets the item lock covers: asks for its PIN or password, three tries.
    /// Does nothing when the vault has no such lock or the secrets are open already.
    pub fn open_secrets(&mut self, prompter: &mut Prompter) -> Result<()> {
        if !self.lock_closed() {
            return Ok(());
        }
        let guard = self.vault.item_guard();
        let legacy = guard.is_legacy();
        let label = if guard.check == vault_core::GuardCheck::Pin {
            "Item PIN"
        } else {
            "Item password"
        };
        for _ in 0..3 {
            let typed = prompter.secret(label)?;
            if self.vault.unlock_secrets(&typed).map_err(explain)? {
                // Items added while it was closed are sealed under it now, and a v5 lock
                // has just become encryption: both are kept.
                if self.vault.seal_pending().map_err(explain)? > 0 || legacy {
                    self.save()?;
                }
                return Ok(());
            }
            eprintln!("That isn't it.");
        }
        anyhow::bail!("wrong three times: the item's secrets stay locked")
    }

    /// One item, asking for the item PIN or password first when its secrets are locked.
    /// Showing, copying, changing and deleting an item all come through here.
    pub fn open_item(
        &mut self,
        id: &vault_core::ItemId,
        prompter: &mut Prompter,
    ) -> Result<vault_core::ItemData> {
        let item = self.vault.get_item(id).map_err(explain)?;
        // An item added while the item lock was closed is not sealed under it yet, and an
        // item behind a v5 lock never is, so they read in full: the check is asked for all
        // the same (and seals them).
        let waits = self.lock_closed() && self.vault.guards(&item);
        if !item.is_locked() && !waits {
            return Ok(item);
        }
        self.open_secrets(prompter)?;
        self.vault.get_item(id).map_err(explain)
    }

    /// The fingerprint of the file as this session read or last wrote it.
    pub fn file_hash(&self) -> [u8; 32] {
        self.file_hash
    }

    /// The vault file now holds what this session wrote another way (`replace_then_keep`),
    /// with `hash` as its fingerprint.
    pub fn wrote(&mut self, hash: [u8; 32]) {
        self.file_hash = hash;
    }

    /// Encrypts and writes the vault, unless the file changed since this session read it.
    pub fn save(&mut self) -> Result<()> {
        let bytes = self.vault.to_bytes().map_err(explain)?;
        write_unless_changed(&self.path, &self.file_hash, &bytes)?;
        self.file_hash = storage::fingerprint(&bytes);
        device::record_revision(&self.vault.id_hex(), self.vault.revision())
    }
}

/// Writes the vault with its recovery parts retired over `read`, the file they were just
/// checked against, then runs `keep` (which keeps the Secret Key they brought back on this
/// device). Returns the fingerprint of what was written.
///
/// When the file changed in the meantime, nothing is written and the parts still work: the
/// other writer's changes (a new item, even a new master password) stay. When `keep` fails,
/// the file is put back as it was read, so the parts aren't used up for nothing.
fn retire_parts(
    path: &Path,
    vault: &mut Vault,
    read: &[u8],
    keep: impl FnOnce() -> Result<()>,
) -> Result<[u8; 32]> {
    vault.clear_recovery_parts();
    let written = vault.to_bytes().map_err(explain)?;
    replace_then_keep(path, read, &written, keep).map_err(|failed| match failed {
        NotKept::NotWritten(err) => err.context(
            "the recovery parts you typed still work, and this device didn't keep the Secret Key",
        ),
        NotKept::PutBack(err) => err.context("the recovery parts you typed still work"),
        NotKept::Replaced { error, back } => error.context(format!(
            "the recovery parts you typed no longer work, and putting them back failed \
             ({back:#})"
        )),
    })
}

/// How [`replace_then_keep`] failed, and so what the vault file holds.
#[derive(Debug)]
pub enum NotKept {
    /// Nothing was written (the file changed since it was read, or the write failed): the
    /// file is as it was.
    NotWritten(anyhow::Error),
    /// Keeping failed, and the file was put back as it was read.
    PutBack(anyhow::Error),
    /// Keeping failed (`error`), and putting the file back failed too (`back`): it holds the
    /// new bytes, and whatever opens only them must be shown.
    Replaced {
        error: anyhow::Error,
        back: anyhow::Error,
    },
}

/// Writes `written` over the vault file if it still holds `read` (what `written` was made
/// from), then runs `keep`, which keeps on this device what opens the new file (its Secret
/// Key). Both or neither: when `keep` fails, the file is put back as it was read, so a key
/// that was never kept doesn't become the only one that opens it. Returns the fingerprint of
/// what was written.
pub fn replace_then_keep(
    path: &Path,
    read: &[u8],
    written: &[u8],
    keep: impl FnOnce() -> Result<()>,
) -> std::result::Result<[u8; 32], NotKept> {
    write_unless_changed(path, &storage::fingerprint(read), written)
        .map_err(NotKept::NotWritten)?;
    let written_hash = storage::fingerprint(written);
    if let Err(error) = keep() {
        return Err(match write_unless_changed(path, &written_hash, read) {
            Ok(()) => NotKept::PutBack(error),
            Err(back) => NotKept::Replaced { error, back },
        });
    }
    Ok(written_hash)
}

/// Writes `bytes` over the vault file, unless it no longer holds what `read` was taken from.
///
/// The file is compared before anything is written, and again by
/// [`storage::write_atomic_if_unchanged`] once the new file is on disk, right before its
/// rename: a save by the app while this one was being written is noticed too, and kept.
pub fn write_unless_changed(path: &Path, read: &[u8; 32], bytes: &[u8]) -> Result<()> {
    ensure_unchanged(path, read)?;
    match storage::write_atomic_if_unchanged(path, read, bytes) {
        Ok(()) => Ok(()),
        Err(CoreError::FileChanged) => Err(changed_meanwhile(path)),
        Err(err) => Err(explain(err)),
    }
}

/// Someone else saved the vault file while this command ran.
fn changed_meanwhile(path: &Path) -> anyhow::Error {
    anyhow!(
        "{} changed while this command was running (another app or device saved it). \
         Nothing was written: run the command again.",
        path.display()
    )
}

/// Refuses to go on when the vault file no longer holds what was read: someone else (the
/// app, another device's sync, another command) wrote it in the meantime, and saving now
/// would throw their changes away (AGENTS.md §4.1, rule 7).
fn ensure_unchanged(path: &Path, read: &[u8; 32]) -> Result<()> {
    let now = storage::read(path).map_err(explain)?;
    if storage::fingerprint(&now) != *read {
        return Err(changed_meanwhile(path));
    }
    Ok(())
}

pub fn read_vault_file(path: &Path) -> Result<Vec<u8>> {
    if !path.exists() {
        bail!(
            "no vault at {} (create one with `vault init`, or pass --vault)",
            path.display()
        );
    }
    storage::read(path).map_err(explain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_read_as_the_apps_show_them() {
        assert_eq!(date_time(1_700_000_000, 0), "2023-11-14 22:13");
        assert_eq!(date_time(1_700_000_000, -180), "2023-11-14 19:13");
        assert_eq!(date_time(951_782_400, 0), "2000-02-29 00:00");
        assert_eq!(minutes_seconds(125), "2:05");
        assert_eq!(minutes_seconds(30), "0:30");
    }

    #[test]
    fn a_file_changed_by_someone_else_is_not_written_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        storage::write_atomic(&path, b"as read").unwrap();
        let read = storage::fingerprint(b"as read");
        ensure_unchanged(&path, &read).unwrap();

        // The app (or a sync tool) saves in the meantime.
        storage::write_atomic(&path, b"saved elsewhere").unwrap();
        let refused = ensure_unchanged(&path, &read).unwrap_err().to_string();
        assert!(
            refused.contains("changed while this command was running"),
            "{refused}"
        );
    }

    const PASSWORD: &str = "unit test master passphrase";

    /// A test vault with recovery parts, written at `path`: its bytes and the vault, open.
    fn vault_with_parts(path: &Path) -> (Vec<u8>, Vault, SecretKey) {
        vault_with(path, &vault_core::RecoveryParts::generate().unwrap())
    }

    /// [`vault_with_parts`], with these parts.
    fn vault_with(path: &Path, parts: &vault_core::RecoveryParts) -> (Vec<u8>, Vault, SecretKey) {
        let secret_key = SecretKey::generate().unwrap();
        let kdf = vault_core::KdfParams::minimum().unwrap();
        let mut vault = Vault::create(PASSWORD, &secret_key, None, kdf).unwrap();
        vault.set_recovery_parts(parts, &secret_key).unwrap();
        let bytes = vault.to_bytes().unwrap();
        storage::write_atomic(path, &bytes).unwrap();
        let vault = Vault::open(&bytes, unlock(&secret_key)).unwrap();
        (bytes, vault, secret_key)
    }

    fn unlock(secret_key: &SecretKey) -> Unlock<'_> {
        Unlock::Password {
            password: PASSWORD,
            secret_key,
        }
    }

    fn has_parts(path: &Path) -> bool {
        Vault::inspect(&storage::read(path).unwrap())
            .unwrap()
            .has_recovery_parts
    }

    #[test]
    fn used_parts_are_not_retired_over_another_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let (read, mut vault, secret_key) = vault_with_parts(&path);

        // While the command waits for the prompts, the app adds an item and saves.
        let mut other = Vault::open(&read, unlock(&secret_key)).unwrap();
        other
            .add_item(&vault_core::ItemData::login(
                "Saved meanwhile",
                "test-user",
                "test-item-password",
                "https://saved.example",
            ))
            .unwrap();
        let saved = other.to_bytes().unwrap();
        storage::write_atomic(&path, &saved).unwrap();

        let refused = retire_parts(&path, &mut vault, &read, || {
            panic!("the Secret Key is kept only once the parts are retired")
        })
        .unwrap_err();
        let message = format!("{refused:#}");
        assert!(
            message.contains("changed while this command was running")
                && message.contains("still work"),
            "{message}"
        );
        // The app's save is what the file holds, parts and all.
        assert_eq!(storage::read(&path).unwrap(), saved);
        assert!(has_parts(&path));
    }

    #[test]
    fn used_parts_are_retired_before_the_secret_key_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let (read, mut vault, _) = vault_with_parts(&path);

        let mut kept = false;
        let written = retire_parts(&path, &mut vault, &read, || {
            assert!(!has_parts(&path), "retired on disk first");
            kept = true;
            Ok(())
        })
        .unwrap();
        assert!(kept);
        assert_eq!(
            written,
            storage::fingerprint(&storage::read(&path).unwrap())
        );
        assert!(!has_parts(&path));
    }

    #[test]
    fn a_secret_key_that_cant_be_kept_leaves_the_parts_working() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let (read, mut vault, _) = vault_with_parts(&path);

        let failed = retire_parts(&path, &mut vault, &read, || {
            bail!("no credential store here")
        })
        .unwrap_err();
        let message = format!("{failed:#}");
        assert!(
            message.contains("no credential store here") && message.contains("still work"),
            "{message}"
        );
        assert_eq!(storage::read(&path).unwrap(), read);
        assert!(has_parts(&path));
    }

    /// What the vault file holds after each way [`replace_then_keep`] can end.
    #[test]
    fn a_replaced_file_is_kept_with_its_key_or_put_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let (old, new) = (b"as read".as_slice(), b"as written".as_slice());
        let fresh = || storage::write_atomic(&path, old).unwrap();

        fresh();
        let written = replace_then_keep(&path, old, new, || {
            assert_eq!(
                storage::read(&path).unwrap(),
                new,
                "written before it is kept"
            );
            Ok(())
        });
        assert_eq!(written.unwrap(), storage::fingerprint(new));
        assert_eq!(storage::read(&path).unwrap(), new);

        // Changed since it was read: not written, not kept.
        storage::write_atomic(&path, b"saved meanwhile").unwrap();
        let failed = replace_then_keep(&path, old, new, || panic!("kept, though not written"));
        assert!(matches!(failed, Err(NotKept::NotWritten(_))));
        assert_eq!(storage::read(&path).unwrap(), b"saved meanwhile");

        // Not kept: put back.
        fresh();
        let failed = replace_then_keep(&path, old, new, || bail!("no credential store here"));
        assert!(matches!(failed, Err(NotKept::PutBack(_))));
        assert_eq!(storage::read(&path).unwrap(), old);

        // Not kept, and changed again before it could be put back: said so.
        fresh();
        let failed = replace_then_keep(&path, old, new, || {
            storage::write_atomic(&path, b"saved meanwhile").unwrap();
            bail!("no credential store here")
        });
        let Err(NotKept::Replaced { error, back }) = failed else {
            panic!("{failed:?}");
        };
        assert!(format!("{error:#}").contains("no credential store here"));
        assert!(format!("{back:#}").contains("changed while this command was running"));
        assert_eq!(storage::read(&path).unwrap(), b"saved meanwhile");
    }

    /// PM-14, through `Session::unlock`: two recovery parts typed while the app saves the
    /// vault. Nothing is written over the app's save, the parts still work, and this device
    /// keeps no Secret Key. Run as a process of its own (this test again) with `VAULT_HOME` in
    /// a temporary folder, so the device state it reads and could write is a test's. The OS
    /// credential store is the real one, as in tests/cli.rs (Windows only, as they are), asked
    /// only about this test vault.
    #[cfg(windows)]
    #[test]
    fn recovery_parts_typed_while_the_app_saves_retire_nothing() {
        const CHILD: &str = "VAULT_TEST_PARTS_TYPED_WHILE_SAVED";
        if std::env::var_os(CHILD).is_some() {
            return parts_typed_while_the_app_saves();
        }
        let home = tempfile::tempdir().unwrap();
        let (_, tests) = module_path!().split_once("::").unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!(
                "{tests}::recovery_parts_typed_while_the_app_saves_retire_nothing"
            ))
            .arg("--nocapture")
            .env(CHILD, "1")
            .env("VAULT_HOME", home.path())
            .env_remove("VAULT_FILE")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > until {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the test's own process didn't end");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{said}");
        assert!(said.contains("1 passed"), "it ran: {said}");
    }

    /// What the test above runs in its own process.
    #[cfg(windows)]
    fn parts_typed_while_the_app_saves() {
        assert!(std::env::var_os("VAULT_HOME").is_some());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let parts = vault_core::RecoveryParts::generate().unwrap();
        let (read, _, secret_key) = vault_with(&path, &parts);
        let id = Vault::inspect(&read).unwrap().id_hex;
        let mut app = Vault::open(&read, unlock(&secret_key)).unwrap();
        app.add_item(&vault_core::ItemData::login(
            "Saved meanwhile",
            "test-user",
            "test-item-password",
            "https://saved.example",
        ))
        .unwrap();
        let saved = app.to_bytes().unwrap();

        let [first, second] = [vault_core::PartLabel::A, vault_core::PartLabel::B]
            .map(|label| parts.part(label).to_display_string().as_str().to_owned());
        let (at, app_save) = (path.clone(), saved.clone());
        let mut prompter = Prompter::scripted(&[&first, &second, PASSWORD], move |label| {
            // The app saves while the master password is typed.
            if label == "Master password" {
                storage::write_atomic(&at, &app_save).unwrap();
            }
        });
        let unlocked = Session::unlock(&path, &mut prompter, false, None);
        let kept = secret_store::load(&id);
        // Whatever a wrong order left in the credential store goes before anything is checked.
        let _ = secret_store::forget(&id);
        let refused = match unlocked {
            Ok(_) => panic!("unlocked and saved over the app's save"),
            Err(err) => format!("{err:#}"),
        };
        assert!(
            refused.contains("changed while this command was running")
                && refused.contains("still work"),
            "{refused}"
        );
        assert_eq!(storage::read(&path).unwrap(), saved, "the app's save stays");
        assert!(has_parts(&path), "the parts still work");
        assert!(
            kept.unwrap().is_none(),
            "this device kept the Secret Key the parts brought back"
        );
    }
}
