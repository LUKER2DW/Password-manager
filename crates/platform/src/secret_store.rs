//! The Secret Key lives in the OS credential store (Windows Credential Manager, macOS Keychain,
//! Secret Service on Linux; on Android, SharedPreferences encrypted with a key held in the
//! Android Keystore) — never in the vault file or in plain files.
//!
//! On Windows the credential store is DPAPI underneath: any program of the same user reads it,
//! and a copy of the profile opens elsewhere with the user's password. Where the computer has
//! a TPM, the Secret Key is kept under a key that never leaves the chip instead (CRYPTO.md
//! §2.2.1): a new random key seals it, the TPM's RSA key ([`crate::tpm`]) wraps that key, and
//! only the result is stored, as `secret-key-tpm:<vault id>`. The plain form,
//! `secret-key:<vault id>`, is written only where the chip can't take it; one kept before is
//! moved under the chip once the vault opens with it ([`settle`]), and goes only after the new
//! form was read back and found to be the same key.
//!
//! The chip is behind [`KeyWrapper`], so the logic is tested with a stand-in
//! ([`MemoryChip`]); the apps' tests use that one too ([`use_key_wrapper`]) and make no keys
//! in the real TPM.

use std::sync::{Arc, PoisonError, RwLock};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use keyring_core::{Entry, Error as StoreError};
use vault_core::{SecretKey, kept_key};
use zeroize::Zeroizing;

const SERVICE: &str = "vault-cli";

/// How this device keeps a vault's Secret Key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    /// Under a key in the security chip (the TPM): a copy of the disk, of the profile or of
    /// the credential store doesn't carry it.
    Chip,
    /// In the OS credential store only (DPAPI on Windows), where there is no chip to take it:
    /// a copy of the profile opens it with the user's password.
    System,
}

/// What [`load_checked`] found for a vault.
#[derive(Debug)]
pub enum Loaded {
    Key(SecretKey),
    /// No Secret Key is kept for this vault here.
    Missing,
    /// One is kept under the chip, but the chip no longer opens it: it was cleared, replaced
    /// or turned off. The emergency kit's Secret Key is needed; once it opens the vault it is
    /// kept again ([`settle`]).
    ChipLost,
    /// Two different Secret Keys are kept (an older version of an app wrote one beside the
    /// chip's): which one opens the vault isn't known, so the kit's is needed.
    Conflict,
}

/// A key that never leaves a chip, used by name: what wraps the key that seals the Secret
/// Key on this device (the TPM on Windows, [`crate::tpm::Tpm`]).
pub trait KeyWrapper: Send + Sync + std::fmt::Debug {
    /// Makes the key `name` anew, replacing one of that name.
    fn create(&self, name: &str) -> Result<(), ChipError>;
    /// Encrypts `data` to the key `name`, bound to `label`.
    fn wrap(&self, name: &str, label: &[u8], data: &[u8]) -> Result<Vec<u8>, ChipError>;
    /// Decrypts in the chip what [`KeyWrapper::wrap`] gave for the same name and label.
    fn unwrap(
        &self,
        name: &str,
        label: &[u8],
        wrapped: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChipError>;
    /// Deletes the key `name`; whether there was one.
    fn delete(&self, name: &str) -> Result<bool, ChipError>;
}

/// Why the chip didn't do what was asked.
#[derive(Debug)]
pub enum ChipError {
    /// The key is gone for good (the chip was cleared or replaced), or isn't the one the
    /// data was wrapped to.
    Lost,
    /// Anything else, which may pass (the chip busy, its service starting): what is stored
    /// is kept as it is.
    Failed(anyhow::Error),
}

impl std::fmt::Display for ChipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lost => f.write_str("the security chip (TPM) no longer has this key"),
            Self::Failed(err) => write!(f, "{err:#}"),
        }
    }
}

/// The chip chosen for this process: unset until first used (then this device's own), or
/// what [`use_key_wrapper`] put in its place.
#[allow(clippy::type_complexity, reason = "one static, read in one place")]
static WRAPPER: RwLock<Option<Option<Arc<dyn KeyWrapper>>>> = RwLock::new(None);

fn wrapper() -> Option<Arc<dyn KeyWrapper>> {
    if let Some(chosen) = WRAPPER
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
    {
        return chosen.clone();
    }
    WRAPPER
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(system_wrapper)
        .clone()
}

fn system_wrapper() -> Option<Arc<dyn KeyWrapper>> {
    #[cfg(windows)]
    {
        crate::tpm::Tpm::open().map(|tpm| Arc::new(tpm) as Arc<dyn KeyWrapper>)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Uses `wrapper` in place of this device's chip from now on in this process; `None` keeps
/// the plain form only. For tests and the screenshots, which must make no keys in the real
/// TPM: they set it before anything stores a Secret Key.
pub fn use_key_wrapper(wrapper: Option<Arc<dyn KeyWrapper>>) {
    *WRAPPER.write().unwrap_or_else(PoisonError::into_inner) = Some(wrapper);
}

/// Keeps `key` for the vault `vault_id` on this device: under the chip when there is one
/// that takes it (checked by reading it back), else in the credential store as it is.
pub fn store(vault_id: &str, key: &SecretKey) -> Result<()> {
    keeper(vault_id, |keeper| keeper.store(key)).map(|_| ())
}

/// The Secret Key kept for `vault_id`, or `None` when there is none this device can use.
pub fn load(vault_id: &str) -> Result<Option<SecretKey>> {
    keeper(vault_id, |keeper| keeper.load()).map(|loaded| match loaded {
        Loaded::Key(key) => Some(key),
        Loaded::Missing | Loaded::ChipLost | Loaded::Conflict => None,
    })
}

/// The Secret Key kept for `vault_id`, or why there is none to use. An error is one that may
/// pass (the chip didn't answer, the store couldn't be read): nothing is deleted for it.
pub fn load_checked(vault_id: &str) -> Result<Loaded> {
    keeper(vault_id, |keeper| keeper.load())
}

/// After the vault `vault_id` opened with `key`: makes sure this device keeps exactly that
/// key, in the strongest form it can. A plain key is moved under the chip (checked before
/// the plain one goes), a lost or different one replaced. Can take a second or two the first
/// time (the chip makes its key), so never on a UI thread.
pub fn settle(vault_id: &str, key: &SecretKey) -> Result<Kept> {
    keeper(vault_id, |keeper| keeper.settle(key))
}

/// How the Secret Key of `vault_id` is kept here, without opening it (nothing is asked of
/// the chip): `None` when it isn't.
pub fn kept(vault_id: &str) -> Result<Option<Kept>> {
    // Read from the store's entries alone: the chip isn't even opened (the start screen asks).
    Keeper {
        entries: &SystemEntries,
        chip: None,
        id: vault_id,
    }
    .kept()
}

/// Forgets the Secret Key of `vault_id` on this device, in both forms, and the chip's key.
/// Returns whether a key was kept.
pub fn forget(vault_id: &str) -> Result<bool> {
    keeper(vault_id, |keeper| keeper.forget())
}

fn keeper<T>(vault_id: &str, run: impl FnOnce(&Keeper<'_>) -> Result<T>) -> Result<T> {
    let chip = wrapper();
    run(&Keeper {
        entries: &SystemEntries,
        chip: chip.as_deref(),
        id: vault_id,
    })
}

/// The credential store as text entries: a trait so the logic is tested without the OS's.
trait Entries {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>>;
    fn set(&self, account: &str, text: &str) -> Result<()>;
    fn delete(&self, account: &str) -> Result<bool>;
}

struct SystemEntries;

impl Entries for SystemEntries {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        load_text(account)
    }
    fn set(&self, account: &str, text: &str) -> Result<()> {
        store_text(account, text)
    }
    fn delete(&self, account: &str) -> Result<bool> {
        forget_text(account)
    }
}

/// One vault's Secret Key in the store, with the chip (if any).
struct Keeper<'a> {
    entries: &'a dyn Entries,
    chip: Option<&'a dyn KeyWrapper>,
    id: &'a str,
}

fn damaged() -> ChipError {
    ChipError::Failed(anyhow!(
        "the Secret Key kept under the security chip is damaged"
    ))
}

impl Keeper<'_> {
    fn plain_account(&self) -> String {
        format!("secret-key:{}", self.id)
    }

    fn chip_account(&self) -> String {
        format!("secret-key-tpm:{}", self.id)
    }

    /// The chip's key for this vault.
    fn key_name(&self) -> String {
        key_name(self.id)
    }

    fn plain(&self) -> Result<Option<SecretKey>> {
        let Some(text) = self.entries.get(&self.plain_account())? else {
            return Ok(None);
        };
        SecretKey::parse(&text)
            .map(Some)
            .map_err(|err| anyhow!(err).context("the Secret Key in the OS credential store"))
    }

    /// The key kept under the chip: `None` when none is stored.
    fn wrapped(&self) -> Result<Option<Result<SecretKey, ChipError>>> {
        let Some(text) = self.entries.get(&self.chip_account())? else {
            return Ok(None);
        };
        Ok(Some(self.open(&text)))
    }

    fn open(&self, text: &str) -> Result<SecretKey, ChipError> {
        // A form under a chip this device no longer has opens nowhere.
        let chip = self.chip.ok_or(ChipError::Lost)?;
        let kept = BASE64.decode(text.trim()).map_err(|_| damaged())?;
        let (wrapped, sealed) = kept_key::decode(&kept).map_err(|_| damaged())?;
        let kek = chip.unwrap(&self.key_name(), kept_key::WRAP_LABEL, wrapped)?;
        kept_key::open(&kek, self.id, sealed).map_err(|_| damaged())
    }

    fn load(&self) -> Result<Loaded> {
        let plain = self.plain();
        Ok(match self.wrapped()? {
            None => match plain? {
                Some(key) => Loaded::Key(key),
                None => Loaded::Missing,
            },
            Some(Ok(key)) => match plain {
                Ok(Some(other)) if other != key => Loaded::Conflict,
                _ => Loaded::Key(key),
            },
            // The chip's form is dead; a plain one beside it is the one left.
            Some(Err(ChipError::Lost)) => match plain? {
                Some(key) => Loaded::Key(key),
                None => Loaded::ChipLost,
            },
            Some(Err(ChipError::Failed(err))) => return Err(err),
        })
    }

    fn store(&self, key: &SecretKey) -> Result<Kept> {
        if let Some(chip) = self.chip {
            // A plain key that isn't this one is wrong from now on: it goes first, so no
            // moment leaves two different keys kept.
            if matches!(self.plain(), Ok(Some(old)) if old != *key) {
                self.entries.delete(&self.plain_account())?;
            }
            if self.store_wrapped(chip, key).is_ok() {
                self.entries.delete(&self.plain_account())?;
                return Ok(Kept::Chip);
            }
        }
        self.entries
            .set(&self.plain_account(), &key.to_display_string())?;
        // A form under the chip from before would hide this key: it goes, with its chip key.
        if self.entries.delete(&self.chip_account())?
            && let Some(chip) = self.chip
        {
            let _ = chip.delete(&self.key_name());
        }
        Ok(Kept::System)
    }

    /// Seals `key` under a new key-encryption key, has the chip wrap that, writes the result
    /// and reads it back through the chip: done only when the same key comes back.
    fn store_wrapped(&self, chip: &dyn KeyWrapper, key: &SecretKey) -> Result<(), ChipError> {
        let name = self.key_name();
        let label = kept_key::WRAP_LABEL;
        let (kek, sealed) =
            kept_key::seal(key, self.id).map_err(|err| ChipError::Failed(anyhow!(err)))?;
        let mut made = false;
        loop {
            let wrapped = match chip.wrap(&name, label, kek.as_ref()) {
                // No key of this name yet: made once.
                Err(ChipError::Lost) if !made => {
                    chip.create(&name)?;
                    made = true;
                    continue;
                }
                other => other?,
            };
            let kept = kept_key::encode(&wrapped, &sealed).map_err(|_| damaged())?;
            self.entries
                .set(&self.chip_account(), &BASE64.encode(kept))
                .map_err(ChipError::Failed)?;
            match self.wrapped().map_err(ChipError::Failed)? {
                Some(Ok(read)) if read == *key => return Ok(()),
                // A key that still encrypts (that half is done in software) but no longer
                // decrypts, after the chip was cleared: made anew, once.
                Some(Err(ChipError::Lost)) if !made => {
                    chip.create(&name)?;
                    made = true;
                }
                Some(Err(err)) => return Err(err),
                _ => {
                    return Err(ChipError::Failed(anyhow!(
                        "the Secret Key read back from the security chip isn't the one stored"
                    )));
                }
            }
        }
    }

    fn settle(&self, key: &SecretKey) -> Result<Kept> {
        let wrapped = match self.wrapped()? {
            // The chip didn't answer: nothing is rewritten for an error that may pass.
            Some(Err(ChipError::Failed(err))) => return Err(err),
            other => other,
        };
        if matches!(&wrapped, Some(Ok(kept)) if kept == key) {
            // Under the chip already: a plain copy left beside it goes.
            self.entries.delete(&self.plain_account())?;
            return Ok(Kept::Chip);
        }
        if wrapped.is_none()
            && self.chip.is_none()
            && matches!(self.plain(), Ok(Some(plain)) if plain == *key)
        {
            return Ok(Kept::System);
        }
        // Not kept, kept plain where the chip could take it, under a chip key that is gone,
        // or a key that isn't this one: kept anew.
        self.store(key)
    }

    fn kept(&self) -> Result<Option<Kept>> {
        if self.entries.get(&self.chip_account())?.is_some() {
            return Ok(Some(Kept::Chip));
        }
        Ok(self
            .entries
            .get(&self.plain_account())?
            .map(|_| Kept::System))
    }

    fn forget(&self) -> Result<bool> {
        let wrapped = self.entries.delete(&self.chip_account())?;
        let plain = self.entries.delete(&self.plain_account())?;
        if let Some(chip) = self.chip {
            let _ = chip.delete(&self.key_name());
        }
        Ok(wrapped || plain)
    }
}

/// The name of the chip's key for a vault: one per vault and Windows user.
fn key_name(vault_id: &str) -> String {
    format!("vault-secret-key-{vault_id}")
}

/// On Android, the Keystore-backed store becomes the default once, before the first entry.
#[cfg(target_os = "android")]
fn ready() -> Result<()> {
    static STORE: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    STORE
        .get_or_init(|| {
            let store = android_native_keyring_store::Store::new().map_err(|e| e.to_string())?;
            keyring_core::set_default_store(store);
            Ok(())
        })
        .clone()
        .map_err(|e| anyhow!(e).context("opening the Android Keystore"))
}

/// Elsewhere the `keyring` crate sets the OS's store as the default, once.
#[cfg(not(target_os = "android"))]
fn ready() -> Result<()> {
    keyring::Entry::store_status()
        .as_ref()
        .map_err(|err| anyhow!("{err}").context("opening the OS credential store"))
        .copied()
}

fn text_entry(account: &str) -> Result<Entry> {
    ready()?;
    // On Windows the entries stay on this computer: the store's default ("Enterprise")
    // travels with a domain's roaming profile to every computer the user signs in to.
    #[cfg(windows)]
    let entry = Entry::new_with_modifiers(
        SERVICE,
        account,
        &std::collections::HashMap::from([("persistence", "Local")]),
    );
    #[cfg(not(windows))]
    let entry = Entry::new(SERVICE, account);
    entry.context("opening the OS credential store")
}

fn store_text(account: &str, text: &str) -> Result<()> {
    text_entry(account)?
        .set_password(text)
        .context("saving in the OS credential store")
}

fn load_text(account: &str) -> Result<Option<Zeroizing<String>>> {
    match text_entry(account)?.get_password() {
        Ok(text) => Ok(Some(Zeroizing::new(text))),
        Err(StoreError::NoEntry) => Ok(None),
        Err(error) => Err(anyhow!(error).context("reading the OS credential store")),
    }
}

fn forget_text(account: &str) -> Result<bool> {
    match text_entry(account)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(StoreError::NoEntry) => Ok(false),
        Err(error) => Err(anyhow!(error).context("deleting from the OS credential store")),
    }
}

/// The key device `device` (hex) signs its requests to a sync server with (its secret
/// seed), per vault. Never in the vault file or in device state.
pub fn store_sync_key(vault_id: &str, device: &str, seed: &[u8; 32]) -> Result<()> {
    let text = Zeroizing::new(vault_sync_wire::hex(seed));
    store_text(&format!("sync-key:{vault_id}:{device}"), &text)
}

pub fn load_sync_key(vault_id: &str, device: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let Some(text) = load_text(&format!("sync-key:{vault_id}:{device}"))? else {
        return Ok(None);
    };
    let seed = vault_sync_wire::unhex::<32>(&text)
        .ok_or_else(|| anyhow!("the sync key in the OS credential store is damaged"))?;
    Ok(Some(Zeroizing::new(seed)))
}

pub fn forget_sync_key(vault_id: &str, device: &str) -> Result<bool> {
    forget_text(&format!("sync-key:{vault_id}:{device}"))
}

/// The WebDAV password for a vault's sync.
pub fn store_webdav_password(vault_id: &str, password: &str) -> Result<()> {
    store_text(&format!("webdav:{vault_id}"), password)
}

pub fn load_webdav_password(vault_id: &str) -> Result<Option<Zeroizing<String>>> {
    load_text(&format!("webdav:{vault_id}"))
}

pub fn forget_webdav_password(vault_id: &str) -> Result<bool> {
    forget_text(&format!("webdav:{vault_id}"))
}

/// A stand-in for the chip that keeps its keys in this process's memory: what it wraps
/// opens only here, while it lasts. For tests and the screenshots ([`use_key_wrapper`]).
#[cfg(any(test, feature = "test-chip"))]
#[derive(Debug, Default)]
pub struct MemoryChip {
    keys: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
    failing: std::sync::atomic::AtomicBool,
}

#[cfg(any(test, feature = "test-chip"))]
impl MemoryChip {
    /// Forgets the key of the vault `vault_id`, as clearing a TPM does.
    pub fn lose(&self, vault_id: &str) {
        self.keys().remove(&key_name(vault_id));
    }

    /// Whether every call fails from now on, as a chip that doesn't answer.
    pub fn set_failing(&self, failing: bool) {
        self.failing
            .store(failing, std::sync::atomic::Ordering::Relaxed);
    }

    fn keys(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, [u8; 32]>> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn check(&self) -> Result<(), ChipError> {
        if self.failing.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ChipError::Failed(anyhow!("the stand-in chip is failing")));
        }
        Ok(())
    }

    /// A pad and a check for `data` of 32 bytes, from the key and the label (a stand-in, not
    /// a cipher: it only has to open what it wrapped, and nothing else).
    fn pad(key: &[u8; 32], label: &[u8], part: u8) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::new()
            .chain_update([part])
            .chain_update(key)
            .chain_update(label)
            .finalize()
            .into()
    }
}

#[cfg(any(test, feature = "test-chip"))]
impl KeyWrapper for MemoryChip {
    fn create(&self, name: &str) -> Result<(), ChipError> {
        self.check()?;
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|err| ChipError::Failed(anyhow!("{err}")))?;
        self.keys().insert(name.to_owned(), key);
        Ok(())
    }

    fn wrap(&self, name: &str, label: &[u8], data: &[u8]) -> Result<Vec<u8>, ChipError> {
        self.check()?;
        let key = *self.keys().get(name).ok_or(ChipError::Lost)?;
        let data: &[u8; 32] = data
            .try_into()
            .map_err(|_| ChipError::Failed(anyhow!("32 bytes only")))?;
        let pad = Self::pad(&key, label, 0);
        let mut out = vec![0u8; kept_key::WRAPPED_LEN];
        for (i, byte) in data.iter().enumerate() {
            out[i] = byte ^ pad[i];
        }
        out[32..64].copy_from_slice(&Self::pad(&key, &[label, data].concat(), 1));
        Ok(out)
    }

    fn unwrap(
        &self,
        name: &str,
        label: &[u8],
        wrapped: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChipError> {
        self.check()?;
        let key = *self.keys().get(name).ok_or(ChipError::Lost)?;
        if wrapped.len() != kept_key::WRAPPED_LEN {
            return Err(ChipError::Lost);
        }
        let pad = Self::pad(&key, label, 0);
        let data: Zeroizing<Vec<u8>> = Zeroizing::new(
            wrapped[..32]
                .iter()
                .zip(pad)
                .map(|(byte, pad)| byte ^ pad)
                .collect(),
        );
        if wrapped[32..64] != Self::pad(&key, &[label, &data].concat(), 1) {
            return Err(ChipError::Lost);
        }
        Ok(data)
    }

    fn delete(&self, name: &str) -> Result<bool, ChipError> {
        self.check()?;
        Ok(self.keys().remove(name).is_some())
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use super::*;

    const ID: &str = "00112233445566778899aabbccddeeff";

    /// The credential store in memory; `spoil` changes what is written to the chip's entry.
    #[derive(Default)]
    struct MemoryEntries {
        map: RefCell<HashMap<String, String>>,
        spoil: bool,
    }

    impl Entries for MemoryEntries {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
            Ok(self.map.borrow().get(account).cloned().map(Zeroizing::new))
        }
        fn set(&self, account: &str, text: &str) -> Result<()> {
            let mut text = text.to_owned();
            if self.spoil && account.starts_with("secret-key-tpm:") {
                text = BASE64.encode(b"\x01not what was written");
            }
            self.map.borrow_mut().insert(account.to_owned(), text);
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<bool> {
            Ok(self.map.borrow_mut().remove(account).is_some())
        }
    }

    impl MemoryEntries {
        fn has(&self, account: &str) -> bool {
            self.map.borrow().contains_key(account)
        }
        fn plain(&self) -> bool {
            self.has(&format!("secret-key:{ID}"))
        }
        fn wrapped(&self) -> bool {
            self.has(&format!("secret-key-tpm:{ID}"))
        }
    }

    fn keeper<'a>(entries: &'a MemoryEntries, chip: Option<&'a MemoryChip>) -> Keeper<'a> {
        Keeper {
            entries,
            chip: chip.map(|chip| chip as &dyn KeyWrapper),
            id: ID,
        }
    }

    fn key_of(loaded: Loaded) -> SecretKey {
        match loaded {
            Loaded::Key(key) => key,
            other => panic!("no key: {other:?}"),
        }
    }

    #[test]
    fn with_a_chip_only_the_wrapped_form_is_written() {
        let (entries, chip) = (MemoryEntries::default(), MemoryChip::default());
        let keeper = keeper(&entries, Some(&chip));
        let key = SecretKey::generate().unwrap();
        assert_eq!(keeper.store(&key).unwrap(), Kept::Chip);
        assert!(entries.wrapped() && !entries.plain());
        // What is stored names no part of the key.
        let text = entries
            .get(&format!("secret-key-tpm:{ID}"))
            .unwrap()
            .unwrap();
        assert!(!text.contains(key.to_display_string().as_str()));
        assert_eq!(key_of(keeper.load().unwrap()), key);
        assert_eq!(keeper.kept().unwrap(), Some(Kept::Chip));
        // Settling with the same key changes nothing.
        assert_eq!(keeper.settle(&key).unwrap(), Kept::Chip);
        assert!(entries.wrapped() && !entries.plain());
    }

    #[test]
    fn without_a_chip_the_plain_form_stays() {
        let entries = MemoryEntries::default();
        let keeper = keeper(&entries, None);
        let key = SecretKey::generate().unwrap();
        assert_eq!(keeper.store(&key).unwrap(), Kept::System);
        assert!(entries.plain() && !entries.wrapped());
        assert_eq!(key_of(keeper.load().unwrap()), key);
        assert_eq!(keeper.settle(&key).unwrap(), Kept::System);
        assert_eq!(keeper.kept().unwrap(), Some(Kept::System));
    }

    #[test]
    fn a_plain_key_moves_under_the_chip_once_it_reads_back() {
        let (entries, chip) = (MemoryEntries::default(), MemoryChip::default());
        let key = SecretKey::generate().unwrap();
        keeper(&entries, None).store(&key).unwrap();

        let keeper = keeper(&entries, Some(&chip));
        assert_eq!(key_of(keeper.load().unwrap()), key);
        assert_eq!(keeper.settle(&key).unwrap(), Kept::Chip);
        assert!(entries.wrapped() && !entries.plain());
        assert_eq!(key_of(keeper.load().unwrap()), key);
    }

    #[test]
    fn a_move_that_doesnt_read_back_keeps_the_plain_key() {
        let key = SecretKey::generate().unwrap();
        // The chip fails: nothing moves, the plain key stays.
        let (entries, chip) = (MemoryEntries::default(), MemoryChip::default());
        keeper(&entries, None).store(&key).unwrap();
        chip.set_failing(true);
        assert_eq!(
            keeper(&entries, Some(&chip)).settle(&key).unwrap(),
            Kept::System
        );
        assert!(entries.plain() && !entries.wrapped());

        // The store gives back something else than what was written: the same.
        let entries = MemoryEntries {
            spoil: true,
            ..MemoryEntries::default()
        };
        let chip = MemoryChip::default();
        keeper(&entries, None).store(&key).unwrap();
        let keeper = keeper(&entries, Some(&chip));
        assert_eq!(keeper.settle(&key).unwrap(), Kept::System);
        assert!(entries.plain() && !entries.wrapped());
        assert_eq!(key_of(keeper.load().unwrap()), key);
    }

    #[test]
    fn a_cleared_chip_asks_for_the_kit_and_keeps_what_is_stored() {
        let (entries, chip) = (MemoryEntries::default(), MemoryChip::default());
        let keeper = keeper(&entries, Some(&chip));
        let key = SecretKey::generate().unwrap();
        keeper.store(&key).unwrap();

        chip.lose(ID);
        assert!(matches!(keeper.load().unwrap(), Loaded::ChipLost));
        assert!(
            entries.wrapped(),
            "nothing is deleted when the chip says no"
        );
        // The kit's key typed, the vault opened: kept again under a new chip key.
        assert_eq!(keeper.settle(&key).unwrap(), Kept::Chip);
        assert_eq!(key_of(keeper.load().unwrap()), key);

        // A computer that has no chip any more (turned off in its firmware): the same.
        assert!(matches!(
            self::keeper(&entries, None).load().unwrap(),
            Loaded::ChipLost
        ));
    }

    #[test]
    fn a_chip_that_doesnt_answer_is_an_error_not_a_loss() {
        let (entries, chip) = (MemoryEntries::default(), MemoryChip::default());
        let keeper = keeper(&entries, Some(&chip));
        let key = SecretKey::generate().unwrap();
        keeper.store(&key).unwrap();
        chip.set_failing(true);
        assert!(keeper.load().is_err());
        // Settling then rewrites nothing either: the form under the chip stays as it is.
        assert!(keeper.settle(&key).is_err());
        assert!(entries.wrapped() && !entries.plain());
        chip.set_failing(false);
        assert_eq!(key_of(keeper.load().unwrap()), key);
    }

    #[test]
    fn a_failing_chip_falls_back_to_the_plain_form_and_drops_an_older_wrapped_one() {
        let (entries, chip) = (MemoryEntries::default(), MemoryChip::default());
        let keeper = keeper(&entries, Some(&chip));
        let old = SecretKey::generate().unwrap();
        keeper.store(&old).unwrap();
        chip.set_failing(true);
        let new = SecretKey::generate().unwrap();
        assert_eq!(keeper.store(&new).unwrap(), Kept::System);
        assert!(entries.plain() && !entries.wrapped());
        chip.set_failing(false);
        assert_eq!(key_of(keeper.load().unwrap()), new);
        // Later, with the chip answering, the next settle moves it under the chip.
        assert_eq!(keeper.settle(&new).unwrap(), Kept::Chip);
        assert!(entries.wrapped() && !entries.plain());
    }

    #[test]
    fn two_different_keys_kept_ask_for_the_kit() {
        let (entries, chip) = (MemoryEntries::default(), MemoryChip::default());
        let keeper = keeper(&entries, Some(&chip));
        let wrapped = SecretKey::generate().unwrap();
        keeper.store(&wrapped).unwrap();
        // An older app, that knows nothing of the chip, kept another one beside it.
        let plain = SecretKey::generate().unwrap();
        entries
            .set(&format!("secret-key:{ID}"), &plain.to_display_string())
            .unwrap();
        assert!(matches!(keeper.load().unwrap(), Loaded::Conflict));
        // The same key in both is no conflict; settling drops the plain copy.
        entries
            .set(&format!("secret-key:{ID}"), &wrapped.to_display_string())
            .unwrap();
        assert_eq!(key_of(keeper.load().unwrap()), wrapped);
        entries
            .set(&format!("secret-key:{ID}"), &plain.to_display_string())
            .unwrap();
        // The vault opened with the plain one: it is the one kept from now on.
        assert_eq!(keeper.settle(&plain).unwrap(), Kept::Chip);
        assert!(entries.wrapped() && !entries.plain());
        assert_eq!(key_of(keeper.load().unwrap()), plain);
    }

    #[test]
    fn a_new_key_replaces_the_old_in_both_forms() {
        let (entries, chip) = (MemoryEntries::default(), MemoryChip::default());
        let old = SecretKey::generate().unwrap();
        keeper(&entries, None).store(&old).unwrap();
        let keeper = keeper(&entries, Some(&chip));
        let new = SecretKey::generate().unwrap();
        assert_eq!(keeper.store(&new).unwrap(), Kept::Chip);
        assert!(!entries.plain());
        assert_eq!(key_of(keeper.load().unwrap()), new);
    }

    #[test]
    fn damaged_forms_are_errors() {
        let (entries, chip) = (MemoryEntries::default(), MemoryChip::default());
        let keeper = keeper(&entries, Some(&chip));
        keeper.store(&SecretKey::generate().unwrap()).unwrap();
        let account = format!("secret-key-tpm:{ID}");
        let text = entries.get(&account).unwrap().unwrap();
        let mut bytes = BASE64.decode(text.as_str()).unwrap();
        // The sealed key changed: the chip unwraps, the seal doesn't open.
        *bytes.last_mut().unwrap() ^= 1;
        entries.set(&account, &BASE64.encode(&bytes)).unwrap();
        assert!(keeper.load().is_err());
        entries.set(&account, "not base64!").unwrap();
        assert!(keeper.load().is_err());
        entries
            .set(&format!("secret-key:{ID}"), "S0-not-a-key")
            .unwrap();
        entries.delete(&account).unwrap();
        assert!(keeper.load().is_err());
    }

    #[test]
    fn forget_removes_both_forms_and_the_chip_key() {
        let (entries, chip) = (MemoryEntries::default(), MemoryChip::default());
        let keeper = keeper(&entries, Some(&chip));
        let key = SecretKey::generate().unwrap();
        keeper.store(&key).unwrap();
        entries
            .set(&format!("secret-key:{ID}"), &key.to_display_string())
            .unwrap();
        assert!(keeper.forget().unwrap());
        assert!(!entries.plain() && !entries.wrapped());
        assert!(chip.keys().is_empty());
        assert!(!keeper.forget().unwrap());
        assert!(matches!(keeper.load().unwrap(), Loaded::Missing));
        assert_eq!(keeper.kept().unwrap(), None);
    }

    /// The real store and this computer's TPM, with a vault id made for the test and removed
    /// after it. Skipped in CI and where there is no TPM.
    #[cfg(windows)]
    #[test]
    fn the_real_store_keeps_the_key_under_this_computers_tpm() {
        use std::time::Instant;

        if std::env::var_os("CI").is_some() {
            eprintln!("skipped: no TPM tests in CI");
            return;
        }
        let Some(tpm) = crate::tpm::Tpm::open() else {
            eprintln!("skipped: no TPM here");
            return;
        };
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let id: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let keeper = Keeper {
            entries: &SystemEntries,
            chip: Some(&tpm),
            id: &id,
        };
        struct Forget<'a>(&'a Keeper<'a>);
        impl Drop for Forget<'_> {
            fn drop(&mut self) {
                let _ = self.0.forget();
            }
        }
        let _cleanup = Forget(&keeper);

        // A key kept the old way, then moved under the chip.
        let key = SecretKey::generate().unwrap();
        SystemEntries
            .set(&keeper.plain_account(), &key.to_display_string())
            .unwrap();
        let started = Instant::now();
        assert_eq!(keeper.settle(&key).unwrap(), Kept::Chip);
        eprintln!(
            "moved under the TPM (its key made, wrapped, written, read back) in {:?}",
            started.elapsed()
        );
        assert!(
            SystemEntries
                .get(&keeper.plain_account())
                .unwrap()
                .is_none()
        );
        let started = Instant::now();
        assert_eq!(key_of(keeper.load().unwrap()), key);
        eprintln!("loaded (unwrapped in the TPM) in {:?}", started.elapsed());

        // A new key for the same vault reuses the chip's key.
        let new = SecretKey::generate().unwrap();
        let started = Instant::now();
        assert_eq!(keeper.store(&new).unwrap(), Kept::Chip);
        eprintln!("stored again in {:?}", started.elapsed());
        assert_eq!(key_of(keeper.load().unwrap()), new);

        // Kept on this computer only, not in a roaming profile.
        let entry = text_entry(&keeper.chip_account()).unwrap();
        assert_eq!(entry.get_attributes().unwrap()["persistence"], "Local");

        assert!(keeper.forget().unwrap());
        assert!(matches!(keeper.load().unwrap(), Loaded::Missing));
        assert!(!tpm.delete(&keeper.key_name()).unwrap());
    }
}
