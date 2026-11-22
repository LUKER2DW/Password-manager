//! Vault item model (spec: VAULT_FORMAT.md §4).

use std::fmt;

// The std clock on a computer or phone; the browser's in a web build (std's panics there).
use web_time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Result, random};

/// Random 128-bit item identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ItemId([u8; 16]);

impl ItemId {
    pub(crate) fn generate() -> Result<Self> {
        random::array().map(Self)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lowercase hex form (32 characters).
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parses the hex form produced by [`ItemId::to_hex`].
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 32 || !text.is_ascii() {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Debug for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ItemId({})", self.to_hex())
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Random 128-bit folder identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FolderId([u8; 16]);

impl FolderId {
    pub(crate) fn generate() -> Result<Self> {
        random::array().map(Self)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lowercase hex form (32 characters).
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parses the hex form produced by [`FolderId::to_hex`].
    pub fn from_hex(text: &str) -> Option<Self> {
        ItemId::from_hex(text).map(|id| Self(id.0))
    }
}

impl fmt::Debug for FolderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FolderId({})", self.to_hex())
    }
}

/// A folder to file items in (like Bitwarden's). Its name is encrypted with the vault body.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Folder {
    #[zeroize(skip)]
    pub id: FolderId,
    pub name: String,
    /// Icon name chosen by the user ("" = the plain folder icon). (Format v3.)
    pub icon: String,
    /// Colour index chosen by the user (0 = default). (Format v3.)
    #[zeroize(skip)]
    pub color: u8,
    /// A website or image link whose picture replaces the icon ("" = none). (Format v4.)
    pub icon_url: String,
}

/// Folder as stored by format v3 (icon and colour, no picture link).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct FolderV3 {
    #[zeroize(skip)]
    pub(crate) id: FolderId,
    pub(crate) name: String,
    pub(crate) icon: String,
    #[zeroize(skip)]
    pub(crate) color: u8,
}

impl fmt::Debug for FolderV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderV3")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl FolderV3 {
    pub(crate) fn upgrade(mut self) -> Folder {
        Folder {
            id: self.id,
            name: std::mem::take(&mut self.name),
            icon: std::mem::take(&mut self.icon),
            color: self.color,
            icon_url: String::new(),
        }
    }
}

/// Folder as stored by formats v1 and v2 (before icons and colours).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct FolderV1 {
    #[zeroize(skip)]
    pub(crate) id: FolderId,
    pub(crate) name: String,
}

impl fmt::Debug for FolderV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderV1")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl FolderV1 {
    pub(crate) fn upgrade(mut self) -> Folder {
        Folder {
            id: self.id,
            name: std::mem::take(&mut self.name),
            icon: String::new(),
            color: 0,
            icon_url: String::new(),
        }
    }
}

impl Folder {
    /// Longest icon name accepted.
    pub const MAX_ICON_CHARS: usize = 32;
    /// Longest picture link accepted.
    pub const MAX_ICON_URL_CHARS: usize = 2048;
    /// Highest colour index accepted.
    pub const MAX_COLOR: u8 = 15;
}

impl fmt::Debug for Folder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Folder")
            .field("id", &self.id)
            .field("name", &self.name)
            .finish()
    }
}

/// One of an account's single-use backup codes for two-step sign-in.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode {
    pub code: String,
    /// Marked by the user once spent; kept so they can see how many are left.
    pub used: bool,
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryCode")
            .field("code", &"<redacted>")
            .field("used", &self.used)
            .finish()
    }
}

impl RecoveryCode {
    /// Parses pasted codes: one per line (or separated by commas/semicolons), surrounding
    /// spaces, bullets and numbering such as `1.` removed, empty lines skipped.
    pub fn parse_list(text: &str) -> Vec<RecoveryCode> {
        text.split(['\n', ',', ';'])
            .map(|line| {
                let line = line.trim().trim_start_matches(['-', '*', '•']).trim();
                // "1. abcd-efgh" / "1) abcd-efgh"
                let line = match line.split_once([' ', '\t']) {
                    Some((number, rest))
                        if number
                            .trim_end_matches(['.', ')'])
                            .chars()
                            .all(|c| c.is_ascii_digit())
                            && number.ends_with(['.', ')']) =>
                    {
                        rest.trim()
                    }
                    _ => line,
                };
                line.to_owned()
            })
            .filter(|code| !code.is_empty())
            .map(|code| RecoveryCode { code, used: false })
            .collect()
    }
}

/// A password an item used before (format v2).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordChange {
    pub password: String,
    /// When it stopped being the password (Unix seconds).
    pub replaced_at: i64,
}

impl fmt::Debug for PasswordChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordChange")
            .field("password", &"<redacted>")
            .field("replaced_at", &self.replaced_at)
            .finish()
    }
}

/// Settings stored inside the vault (encrypted with it), so they follow the vault to every
/// device. (Format v2.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSettings {
    /// Shown in the app instead of the file name when not empty.
    pub name: String,
    /// Old passwords kept per item (0 = keep none).
    pub history_limit: u16,
}

impl VaultSettings {
    pub const DEFAULT_HISTORY_LIMIT: u16 = 10;
    pub const MAX_HISTORY_LIMIT: u16 = 100;
    pub const MAX_NAME_CHARS: usize = 60;
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            name: String::new(),
            history_limit: Self::DEFAULT_HISTORY_LIMIT,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ItemKind {
    #[default]
    Login,
    Card,
    SecureNote,
    Passkey,
    /// An SSH key pair: the private key where a login keeps its password, the public key and
    /// its fingerprint in fields (format v9; see `crate::ssh`).
    SshKey,
}

/// A file kept with an item (format v9): a scan, a document, a key file. It is encrypted with
/// the item, and with the item lock when the item is locked.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Attachment {
    pub name: String,
    /// Unix seconds.
    pub added_at: i64,
    pub data: Vec<u8>,
}

impl Attachment {
    /// The largest file an item keeps: the whole vault is one file, written and synced whole.
    pub const MAX_BYTES: usize = 5 * 1024 * 1024;
    /// The most files one item keeps.
    pub const MAX_PER_ITEM: usize = 10;
    const MAX_NAME_CHARS: usize = 255;

    /// A file to attach, named after its last path part (`/` and `\` both split).
    pub fn new(name: &str, data: Vec<u8>) -> crate::Result<Self> {
        let name = name.rsplit(['/', '\\']).next().unwrap_or_default().trim();
        if data.len() > Self::MAX_BYTES {
            return Err(crate::Error::AttachmentTooLarge);
        }
        if name.is_empty()
            || name.chars().count() > Self::MAX_NAME_CHARS
            || name.chars().any(char::is_control)
        {
            return Err(crate::Error::InvalidName);
        }
        Ok(Self {
            name: name.to_owned(),
            added_at: unix_now(),
            data,
        })
    }
}

impl fmt::Debug for Attachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attachment")
            .field("name", &self.name)
            .field("bytes", &self.data.len())
            .finish()
    }
}

/// A user-defined extra field.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    /// Hidden by default in the UI (e.g. PINs, security answers).
    pub sensitive: bool,
}

impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value: &dyn fmt::Debug = if self.sensitive {
            &"<redacted>"
        } else {
            &self.value
        };
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field("value", value)
            .finish()
    }
}

/// Decrypted contents of an item. Wiped from memory when dropped.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ItemData {
    #[zeroize(skip)]
    pub kind: ItemKind,
    pub title: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub notes: String,
    /// `otpauth://` URI or Base32 TOTP secret; empty when the item has no TOTP.
    pub totp: String,
    pub favorite: bool,
    pub custom_fields: Vec<CustomField>,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
    /// Folder the item is filed in; `None` = no folder. (Format v1.)
    #[zeroize(skip)]
    pub folder: Option<FolderId>,
    /// The account's backup codes for two-step sign-in. (Format v1.)
    pub recovery_codes: Vec<RecoveryCode>,
    /// Earlier passwords, oldest first; filled in by [`crate::Vault::update_item`] when the
    /// password changes. (Format v2.)
    pub password_history: Vec<PasswordChange>,
    /// When the current password was set (Unix seconds; 0 = unknown, before format v2).
    pub password_changed_at: i64,
    /// Website whose icon stands for this item ("" = its first URL). (Format v3.)
    pub icon_url: String,
    /// Ask for the master password again before showing or copying this item's secrets.
    /// The client enforces it; it guards against someone at an unlocked computer, not against
    /// malware that already reads the unlocked vault. (Format v5.)
    #[zeroize(skip)]
    pub reprompt: bool,
    /// Present while the item's secrets are locked: they are encrypted under the item guard
    /// key and the fields that hold them are empty. (Format v6.)
    #[zeroize(skip)]
    pub sealed: Option<SealedSecrets>,
    /// Files kept with the item; empty while it is locked. (Format v9.)
    pub attachments: Vec<Attachment>,
}

/// A guarded item's secrets, encrypted under the item guard key, with the few facts a locked
/// item still tells. (Format v6.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecrets {
    pub(crate) ciphertext: Vec<u8>,
    pub has_password: bool,
    pub has_totp: bool,
    /// Cards: "Visa •••• 4242" when the number is stored, else empty.
    pub card_hint: String,
    pub card_brand: crate::card::Brand,
}

/// The part of an item that the item guard encrypts: password, one-time code secret, the
/// values of hidden fields (in order), recovery codes, earlier passwords, and the text of a
/// secure note.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ItemSecrets {
    password: String,
    totp: String,
    notes: String,
    fields: Vec<String>,
    recovery_codes: Vec<RecoveryCode>,
    password_history: Vec<PasswordChange>,
    /// Format v9: the item's files.
    attachments: Vec<Attachment>,
}

/// Sealed secrets as written from format v6 to v8 (before attachments). A guarded item keeps
/// its secrets sealed until the guard opens, so these are read as they are found.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ItemSecretsV6 {
    password: String,
    totp: String,
    notes: String,
    fields: Vec<String>,
    recovery_codes: Vec<RecoveryCode>,
    password_history: Vec<PasswordChange>,
}

impl ItemSecrets {
    /// Reads sealed secrets in the current layout or the one before attachments.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if let Ok(secrets) = crate::format::decode_exact::<Self>(bytes) {
            return Ok(secrets);
        }
        let mut old: ItemSecretsV6 = crate::format::decode_exact(bytes)?;
        Ok(Self {
            password: std::mem::take(&mut old.password),
            totp: std::mem::take(&mut old.totp),
            notes: std::mem::take(&mut old.notes),
            fields: std::mem::take(&mut old.fields),
            recovery_codes: std::mem::take(&mut old.recovery_codes),
            password_history: std::mem::take(&mut old.password_history),
            attachments: Vec::new(),
        })
    }
}

impl ItemData {
    /// The item's secrets are still encrypted: password, one-time code, recovery codes, hidden
    /// fields and history are empty here until the item guard is passed.
    pub fn is_locked(&self) -> bool {
        self.sealed.is_some()
    }

    /// Moves the secrets out, leaving what a locked item still shows.
    pub(crate) fn take_secrets(&mut self) -> ItemSecrets {
        ItemSecrets {
            password: std::mem::take(&mut self.password),
            totp: std::mem::take(&mut self.totp),
            notes: if self.kind == ItemKind::SecureNote {
                std::mem::take(&mut self.notes)
            } else {
                String::new()
            },
            fields: self
                .custom_fields
                .iter_mut()
                .filter(|field| field.sensitive)
                .map(|field| std::mem::take(&mut field.value))
                .collect(),
            recovery_codes: std::mem::take(&mut self.recovery_codes),
            password_history: std::mem::take(&mut self.password_history),
            attachments: std::mem::take(&mut self.attachments),
        }
    }

    /// Puts secrets taken by [`ItemData::take_secrets`] back.
    pub(crate) fn put_secrets(&mut self, mut secrets: ItemSecrets) -> Result<()> {
        let hidden = self.custom_fields.iter().filter(|f| f.sensitive).count();
        if hidden != secrets.fields.len() {
            return Err(crate::Error::Malformed);
        }
        self.password = std::mem::take(&mut secrets.password);
        self.totp = std::mem::take(&mut secrets.totp);
        if self.kind == ItemKind::SecureNote {
            self.notes = std::mem::take(&mut secrets.notes);
        }
        for (field, value) in self
            .custom_fields
            .iter_mut()
            .filter(|field| field.sensitive)
            .zip(secrets.fields.iter_mut())
        {
            field.value = std::mem::take(value);
        }
        self.recovery_codes = std::mem::take(&mut secrets.recovery_codes);
        self.password_history = std::mem::take(&mut secrets.password_history);
        self.attachments = std::mem::take(&mut secrets.attachments);
        Ok(())
    }

    /// Whether the attached files keep to the limits ([`Attachment::MAX_BYTES`],
    /// [`Attachment::MAX_PER_ITEM`]).
    pub(crate) fn check_attachments(&self) -> Result<()> {
        if self.attachments.len() > Attachment::MAX_PER_ITEM
            || self
                .attachments
                .iter()
                .any(|file| file.data.len() > Attachment::MAX_BYTES)
        {
            return Err(crate::Error::AttachmentTooLarge);
        }
        Ok(())
    }

    /// Empty item of the given kind, timestamped now.
    pub fn new(kind: ItemKind, title: &str) -> Self {
        // `ZeroizeOnDrop` implements `Drop`, which forbids struct-update syntax
        // (`..Default::default()`), so every field is listed explicitly.
        let now = unix_now();
        Self {
            kind,
            title: title.to_owned(),
            username: String::new(),
            password: String::new(),
            urls: Vec::new(),
            notes: String::new(),
            totp: String::new(),
            favorite: false,
            custom_fields: Vec::new(),
            created_at: now,
            updated_at: now,
            folder: None,
            recovery_codes: Vec::new(),
            password_history: Vec::new(),
            password_changed_at: 0,
            icon_url: String::new(),
            reprompt: false,
            sealed: None,
            attachments: Vec::new(),
        }
    }

    /// When the current password was set, falling back to when the item was created.
    pub fn password_set_at(&self) -> i64 {
        if self.password_changed_at > 0 {
            self.password_changed_at
        } else {
            self.created_at
        }
    }

    /// Backup codes not yet marked as used.
    pub fn recovery_codes_left(&self) -> usize {
        self.recovery_codes.iter().filter(|c| !c.used).count()
    }

    /// Convenience constructor for a login.
    pub fn login(title: &str, username: &str, password: &str, url: &str) -> Self {
        let mut item = Self::new(ItemKind::Login, title);
        item.username = username.to_owned();
        item.password = password.to_owned();
        if !url.is_empty() {
            item.urls.push(url.to_owned());
        }
        item
    }

    /// Updates `updated_at` to the current time.
    pub fn touch(&mut self) {
        self.updated_at = unix_now();
    }
}

impl fmt::Debug for ItemData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemData")
            .field("kind", &self.kind)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("urls", &self.urls)
            .field("notes", &"<redacted>")
            .field(
                "totp",
                &if self.totp.is_empty() {
                    ""
                } else {
                    "<redacted>"
                },
            )
            .field("favorite", &self.favorite)
            .field("custom_fields", &self.custom_fields)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("folder", &self.folder)
            .field("recovery_codes", &self.recovery_codes.len())
            .field("password_history", &self.password_history.len())
            .field("password_changed_at", &self.password_changed_at)
            .field("icon_url", &self.icon_url)
            .field("locked", &self.sealed.is_some())
            .field("attachments", &self.attachments)
            .finish()
    }
}

/// Item data as stored by format v0 (before folders and recovery codes). Read-only: v0 vaults
/// are upgraded when opened.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ItemDataV0 {
    #[zeroize(skip)]
    pub(crate) kind: ItemKind,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) urls: Vec<String>,
    pub(crate) notes: String,
    pub(crate) totp: String,
    pub(crate) favorite: bool,
    pub(crate) custom_fields: Vec<CustomField>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

impl ItemDataV0 {
    /// Moves the fields into the current item layout (`take` leaves wiped-on-drop empties).
    pub(crate) fn upgrade(mut self) -> ItemData {
        ItemData {
            password_history: Vec::new(),
            password_changed_at: 0,
            icon_url: String::new(),
            reprompt: false,
            sealed: None,
            kind: self.kind,
            title: std::mem::take(&mut self.title),
            username: std::mem::take(&mut self.username),
            password: std::mem::take(&mut self.password),
            urls: std::mem::take(&mut self.urls),
            notes: std::mem::take(&mut self.notes),
            totp: std::mem::take(&mut self.totp),
            favorite: self.favorite,
            custom_fields: std::mem::take(&mut self.custom_fields),
            created_at: self.created_at,
            updated_at: self.updated_at,
            folder: None,
            recovery_codes: Vec::new(),
            attachments: Vec::new(),
        }
    }
}

/// Item data as stored by format v1 (before password history). Read-only: v1 vaults are
/// upgraded when opened.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ItemDataV1 {
    #[zeroize(skip)]
    pub(crate) kind: ItemKind,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) urls: Vec<String>,
    pub(crate) notes: String,
    pub(crate) totp: String,
    pub(crate) favorite: bool,
    pub(crate) custom_fields: Vec<CustomField>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    #[zeroize(skip)]
    pub(crate) folder: Option<FolderId>,
    pub(crate) recovery_codes: Vec<RecoveryCode>,
}

impl ItemDataV1 {
    /// Moves the fields into the current item layout (`take` leaves wiped-on-drop empties).
    pub(crate) fn upgrade(mut self) -> ItemData {
        ItemData {
            kind: self.kind,
            title: std::mem::take(&mut self.title),
            username: std::mem::take(&mut self.username),
            password: std::mem::take(&mut self.password),
            urls: std::mem::take(&mut self.urls),
            notes: std::mem::take(&mut self.notes),
            totp: std::mem::take(&mut self.totp),
            favorite: self.favorite,
            custom_fields: std::mem::take(&mut self.custom_fields),
            created_at: self.created_at,
            updated_at: self.updated_at,
            folder: self.folder,
            recovery_codes: std::mem::take(&mut self.recovery_codes),
            password_history: Vec::new(),
            password_changed_at: 0,
            icon_url: String::new(),
            reprompt: false,
            sealed: None,
            attachments: Vec::new(),
        }
    }
}

/// Item data as stored by format v2 (before custom icons). Read-only: v2 vaults are upgraded
/// when opened.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ItemDataV2 {
    #[zeroize(skip)]
    pub(crate) kind: ItemKind,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) urls: Vec<String>,
    pub(crate) notes: String,
    pub(crate) totp: String,
    pub(crate) favorite: bool,
    pub(crate) custom_fields: Vec<CustomField>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    #[zeroize(skip)]
    pub(crate) folder: Option<FolderId>,
    pub(crate) recovery_codes: Vec<RecoveryCode>,
    pub(crate) password_history: Vec<PasswordChange>,
    pub(crate) password_changed_at: i64,
}

impl ItemDataV2 {
    /// Moves the fields into the current item layout (`take` leaves wiped-on-drop empties).
    pub(crate) fn upgrade(mut self) -> ItemData {
        ItemData {
            kind: self.kind,
            title: std::mem::take(&mut self.title),
            username: std::mem::take(&mut self.username),
            password: std::mem::take(&mut self.password),
            urls: std::mem::take(&mut self.urls),
            notes: std::mem::take(&mut self.notes),
            totp: std::mem::take(&mut self.totp),
            favorite: self.favorite,
            custom_fields: std::mem::take(&mut self.custom_fields),
            created_at: self.created_at,
            updated_at: self.updated_at,
            folder: self.folder,
            recovery_codes: std::mem::take(&mut self.recovery_codes),
            password_history: std::mem::take(&mut self.password_history),
            password_changed_at: self.password_changed_at,
            icon_url: String::new(),
            reprompt: false,
            sealed: None,
            attachments: Vec::new(),
        }
    }
}

/// Item data as stored by formats v3 and v4 (before the re-prompt flag). Read-only: those
/// vaults are upgraded when opened.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ItemDataV3 {
    #[zeroize(skip)]
    pub(crate) kind: ItemKind,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) urls: Vec<String>,
    pub(crate) notes: String,
    pub(crate) totp: String,
    pub(crate) favorite: bool,
    pub(crate) custom_fields: Vec<CustomField>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    #[zeroize(skip)]
    pub(crate) folder: Option<FolderId>,
    pub(crate) recovery_codes: Vec<RecoveryCode>,
    pub(crate) password_history: Vec<PasswordChange>,
    pub(crate) password_changed_at: i64,
    pub(crate) icon_url: String,
}

impl ItemDataV3 {
    /// Moves the fields into the current item layout (`take` leaves wiped-on-drop empties).
    pub(crate) fn upgrade(mut self) -> ItemData {
        ItemData {
            kind: self.kind,
            title: std::mem::take(&mut self.title),
            username: std::mem::take(&mut self.username),
            password: std::mem::take(&mut self.password),
            urls: std::mem::take(&mut self.urls),
            notes: std::mem::take(&mut self.notes),
            totp: std::mem::take(&mut self.totp),
            favorite: self.favorite,
            custom_fields: std::mem::take(&mut self.custom_fields),
            created_at: self.created_at,
            updated_at: self.updated_at,
            folder: self.folder,
            recovery_codes: std::mem::take(&mut self.recovery_codes),
            password_history: std::mem::take(&mut self.password_history),
            password_changed_at: self.password_changed_at,
            icon_url: std::mem::take(&mut self.icon_url),
            reprompt: false,
            sealed: None,
            attachments: Vec::new(),
        }
    }
}

/// Item data as stored by format v5 (before sealed secrets). Read-only: v5 vaults are upgraded
/// when opened.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ItemDataV5 {
    #[zeroize(skip)]
    pub(crate) kind: ItemKind,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) urls: Vec<String>,
    pub(crate) notes: String,
    pub(crate) totp: String,
    pub(crate) favorite: bool,
    pub(crate) custom_fields: Vec<CustomField>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    #[zeroize(skip)]
    pub(crate) folder: Option<FolderId>,
    pub(crate) recovery_codes: Vec<RecoveryCode>,
    pub(crate) password_history: Vec<PasswordChange>,
    pub(crate) password_changed_at: i64,
    pub(crate) icon_url: String,
    #[zeroize(skip)]
    pub(crate) reprompt: bool,
}

impl ItemDataV5 {
    /// Moves the fields into the current item layout (`take` leaves wiped-on-drop empties).
    pub(crate) fn upgrade(mut self) -> ItemData {
        ItemData {
            kind: self.kind,
            title: std::mem::take(&mut self.title),
            username: std::mem::take(&mut self.username),
            password: std::mem::take(&mut self.password),
            urls: std::mem::take(&mut self.urls),
            notes: std::mem::take(&mut self.notes),
            totp: std::mem::take(&mut self.totp),
            favorite: self.favorite,
            custom_fields: std::mem::take(&mut self.custom_fields),
            created_at: self.created_at,
            updated_at: self.updated_at,
            folder: self.folder,
            recovery_codes: std::mem::take(&mut self.recovery_codes),
            password_history: std::mem::take(&mut self.password_history),
            password_changed_at: self.password_changed_at,
            icon_url: std::mem::take(&mut self.icon_url),
            reprompt: self.reprompt,
            sealed: None,
            attachments: Vec::new(),
        }
    }
}

/// Item data as stored from format v6 to v8 (before attachments and SSH keys). Read-only: such
/// vaults are upgraded when opened.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ItemDataV8 {
    #[zeroize(skip)]
    pub(crate) kind: ItemKind,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) urls: Vec<String>,
    pub(crate) notes: String,
    pub(crate) totp: String,
    pub(crate) favorite: bool,
    pub(crate) custom_fields: Vec<CustomField>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    #[zeroize(skip)]
    pub(crate) folder: Option<FolderId>,
    pub(crate) recovery_codes: Vec<RecoveryCode>,
    pub(crate) password_history: Vec<PasswordChange>,
    pub(crate) password_changed_at: i64,
    pub(crate) icon_url: String,
    #[zeroize(skip)]
    pub(crate) reprompt: bool,
    #[zeroize(skip)]
    pub(crate) sealed: Option<SealedSecrets>,
}

impl ItemDataV8 {
    /// Moves the fields into the current item layout; sealed secrets stay sealed as they are.
    pub(crate) fn upgrade(mut self) -> ItemData {
        ItemData {
            kind: self.kind,
            title: std::mem::take(&mut self.title),
            username: std::mem::take(&mut self.username),
            password: std::mem::take(&mut self.password),
            urls: std::mem::take(&mut self.urls),
            notes: std::mem::take(&mut self.notes),
            totp: std::mem::take(&mut self.totp),
            favorite: self.favorite,
            custom_fields: std::mem::take(&mut self.custom_fields),
            created_at: self.created_at,
            updated_at: self.updated_at,
            folder: self.folder,
            recovery_codes: std::mem::take(&mut self.recovery_codes),
            password_history: std::mem::take(&mut self.password_history),
            password_changed_at: self.password_changed_at,
            icon_url: std::mem::take(&mut self.icon_url),
            reprompt: self.reprompt,
            sealed: self.sealed.take(),
            attachments: Vec::new(),
        }
    }
}

/// Non-secret overview of an item, for list views. Wiped from memory when dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ItemSummary {
    #[zeroize(skip)]
    pub id: ItemId,
    #[zeroize(skip)]
    pub kind: ItemKind,
    pub title: String,
    pub username: String,
    pub url: String,
    pub favorite: bool,
    #[zeroize(skip)]
    pub folder: Option<FolderId>,
    /// The item has a one-time code secret (shown on the Authenticator page).
    pub has_totp: bool,
    /// Cards: "Visa •••• 4242" when the number is stored, else empty.
    pub card_hint: String,
    /// Cards: the network, from the number's first digits.
    #[zeroize(skip)]
    pub card_brand: crate::card::Brand,
    /// Website chosen for the item's icon ("" = `url`).
    pub icon_url: String,
    /// The item is marked to have its secrets guarded.
    #[zeroize(skip)]
    pub reprompt: bool,
    /// The item's secrets are still encrypted under the item guard key.
    #[zeroize(skip)]
    pub locked: bool,
    /// The item has a password.
    #[zeroize(skip)]
    pub has_password: bool,
    /// How many files are attached (0 while the item is locked).
    #[zeroize(skip)]
    pub attachments: usize,
}

impl ItemSummary {
    pub(crate) fn from_data(id: ItemId, data: &ItemData) -> Self {
        let (has_password, has_totp, card_hint, card_brand) = match &data.sealed {
            Some(sealed) => (
                sealed.has_password,
                sealed.has_totp,
                sealed.card_hint.clone(),
                sealed.card_brand,
            ),
            None if data.kind == ItemKind::Card => {
                let number = crate::card::CardDetails::from_item(data).number;
                (
                    !data.password.is_empty(),
                    !data.totp.trim().is_empty(),
                    if number.len() >= 4 {
                        crate::card::masked(&number)
                    } else {
                        String::new()
                    },
                    crate::card::detect_brand(&number),
                )
            }
            None => (
                !data.password.is_empty(),
                !data.totp.trim().is_empty(),
                String::new(),
                crate::card::Brand::Unknown,
            ),
        };
        Self {
            id,
            kind: data.kind,
            title: data.title.clone(),
            username: data.username.clone(),
            url: data.urls.first().cloned().unwrap_or_default(),
            favorite: data.favorite,
            folder: data.folder,
            has_totp,
            card_hint,
            icon_url: data.icon_url.clone(),
            reprompt: data.reprompt,
            locked: data.is_locked(),
            has_password,
            card_brand,
            attachments: data.attachments.len(),
        }
    }
}

impl fmt::Debug for ItemSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemSummary")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_id_hex_round_trip() {
        let id = ItemId::generate().unwrap();
        assert_eq!(ItemId::from_hex(&id.to_hex()), Some(id));
        assert_eq!(ItemId::from_hex("zz"), None);
        assert_eq!(ItemId::from_hex(&"g".repeat(32)), None);
    }

    #[test]
    fn debug_redacts_secrets() {
        let mut item = ItemData::login("GitHub", "me", "hunter2", "https://github.com");
        item.notes = "recovery codes: 1234".into();
        item.custom_fields.push(CustomField {
            name: "PIN".into(),
            value: "9876".into(),
            sensitive: true,
        });
        let text = format!("{item:?}");
        assert!(text.contains("GitHub"));
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("1234"));
        assert!(!text.contains("9876"));
    }

    #[test]
    fn recovery_codes_are_parsed_from_pasted_text() {
        let pasted = "  1. abcd-efgh\n2) ijkl-mnop\n\n- qrst-uvwx\n• yz12-3456 , 7890-abcd;  \n";
        let codes: Vec<String> = RecoveryCode::parse_list(pasted)
            .into_iter()
            .map(|c| c.code.clone())
            .collect();
        assert_eq!(
            codes,
            [
                "abcd-efgh",
                "ijkl-mnop",
                "qrst-uvwx",
                "yz12-3456",
                "7890-abcd"
            ]
        );
        // Codes that contain spaces are kept whole.
        assert_eq!(RecoveryCode::parse_list("abcd efgh")[0].code, "abcd efgh");
        let mut item = ItemData::new(ItemKind::Login, "x");
        item.recovery_codes = RecoveryCode::parse_list("a\nb\nc");
        item.recovery_codes[1].used = true;
        assert_eq!(item.recovery_codes_left(), 2);
        assert!(!format!("{item:?}").contains("\"a\""));
    }

    #[test]
    fn login_constructor() {
        let item = ItemData::login("t", "u", "p", "");
        assert_eq!(item.kind, ItemKind::Login);
        assert!(item.urls.is_empty());
        assert!(item.created_at > 0);
    }
}
