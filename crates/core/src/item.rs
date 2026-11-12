//! Vault item model (spec: VAULT_FORMAT.md §4).

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ItemKind {
    #[default]
    Login,
    Card,
    SecureNote,
    Passkey,
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
}

impl ItemData {
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
        }
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
            .finish()
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
}

impl ItemSummary {
    pub(crate) fn from_data(id: ItemId, data: &ItemData) -> Self {
        Self {
            id,
            kind: data.kind,
            title: data.title.clone(),
            username: data.username.clone(),
            url: data.urls.first().cloned().unwrap_or_default(),
            favorite: data.favorite,
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

fn unix_now() -> i64 {
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
    fn login_constructor() {
        let item = ItemData::login("t", "u", "p", "");
        assert_eq!(item.kind, ItemKind::Login);
        assert!(item.urls.is_empty());
        assert!(item.created_at > 0);
    }
}
