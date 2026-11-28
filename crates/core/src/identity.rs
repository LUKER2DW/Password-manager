//! Identity items (format v11): a person's details kept as custom fields with fixed names, as
//! cards keep theirs (`crate::card`), so they survive import and export unchanged. The name is
//! the item's `username`. Document numbers are hidden fields, so the item lock covers them.

use crate::{CustomField, ItemData, ItemKind};

pub const EMAIL: &str = "Email";
pub const PHONE: &str = "Phone";
pub const ADDRESS: &str = "Address";
pub const CITY: &str = "City";
pub const REGION: &str = "State or region";
pub const POSTAL_CODE: &str = "Postal code";
pub const COUNTRY: &str = "Country";
pub const BIRTH_DATE: &str = "Birth date";
pub const COMPANY: &str = "Company";
pub const ID_NUMBER: &str = "ID number";
pub const TAX_NUMBER: &str = "Tax number";
pub const PASSPORT: &str = "Passport number";
pub const DRIVING_LICENCE: &str = "Driving licence";

/// The details an identity offers, in the order shown, and whether each is hidden.
pub const FIELDS: [(&str, bool); 13] = [
    (EMAIL, false),
    (PHONE, false),
    (ADDRESS, false),
    (CITY, false),
    (REGION, false),
    (POSTAL_CODE, false),
    (COUNTRY, false),
    (BIRTH_DATE, false),
    (COMPANY, false),
    (ID_NUMBER, true),
    (TAX_NUMBER, true),
    (PASSPORT, true),
    (DRIVING_LICENCE, true),
];

/// Whether `name` is one of an identity's own fields (ignoring case).
pub fn is_reserved(name: &str) -> bool {
    FIELDS
        .iter()
        .any(|(field, _)| field.eq_ignore_ascii_case(name))
}

/// A new identity named `title`, with every detail offered and empty.
pub fn new(title: &str) -> ItemData {
    let mut item = ItemData::new(ItemKind::Identity, title);
    item.custom_fields = FIELDS
        .iter()
        .map(|(name, sensitive)| CustomField {
            name: (*name).to_owned(),
            value: String::new(),
            sensitive: *sensitive,
        })
        .collect();
    item
}

/// The value of detail `name` (empty when it isn't there).
pub fn get(item: &ItemData, name: &str) -> String {
    item.custom_fields
        .iter()
        .find(|f| f.name.eq_ignore_ascii_case(name))
        .map(|f| f.value.clone())
        .unwrap_or_default()
}

/// Sets detail `name`: trimmed, hidden when it is a document number; an empty value removes
/// it. The identity's own details stay first, in their order, then the other fields.
pub fn set(item: &mut ItemData, name: &str, value: &str) {
    let value = value.trim();
    let sensitive = FIELDS
        .iter()
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .is_some_and(|(_, hidden)| *hidden);
    match item
        .custom_fields
        .iter()
        .position(|f| f.name.eq_ignore_ascii_case(name))
    {
        Some(index) if value.is_empty() => {
            item.custom_fields.remove(index);
        }
        Some(index) => {
            item.custom_fields[index].value = value.to_owned();
            item.custom_fields[index].sensitive |= sensitive;
        }
        None if value.is_empty() => {}
        None => item.custom_fields.push(CustomField {
            name: name.to_owned(),
            value: value.to_owned(),
            sensitive,
        }),
    }
    tidy(item);
}

/// The identity's own details first, in [`FIELDS`] order, the empty ones dropped; the other
/// fields after them, as they were.
pub fn tidy(item: &mut ItemData) {
    let fields = std::mem::take(&mut item.custom_fields);
    let (mut own, others): (Vec<CustomField>, Vec<CustomField>) =
        fields.into_iter().partition(|f| is_reserved(&f.name));
    own.retain(|f| !f.value.trim().is_empty());
    own.sort_by_key(|f| {
        FIELDS
            .iter()
            .position(|(name, _)| name.eq_ignore_ascii_case(&f.name))
            .unwrap_or(usize::MAX)
    });
    item.custom_fields = own;
    item.custom_fields.extend(others);
}

/// The one line that stands for an identity in a list: its email, else its phone, else its
/// city and country.
pub fn summary(item: &ItemData) -> String {
    let email = get(item, EMAIL);
    if !email.is_empty() {
        return email;
    }
    let phone = get(item, PHONE);
    if !phone.is_empty() {
        return phone;
    }
    [get(item, CITY), get(item, COUNTRY)]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details_are_kept_in_order_and_documents_hidden() {
        let mut item = new("Me");
        assert_eq!(item.kind, ItemKind::Identity);
        assert_eq!(item.custom_fields.len(), FIELDS.len());
        item.custom_fields.push(CustomField {
            name: "Nickname".into(),
            value: "Tester".into(),
            sensitive: false,
        });
        set(&mut item, PASSPORT, " X1234567 ");
        set(&mut item, EMAIL, "test@example.invalid");
        let names: Vec<&str> = item.custom_fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, [EMAIL, PASSPORT, "Nickname"]);
        assert!(item.custom_fields[1].sensitive);
        assert_eq!(get(&item, "passport NUMBER"), "X1234567");
        assert_eq!(summary(&item), "test@example.invalid");
        set(&mut item, EMAIL, "");
        set(&mut item, CITY, "Testville");
        set(&mut item, COUNTRY, "Nowhere");
        assert_eq!(summary(&item), "Testville, Nowhere");
        assert!(!format!("{item:?}").contains("X1234567"));
    }
}
