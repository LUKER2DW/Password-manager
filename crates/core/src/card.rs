//! Payment cards: the fields a Card item keeps and the checks on them.
//!
//! Card details are stored as custom fields with fixed names — the same names the importers
//! produce and the exporters write — so a card survives import and export unchanged. The PIN is
//! the item's `password` and the name on the card its `username`. The PIN is never generated:
//! the bank issues it.

use crate::{CustomField, ItemData};

pub const NUMBER: &str = "Number";
pub const EXPIRY: &str = "Expiry";
pub const SECURITY_CODE: &str = "Security code";
pub const BRAND: &str = "Brand";

/// Field names managed by the card editor (not shown among the item's other fields).
pub const RESERVED: [&str; 4] = [NUMBER, EXPIRY, SECURITY_CODE, BRAND];

/// Stored (by position) in the hints of a locked card: new networks go before `Unknown`'s
/// place only with a format change, otherwise at the end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Brand {
    Visa,
    Mastercard,
    Amex,
    Elo,
    Hipercard,
    Discover,
    Diners,
    Jcb,
    Maestro,
    #[default]
    Unknown,
}

impl Brand {
    pub fn name(self) -> &'static str {
        match self {
            Brand::Visa => "Visa",
            Brand::Mastercard => "Mastercard",
            Brand::Amex => "American Express",
            Brand::Elo => "Elo",
            Brand::Hipercard => "Hipercard",
            Brand::Discover => "Discover",
            Brand::Diners => "Diners Club",
            Brand::Jcb => "JCB",
            Brand::Maestro => "Maestro",
            Brand::Unknown => "",
        }
    }
}

/// Only the digits of a typed or pasted card number (spaces, dashes and dots dropped).
pub fn digits(text: &str) -> String {
    text.chars().filter(char::is_ascii_digit).collect()
}

fn prefix(digits: &str, len: usize) -> Option<u32> {
    digits.get(..len)?.parse().ok()
}

fn in_ranges(value: Option<u32>, ranges: &[(u32, u32)]) -> bool {
    value.is_some_and(|v| ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&v)))
}

/// The card network, from the number's first digits (IIN ranges). Elo and Hipercard are
/// checked first because some of their ranges sit inside Visa's and Mastercard's.
pub fn detect_brand(digits: &str) -> Brand {
    const ELO: &[(u32, u32)] = &[
        (401_178, 401_179),
        (431_274, 431_274),
        (438_935, 438_935),
        (451_416, 451_416),
        (457_393, 457_393),
        (457_631, 457_632),
        (504_175, 504_175),
        (506_699, 506_778),
        (509_000, 509_999),
        (627_780, 627_780),
        (636_297, 636_297),
        (636_368, 636_368),
        (650_031, 650_033),
        (650_035, 650_051),
        (650_405, 650_439),
        (650_485, 650_538),
        (650_541, 650_598),
        (650_700, 650_718),
        (650_720, 650_727),
        (650_901, 650_978),
        (651_652, 651_679),
        (655_000, 655_019),
        (655_021, 655_058),
    ];
    let six = prefix(digits, 6);
    if in_ranges(six, ELO) {
        return Brand::Elo;
    }
    if six == Some(606_282) || prefix(digits, 4) == Some(3841) {
        return Brand::Hipercard;
    }
    let two = prefix(digits, 2);
    let four = prefix(digits, 4);
    if digits.starts_with('4') {
        Brand::Visa
    } else if in_ranges(two, &[(51, 55)]) || in_ranges(four, &[(2221, 2720)]) {
        Brand::Mastercard
    } else if matches!(two, Some(34 | 37)) {
        Brand::Amex
    } else if four == Some(6011) || two == Some(65) || in_ranges(prefix(digits, 3), &[(644, 649)]) {
        Brand::Discover
    } else if matches!(two, Some(36 | 38)) || in_ranges(prefix(digits, 3), &[(300, 305)]) {
        Brand::Diners
    } else if in_ranges(four, &[(3528, 3589)]) {
        Brand::Jcb
    } else if matches!(two, Some(50 | 56..=69)) {
        Brand::Maestro
    } else {
        Brand::Unknown
    }
}

/// Luhn checksum, which every card number carries: catches a mistyped or swapped digit.
pub fn luhn_valid(digits: &str) -> bool {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let sum: u32 = digits
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let d = u32::from(b - b'0');
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// "4111111111111111" → "4111 1111 1111 1111"; American Express as 4-6-5.
pub fn group(digits: &str) -> String {
    let sizes: &[usize] = if detect_brand(digits) == Brand::Amex && digits.len() == 15 {
        &[4, 6, 5]
    } else {
        &[4, 4, 4, 4, 4]
    };
    let mut out = String::with_capacity(digits.len() + 5);
    let mut rest = digits;
    for &size in sizes {
        if rest.is_empty() {
            break;
        }
        let (head, tail) = rest.split_at(size.min(rest.len()));
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(head);
        rest = tail;
    }
    if !rest.is_empty() {
        out.push(' ');
        out.push_str(rest);
    }
    out
}

/// "Visa •••• 4242" (or just "•••• 4242" for an unknown brand).
pub fn masked(digits: &str) -> String {
    let last4 = &digits[digits.len().saturating_sub(4)..];
    match detect_brand(digits).name() {
        "" => format!("•••• {last4}"),
        brand => format!("{brand} •••• {last4}"),
    }
}

/// Month and four-digit year from "MM/YY", "MM/YYYY", "MM-YY", "MM YY" or "MMYY".
pub fn parse_expiry(text: &str) -> Option<(u32, u32)> {
    let text = text.trim();
    let (month, year) = match text.split_once(['/', '-', ' ', '.']) {
        Some((m, y)) => (m.trim(), y.trim()),
        // Four bytes that are not four ASCII characters (`a€`) have no split after the second.
        None if text.len() == 4 && text.is_ascii() => text.split_at(2),
        None => return None,
    };
    let month: u32 = month.parse().ok()?;
    let year: u32 = match year.len() {
        2 => 2000 + year.parse::<u32>().ok()?,
        4 => year.parse().ok()?,
        _ => return None,
    };
    ((1..=12).contains(&month) && (2000..=2099).contains(&year)).then_some((month, year))
}

/// "MM/YY" for display and storage.
pub fn format_expiry((month, year): (u32, u32)) -> String {
    format!("{month:02}/{:02}", year % 100)
}

/// A card is valid through the last day of its expiry month.
pub fn is_expired((month, year): (u32, u32), (now_month, now_year): (u32, u32)) -> bool {
    (year, month) < (now_year, now_month)
}

/// What is wrong with a card being saved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardProblem {
    /// Not 12–19 digits, or the checksum fails (a typo).
    Number,
    /// Not a month and year.
    Expiry,
    /// Not 3–4 digits.
    SecurityCode,
    /// Not 4–12 digits.
    Pin,
}

/// The card's details as typed in the editor. Empty means "not stored".
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CardDetails {
    pub number: String,
    pub expiry: String,
    pub security_code: String,
}

/// Never prints the number or the security code (AGENTS.md §4.1, rule 2).
impl std::fmt::Debug for CardDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardDetails")
            .field("number", &masked(&digits(&self.number)))
            .field("expiry", &self.expiry)
            .field("security_code", &"<redacted>")
            .finish()
    }
}

impl CardDetails {
    /// Reads the details from a Card item's fields.
    pub fn from_item(item: &ItemData) -> Self {
        let get = |name: &str| {
            item.custom_fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(name))
                .map(|f| f.value.clone())
                .unwrap_or_default()
        };
        Self {
            number: digits(&get(NUMBER)),
            expiry: get(EXPIRY),
            security_code: get(SECURITY_CODE),
        }
    }

    /// Checks the details and the PIN; empty values are allowed (a card can be partial).
    pub fn validate(&self, pin: &str) -> Result<(), CardProblem> {
        let number = digits(&self.number);
        if !self.number.trim().is_empty()
            && (!(12..=19).contains(&number.len()) || !luhn_valid(&number))
        {
            return Err(CardProblem::Number);
        }
        if !self.expiry.trim().is_empty() && parse_expiry(&self.expiry).is_none() {
            return Err(CardProblem::Expiry);
        }
        let code = self.security_code.trim();
        if !code.is_empty()
            && (!(code.len() == 3 || code.len() == 4) || !code.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(CardProblem::SecurityCode);
        }
        if !pin.is_empty()
            && (!(4..=12).contains(&pin.len()) || !pin.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(CardProblem::Pin);
        }
        Ok(())
    }

    /// Writes the details into the item's fields (normalized: digits only, expiry as MM/YY,
    /// brand detected), replacing earlier values and removing empty ones.
    pub fn apply(&self, item: &mut ItemData) {
        let number = digits(&self.number);
        let expiry = parse_expiry(&self.expiry)
            .map(format_expiry)
            .unwrap_or_default();
        let brand = if number.is_empty() {
            String::new()
        } else {
            detect_brand(&number).name().to_owned()
        };
        let values = [
            (NUMBER, number, true),
            (EXPIRY, expiry, false),
            (SECURITY_CODE, self.security_code.trim().to_owned(), true),
            (BRAND, brand, false),
        ];
        // Keep the fields that aren't card details, in their order; then the details.
        item.custom_fields.retain(|f| {
            !RESERVED
                .iter()
                .any(|name| f.name.eq_ignore_ascii_case(name))
        });
        let others = std::mem::take(&mut item.custom_fields);
        for (name, value, sensitive) in values {
            if !value.is_empty() {
                item.custom_fields.push(CustomField {
                    name: name.to_owned(),
                    value,
                    sensitive,
                });
            }
        }
        item.custom_fields.extend(others);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ItemKind;

    #[test]
    fn brands() {
        assert_eq!(detect_brand("4111111111111111"), Brand::Visa);
        assert_eq!(detect_brand("5555555555554444"), Brand::Mastercard);
        assert_eq!(detect_brand("2223003122003222"), Brand::Mastercard);
        assert_eq!(detect_brand("378282246310005"), Brand::Amex);
        assert_eq!(detect_brand("6362970000457013"), Brand::Elo);
        assert_eq!(detect_brand("5067000000000000"), Brand::Elo);
        assert_eq!(detect_brand("6062825624254001"), Brand::Hipercard);
        assert_eq!(detect_brand("6011111111111117"), Brand::Discover);
        assert_eq!(detect_brand("3566002020360505"), Brand::Jcb);
        assert_eq!(detect_brand("9"), Brand::Unknown);
    }

    #[test]
    fn luhn_and_grouping() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
        assert!(!luhn_valid(""));
        assert_eq!(group("4111111111111111"), "4111 1111 1111 1111");
        assert_eq!(group("378282246310005"), "3782 822463 10005");
        assert_eq!(masked("4111111111111111"), "Visa •••• 1111");
        assert_eq!(digits(" 4111-1111 1111.1111 "), "4111111111111111");
    }

    #[test]
    fn expiry() {
        assert_eq!(parse_expiry("08/29"), Some((8, 2029)));
        assert_eq!(parse_expiry("8/2029"), Some((8, 2029)));
        assert_eq!(parse_expiry("0829"), Some((8, 2029)));
        assert_eq!(parse_expiry("13/29"), None);
        assert_eq!(parse_expiry("soon"), None);
        // Four bytes but not four characters: refused, never a panic.
        assert_eq!(parse_expiry("a€"), None);
        assert_eq!(parse_expiry("é€"), None);
        assert_eq!(format_expiry((8, 2029)), "08/29");
        assert!(is_expired((10, 2026), (11, 2026)));
        assert!(
            !is_expired((11, 2026), (11, 2026)),
            "valid through its month"
        );
    }

    #[test]
    fn validation_and_storage() {
        let card = CardDetails {
            number: "4111 1111 1111 1111".into(),
            expiry: "8/2029".into(),
            security_code: "123".into(),
        };
        assert_eq!(card.validate("1234"), Ok(()));
        assert_eq!(card.validate("12"), Err(CardProblem::Pin));
        assert_eq!(card.validate("12ab"), Err(CardProblem::Pin));
        let typo = CardDetails {
            number: "4111 1111 1111 1112".into(),
            ..card.clone()
        };
        assert_eq!(typo.validate(""), Err(CardProblem::Number));
        let bad_code = CardDetails {
            security_code: "12".into(),
            ..card.clone()
        };
        assert_eq!(bad_code.validate(""), Err(CardProblem::SecurityCode));
        assert_eq!(
            CardDetails::default().validate(""),
            Ok(()),
            "a partial card is fine"
        );

        let mut item = ItemData::new(ItemKind::Card, "Visa");
        item.custom_fields.push(CustomField {
            name: "Bank phone".into(),
            value: "0800".into(),
            sensitive: false,
        });
        card.apply(&mut item);
        let names: Vec<&str> = item.custom_fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            ["Number", "Expiry", "Security code", "Brand", "Bank phone"]
        );
        assert_eq!(item.custom_fields[0].value, "4111111111111111");
        assert_eq!(item.custom_fields[1].value, "08/29");
        assert!(item.custom_fields[0].sensitive && item.custom_fields[2].sensitive);
        assert_eq!(CardDetails::from_item(&item).number, "4111111111111111");

        // Clearing a detail removes its field.
        let cleared = CardDetails {
            security_code: String::new(),
            ..card
        };
        cleared.apply(&mut item);
        assert!(!item.custom_fields.iter().any(|f| f.name == SECURITY_CODE));
    }
}
