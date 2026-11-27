//! The emergency kit's keys, recognised in what a page sends.
//!
//! The Secret Key and the recovery parts are typed into the app only: never into a website.
//! A page that asks for one is phishing for the second factor, the one thing that keeps a
//! stolen master password from opening a copied vault file. They are easy to recognise
//! without knowing any of them, by the shape `vault_core` prints them in: a prefix (`S0` for
//! the Secret Key, `A0`, `B0` and `C0` for the recovery parts, `R0` for the Recovery Key of
//! older kits), then Crockford Base32 characters in groups (four of seven, or nine of six for
//! `R0`), the last group ending in the key's checksum.
//!
//! The extension refuses them in every page with the same rule (`apps/extension/kit.js`,
//! before anything reaches the app); the app checks again what a page sends it, so a login
//! whose "password" is one of them is never saved, compared or offered.
//!
//! The rule is the printed shape, not the checksum: a key typed with one wrong character is
//! still almost all of the key. Lower case, Crockford's aliases (`O` for `0`, `I` and `L` for
//! `1`), spaces instead of dashes or no separators at all are the same key, as for
//! `vault_core::SecretKey::parse`. The prefix must stand apart (`XS0…` is no key), and so must
//! the end (a longer run of such characters is something else). The padding bits a printed key
//! always has as zero must be zero.

/// How many data characters follow each prefix: the key's bytes in Base32 (with the zero bits
/// that fill its last character) and two characters of checksum.
const SHAPES: [(&[u8; 2], usize, u32); 5] = [
    // 16 bytes: 26 characters, the last with 2 padding bits, and 2 of checksum.
    (b"S0", 28, 2),
    (b"A0", 28, 2),
    (b"B0", 28, 2),
    (b"C0", 28, 2),
    // 32 bytes: 52 characters, the last with 4 padding bits, and 2 of checksum.
    (b"R0", 54, 4),
];

/// At most this many separators (dashes, spaces) between two characters of a key.
const MAX_GAP: usize = 3;
/// Only the first this many bytes of a text are looked at: what a field holds.
const MAX_SCANNED: usize = 4096;

/// Whether `text` holds one of the emergency kit's keys in its printed shape.
pub fn holds_kit_key(text: &str) -> bool {
    let bytes = &text.as_bytes()[..text.len().min(MAX_SCANNED)];
    (0..bytes.len().saturating_sub(1)).any(|start| key_at(bytes, start))
}

/// Whether a key starts at `start`: a prefix that stands apart, then its characters.
fn key_at(bytes: &[u8], start: usize) -> bool {
    if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
        return false;
    }
    let prefix = [bytes[start].to_ascii_uppercase(), bytes[start + 1]];
    SHAPES
        .iter()
        .find(|(shape, ..)| **shape == prefix)
        .is_some_and(|&(_, count, padding)| data_fits(bytes, start + 2, count, padding))
}

/// Whether exactly `count` data characters follow `from` (separators between them allowed),
/// the last data character before the checksum has its `padding` low bits zero, and nothing
/// that could continue the key comes after.
fn data_fits(bytes: &[u8], from: usize, count: usize, padding: u32) -> bool {
    let mut at = from;
    let mut values = Vec::with_capacity(count);
    while values.len() < count {
        let gap_start = at;
        while at < bytes.len() && is_separator(bytes[at]) {
            at += 1;
        }
        if at - gap_start > MAX_GAP {
            return false;
        }
        match bytes.get(at).copied().and_then(symbol) {
            Some(value) => values.push(value),
            None => return false,
        }
        at += 1;
    }
    // Not followed by another character of a key, right after or after one dash.
    let next = bytes.get(at).copied();
    let after_dash = (next == Some(b'-'))
        .then(|| bytes.get(at + 1).copied())
        .flatten();
    if next.is_some_and(|b| b.is_ascii_alphanumeric())
        || after_dash.is_some_and(|b| b.is_ascii_alphanumeric())
    {
        return false;
    }
    // The last character of the key's bytes, before the two of checksum.
    let last = values[count - 3];
    last & ((1 << padding) - 1) == 0
}

fn is_separator(byte: u8) -> bool {
    byte == b'-' || byte.is_ascii_whitespace()
}

/// The value of one Crockford Base32 character, as `vault_core` reads it: lower case too, `O`
/// as `0`, `I` and `L` as `1`; `U` is not one.
fn symbol(byte: u8) -> Option<u8> {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    match byte.to_ascii_uppercase() {
        b'O' => Some(0),
        b'I' | b'L' => Some(1),
        upper => ALPHABET
            .iter()
            .position(|&a| a == upper)
            .and_then(|p| u8::try_from(p).ok()),
    }
}

#[cfg(test)]
mod tests {
    use vault_core::{PartLabel, RecoveryKey, RecoveryPart, RecoveryParts, SecretKey};

    use super::*;

    /// The shapes are the ones `vault_core` prints: its own constants, and keys it makes.
    #[test]
    fn the_shapes_are_vault_cores() {
        assert_eq!(RecoveryPart::GROUPS * RecoveryPart::GROUP_LEN, SHAPES[1].1);
        assert_eq!(RecoveryKey::GROUPS * RecoveryKey::GROUP_LEN, SHAPES[4].1);
        assert_eq!(RecoveryKey::PREFIX.as_bytes(), SHAPES[4].0);
        for label in PartLabel::ALL {
            assert!(
                SHAPES
                    .iter()
                    .any(|(prefix, ..)| *prefix == label.prefix().as_bytes())
            );
        }
    }

    /// Keys as the kit prints them, made for this test.
    fn printed() -> Vec<String> {
        let mut keys = vec![
            SecretKey::generate()
                .unwrap()
                .to_display_string()
                .to_string(),
            RecoveryKey::generate()
                .unwrap()
                .to_display_string()
                .to_string(),
        ];
        let parts = RecoveryParts::generate().unwrap();
        for label in PartLabel::ALL {
            keys.push(parts.part(label).to_display_string().to_string());
        }
        keys
    }

    #[test]
    fn every_printed_key_is_recognised_however_it_is_written() {
        for _ in 0..20 {
            for key in printed() {
                assert!(holds_kit_key(&key), "{key}");
                assert!(holds_kit_key(&key.to_lowercase()), "{key}");
                assert!(holds_kit_key(&key.replace('-', " ")), "{key}");
                assert!(holds_kit_key(&key.replace('-', "")), "{key}");
                assert!(holds_kit_key(&format!("My key: {key}, thanks")), "{key}");
                assert!(holds_kit_key(&format!("{key}\n")), "{key}");
                assert!(holds_kit_key(&format!("(\"{key}\")")), "{key}");
                // Crockford's aliases.
                assert!(
                    holds_kit_key(&key.replace('0', "O").replacen("O", "0", 1)),
                    "{key}"
                );
            }
        }
    }

    #[test]
    fn other_text_is_not_a_key() {
        let key = SecretKey::generate()
            .unwrap()
            .to_display_string()
            .to_string();
        let groups = &key[2..];
        for text in [
            String::new(),
            "S0".to_owned(),
            "hunter2".to_owned(),
            // Another prefix, a letter for the zero, or one glued to what is before.
            format!("D0{groups}"),
            format!("SO{groups}"),
            format!("XS0{groups}"),
            format!("1{key}"),
            // A character short, or one more after it.
            key[..key.len() - 1].to_owned(),
            format!("{key}A"),
            format!("{key}-A"),
            // `U` is not in the alphabet.
            format!("S0-UUUUUUU{}", &groups[8..]),
            // Too many separators between two characters.
            key.replacen('-', "----", 2),
            // Non-ASCII letters that upper-case to a prefix or a key character.
            format!("\u{17f}0{groups}"),
            format!(
                "S0-\u{131}\u{131}\u{131}\u{131}\u{131}\u{131}\u{131}{}",
                &groups[8..]
            ),
            // A token with a key's characters inside.
            format!("tok_9f8s{}", key.replace('-', "")),
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_owned(),
        ] {
            assert!(!holds_kit_key(&text), "{text}");
        }
        // The bits that fill a key's last character are zero in every printed key.
        let mut padded = key.replace('-', "").into_bytes();
        let last = 2 + 25;
        padded[last] = b'Z';
        assert!(!holds_kit_key(std::str::from_utf8(&padded).unwrap()));
    }
}
