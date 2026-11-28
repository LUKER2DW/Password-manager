//! The password of the emergency kit's saved PDF files (CRYPTO.md §3.10): four words derived
//! from the vault key, bound to the Secret Key and the kit, never stored. The app shows it on
//! the kit page whenever the vault is open; it is never printed on the kit itself.

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{SecretKey, generator};

const LABEL: &[u8] = b"vault-v0/kit-pdf/password";
/// What HKDF gives first: 32 two-byte draws, which give four words but about once in 2^112.
const FIRST_LEN: usize = 64;
/// HKDF-SHA-256's longest output, read on in that case (the first 64 bytes are its start).
const LONGEST_LEN: usize = 255 * 32;
/// Draws at or above this (8 × 7,776) are skipped, so every word is equally likely.
const DRAW_LIMIT: u16 = 62_208;

/// The password the emergency kit's saved PDF files open with: four words of the EFF large
/// list (about 51.7 bits), in small letters, separated by spaces. Wiped when dropped.
pub struct KitPdfPassword(Zeroizing<String>);

impl KitPdfPassword {
    /// How many words it has.
    pub const WORDS: usize = 4;

    /// As shown and typed: the words separated by single spaces.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KitPdfPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KitPdfPassword(<redacted>)")
    }
}

/// The password from `k_pdf` (`subkey("kit-pdf")`), the vault's Secret Key, its id and the
/// current kit's id (`None` when the vault has no recovery parts).
pub(crate) fn derive(
    k_pdf: &[u8; 32],
    secret_key: &SecretKey,
    vault_id: &[u8; 16],
    kit_id: Option<&[u8; 16]>,
) -> KitPdfPassword {
    let password = derive_inner(k_pdf, secret_key, vault_id, kit_id);
    // The hash's blocks below here held the Secret Key and the subkey.
    crate::memory::clear_stack();
    password
}

/// [`derive`]'s work, in a frame of its own below the one that clears the stack.
#[inline(never)]
fn derive_inner(
    k_pdf: &[u8; 32],
    secret_key: &SecretKey,
    vault_id: &[u8; 16],
    kit_id: Option<&[u8; 16]>,
) -> KitPdfPassword {
    let mut ikm = Zeroizing::new([0u8; 32 + 16]);
    ikm[..32].copy_from_slice(k_pdf);
    ikm[32..].copy_from_slice(secret_key.open().as_ref());
    let mut kit = [0u8; 17];
    let kit: &[u8] = match kit_id {
        Some(id) => {
            kit[0] = 0x01;
            kit[1..].copy_from_slice(id);
            &kit
        }
        None => &kit[..1],
    };
    let hkdf = Hkdf::<Sha256>::new(Some(vault_id), ikm.as_ref());
    let stream = |len: usize| {
        let mut out = Zeroizing::new(vec![0u8; len]);
        hkdf.expand_multi_info(&[LABEL, kit], &mut out)
            .expect("at most 255 blocks is a valid HKDF-SHA-256 output length");
        out
    };
    let indices = pick_words(&stream(FIRST_LEN))
        .or_else(|| pick_words(&stream(LONGEST_LEN)))
        .expect("four words out of 4,080 draws");
    let words = generator::eff_words();
    let mut text = Zeroizing::new(String::with_capacity(KitPdfPassword::WORDS * 10));
    for (n, index) in indices.iter().enumerate() {
        if n > 0 {
            text.push(' ');
        }
        text.push_str(words[*index]);
    }
    KitPdfPassword(text)
}

/// The first four word indices in `stream`, read as big-endian two-byte draws: a draw below
/// 62,208 gives the word at its value mod 7,776, a higher one is skipped.
fn pick_words(stream: &[u8]) -> Option<[usize; KitPdfPassword::WORDS]> {
    let mut picked = [0usize; KitPdfPassword::WORDS];
    let mut count = 0;
    for pair in stream.as_chunks::<2>().0 {
        let draw = u16::from_be_bytes(*pair);
        if draw >= DRAW_LIMIT {
            continue;
        }
        picked[count] = usize::from(draw) % generator::EFF_WORD_COUNT;
        count += 1;
        if count == picked.len() {
            return Some(picked);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::VaultKey;

    /// Known answers, computed apart (Python's `cryptography` HKDF and the same word list
    /// read from its file) from the vault key on: `subkey("kit-pdf")`, then the password.
    #[test]
    fn known_answers() {
        let vault_key = VaultKey::from_slice(&(0x00..0x20).collect::<Vec<u8>>()).unwrap();
        let vault_id: [u8; 16] = std::array::from_fn(|i| 0xA0 + i as u8);
        let secret_key = SecretKey::from_bytes(std::array::from_fn(|i| 0x10 + i as u8));
        let kit_id: [u8; 16] = std::array::from_fn(|i| 0xC0 + i as u8);
        let k_pdf = vault_key.subkey(b"kit-pdf", &vault_id);
        assert_eq!(
            derive(&k_pdf, &secret_key, &vault_id, Some(&kit_id)).as_str(),
            "cupped reverend native quaking"
        );
        assert_eq!(
            derive(&k_pdf, &secret_key, &vault_id, None).as_str(),
            "primary fretted stark fretful"
        );
    }

    /// Draws at or above 62,208 are skipped; the others give their value mod 7,776.
    #[test]
    fn uneven_draws_are_skipped() {
        let stream = [
            0xFF, 0xFF, // 65,535: skipped
            0xF3, 0x00, // 62,208: skipped
            0xF2, 0xFF, // 62,207 → 7,775
            0x00, 0x00, // 0
            0x1E, 0x60, // 7,776 → 0
            0x00, 0x05, // 5
            0x00, 0x09, // not needed
        ];
        assert_eq!(pick_words(&stream), Some([7_775, 0, 0, 5]));
        assert_eq!(pick_words(&stream[..10]), None, "only three words in it");
    }

    #[test]
    fn each_input_changes_it() {
        let vault_id = [7u8; 16];
        let secret_key = SecretKey::generate().unwrap();
        let k_pdf = [1u8; 32];
        let base = derive(&k_pdf, &secret_key, &vault_id, Some(&[2u8; 16]));
        let text = base.as_str();
        let words: Vec<&str> = text.split(' ').collect();
        assert_eq!(words.len(), 4);
        assert!(
            words
                .iter()
                .all(|word| generator::eff_words().contains(word))
        );
        assert!(text.len() <= 4 * 9 + 3, "far under the PDF's 127 bytes");
        let others = [
            derive(&[3u8; 32], &secret_key, &vault_id, Some(&[2u8; 16])),
            derive(
                &k_pdf,
                &SecretKey::generate().unwrap(),
                &vault_id,
                Some(&[2u8; 16]),
            ),
            derive(&k_pdf, &secret_key, &[8u8; 16], Some(&[2u8; 16])),
            derive(&k_pdf, &secret_key, &vault_id, Some(&[4u8; 16])),
            derive(&k_pdf, &secret_key, &vault_id, None),
        ];
        for other in &others {
            assert_ne!(other.as_str(), text);
        }
        assert_eq!(
            derive(&k_pdf, &secret_key, &vault_id, Some(&[2u8; 16])).as_str(),
            text,
            "the same kit gives the same password again"
        );
        assert_eq!(format!("{base:?}"), "KitPdfPassword(<redacted>)");
    }
}
