//! Crockford Base32 (https://www.crockford.com/base32.html) for human-readable keys.
//!
//! No padding characters; the final group is zero-padded on the right, and decoding rejects
//! non-zero padding bits so every key has exactly one canonical text form.

use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of Base32 characters needed for `bytes` bytes.
pub(crate) const fn encoded_len(bytes: usize) -> usize {
    (bytes * 8).div_ceil(5)
}

/// Appends the encoding of `bytes` to `out`. Reserve capacity beforehand to avoid reallocation.
pub(crate) fn encode_into(bytes: &[u8], out: &mut String) {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &byte in bytes {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    acc.zeroize();
}

/// Appends a single character for a 5-bit value.
pub(crate) fn push_symbol(value: u8, out: &mut String) {
    out.push(char::from(ALPHABET[usize::from(value & 31)]));
}

/// Decodes one character, accepting lowercase and Crockford's aliases (O→0, I/L→1).
pub(crate) fn decode_symbol(c: u8) -> Option<u8> {
    match c.to_ascii_uppercase() {
        b'O' => Some(0),
        b'I' | b'L' => Some(1),
        upper => ALPHABET.iter().position(|&a| a == upper).map(|p| p as u8),
    }
}

/// Decodes exactly `out_len` bytes from `text` (no separators allowed here).
pub(crate) fn decode(text: &[u8], out_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    if text.len() != encoded_len(out_len) {
        return Err(Error::InvalidKeyFormat);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(out_len));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in text {
        let value = decode_symbol(c).ok_or(Error::InvalidKeyFormat)?;
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    let padding_is_zero = acc == 0;
    acc.zeroize();
    if !padding_is_zero || out.len() != out_len {
        return Err(Error::InvalidKeyFormat);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(bytes: &[u8]) -> String {
        let mut s = String::new();
        encode_into(bytes, &mut s);
        s
    }

    #[test]
    fn known_values() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(&[0x00]), "00");
        assert_eq!(encode(&[0xFF]), "ZW");
        assert_eq!(encode(&[0xFF; 5]), "ZZZZZZZZ");
        assert_eq!(encode(b"foobar"), "CSQPYRK1E8");
    }

    #[test]
    fn round_trip_all_lengths() {
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = encode(&bytes);
            assert_eq!(text.len(), encoded_len(len));
            assert_eq!(decode(text.as_bytes(), len).unwrap().as_slice(), &bytes[..]);
        }
    }

    #[test]
    fn aliases_and_lowercase() {
        assert_eq!(decode(b"csqpyrk1e8", 6).unwrap().as_slice(), b"foobar");
        assert_eq!(decode(b"CSQPYRKIE8", 6).unwrap().as_slice(), b"foobar");
        assert_eq!(decode(b"CSQPYRKLE8", 6).unwrap().as_slice(), b"foobar");
        assert_eq!(decode(b"OO", 1).unwrap().as_slice(), &[0x00]);
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(decode(b"U0", 1).is_err(), "U is not in the alphabet");
        assert!(decode(b"0", 1).is_err(), "wrong length");
        assert!(decode(b"ZZ", 1).is_err(), "non-zero padding bits");
    }
}
