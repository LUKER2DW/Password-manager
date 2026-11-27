//! Fixed-capacity, page-locked, zeroizing buffer for secrets typed by the user.
//!
//! - Never reallocates, so no stale copies are left on the heap.
//! - Every removed byte is overwritten with zeros (backspace, clear, drop).
//! - It lives in a [`SecretSlot`]: on Windows, in the one area of memory the process locks in
//!   RAM (`VirtualLock`, never written to the pagefile; KeePass CVE-2023-32784 is the
//!   cautionary tale) and keeps out of crash reports.
//!
//! The UI only learns how many characters were typed.

use std::fmt;

use zeroize::Zeroize;

use crate::secure_memory::{SLOT_BYTES, SecretSlot};

/// Maximum secret length in UTF-8 bytes.
pub const MAX_SECRET_BYTES: usize = SLOT_BYTES;

pub struct SecretBuffer {
    bytes: SecretSlot,
    len: usize,
    chars: usize,
}

impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuffer({} chars, <redacted>)", self.chars)
    }
}

impl Default for SecretBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBuffer {
    pub fn new() -> Self {
        Self {
            bytes: SecretSlot::new(),
            len: 0,
            chars: 0,
        }
    }

    /// Whether the buffer is in memory locked in RAM (see [`SecretSlot::is_locked`]).
    pub fn is_locked(&self) -> bool {
        self.bytes.is_locked()
    }

    /// Whether `c` can be part of a secret: control characters and private-use code points
    /// (what UI toolkits use for special keys, and what a phone's hidden input holds instead
    /// of the secret) never are.
    pub fn takes(c: char) -> bool {
        !(c.is_control() || ('\u{E000}'..='\u{F8FF}').contains(&c) || c >= '\u{F0000}')
    }

    /// Appends the characters it [takes](Self::takes) and skips the others. Returns `false`
    /// if the buffer is full.
    pub fn push_str(&mut self, text: &str) -> bool {
        for c in text.chars() {
            if !Self::takes(c) {
                continue;
            }
            let mut encoded = [0u8; 4];
            let width = c.encode_utf8(&mut encoded).len();
            if self.len + width > MAX_SECRET_BYTES {
                encoded.zeroize();
                return false;
            }
            self.bytes[self.len..self.len + width].copy_from_slice(&encoded[..width]);
            encoded.zeroize();
            self.len += width;
            self.chars += 1;
        }
        true
    }

    /// Removes the last character and wipes its bytes.
    pub fn backspace(&mut self) {
        if self.len == 0 {
            return;
        }
        let mut start = self.len - 1;
        while start > 0 && (self.bytes[start] & 0b1100_0000) == 0b1000_0000 {
            start -= 1;
        }
        self.bytes[start..self.len].zeroize();
        self.len = start;
        self.chars -= 1;
    }

    /// Where character `index` starts, in bytes (the end for an index past it).
    pub fn byte_offset(&self, index: usize) -> usize {
        self.as_str()
            .char_indices()
            .nth(index)
            .map_or(self.len, |(at, _)| at)
    }

    /// Inserts the characters it [takes](Self::takes) before character `index` (at the end
    /// past it), moving the rest along inside the buffer. Returns how many went in; it stops
    /// at the first that doesn't fit.
    pub fn insert_str(&mut self, index: usize, text: &str) -> usize {
        let mut at = self.byte_offset(index);
        let mut added = 0;
        for c in text.chars() {
            if !Self::takes(c) {
                continue;
            }
            let mut encoded = [0u8; 4];
            let width = c.encode_utf8(&mut encoded).len();
            if self.len + width > MAX_SECRET_BYTES {
                encoded.zeroize();
                break;
            }
            self.bytes.copy_within(at..self.len, at + width);
            self.bytes[at..at + width].copy_from_slice(&encoded[..width]);
            encoded.zeroize();
            self.len += width;
            self.chars += 1;
            at += width;
            added += 1;
        }
        added
    }

    /// Removes `count` characters from character `index` on, and wipes the bytes left free
    /// at the end.
    pub fn remove(&mut self, index: usize, count: usize) {
        if count == 0 || index >= self.chars {
            return;
        }
        let count = count.min(self.chars - index);
        let start = self.byte_offset(index);
        let end = self.byte_offset(index + count);
        self.bytes.copy_within(end..self.len, start);
        let len = self.len - (end - start);
        self.bytes[len..self.len].zeroize();
        self.len = len;
        self.chars -= count;
    }

    pub fn clear(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
        self.chars = 0;
    }

    pub fn char_count(&self) -> usize {
        self.chars
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The secret as text. Valid UTF-8 by construction.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len])
            .expect("only whole UTF-8 characters are stored")
    }

    /// Constant-time-ish comparison of two buffers (length leak is acceptable here).
    pub fn matches(&self, other: &SecretBuffer) -> bool {
        self.len == other.len
            && self.bytes[..self.len]
                .iter()
                .zip(&other.bytes[..other.len])
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }

    /// Replaces the contents with `text` (e.g. a generated passphrase the user accepted).
    pub fn set(&mut self, text: &str) -> bool {
        self.clear();
        self.push_str(text)
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        // The slot wipes itself too; this keeps the counts right until then.
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multibyte_backspace_wipes_bytes() {
        let mut buffer = SecretBuffer::new();
        assert!(buffer.push_str("aé€😀"));
        assert_eq!(buffer.char_count(), 4);
        buffer.backspace();
        assert_eq!(buffer.as_str(), "aé€");
        assert!(
            buffer.bytes["aé€".len().."aé€😀".len()]
                .iter()
                .all(|&b| b == 0)
        );
        for _ in 0..5 {
            buffer.backspace();
        }
        assert!(buffer.is_empty());
    }

    #[test]
    fn ignores_special_keys() {
        let mut buffer = SecretBuffer::new();
        buffer.push_str("\u{F702}\u{0010}\t\nx\u{1}\u{80}\u{E000}\u{F0000}\u{10FFFD}");
        assert_eq!(buffer.as_str(), "x");
        assert!(SecretBuffer::takes('é') && SecretBuffer::takes('€') && SecretBuffer::takes('😀'));
    }

    #[test]
    fn refuses_overflow_and_compares() {
        let mut a = SecretBuffer::new();
        assert!(a.push_str(&"a".repeat(MAX_SECRET_BYTES)));
        assert!(!a.push_str("b"));
        let mut b = SecretBuffer::new();
        b.set(&"a".repeat(MAX_SECRET_BYTES));
        assert!(a.matches(&b));
        b.backspace();
        assert!(!a.matches(&b));
    }

    #[test]
    fn inserts_and_removes_in_the_middle() {
        let mut buffer = SecretBuffer::new();
        buffer.push_str("acé");
        assert_eq!(buffer.insert_str(1, "b"), 1);
        assert_eq!(buffer.as_str(), "abcé");
        assert_eq!(buffer.insert_str(0, "€\u{1}"), 1);
        assert_eq!(buffer.as_str(), "€abcé");
        assert_eq!(buffer.insert_str(99, "😀"), 1);
        assert_eq!(buffer.as_str(), "€abcé😀");
        assert_eq!(buffer.char_count(), 6);
        assert_eq!(buffer.byte_offset(1), "€".len());
        buffer.remove(0, 2);
        assert_eq!(buffer.as_str(), "bcé😀");
        buffer.remove(2, 9);
        assert_eq!(buffer.as_str(), "bc");
        assert_eq!(buffer.char_count(), 2);
        // Nothing of what was removed stays behind the end.
        assert!(buffer.bytes[2..].iter().all(|&b| b == 0));
        buffer.remove(5, 1);
        assert_eq!(buffer.as_str(), "bc");
        // A full buffer takes nothing more, in the middle either.
        let mut full = SecretBuffer::new();
        full.push_str(&"a".repeat(MAX_SECRET_BYTES));
        assert_eq!(full.insert_str(3, "b"), 0);
        assert_eq!(full.as_str(), "a".repeat(MAX_SECRET_BYTES));
    }

    /// On Windows a buffer is in the locked area; two buffers never share bytes.
    #[test]
    fn buffers_are_locked_and_apart() {
        let _turn = crate::secure_memory::AREA_TURN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut a = SecretBuffer::new();
        let mut b = SecretBuffer::new();
        assert_eq!(a.is_locked(), cfg!(windows));
        a.push_str("first");
        b.push_str("second");
        drop(a);
        assert_eq!(
            b.as_str(),
            "second",
            "dropping one leaves the other as it was"
        );
        assert_eq!(b.is_locked(), cfg!(windows), "and still locked");
    }

    #[test]
    fn clear_and_debug() {
        let mut buffer = SecretBuffer::new();
        buffer.push_str("hunter2");
        assert_eq!(format!("{buffer:?}"), "SecretBuffer(7 chars, <redacted>)");
        buffer.clear();
        assert!(buffer.bytes.iter().all(|&b| b == 0));
    }
}
