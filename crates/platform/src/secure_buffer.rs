//! Fixed-capacity, page-locked, zeroizing buffer for secrets typed by the user.
//!
//! - Never reallocates, so no stale copies are left on the heap.
//! - Every removed byte is overwritten with zeros (backspace, clear, drop).
//! - On Windows the pages are locked in RAM (`VirtualLock`) so they are not written to the
//!   pagefile (KeePass CVE-2023-32784 is the cautionary tale).
//!
//! The UI only learns how many characters were typed.

use std::fmt;

use zeroize::Zeroize;

/// Maximum secret length in UTF-8 bytes.
pub const MAX_SECRET_BYTES: usize = 1024;

pub struct SecretBuffer {
    bytes: Box<[u8; MAX_SECRET_BYTES]>,
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
        let buffer = Self {
            bytes: Box::new([0u8; MAX_SECRET_BYTES]),
            len: 0,
            chars: 0,
        };
        lock_pages(buffer.bytes.as_ptr(), MAX_SECRET_BYTES);
        buffer
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
        self.clear();
        unlock_pages(self.bytes.as_ptr(), MAX_SECRET_BYTES);
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn lock_pages(ptr: *const u8, len: usize) {
    use windows_sys::Win32::System::Memory::VirtualLock;
    // SAFETY: `ptr..ptr+len` is a live heap allocation owned by the buffer for its whole life.
    // Failure (e.g. working-set quota) only loses the pagefile protection, so it is ignored.
    unsafe {
        VirtualLock(ptr.cast(), len);
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn unlock_pages(ptr: *const u8, len: usize) {
    use windows_sys::Win32::System::Memory::VirtualUnlock;
    // SAFETY: same allocation that was locked in `lock_pages`, still alive during `drop`.
    unsafe {
        VirtualUnlock(ptr.cast(), len);
    }
}

#[cfg(not(windows))]
fn lock_pages(_ptr: *const u8, _len: usize) {}

#[cfg(not(windows))]
fn unlock_pages(_ptr: *const u8, _len: usize) {}

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
    fn clear_and_debug() {
        let mut buffer = SecretBuffer::new();
        buffer.push_str("hunter2");
        assert_eq!(format!("{buffer:?}"), "SecretBuffer(7 chars, <redacted>)");
        buffer.clear();
        assert!(buffer.bytes.iter().all(|&b| b == 0));
    }
}
