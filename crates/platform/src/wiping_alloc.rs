//! The apps' global allocator: the system's own, with every block wiped before it is freed.
//!
//! Without it a freed `String` or `Vec` stays in the heap as it was until something else is
//! written over it. Measured on Windows: the end of a freed secret is still there (the heap
//! reuses only its first bytes for its own bookkeeping), and so is each smaller copy a `Vec`
//! that grew was moved out of. `Zeroizing` covers the values known to be secret; this covers
//! the rest: a secret passing through serde, a Slint string, a dependency's buffer.
//!
//! A block that grows or shrinks is always moved (a new block, the contents copied, the old
//! one wiped and freed): the system's own `realloc` may move it and leave the old block as it
//! was.
//!
//! Only Rust's heap is covered: what the system or a C library allocates for itself (Skia's
//! buffers, the strings of UI Automation, a credential read from Windows) is theirs.
//!
//! Each program installs it once (the desktop app in its library, so its tests and the
//! screenshots run it too; the CLI; the Android app's library):
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOCATOR: vault_platform::wiping_alloc::WipingAllocator =
//!     vault_platform::wiping_alloc::WipingAllocator;
//! ```

use std::alloc::{GlobalAlloc, Layout, System};

/// The system allocator, wiping each block before it is freed (see the module's notes).
#[derive(Debug, Clone, Copy, Default)]
pub struct WipingAllocator;

/// Writes zeros over `len` bytes at `ptr`.
///
/// # Safety
/// `ptr..ptr + len` must be writable memory of one allocation.
#[allow(unsafe_code)]
unsafe fn write_zeros(ptr: *mut u8, len: usize) {
    // SAFETY: per the function's contract.
    unsafe {
        ptr.write_bytes(0, len);
    }
}

/// [`write_zeros`], called through a pointer read with a volatile load: the compiler can't
/// know what it calls, so it can't drop the writes as useless on memory about to be freed.
/// (A `memset` this way, many times faster than wiping byte by byte.)
static WIPE: unsafe fn(*mut u8, usize) = write_zeros;

// SAFETY: every block comes from `System` with the layout it is given back with; `dealloc`
// only writes inside the block before handing it back; `realloc` copies the smaller of the two
// sizes between two live blocks of the same alignment, then frees the old one through
// `dealloc`.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for WipingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is `System.alloc`'s.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is `System.alloc_zeroed`'s.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is a live block of `layout.size()` bytes (the caller's contract), so
        // it can be written over before it is handed back to `System`; `WIPE` is a static
        // that is always initialised.
        unsafe {
            let wipe = std::ptr::read_volatile(&raw const WIPE);
            wipe(ptr, layout.size());
            System.dealloc(ptr, layout);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller guarantees `new_size`, rounded up to `layout.align()`, doesn't
        // overflow `isize` and isn't zero, which is all `Layout` asks; both blocks are live
        // while the smaller size is copied.
        unsafe {
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let moved = self.alloc(new_layout);
            if !moved.is_null() {
                std::ptr::copy_nonoverlapping(ptr, moved, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
            moved
        }
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout};

    use super::WipingAllocator;

    /// A block keeps its contents as it grows and shrinks, at any alignment.
    #[test]
    fn moves_keep_the_contents() {
        for align in [1, 8, 64, 4096] {
            let layout = Layout::from_size_align(100, align).unwrap();
            // SAFETY: each block is used within its size and freed once with its own layout.
            #[allow(unsafe_code)]
            unsafe {
                let block = WipingAllocator.alloc(layout);
                assert!(!block.is_null());
                assert_eq!(block as usize % align, 0);
                for i in 0..100u8 {
                    block.add(usize::from(i)).write(i);
                }
                let grown = WipingAllocator.realloc(block, layout, 5000);
                assert!(!grown.is_null());
                assert_eq!(grown as usize % align, 0);
                for i in 0..100u8 {
                    assert_eq!(grown.add(usize::from(i)).read(), i);
                }
                let grown_layout = Layout::from_size_align(5000, align).unwrap();
                let shrunk = WipingAllocator.realloc(grown, grown_layout, 10);
                assert!(!shrunk.is_null());
                for i in 0..10u8 {
                    assert_eq!(shrunk.add(usize::from(i)).read(), i);
                }
                WipingAllocator.dealloc(shrunk, Layout::from_size_align(10, align).unwrap());

                let zeroed = WipingAllocator.alloc_zeroed(layout);
                assert!((0..100).all(|i| zeroed.add(i).read() == 0));
                WipingAllocator.dealloc(zeroed, layout);
            }
        }
    }
}
