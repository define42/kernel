//! A bounded heap owned entirely by the current userspace process.
//!
//! Every free block begins with an intrusive header. Allocations and free
//! blocks are rounded to the header size, so splitting never leaves an
//! unusable fragment. The address-sorted free list coalesces adjacent blocks.
//! Metadata is untrusted userspace memory; the kernel never follows it.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::mem::size_of;
use core::ptr::{self, null_mut};
use core::sync::atomic::{AtomicBool, Ordering};

#[repr(C)]
struct FreeBlock {
    size: usize,
    next: *mut FreeBlock,
}

// A power of two on the supported x86_64 target, and sufficient for the
// header's alignment. All block boundaries and sizes are multiples of this.
const GRANULE: usize = size_of::<FreeBlock>();

struct Arena {
    first: *mut FreeBlock,
    initialized: bool,
}

/// An allocator over one caller-supplied, exclusive memory region.
///
/// It never requests more memory from the kernel. Exhaustion returns null.
/// The lock serializes all metadata operations, including initialization;
/// allocation must not be reentered from a signal/interrupt handler.
pub struct Allocator {
    locked: AtomicBool,
    arena: UnsafeCell<Arena>,
}

// SAFETY: only a holder of `locked` accesses `arena` or free-block headers.
// Live allocations are disjoint, and their ownership belongs to the caller.
unsafe impl Sync for Allocator {}

struct Locked<'a> {
    locked: &'a AtomicBool,
    arena: &'a mut Arena,
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        self.locked.store(false, Ordering::Release);
    }
}

impl Allocator {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            arena: UnsafeCell::new(Arena {
                first: null_mut(),
                initialized: false,
            }),
        }
    }

    /// Initialize once, trimming the region to complete allocation granules.
    /// Returns false for an unusable region or an already initialized arena,
    /// leaving the existing state untouched.
    ///
    /// # Safety
    /// `base..base + length` must be one writable allocation, exclusive to
    /// this allocator, and remain valid while the allocator or any of its
    /// allocations may be used. Its contents may be overwritten immediately.
    /// The region must not overlap this `Allocator` or another live object.
    pub unsafe fn initialize(&self, base: *mut u8, length: usize) -> bool {
        let guard = self.lock();
        if guard.arena.initialized || base.is_null() || length > isize::MAX as usize {
            return false;
        }
        let address = base as usize;
        let Some(start) = align_up(address, GRANULE) else {
            return false;
        };
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        let end = end & !(GRANULE - 1);
        let Some(size) = end.checked_sub(start).filter(|size| *size >= GRANULE) else {
            return false;
        };
        // SAFETY: the aligned subregion lies within the caller's exclusive
        // allocation and has enough space and alignment for a header.
        let first = unsafe { base.add(start - address).cast::<FreeBlock>() };
        unsafe {
            first.write(FreeBlock {
                size,
                next: null_mut(),
            });
        }
        guard.arena.first = first;
        guard.arena.initialized = true;
        true
    }

    fn lock(&self) -> Locked<'_> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
        Locked {
            locked: &self.locked,
            // SAFETY: acquisition above gives exclusive access until the
            // guard's release store. No references escape the guard.
            arena: unsafe { &mut *self.arena.get() },
        }
    }
}

impl Default for Allocator {
    fn default() -> Self {
        Self::new()
    }
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

fn allocation_size(layout: Layout) -> Option<usize> {
    if layout.size() == 0 {
        return None;
    }
    align_up(layout.size(), GRANULE).filter(|size| *size <= isize::MAX as usize)
}

impl Arena {
    // SAFETY invariant for all methods: the allocator lock is held; the list
    // contains only disjoint free blocks within the initialized arena, sorted
    // by increasing address. Each size and boundary is GRANULE-aligned and
    // each block has room for its header. No live allocation is in the list.
    unsafe fn allocate(&mut self, layout: Layout) -> *mut u8 {
        let Some(size) = allocation_size(layout) else {
            return null_mut();
        };
        let alignment = layout.align().max(GRANULE);
        let mut previous: *mut FreeBlock = null_mut();
        let mut block = self.first;
        while !block.is_null() {
            // SAFETY: block is a current free-list node under the lock.
            let (block_size, next) = unsafe { ((*block).size, (*block).next) };
            let Some(address) = align_up(block as usize, alignment) else {
                return null_mut();
            };
            let prefix = address - block as usize;
            if let Some(available) = block_size.checked_sub(prefix)
                && available >= size
            {
                let suffix = available - size;
                // SAFETY: prefix + size <= block_size. All boundaries remain
                // GRANULE-aligned, so a nonempty suffix holds a full header.
                let allocation = unsafe { block.cast::<u8>().add(prefix) };
                let replacement = if suffix == 0 {
                    next
                } else {
                    let tail = unsafe { allocation.add(size).cast::<FreeBlock>() };
                    unsafe { tail.write(FreeBlock { size: suffix, next }) };
                    tail
                };
                unsafe {
                    if prefix != 0 {
                        (*block).size = prefix;
                        (*block).next = replacement;
                    } else if previous.is_null() {
                        self.first = replacement;
                    } else {
                        (*previous).next = replacement;
                    }
                }
                return allocation;
            }
            previous = block;
            block = next;
        }
        null_mut()
    }

    /// Return an entire normalized allocation, or its aligned trailing part.
    unsafe fn release(&mut self, allocation: *mut u8, size: usize) {
        let address = allocation as usize;
        let mut previous: *mut FreeBlock = null_mut();
        let mut next = self.first;
        while !next.is_null() && (next as usize) < address {
            previous = next;
            // SAFETY: next is a current free-list node under the lock.
            next = unsafe { (*next).next };
        }
        let block = allocation.cast::<FreeBlock>();
        // SAFETY: the caller returns disjoint, aligned live allocation bytes
        // of at least GRANULE length. Rejoining them cannot exceed the arena.
        unsafe {
            block.write(FreeBlock { size, next });
            if !next.is_null() && address + size == next as usize {
                (*block).size += (*next).size;
                (*block).next = (*next).next;
            }
            if previous.is_null() {
                self.first = block;
            } else if previous as usize + (*previous).size == address {
                (*previous).size += (*block).size;
                (*previous).next = (*block).next;
            } else {
                (*previous).next = block;
            }
        }
    }

    unsafe fn resize(&mut self, allocation: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return null_mut();
        };
        let (Some(old_size), Some(size)) = (allocation_size(layout), allocation_size(new_layout))
        else {
            return null_mut();
        };
        if size <= old_size {
            if size < old_size {
                // SAFETY: this trailing subregion is no longer live and is
                // GRANULE-aligned, with room for at least one free header.
                unsafe { self.release(allocation.add(size), old_size - size) };
            }
            return allocation;
        }

        // Try to consume a neighboring free block before moving the allocation.
        let end = allocation as usize + old_size;
        let extra = size - old_size;
        let mut previous: *mut FreeBlock = null_mut();
        let mut block = self.first;
        while !block.is_null() && (block as usize) < end {
            previous = block;
            // SAFETY: block is a current free-list node under the lock.
            block = unsafe { (*block).next };
        }
        if !block.is_null() && block as usize == end {
            // SAFETY: block is a current free-list node under the lock.
            let (block_size, next) = unsafe { ((*block).size, (*block).next) };
            if block_size >= extra {
                let replacement = if block_size == extra {
                    next
                } else {
                    // SAFETY: extra is a multiple of GRANULE within block;
                    // the remaining nonempty region fits an aligned header.
                    let tail = unsafe { block.cast::<u8>().add(extra).cast::<FreeBlock>() };
                    unsafe {
                        tail.write(FreeBlock {
                            size: block_size - extra,
                            next,
                        });
                    }
                    tail
                };
                if previous.is_null() {
                    self.first = replacement;
                } else {
                    // SAFETY: previous remains a live free-list node.
                    unsafe { (*previous).next = replacement };
                }
                return allocation;
            }
        }

        // SAFETY: the old allocation stays live until its replacement exists.
        let replacement = unsafe { self.allocate(new_layout) };
        if !replacement.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(allocation, replacement, layout.size().min(new_size));
                self.release(allocation, old_size);
            }
        }
        replacement
    }
}

// SAFETY: each successful allocation is properly aligned, disjoint, and valid
// for the requested size. The caller must obey GlobalAlloc's layout, lifetime,
// and unique-ownership contracts when freeing or resizing. Methods use no
// allocation, formatting, assertions, or other operations that can unwind.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the guard exclusively owns free-list metadata.
        unsafe { self.lock().arena.allocate(layout) }
    }

    unsafe fn dealloc(&self, allocation: *mut u8, layout: Layout) {
        if let Some(size) = allocation_size(layout) {
            // SAFETY: GlobalAlloc's caller returns a live allocation with its
            // original layout. The lock serializes insertion and coalescing.
            unsafe { self.lock().arena.release(allocation, size) };
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc's caller provides a valid nonzero layout.
        let allocation = unsafe { self.alloc(layout) };
        if !allocation.is_null() {
            // SAFETY: only this caller owns the new allocation's payload.
            unsafe { allocation.write_bytes(0, layout.size()) };
        }
        allocation
    }

    unsafe fn realloc(&self, allocation: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: GlobalAlloc's caller supplies a live allocation and its
        // original layout. The guard serializes all metadata changes.
        unsafe { self.lock().arena.resize(allocation, layout, new_size) }
    }
}

#[cfg(target_os = "none")]
#[global_allocator]
pub static ALLOCATOR: Allocator = Allocator::new();

/// Initialize this process's private, kernel-mapped arena before using `alloc`.
///
/// # Safety
/// The kernel must have mapped the complete ABI heap range as private writable
/// memory. This function must run before any other code uses that memory.
#[cfg(target_os = "none")]
pub unsafe fn init() -> bool {
    // SAFETY: the process startup contract provides the exclusive mapping.
    unsafe {
        ALLOCATOR.initialize(
            crate::abi::USER_HEAP_BASE as *mut u8,
            crate::abi::USER_HEAP_SIZE,
        )
    }
}
