#[path = "../../../userspace/heap.rs"]
mod heap;

use core::alloc::{GlobalAlloc, Layout};
use heap::Allocator;

struct TestArena {
    allocator: Allocator,
    // Keep only a raw pointer: a shared reference to a Box-backed byte slice
    // would freeze the memory that the allocator must mutate through pointers.
    storage: *mut u8,
    size: usize,
}

impl TestArena {
    fn new(size: usize) -> Self {
        assert_eq!(size % 16, 0);
        let layout = Layout::from_size_align(size, 16).unwrap();
        // SAFETY: the nonzero layout is valid; Drop frees this allocation only
        // after the test has finished using the allocator and its blocks.
        let storage = unsafe { std::alloc::alloc(layout) };
        assert!(!storage.is_null());
        let allocator = Allocator::new();
        assert!(unsafe { allocator.initialize(storage, size) });
        Self {
            allocator,
            storage,
            size,
        }
    }

    fn size(&self) -> usize {
        self.size
    }

    fn check_recovered(&self) {
        let layout = Layout::from_size_align(self.size(), 16).unwrap();
        // SAFETY: a valid nonzero layout, with the matching deallocation below.
        let allocation = unsafe { self.allocator.alloc(layout) };
        assert_eq!(allocation, self.storage);
        unsafe { allocation.write_bytes(0x6b, self.size()) };
        let small = Layout::from_size_align(1, 1).unwrap();
        assert!(unsafe { self.allocator.alloc(small) }.is_null());
        unsafe { self.allocator.dealloc(allocation, layout) };
    }
}

impl Drop for TestArena {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(self.size, 16).unwrap();
        // SAFETY: this exactly matches the backing allocation in new().
        unsafe { std::alloc::dealloc(self.storage, layout) };
    }
}

struct Block {
    pointer: *mut u8,
    layout: Layout,
    byte: u8,
}

impl Block {
    fn allocate(arena: &Allocator, size: usize, align: usize, byte: u8) -> Option<Self> {
        let layout = Layout::from_size_align(size, align).unwrap();
        let pointer = unsafe { arena.alloc(layout) };
        if pointer.is_null() {
            return None;
        }
        assert_eq!(pointer as usize % align, 0);
        unsafe { pointer.write_bytes(byte, size) };
        Some(Self {
            pointer,
            layout,
            byte,
        })
    }

    fn verify(&self) {
        assert_eq!(self.pointer as usize % self.layout.align(), 0);
        let bytes = unsafe { core::slice::from_raw_parts(self.pointer, self.layout.size()) };
        assert!(bytes.iter().all(|&byte| byte == self.byte));
    }

    fn free(self, arena: &Allocator) {
        self.verify();
        unsafe { arena.dealloc(self.pointer, self.layout) };
    }

    fn resize(&mut self, arena: &Allocator, size: usize) -> bool {
        self.verify();
        let replacement = unsafe { arena.realloc(self.pointer, self.layout, size) };
        if replacement.is_null() {
            self.verify();
            return false;
        }
        let preserved =
            unsafe { core::slice::from_raw_parts(replacement, self.layout.size().min(size)) };
        assert!(preserved.iter().all(|&byte| byte == self.byte));
        assert_eq!(replacement as usize % self.layout.align(), 0);
        self.pointer = replacement;
        self.layout = Layout::from_size_align(size, self.layout.align()).unwrap();
        unsafe { self.pointer.write_bytes(self.byte, size) };
        true
    }
}

#[test]
fn uninitialized_allocator_returns_null_and_reinitialization_keeps_live_data() {
    let arena = Allocator::new();
    let layout = Layout::from_size_align(16, 16).unwrap();
    assert!(unsafe { arena.alloc(layout) }.is_null());
    assert!(unsafe { arena.alloc_zeroed(layout) }.is_null());

    let mut storage = [0u128; 32];
    assert!(!unsafe { arena.initialize(storage.as_mut_ptr().cast(), 0) });
    assert!(!unsafe { arena.initialize(storage.as_mut_ptr().cast(), 15) });
    assert!(unsafe { arena.initialize(storage.as_mut_ptr().cast(), 512) });
    let block = Block::allocate(&arena, 128, 16, 0xab).unwrap();
    assert!(!unsafe { arena.initialize(storage.as_mut_ptr().cast(), 512) });
    block.free(&arena);
}

#[test]
fn initialization_trims_unaligned_ends_without_touching_outside_bytes() {
    let mut storage = [u128::MAX; 32];
    let base = storage.as_mut_ptr().cast::<u8>();
    let arena = Allocator::new();
    assert!(unsafe { arena.initialize(base.add(1), 510) });
    // [1, 511) trims to [16, 496), leaving the outside granules untouched.
    let layout = Layout::from_size_align(480, 16).unwrap();
    let allocation = unsafe { arena.alloc(layout) };
    assert_eq!(allocation, unsafe { base.add(16) });
    unsafe { allocation.write_bytes(0x36, 480) };
    unsafe { arena.dealloc(allocation, layout) };
    let bytes = unsafe { core::slice::from_raw_parts(base, 512) };
    assert!(bytes[..16].iter().all(|&byte| byte == 0xff));
    assert!(bytes[496..].iter().all(|&byte| byte == 0xff));
}

#[test]
fn sizes_and_large_alignments_are_disjoint_and_fully_recoverable() {
    // Keeping eleven 64 KiB-aligned allocations live deliberately requires
    // a larger arena than the kernel reserves for an individual process.
    let arena = TestArena::new(1024 * 1024);
    let mut blocks: Vec<Block> = Vec::new();
    for align in [1, 2, 4, 8, 16, 32, 64, 256, 4096, 65536] {
        for size in [1, 2, 7, 15, 16, 17, 31, 32, 63, 255, 4097] {
            let block = Block::allocate(&arena.allocator, size, align, blocks.len() as u8).unwrap();
            for other in &blocks {
                let start = block.pointer as usize;
                let end = start + block.layout.size();
                let other_start = other.pointer as usize;
                let other_end = other_start + other.layout.size();
                assert!(end <= other_start || other_end <= start);
                other.verify();
            }
            blocks.push(block);
        }
    }
    while !blocks.is_empty() {
        let index = blocks.len() / 2;
        blocks.remove(index).free(&arena.allocator);
    }
    arena.check_recovered();
}

#[test]
fn exhaustion_returns_null_and_freeing_one_block_makes_it_reusable() {
    let arena = TestArena::new(8192);
    let mut blocks = Vec::new();
    while let Some(block) = Block::allocate(&arena.allocator, 1, 1, blocks.len() as u8) {
        blocks.push(block);
    }
    assert_eq!(blocks.len(), 8192 / 16);
    let freed = blocks.remove(123);
    let address = freed.pointer;
    freed.free(&arena.allocator);
    let replacement = Block::allocate(&arena.allocator, 16, 16, 0xee).unwrap();
    assert_eq!(replacement.pointer, address);
    assert!(Block::allocate(&arena.allocator, 1, 1, 0xff).is_none());
    replacement.free(&arena.allocator);
    for block in blocks.into_iter().rev() {
        block.free(&arena.allocator);
    }
    arena.check_recovered();
}

#[test]
fn frees_coalesce_with_both_neighbors() {
    let arena = TestArena::new(512);
    let first = Block::allocate(&arena.allocator, 128, 16, 1).unwrap();
    let middle = Block::allocate(&arena.allocator, 128, 16, 2).unwrap();
    let third = Block::allocate(&arena.allocator, 128, 16, 3).unwrap();
    let last = Block::allocate(&arena.allocator, 128, 16, 4).unwrap();
    let start = first.pointer;
    first.free(&arena.allocator);
    third.free(&arena.allocator);
    assert!(Block::allocate(&arena.allocator, 256, 16, 5).is_none());
    middle.free(&arena.allocator);
    let joined = Block::allocate(&arena.allocator, 384, 16, 6).unwrap();
    assert_eq!(joined.pointer, start);
    last.free(&arena.allocator);
    joined.free(&arena.allocator);
    arena.check_recovered();
}

#[test]
fn impossible_sizes_and_alignment_preserve_existing_allocations() {
    let arena = TestArena::new(4096);
    let block = Block::allocate(&arena.allocator, 128, 16, 0xc7).unwrap();
    for layout in [
        Layout::from_size_align(isize::MAX as usize, 1).unwrap(),
        Layout::from_size_align(1, 1usize << 62).unwrap(),
        Layout::from_size_align(8192, 16).unwrap(),
    ] {
        assert!(unsafe { arena.allocator.alloc(layout) }.is_null());
        assert!(unsafe { arena.allocator.alloc_zeroed(layout) }.is_null());
        block.verify();
    }
    assert!(
        unsafe {
            arena
                .allocator
                .realloc(block.pointer, block.layout, usize::MAX)
        }
        .is_null()
    );
    block.free(&arena.allocator);
    arena.check_recovered();
}

#[test]
fn zeroed_allocation_clears_recycled_payload() {
    let arena = TestArena::new(4096);
    Block::allocate(&arena.allocator, 4096, 16, 0xf3)
        .unwrap()
        .free(&arena.allocator);
    let layout = Layout::from_size_align(4096, 16).unwrap();
    let allocation = unsafe { arena.allocator.alloc_zeroed(layout) };
    assert!(!allocation.is_null());
    let bytes = unsafe { core::slice::from_raw_parts(allocation, layout.size()) };
    assert!(bytes.iter().all(|&byte| byte == 0));
    unsafe { arena.allocator.dealloc(allocation, layout) };
    arena.check_recovered();
}

#[test]
fn realloc_shrinks_and_grows_in_place_and_releases_the_tail() {
    let arena = TestArena::new(512);
    let mut block = Block::allocate(&arena.allocator, 512, 16, 0x23).unwrap();
    let original = block.pointer;
    assert!(block.resize(&arena.allocator, 255));
    assert_eq!(block.pointer, original);
    let tail = Block::allocate(&arena.allocator, 256, 16, 0x99).unwrap();
    assert_eq!(tail.pointer, unsafe { original.add(256) });
    tail.free(&arena.allocator);
    assert!(block.resize(&arena.allocator, 400));
    assert_eq!(block.pointer, original);
    assert!(block.resize(&arena.allocator, 512));
    assert_eq!(block.pointer, original);
    block.free(&arena.allocator);
    arena.check_recovered();
}

#[test]
fn realloc_moves_when_blocked_and_preserves_alignment_and_contents() {
    let arena = TestArena::new(8192);
    let mut block = Block::allocate(&arena.allocator, 65, 256, 0x51).unwrap();
    let blocker = Block::allocate(&arena.allocator, 1024, 1, 0x7b).unwrap();
    let original = block.pointer;
    assert!(block.resize(&arena.allocator, 2048));
    assert_ne!(block.pointer, original);
    blocker.verify();
    block.free(&arena.allocator);
    blocker.free(&arena.allocator);
    arena.check_recovered();
}

#[test]
fn failed_realloc_keeps_old_allocation_valid_and_unchanged() {
    let arena = TestArena::new(512);
    let mut block = Block::allocate(&arena.allocator, 128, 16, 0x25).unwrap();
    let blocker = Block::allocate(&arena.allocator, 384, 16, 0x8b).unwrap();
    let original = block.pointer;
    assert!(!block.resize(&arena.allocator, 256));
    assert_eq!(block.pointer, original);
    blocker.verify();
    blocker.free(&arena.allocator);
    assert!(block.resize(&arena.allocator, 512));
    assert_eq!(block.pointer, original);
    block.free(&arena.allocator);
    arena.check_recovered();
}

#[test]
fn independent_arenas_do_not_share_allocation_state_or_contents() {
    let first = TestArena::new(1024);
    let second = TestArena::new(1024);
    let a = Block::allocate(&first.allocator, 1024, 16, 0x41).unwrap();
    assert!(Block::allocate(&first.allocator, 1, 1, 0).is_none());
    let b = Block::allocate(&second.allocator, 1024, 16, 0x72).unwrap();
    assert_ne!(a.pointer, b.pointer);
    a.verify();
    b.verify();
    a.free(&first.allocator);
    b.verify();
    first.check_recovered();
    b.free(&second.allocator);
    second.check_recovered();
}

#[test]
fn deterministic_fragmentation_and_realloc_stress_recovers_every_byte() {
    let arena = TestArena::new(64 * 1024);
    let mut slots: Vec<Option<Block>> = (0..128).map(|_| None).collect();
    let mut state = 0x1d82_e0bc_94fa_3157u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as usize
    };
    let mut allocations = 0;
    let mut moved = 0;
    let mut failed = 0;
    for iteration in 0..30_000 {
        let slot = next() % slots.len();
        match slots[slot].take() {
            None => {
                let size = next() % 2048 + 1;
                let alignment = 1 << (next() % 13);
                slots[slot] = Block::allocate(&arena.allocator, size, alignment, slot as u8);
                allocations += usize::from(slots[slot].is_some());
                failed += usize::from(slots[slot].is_none());
            }
            Some(mut block) if next() % 3 != 0 => {
                let before = block.pointer;
                let size = next() % 4096 + 1;
                if block.resize(&arena.allocator, size) {
                    moved += usize::from(before != block.pointer);
                } else {
                    failed += 1;
                }
                slots[slot] = Some(block);
            }
            Some(block) => block.free(&arena.allocator),
        }
        if iteration % 113 == 0 {
            for (index, block) in slots.iter().enumerate() {
                let Some(block) = block else { continue };
                block.verify();
                for other in slots[index + 1..].iter().flatten() {
                    let start = block.pointer as usize;
                    let end = start + block.layout.size();
                    let other_start = other.pointer as usize;
                    let other_end = other_start + other.layout.size();
                    assert!(end <= other_start || other_end <= start);
                }
            }
        }
    }
    assert!(allocations > 1000);
    assert!(moved > 100);
    assert!(failed > 1000);
    for block in slots.into_iter().flatten() {
        block.free(&arena.allocator);
    }
    arena.check_recovered();
}

#[test]
fn concurrent_allocator_operations_keep_blocks_disjoint() {
    let arena = TestArena::new(64 * 1024);
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let allocator = &arena.allocator;
            scope.spawn(move || {
                for iteration in 0..2000 {
                    let size = 1 + (iteration * 31 + worker * 79) % 2048;
                    let mut block = Block::allocate(allocator, size, 64, worker as u8).unwrap();
                    std::thread::yield_now();
                    assert!(block.resize(allocator, 2048));
                    block.free(allocator);
                }
            });
        }
    });
    arena.check_recovered();
}
