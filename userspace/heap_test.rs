//! Allocation and exhaustion checks executed by the real ring-3 program.
use crate::{abi, heap, syscall};
use alloc::{
    alloc::{alloc, alloc_zeroed, dealloc, realloc},
    boxed::Box,
    string::String,
    vec::Vec,
};
use core::{
    alloc::{GlobalAlloc, Layout},
    hint::black_box,
    ptr,
};

fn check_address(pointer: *const u8, length: usize, alignment: usize) {
    let address = pointer as usize;
    assert!(address >= abi::USER_HEAP_BASE as usize);
    assert!(address.checked_add(length).unwrap() <= abi::USER_HEAP_END as usize);
    assert_eq!(address % alignment, 0);
}

pub fn run() -> ! {
    // The previous probe dirties this location. A fresh process restart must
    // clear it; initialization only writes the first free-list node.
    assert_eq!(
        unsafe { ptr::read_volatile((abi::USER_HEAP_END - 1) as *const u8) },
        0
    );
    {
        let number = Box::new(0x1234_5678_9abc_def0u64);
        check_address(
            (&*number as *const u64).cast(),
            size_of::<u64>(),
            align_of::<u64>(),
        );
        assert_eq!(*number, 0x1234_5678_9abc_def0);
        let mut values = Vec::<u64>::new();
        for i in 0..4096 {
            values.push(i ^ 0xa5a5);
        }
        check_address(
            values.as_ptr().cast(),
            values.len() * size_of::<u64>(),
            align_of::<u64>(),
        );
        assert!(
            values
                .iter()
                .enumerate()
                .all(|(i, &value)| value == i as u64 ^ 0xa5a5)
        );
        values.truncate(127);
        values.shrink_to_fit();
        assert_eq!(values.len(), 127);
        assert!(values.try_reserve_exact(abi::USER_HEAP_SIZE).is_err());
        assert_eq!(values[126], 126 ^ 0xa5a5);
        let mut message = String::from("Heap-backed ");
        message.push_str("Box/Vec/String and syscall buffer passed.\n");
        check_address(message.as_ptr(), message.len(), 1);
        // A successful copy from this heap must return the entire log length.
        assert_eq!(
            unsafe {
                syscall::raw(
                    abi::SYS_LOG,
                    message.as_ptr() as u64,
                    message.len() as u64,
                    0,
                )
            },
            message.len() as i64
        );
    }
    // SAFETY: all layouts are valid and nonzero. Pointers are checked before
    // use, remain live through each access, and are freed with matching layouts.
    unsafe {
        let aligned = Layout::from_size_align(6000, 4096).unwrap();
        let pointer = alloc_zeroed(aligned);
        assert!(!pointer.is_null());
        check_address(pointer, aligned.size(), aligned.align());
        assert!(
            core::slice::from_raw_parts(pointer, aligned.size())
                .iter()
                .all(|&b| b == 0)
        );
        ptr::write_bytes(pointer, 0x5a, aligned.size());
        let grown = realloc(pointer, aligned, 16000);
        assert!(!grown.is_null());
        check_address(grown, 16000, aligned.align());
        assert!(
            core::slice::from_raw_parts(grown, aligned.size())
                .iter()
                .all(|&b| b == 0x5a)
        );
        let grown_layout = Layout::from_size_align(16000, 4096).unwrap();
        let failed = realloc(grown, grown_layout, abi::USER_HEAP_SIZE + 1);
        assert!(failed.is_null());
        assert!(
            core::slice::from_raw_parts(grown, aligned.size())
                .iter()
                .all(|&b| b == 0x5a)
        );
        dealloc(grown, grown_layout);
        let whole_layout = Layout::from_size_align(abi::USER_HEAP_SIZE, 16).unwrap();
        let whole = alloc(whole_layout);
        assert_eq!(
            whole as u64,
            abi::USER_HEAP_BASE,
            "freed blocks did not coalesce"
        );
        ptr::write_bytes(whole, 0xa5, abi::USER_HEAP_SIZE);
        let one = Layout::from_size_align(1, 1).unwrap();
        // Call the allocator directly: Rust may elide an alloc::alloc call
        // whose only observation is a null check and assume it succeeded.
        assert!(
            heap::ALLOCATOR.alloc(one).is_null(),
            "exhausted heap accepted allocation"
        );
        let mut fallible = Vec::<u8>::new();
        assert!(fallible.try_reserve_exact(1).is_err());
        assert!(fallible.is_empty());
        dealloc(whole, whole_layout);
        let reused = alloc(whole_layout);
        assert_eq!(reused, whole);
        dealloc(reused, whole_layout);
        for guard in [abi::USER_HEAP_BASE - 1, abi::USER_HEAP_END] {
            assert_eq!(syscall::raw(abi::SYS_LOG, guard, 1, 0), abi::EFAULT);
            assert_eq!(syscall::raw(abi::SYS_RECV, 0, guard, 1), abi::EFAULT);
        }
        assert_eq!(
            syscall::raw(abi::SYS_LOG, abi::USER_HEAP_END - 1, 2, 0),
            abi::EFAULT
        );
        assert_eq!(
            syscall::raw(abi::SYS_RECV, 0, abi::USER_HEAP_END - 1, 2),
            abi::EFAULT
        );
    }
    syscall::log("Userspace heap allocation, reuse, exhaustion, and guard checks passed.\n");
    syscall::exit(0);
}

pub fn infallible_oom() -> ! {
    syscall::log("Userspace heap intentional allocation failure\n");
    // Keep the request observable: the stable alloc crate's default OOM path
    // must reach this process's panic handler and exit, never stop the kernel.
    let buffer = Vec::<u8>::with_capacity(black_box(abi::USER_HEAP_SIZE + 1));
    black_box(buffer);
    syscall::exit(255);
}
