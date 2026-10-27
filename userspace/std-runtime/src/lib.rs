//! Startup and allocator ABI for the kernel's single-threaded std processes.
#![no_std]

#[path = "../../../abi.rs"]
mod abi;
#[path = "../../heap.rs"]
mod heap;

use core::alloc::{GlobalAlloc, Layout};
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

#[global_allocator]
static ALLOCATOR: heap::Allocator = heap::Allocator::new();

static STARTUP_MODE: AtomicU64 = AtomicU64::new(0);

/// The kernel's scalar startup argument; used by the isolated regression image.
pub fn startup_mode() -> u64 {
    STARTUP_MODE.load(Ordering::Relaxed)
}

/// Invoke the kernel ABI. Registers other than RAX are preserved by the kernel.
///
/// # Safety
/// Pointer arguments must satisfy the syscall's ownership and lifetime rules.
/// Negative tests may pass invalid addresses only when the kernel rejects them.
pub unsafe fn raw(number: u64, a: u64, b: u64, c: u64) -> i64 {
    let result: i64;
    unsafe {
        asm!("int 0x80", inlateout("rax") number => result,
            in("rdi") a, in("rsi") b, in("rdx") c);
    }
    result
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(mode: u64, _: u64, _: u64) -> ! {
    // SAFETY: the loader zeros private BSS/heap before each start. Nothing has
    // used std or allocated memory yet, and this process has one user thread.
    if !unsafe { ALLOCATOR.initialize(abi::USER_HEAP_BASE as *mut u8, abi::USER_HEAP_SIZE) } {
        __kernel_std_exit(1);
    }
    STARTUP_MODE.store(mode, Ordering::Relaxed);
    unsafe extern "C" {
        // rustc generates this wrapper around the ordinary Rust fn main; it
        // calls std's lang_start and performs normal runtime cleanup on return.
        fn main(argc: isize, argv: *const *const u8) -> isize;
    }
    // No process arguments exist in this ABI. std's backend exposes an empty
    // iterator and does not dereference argv. The wrapper returns an exit code.
    let code = unsafe { main(0, core::ptr::null()) };
    __kernel_std_exit(code as i32);
}

#[unsafe(no_mangle)]
pub extern "C" fn __kernel_std_exit(code: i32) -> ! {
    unsafe {
        raw(abi::SYS_EXIT, code as u64, 0, 0);
        asm!("ud2", options(noreturn));
    }
}

/// System allocator hooks use the same private arena as the global allocator.
///
/// # Safety
/// Allocation parameters must obey GlobalAlloc; returned storage is caller-owned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __kernel_std_alloc(size: usize, align: usize) -> *mut u8 {
    let Ok(layout) = Layout::from_size_align(size, align) else {
        return core::ptr::null_mut();
    };
    unsafe { ALLOCATOR.alloc(layout) }
}

/// # Safety
/// `pointer` must be live and owned, with its original nonzero size/alignment.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __kernel_std_dealloc(pointer: *mut u8, size: usize, align: usize) {
    if let Ok(layout) = Layout::from_size_align(size, align) {
        unsafe { ALLOCATOR.dealloc(pointer, layout) };
    }
}

/// # Safety
/// Allocation parameters must obey GlobalAlloc; returned storage is caller-owned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __kernel_std_alloc_zeroed(size: usize, align: usize) -> *mut u8 {
    let Ok(layout) = Layout::from_size_align(size, align) else {
        return core::ptr::null_mut();
    };
    unsafe { ALLOCATOR.alloc_zeroed(layout) }
}

/// # Safety
/// `pointer` and its old layout must be live and owned; new_size must be nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __kernel_std_realloc(
    pointer: *mut u8,
    size: usize,
    align: usize,
    new_size: usize,
) -> *mut u8 {
    let Ok(layout) = Layout::from_size_align(size, align) else {
        return core::ptr::null_mut();
    };
    unsafe { ALLOCATOR.realloc(pointer, layout, new_size) }
}
