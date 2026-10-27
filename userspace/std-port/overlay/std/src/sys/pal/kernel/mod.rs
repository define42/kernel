//! Platform support for the kernel's isolated, single-threaded ring-3 processes.
#![forbid(unsafe_op_in_unsafe_fn)]

use crate::io;

pub const SYS_POLL: usize = 0;
pub const SYS_NOW: usize = 1;
pub const SYS_RANDOM_BYTES: usize = 21;
pub const SYS_WRITE: usize = 22;

// The kernel saves every register other than the RAX return value. The interrupt
// also acts as a compiler memory barrier; do not add `nomem` or `readonly`.
#[inline]
pub unsafe fn syscall(number: usize, first: usize, second: usize, third: usize) -> isize {
    let result: isize;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
            options(nostack),
        );
    }
    result
}

unsafe extern "C" {
    fn __kernel_std_exit(code: i32) -> !;
}

// Startup initializes the heap before entering the compiler-generated main.
// SAFETY: called once by std::rt before the application main function.
pub unsafe fn init(_argc: isize, _argv: *const *const u8, _sigpipe: u8) {}

// TLS uses upstream's no_threads storage. Its values are reclaimed with the
// whole process address space at exit/restart; TLS destructors are not run.
// SAFETY: called once by std::rt during process cleanup.
pub unsafe fn cleanup() {}

pub fn unsupported<T>() -> io::Result<T> {
    Err(unsupported_err())
}

pub fn unsupported_err() -> io::Error {
    io::Error::UNSUPPORTED_PLATFORM
}

pub fn exit(code: i32) -> ! {
    unsafe { __kernel_std_exit(code) }
}

pub fn abort_internal() -> ! {
    exit(1)
}

pub fn monotonic_millis() -> u64 {
    let value = unsafe { syscall(SYS_NOW, 0, 0, 0) };
    // Monotonic milliseconds have a signed 64-bit lifetime (>292 million years).
    assert!(value >= 0, "kernel monotonic clock failed");
    value as u64
}
