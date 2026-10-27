//! The network service's small frame-queue and RPC syscall interface.

use core::arch::asm;

use crate::abi;

/// Issue a raw syscall for ABI probes.
///
/// # Safety
/// For calls that can succeed, pointer arguments must respect buffer lifetimes
/// and exclusive access. Invalid pointers are only used to test kernel rejection.
pub unsafe fn raw(number: u64, first: u64, second: u64, third: u64) -> i64 {
    let result: i64;
    // SAFETY: each caller supplies live, correctly borrowed buffers where
    // needed. The kernel preserves every general register except RAX.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
        );
    }
    result
}

fn call(number: u64, first: u64, second: u64, third: u64) -> i64 {
    // SAFETY: safe wrappers below supply valid, correctly borrowed buffers.
    unsafe { raw(number, first, second, third) }
}

pub fn poll() {
    assert_eq!(call(abi::SYS_POLL, 0, 0, 0), 0);
}

pub fn now_millis() -> i64 {
    call(abi::SYS_NOW, 0, 0, 0)
}

pub fn mac() -> Result<[u8; 6], i64> {
    let result = call(abi::SYS_MAC, 0, 0, 0);
    if result < 0 {
        return Err(result);
    }
    let bytes = (result as u64).to_le_bytes();
    Ok([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
}

pub fn receive_frame(bytes: &mut [u8]) -> Result<usize, i64> {
    let result = call(
        abi::SYS_FRAME_RECV,
        bytes.as_mut_ptr() as u64,
        bytes.len() as u64,
        0,
    );
    if result < 0 {
        Err(result)
    } else if result as usize > bytes.len() {
        Err(abi::EINVAL)
    } else {
        Ok(result as usize)
    }
}

pub fn send_frame(bytes: &[u8]) -> Result<(), i64> {
    status(call(
        abi::SYS_FRAME_SEND,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        0,
    ))
}

pub fn request(request: &mut abi::Request) -> Result<(), i64> {
    status(call(
        abi::SYS_NET_REQUEST,
        core::ptr::from_mut(request) as u64,
        size_of::<abi::Request>() as u64,
        0,
    ))
}

pub fn reply(reply: &abi::Reply) -> Result<(), i64> {
    status(call(
        abi::SYS_NET_REPLY,
        core::ptr::from_ref(reply) as u64,
        size_of::<abi::Reply>() as u64,
        0,
    ))
}

pub fn log(message: &str) {
    for chunk in message.as_bytes().chunks(abi::MAX_LOG) {
        let _ = call(abi::SYS_LOG, chunk.as_ptr() as u64, chunk.len() as u64, 0);
    }
}

pub fn exit(code: u64) -> ! {
    call(abi::SYS_EXIT, code, 0, 0);
    // SAFETY: EXIT must not return; terminate if that contract is violated.
    unsafe { asm!("ud2", options(noreturn)) }
}

fn status(result: i64) -> Result<(), i64> {
    if result < 0 { Err(result) } else { Ok(()) }
}
