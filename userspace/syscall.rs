//! Safe socket wrappers for the kernel's nonblocking INT 0x80 ABI.

use core::arch::asm;

use crate::abi;

/// Raw calls may read or write through user pointers. Callers must provide
/// valid buffers with suitable lifetimes and obey Rust's aliasing rules.
pub unsafe fn raw(number: u64, first: u64, second: u64, third: u64) -> i64 {
    let result: i64;
    // SAFETY: the kernel restores all registers except RAX. Memory effects are
    // deliberately unrestricted because RECV writes through a user pointer.
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
    // SAFETY: this private helper is only called with validated buffers below
    // or with syscalls that do not access user memory.
    unsafe { raw(number, first, second, third) }
}

pub fn poll() {
    assert_eq!(call(abi::SYS_POLL, 0, 0, 0), 0);
}

pub fn now_millis() -> i64 {
    call(abi::SYS_NOW, 0, 0, 0)
}

pub fn log(message: &str) {
    for chunk in message.as_bytes().chunks(abi::MAX_LOG) {
        let _ = call(abi::SYS_LOG, chunk.as_ptr() as u64, chunk.len() as u64, 0);
    }
}

pub fn exit(code: u64) -> ! {
    call(abi::SYS_EXIT, code, 0, 0);
    // EXIT never returns; trap if the kernel violates that contract.
    // SAFETY: UD2 deliberately terminates this process.
    unsafe { asm!("ud2", options(noreturn)) }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed,
    Listen,
    SynReceived,
    Established,
    CloseWait,
    Closing,
    TimeWait,
}

pub struct Socket {
    descriptor: u64,
}

impl Socket {
    pub const fn new(descriptor: usize) -> Self {
        Self {
            descriptor: descriptor as u64,
        }
    }

    fn snapshot(&self) -> u64 {
        let result = call(abi::SYS_STATE, self.descriptor, 0, 0);
        assert!(result >= 0, "invalid socket descriptor");
        result as u64
    }

    pub fn state(&self) -> State {
        match self.snapshot() & abi::STATE_MASK {
            abi::CLOSED => State::Closed,
            abi::LISTEN => State::Listen,
            abi::SYN_RECEIVED => State::SynReceived,
            abi::ESTABLISHED => State::Established,
            abi::CLOSE_WAIT => State::CloseWait,
            abi::CLOSING => State::Closing,
            abi::TIME_WAIT => State::TimeWait,
            _ => panic!("unknown socket state"),
        }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self.state(), State::Closed | State::TimeWait)
    }

    pub fn is_listening(&self) -> bool {
        self.state() == State::Listen
    }

    pub fn can_recv(&self) -> bool {
        self.snapshot() & abi::CAN_RECV != 0
    }

    pub fn can_send(&self) -> bool {
        self.snapshot() & abi::CAN_SEND != 0
    }

    pub fn send_queue(&self) -> usize {
        (self.snapshot() >> abi::SEND_QUEUE_SHIFT) as usize
    }

    pub fn recv_slice(&mut self, bytes: &mut [u8]) -> Result<usize, i64> {
        count(call(
            abi::SYS_RECV,
            self.descriptor,
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
        ))
    }

    pub fn send_slice(&mut self, bytes: &[u8]) -> Result<usize, i64> {
        count(call(
            abi::SYS_SEND,
            self.descriptor,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        ))
    }

    pub fn listen(&mut self, port: u16) -> Result<(), i64> {
        count(call(abi::SYS_LISTEN, self.descriptor, port as u64, 0)).map(|_| ())
    }

    pub fn close(&mut self) {
        assert_eq!(call(abi::SYS_CLOSE, self.descriptor, 0, 0), 0);
    }

    pub fn abort(&mut self) {
        assert_eq!(call(abi::SYS_ABORT, self.descriptor, 0, 0), 0);
    }
}

fn count(result: i64) -> Result<usize, i64> {
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}
