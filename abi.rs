//! The fixed memory layout and small, nonblocking ABI shared by kernel and userspace.
#![allow(dead_code)]

/// Each process owns a private, zeroed RW/NX heap at the same virtual address.
/// The kernel leaves one unmapped guard page immediately before and after it.
pub const USER_HEAP_BASE: u64 = 0x4010_0000;
pub const USER_HEAP_SIZE: usize = 512 * 1024;
pub const USER_HEAP_END: u64 = USER_HEAP_BASE + USER_HEAP_SIZE as u64;

pub const SYS_POLL: u64 = 0;
pub const SYS_NOW: u64 = 1;
pub const SYS_STATE: u64 = 2;
pub const SYS_RECV: u64 = 3;
pub const SYS_SEND: u64 = 4;
pub const SYS_CLOSE: u64 = 5;
pub const SYS_ABORT: u64 = 6;
pub const SYS_LISTEN: u64 = 7;
pub const SYS_LOG: u64 = 8;
pub const SYS_EXIT: u64 = 9;

pub const SOCKET_COUNT: usize = 4;
pub const SOCKET_BUFFER_SIZE: usize = 4096;
pub const HTTP_PORT: u16 = 80;
pub const MAX_LOG: usize = 512;

pub const CLOSED: u64 = 0;
pub const LISTEN: u64 = 1;
pub const SYN_RECEIVED: u64 = 2;
pub const ESTABLISHED: u64 = 3;
pub const CLOSE_WAIT: u64 = 4;
pub const CLOSING: u64 = 5;
pub const TIME_WAIT: u64 = 6;
pub const STATE_MASK: u64 = 0xff;
pub const CAN_RECV: u64 = 1 << 8;
pub const CAN_SEND: u64 = 1 << 9;
pub const SEND_QUEUE_SHIFT: u32 = 16;

pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const ENOSYS: i64 = -38;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const EINVAL: i64 = -22;
pub const ENOTCONN: i64 = -107;

// Service capabilities are assigned by the kernel, never selected by a caller.
pub const SYS_FRAME_RECV: u64 = 10;
pub const SYS_FRAME_SEND: u64 = 11;
pub const SYS_NET_REQUEST: u64 = 12;
pub const SYS_NET_REPLY: u64 = 13;
pub const SYS_DRIVER_RX: u64 = 14;
pub const SYS_DRIVER_TX: u64 = 15;
pub const SYS_DRIVER_READY: u64 = 16;
pub const SYS_MAC: u64 = 17;
pub const SYS_MAC_REGISTER: u64 = 18;
/// NETWORK only: fill exactly eight writable user bytes, or return an error.
pub const SYS_RANDOM: u64 = 19;
/// NETWORK only: copy the current canonical network configuration into exactly
/// sixteen writable user bytes. The third argument must be zero.
pub const SYS_NET_CONFIG: u64 = 20;
/// All services: fill up to MAX_RANDOM_BYTES writable user bytes. Arguments are
/// (pointer, length, 0). Returns length; zero length ignores the pointer. Failed
/// entropy generation leaves the complete destination unchanged.
pub const SYS_RANDOM_BYTES: u64 = 21;
pub const MAX_RANDOM_BYTES: usize = 256;
/// All services: write up to MAX_LOG bytes to stdout (fd 1) or stderr (fd 2).
/// Arguments are (fd, pointer, length); returns the accepted input byte count.
/// Raw bytes are preserved, with terminal LF -> CRLF and visible fragment
/// boundaries for bounded shell fairness. EAGAIN means nothing was accepted.
pub const SYS_WRITE: u64 = 22;
pub const NET_CONFIG_SIZE: usize = 16;
/// Physical kernel text used only by privilege/DMA regression probes.
/// Keep in sync with the fixed load address in linker.ld.
pub const KERNEL_PROBE_ADDRESS: u64 = 0x0100_0000;
pub const MAX_FRAME_SIZE: usize = 1514;
pub const DRIVER_MMIO: u64 = 0x5000_0000;
pub const DRIVER_DMA: u64 = 0x5020_0000;
pub const DRIVER_IOVA: u64 = 0x1000_0000;
pub const DRIVER_IOVA_STRIDE: u64 = 0x20_0000;
pub const MAX_NIC_INTERFACES: usize = 8;
pub const EIO: i64 = -5;
pub const ETIMEDOUT: i64 = -110;

/// Fixed, pointer-free socket RPC. IDs are kernel-issued generation tokens.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Request {
    pub id: u64,
    pub operation: u64,
    pub handle: u64,
    pub argument: u64,
    pub length: u64,
    pub data: [u8; SOCKET_BUFFER_SIZE],
}

impl Request {
    pub const fn new() -> Self {
        Self {
            id: 0,
            operation: 0,
            handle: 0,
            argument: 0,
            length: 0,
            data: [0; SOCKET_BUFFER_SIZE],
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Reply {
    pub id: u64,
    pub result: i64,
    pub length: u64,
    pub data: [u8; SOCKET_BUFFER_SIZE],
}

impl Reply {
    pub const fn new() -> Self {
        Self {
            id: 0,
            result: 0,
            length: 0,
            data: [0; SOCKET_BUFFER_SIZE],
        }
    }
}
