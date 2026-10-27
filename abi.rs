//! The small, nonblocking socket ABI shared by the kernel and userspace.
#![allow(dead_code)]

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
pub const MAX_FRAME_SIZE: usize = 1514;
pub const DRIVER_MMIO: u64 = 0x5000_0000;
pub const DRIVER_DMA: u64 = 0x5020_0000;
pub const DRIVER_IOVA: u64 = 0x1000_0000;
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
