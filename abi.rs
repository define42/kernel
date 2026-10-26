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
