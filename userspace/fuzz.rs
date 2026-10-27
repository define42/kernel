//! Seeded ABI robustness checks executed by the real ring-3 test executable.
use crate::{abi, syscall};

pub fn run(seed: u64, iterations: u64) -> ! {
    let mut random = seed.max(1);
    let mut buffer = alloc::boxed::Box::new([0xa5u8; 96]);
    let address = buffer[16..80].as_mut_ptr() as u64;
    for index in 0..iterations {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let fd = (random >> 8) % abi::SOCKET_COUNT as u64;
        let length = 1 + (random >> 16) % 64;
        let invalid = [
            0,
            0x100000,
            0xfed00000,
            abi::USER_HEAP_BASE - 4096,
            abi::USER_HEAP_END,
            0x401effff,
            0x40200000,
            0x0000800000000000,
            u64::MAX - 7,
        ];
        let pointer = invalid[((random >> 32) % invalid.len() as u64) as usize];
        let (number, a, b, c, expected) = match random % 24 {
            0 => (4096 + (random >> 8), 0, 0, 0, abi::ENOSYS),
            1 => (abi::SYS_STATE, 4 + (random >> 8), 0, 0, abi::EBADF),
            2 => (abi::SYS_RECV, fd, pointer, length, abi::EFAULT),
            3 => (abi::SYS_SEND, fd, pointer, length, abi::EFAULT),
            4 => (
                abi::SYS_RECV,
                fd,
                super::_start as *const () as u64,
                length,
                abi::EFAULT,
            ),
            5 => (
                abi::SYS_RECV,
                fd,
                0x40200000 - length + 1,
                length,
                abi::EFAULT,
            ),
            6 => (
                abi::SYS_SEND,
                fd,
                address,
                4097 + (random >> 16),
                abi::EINVAL,
            ),
            7 => (abi::SYS_LOG, address, 513 + (random >> 16), 0, abi::EINVAL),
            8 => (abi::SYS_LOG, pointer, length, 0, abi::EFAULT),
            9 => (abi::SYS_LISTEN, fd, 81 + (random >> 16), 0, abi::EACCES),
            10 => (abi::SYS_RECV, fd, address, 0, 0),
            11 => (abi::SYS_SEND, fd, address, 0, 0),
            12 => (abi::SYS_ABORT, fd, 0, 0, 0),
            13 => (abi::SYS_CLOSE, fd, 0, 0, 0),
            14 => (abi::SYS_POLL, 0, 0, 0, 0),
            15 => (abi::SYS_LOG, address, length, 0, abi::EINVAL), // invalid UTF-8
            16 => (abi::SYS_LOG, address, 0, 0, 0),
            17 => (abi::SYS_STATE, fd, 0, 0, i64::MAX),
            18 => (abi::SYS_LISTEN, fd, 80, 0, i64::MAX),
            19 => (abi::SYS_RECV, fd, address, length, i64::MAX),
            20 => (abi::SYS_SEND, fd, address, length, i64::MAX),
            22 => (
                abi::SYS_FRAME_RECV
                    + ((random >> 24) % (abi::SYS_NET_CONFIG - abi::SYS_FRAME_RECV + 1)),
                address,
                abi::NET_CONFIG_SIZE as u64,
                0,
                abi::EACCES,
            ),
            _ => (abi::SYS_NOW, 0, 0, 0, i64::MAX),
        };
        // SAFETY: invalid pointers are supplied only where the ABI must reject
        // them without dereference. Valid output storage is uniquely borrowed
        // here; no Rust reference to its contents survives this asm call.
        let result = unsafe { syscall::raw(number, a, b, c) };
        if expected != i64::MAX {
            assert_eq!(
                result, expected,
                "seed={seed} case={index} syscall={number} args={a:#x},{b:#x},{c:#x}"
            );
        } else {
            let valid = match number {
                abi::SYS_STATE => {
                    result >= 0 && (result as u64 & abi::STATE_MASK) <= abi::TIME_WAIT
                }
                abi::SYS_LISTEN => result == 0 || result == abi::EINVAL,
                abi::SYS_RECV | abi::SYS_SEND => result == abi::EAGAIN || result == abi::ENOTCONN,
                abi::SYS_NOW => result >= 0,
                _ => false,
            };
            assert!(
                valid,
                "seed={seed} case={index} syscall={number} unexpected={result}"
            );
        }
        assert!(
            buffer.iter().all(|&b| b == 0xa5),
            "seed={seed} case={index}: buffer or canary modified"
        );
    }
    syscall::exit(0);
}
