//! Checked, nonblocking socket calls. No user pointer becomes a Rust reference.

use core::fmt::Write;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;

use crate::{abi, console::Console, time::Clock, userspace::Process};

#[path = "entropy.rs"]
mod entropy;

pub enum Action {
    Continue,
    Poll,
    Exit(u64),
}

pub fn dispatch(
    process: &mut Process,
    sockets: &mut SocketSet<'_>,
    handles: &[SocketHandle; abi::SOCKET_COUNT],
    clock: &Clock,
    console: &mut Console,
) -> Action {
    let context = process.context;
    assert_eq!(context.cs & 3, 3, "system call must originate in ring 3");
    let (number, a, b, c) = (context.rax, context.rdi, context.rsi, context.rdx);
    let mut action = Action::Continue;
    let result = match number {
        abi::SYS_POLL => {
            action = Action::Poll;
            0
        }
        abi::SYS_NOW => clock.now_millis(),
        abi::SYS_EXIT => {
            action = Action::Exit(a);
            0
        }
        abi::SYS_RANDOM_BYTES => random_bytes(process, a, b, c),
        abi::SYS_WRITE => {
            if !matches!(a, 1 | 2) {
                abi::EBADF
            } else if c > abi::MAX_LOG as u64 {
                abi::EINVAL
            } else if c == 0 {
                0
            } else {
                let mut bytes = [0; abi::MAX_LOG];
                let bytes = &mut bytes[..c as usize];
                if process.copy_from_user(b, bytes).is_err() {
                    abi::EFAULT
                } else {
                    match console.write_user_bytes(bytes) {
                        Ok(0) => abi::EAGAIN,
                        Ok(count) => count as i64,
                        Err(()) => abi::EIO,
                    }
                }
            }
        }
        abi::SYS_LOG => {
            if b > abi::MAX_LOG as u64 {
                abi::EINVAL
            } else {
                let mut bytes = [0; abi::MAX_LOG];
                let bytes = &mut bytes[..b as usize];
                if process.copy_from_user(a, bytes).is_err() {
                    abi::EFAULT
                } else if let Ok(message) = core::str::from_utf8(bytes) {
                    console.write_str(message).ok();
                    b as i64
                } else {
                    abi::EINVAL
                }
            }
        }
        abi::SYS_STATE
        | abi::SYS_RECV
        | abi::SYS_SEND
        | abi::SYS_CLOSE
        | abi::SYS_ABORT
        | abi::SYS_LISTEN => {
            if a >= handles.len() as u64 {
                abi::EBADF
            } else {
                let socket = sockets.get_mut::<tcp::Socket>(handles[a as usize]);
                match number {
                    abi::SYS_STATE => {
                        let state = match socket.state() {
                            tcp::State::Closed => abi::CLOSED,
                            tcp::State::Listen => abi::LISTEN,
                            tcp::State::SynReceived => abi::SYN_RECEIVED,
                            tcp::State::Established => abi::ESTABLISHED,
                            tcp::State::CloseWait => abi::CLOSE_WAIT,
                            tcp::State::TimeWait => abi::TIME_WAIT,
                            _ => abi::CLOSING,
                        };
                        (state
                            | if socket.can_recv() { abi::CAN_RECV } else { 0 }
                            | if socket.can_send() { abi::CAN_SEND } else { 0 }
                            | ((socket.send_queue() as u64) << abi::SEND_QUEUE_SHIFT))
                            as i64
                    }
                    abi::SYS_CLOSE => {
                        socket.close();
                        0
                    }
                    abi::SYS_ABORT => {
                        socket.abort();
                        0
                    }
                    abi::SYS_LISTEN => {
                        if b != abi::HTTP_PORT as u64 {
                            abi::EACCES
                        } else if socket.listen(abi::HTTP_PORT).is_ok() {
                            0
                        } else {
                            abi::EINVAL
                        }
                    }
                    abi::SYS_RECV | abi::SYS_SEND => transfer(process, socket, number, b, c),
                    _ => unreachable!(),
                }
            }
        }
        _ => abi::ENOSYS,
    };
    process.context.rax = result as u64;
    action
}

fn transfer(
    process: &mut Process,
    socket: &mut tcp::Socket<'_>,
    number: u64,
    address: u64,
    length: u64,
) -> i64 {
    if length > abi::SOCKET_BUFFER_SIZE as u64 {
        return abi::EINVAL;
    }
    let length = length as usize;
    let receiving = number == abi::SYS_RECV;
    // Validate the complete range before changing socket state or consuming
    // received data. This also checks read-only pages and arithmetic overflow.
    if !process.validate_buffer(address, length, receiving) {
        return abi::EFAULT;
    }
    if length == 0 {
        return 0;
    }
    let mut scratch = [0; abi::SOCKET_BUFFER_SIZE];
    if receiving {
        if !socket.can_recv() {
            return if socket.may_recv() {
                abi::EAGAIN
            } else {
                abi::ENOTCONN
            };
        }
        match socket.recv_slice(&mut scratch[..length]) {
            Ok(count) => {
                process
                    .copy_to_user(address, &scratch[..count])
                    .expect("validated writable userspace buffer");
                count as i64
            }
            Err(_) => abi::ENOTCONN,
        }
    } else {
        if !socket.can_send() {
            return if socket.may_send() {
                abi::EAGAIN
            } else {
                abi::ENOTCONN
            };
        }
        process
            .copy_from_user(address, &mut scratch[..length])
            .expect("validated readable userspace buffer");
        socket
            .send_slice(&scratch[..length])
            .map_or(abi::ENOTCONN, |n| n as i64)
    }
}

/// Generate into private scratch space so entropy failure cannot leave a
/// partially initialized userspace destination that the caller might consume.
fn random_bytes(process: &mut Process, address: u64, length: u64, reserved: u64) -> i64 {
    if length > abi::MAX_RANDOM_BYTES as u64 || reserved != 0 {
        return abi::EINVAL;
    }
    if length == 0 {
        return 0;
    }
    if !process.validate_buffer(address, length as usize, true) {
        return abi::EFAULT;
    }
    let mut bytes = [0; abi::MAX_RANDOM_BYTES];
    for chunk in bytes[..length as usize].chunks_mut(8) {
        let Some(value) = entropy::random_u64() else {
            return abi::EIO;
        };
        chunk.copy_from_slice(&value.to_le_bytes()[..chunk.len()]);
    }
    process
        .copy_to_user(address, &bytes[..length as usize])
        .map_or(abi::EFAULT, |_| length as i64)
}
