//! An independent, freestanding userspace HTTP executable.
#![no_std]
#![no_main]

#[path = "../abi.rs"]
mod abi;
#[cfg(userspace_test)]
mod fuzz;
mod http;
mod syscall;

use core::arch::asm;
use core::fmt::{self, Write};
use core::panic::PanicInfo;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(mode: u64, seed: u64, iterations: u64) -> ! {
    let code_segment: u16;
    // SAFETY: reading CS is unprivileged and does not modify machine state.
    unsafe {
        asm!("mov {segment:x}, cs", segment = out(reg) code_segment, options(nomem, nostack, preserves_flags))
    };
    if code_segment & 3 != 3 {
        syscall::log("Userspace privilege check failed\n");
        syscall::exit(1);
    }
    syscall::log("Userspace web server: CPL=3\n");

    #[cfg(userspace_test)]
    if mode != 0 {
        if mode == 15 {
            fuzz::run(seed, iterations);
        }
        run_probe(mode);
    }
    #[cfg(not(userspace_test))]
    let _ = (mode, seed, iterations);

    let mut connections = [const { http::Connection::new() }; abi::SOCKET_COUNT];
    let mut sockets = core::array::from_fn::<_, { abi::SOCKET_COUNT }, _>(syscall::Socket::new);
    // Arm all listeners before publishing the readiness message.
    let now = syscall::now_millis();
    for (connection, socket) in connections.iter_mut().zip(sockets.iter_mut()) {
        connection.poll(socket, now);
    }
    syscall::log("HTTP listening on 10.0.2.15:80\n");
    loop {
        syscall::poll();
        let now = syscall::now_millis();
        for (connection, socket) in connections.iter_mut().zip(sockets.iter_mut()) {
            connection.poll(socket, now);
        }
    }
}

#[cfg(userspace_test)]
fn run_probe(mode: u64) -> ! {
    const USER_END: u64 = 0x4020_0000;
    const STACK_BOTTOM: u64 = USER_END - 64 * 1024;
    // SAFETY: these isolated test modes deliberately violate the ABI or touch
    // forbidden memory to verify that the kernel contains userspace faults.
    unsafe {
        match mode {
            1 => syscall::exit(3),
            2 => {
                assert_eq!(syscall::raw(u64::MAX, 0, 0, 0), abi::ENOSYS);
                assert_eq!(syscall::raw(abi::SYS_STATE, 4, 0, 0), abi::EBADF);
                assert_eq!(syscall::raw(abi::SYS_SEND, 0, 0x10_0000, 1), abi::EFAULT);
                assert_eq!(
                    syscall::raw(abi::SYS_RECV, 0, _start as *const () as u64, 1),
                    abi::EFAULT
                );
                assert_eq!(syscall::raw(abi::SYS_SEND, 0, 0, 1), abi::EFAULT);
                assert_eq!(syscall::raw(abi::SYS_RECV, 0, 0, 1), abi::EFAULT);
                assert_eq!(
                    syscall::raw(abi::SYS_SEND, 0, USER_END - 8, 16),
                    abi::EFAULT
                );
                assert_eq!(
                    syscall::raw(abi::SYS_SEND, 0, USER_END - 8, usize::MAX as u64),
                    abi::EINVAL
                );
                assert_eq!(syscall::raw(abi::SYS_LISTEN, 0, 81, 0), abi::EACCES);
                syscall::exit(0);
            }
            3 => asm!("mov rax, qword ptr [rdi]", in("rdi") 0x10_0000_u64, out("rax") _),
            4 => asm!("mov byte ptr [rdi], 0", in("rdi") 0x10_0000_u64),
            5 => asm!("mov eax, dword ptr [rdi]", in("rdi") 0xfed0_0000_u64, out("eax") _),
            6 => asm!("out dx, al", in("dx") 0x3f8_u16, in("al") 0_u8),
            7 => asm!("mov byte ptr [rdi], 0x90", in("rdi") _start as *const () as u64),
            8 => asm!(
                "sub rsp, 16",
                "mov byte ptr [rsp], 0xc3",
                "call rsp",
                "add rsp, 16",
            ),
            9 => asm!("mov rax, qword ptr [rdi]", in("rdi") STACK_BOTTOM - 8, out("rax") _),
            10 => asm!("cli"),
            11 => {
                let flags: u64;
                // Keep DF-setting and restoration in one assembly block so
                // no Rust code executes with a backwards string direction.
                asm!(
                    "std",
                    "int 0x80",
                    "pushfq",
                    "pop rdx",
                    "cld",
                    inlateout("rax") abi::SYS_NOW => _,
                    lateout("rdx") flags,
                );
                assert_ne!(flags & (1 << 10), 0, "syscall lost userspace DF");
                syscall::exit(0);
            }
            12 => asm!(
                "mov rsp, 0x0000800000000000",
                "int 0x80",
                "ud2",
                in("rax") abi::SYS_NOW,
                options(noreturn),
            ),
            13 => asm!("2:", "pause", "jmp 2b", options(noreturn)),
            16 => {
                for number in abi::SYS_FRAME_RECV..=abi::SYS_MAC_REGISTER {
                    assert_eq!(syscall::raw(number, 0, 0, 0), abi::EACCES);
                }
                for address in [abi::DRIVER_MMIO, abi::DRIVER_DMA, 0x100000, u64::MAX] {
                    assert_eq!(syscall::raw(abi::SYS_SEND, 0, address, 1), abi::EFAULT);
                    assert_eq!(syscall::raw(abi::SYS_RECV, 0, address, 1), abi::EFAULT);
                }
                assert_eq!(syscall::raw(abi::SYS_LISTEN, 0, 81, 0), abi::EACCES);
                syscall::log("IPC capability checks passed.\n");
                asm!("ud2", options(noreturn));
            }
            14 => loop {
                syscall::raw(abi::SYS_NOW, 0, 0, 0);
            },
            _ => {}
        }
    }
    syscall::exit(255);
}

struct Logger;

impl Write for Logger {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        syscall::log(value);
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    writeln!(Logger, "Userspace panic: {info}").ok();
    syscall::exit(1);
}
