//! Destructive probes run in ring 3; each must return safely to the kernel.

use crate::{abi, arch, console::Console, syscall, time::Clock, userspace::Process};
use core::fmt::Write;
use smoltcp::iface::{SocketHandle, SocketSet};

pub fn run(
    process: &mut Process,
    sockets: &mut SocketSet<'_>,
    handles: &[SocketHandle; abi::SOCKET_COUNT],
    clock: &Clock,
    console: &mut Console,
) -> ! {
    for mode in 1..=12 {
        process.restart(mode);
        let mut calls = 0;
        loop {
            // SAFETY: the loader owns the user pages; descriptor tables and
            // this context remain supervisor-only on our single CPU.
            unsafe { arch::resume(&mut process.context) };
            let context = process.context;
            assert_eq!(context.cs & 3, 3);
            if context.vector != 128 {
                match mode {
                    3..=5 | 7 => {
                        assert_eq!(context.vector, 14, "expected protection fault");
                        assert_eq!(context.error_code & 5, 5, "user protection bits");
                        if mode == 4 || mode == 7 {
                            assert_ne!(context.error_code & 2, 0, "write fault bit");
                        }
                        match mode {
                            3 | 4 => assert_eq!(context.cr2, 0x100000),
                            5 => assert_eq!(context.cr2, 0xfed00000),
                            _ => assert!(context.cr2 >= crate::userspace::USER_BASE),
                        }
                    }
                    12 => assert_eq!(context.vector, 12, "noncanonical user stack"),
                    6 | 10 => assert_eq!(context.vector, 13, "privileged I/O/instruction"),
                    8 => {
                        assert_eq!(context.vector, 14);
                        assert_eq!(context.error_code & 0x15, 0x15, "user NX fault");
                    }
                    9 => {
                        assert_eq!(context.vector, 14);
                        assert_eq!(context.error_code & 5, 4, "unmapped user guard");
                        assert_eq!(context.cr2, crate::userspace::STACK_BOTTOM - 8);
                    }
                    _ => panic!("unexpected user fault in probe {mode}: {context:?}"),
                }
                writeln!(
                    console,
                    "Ring-3 probe {mode}: contained vector {} (error {:#x})",
                    context.vector, context.error_code
                )
                .ok();
                break;
            }
            calls += 1;
            assert!(calls < 100, "probe did not finish");
            match syscall::dispatch(process, sockets, handles, clock, console) {
                syscall::Action::Exit(code) => {
                    assert!(
                        mode <= 2 || mode == 11,
                        "fault probe unexpectedly survived: {mode}"
                    );
                    assert_eq!(code, if mode == 1 { 3 } else { 0 }, "probe exit code");
                    writeln!(console, "Ring-3 probe {mode}: passed (exit {code})").ok();
                    break;
                }
                syscall::Action::Continue => {}
                syscall::Action::Poll => panic!("probe unexpectedly yielded"),
            }
        }
    }
    writeln!(console, "Userspace isolation checks passed.").ok();
    crate::exit_qemu(0x10);
}
