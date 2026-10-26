//! Destructive probes run in ring 3; each must return safely to the kernel.

use crate::{abi, arch, console::Console, syscall, time::Clock, userspace::Process};
use core::fmt::Write;
use smoltcp::iface::{SocketHandle, SocketSet};

#[cfg(all(feature = "userspace-test", not(feature = "fuzz-test")))]
pub fn run(
    process: &mut Process,
    sockets: &mut SocketSet<'_>,
    handles: &[SocketHandle; abi::SOCKET_COUNT],
    clock: &Clock,
    console: &mut Console,
) -> ! {
    crate::memory::check_permissions();
    let (text, data) = crate::memory::probe_addresses();
    // SAFETY: these narrowly scoped probes recover only their expected page
    // fault at an exact instruction/address; the NX target contains RET.
    unsafe {
        assert_eq!(
            arch::probe_write(text),
            Some(3),
            "kernel text must reject writes"
        );
        assert_eq!(
            arch::probe_execute(data),
            Some(17),
            "kernel data must reject execution"
        );
    }
    writeln!(console, "Kernel WP/NX fault checks passed.").ok();
    let ticks_before = crate::timer::ticks();
    for mode in 1..=13 {
        process.restart(mode);
        let mut calls = 0;
        let mut preemptions = 0;
        loop {
            // SAFETY: the loader owns the user pages; descriptor tables and
            // this context remain supervisor-only on our single CPU.
            unsafe { arch::resume(&mut process.context) };
            let context = process.context;
            assert_eq!(context.cs & 3, 3);
            if context.vector == arch::TIMER_VECTOR {
                preemptions += 1;
                if mode == 13 && preemptions >= 3 {
                    writeln!(console, "Ring-3 probe 13: busy loop preempted three times").ok();
                    break;
                }
                continue;
            }
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
    assert!(crate::timer::ticks() >= ticks_before + 3);
    writeln!(console, "Userspace isolation checks passed.").ok();
    crate::exit_qemu(0x10);
}

#[cfg(feature = "fuzz-test")]
pub fn fuzz_run(
    process: &mut Process,
    sockets: &mut SocketSet<'_>,
    handles: &[SocketHandle; abi::SOCKET_COUNT],
    clock: &Clock,
    console: &mut Console,
) -> ! {
    let seed: u64 = env!("KERNEL_FUZZ_SEED").parse().expect("fuzz seed");
    let iterations: u64 = env!("KERNEL_FUZZ_ITERATIONS")
        .parse()
        .expect("fuzz iterations");
    writeln!(console, "Syscall fuzz: seed={seed} iterations={iterations}").ok();
    process.restart(15);
    process.context.rsi = seed;
    process.context.rdx = iterations;
    let mut calls = 0u64;
    let mut preemptions = 0u64;
    loop {
        // SAFETY: same isolated process and mappings as the normal scheduler.
        unsafe { arch::resume(&mut process.context) };
        let context = process.context;
        if context.vector == arch::TIMER_VECTOR {
            preemptions += 1;
            continue;
        }
        assert_eq!(
            context.vector, 128,
            "fuzz seed={seed} calls={calls}: {context:?}"
        );
        calls += 1;
        if calls.is_multiple_of(16384) {
            writeln!(console, "Syscall fuzz progress: seed={seed} calls={calls}").ok();
        }
        match syscall::dispatch(process, sockets, handles, clock, console) {
            syscall::Action::Exit(code) => {
                assert_eq!(code, 0, "syscall fuzz failed seed={seed} calls={calls}");
                assert!(calls >= iterations, "syscall fuzz terminated early");
                crate::memory::check_permissions();
                writeln!(
                    console,
                    "Syscall fuzz passed: seed={seed} calls={calls} preemptions={preemptions}"
                )
                .ok();
                crate::exit_qemu(0x10);
            }
            syscall::Action::Continue | syscall::Action::Poll => {}
        }
    }
}
