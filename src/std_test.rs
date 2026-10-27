//! Execute an ordinary `std` binary in ring 3 and contain its failure modes.

use crate::{abi, arch, console::Console, syscall, time::Clock, userspace::Process};
use core::arch::x86_64::{__cpuid, __cpuid_count};
use core::fmt::Write;
use smoltcp::iface::{SocketHandle, SocketSet};

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
    let entropy = __cpuid(1).ecx & (1 << 30) != 0
        || (__cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & (1 << 18) != 0);
    let probes: &[(u64, u64)] = if entropy {
        &[(0, 0), (1, 1), (2, 1), (3, 7), (0, 0)]
    } else {
        &[(4, 1), (4, 1)]
    };
    let ticks_before = crate::timer::ticks();
    for &(mode, expected) in probes {
        process.restart(mode);
        check_memory(process);
        let start = clock.now_millis();
        let mut calls = 0u64;
        loop {
            // SAFETY: the loader owns the private user mappings. The only CPU
            // enters this loop with interrupts disabled and a valid ring-3 context.
            unsafe { arch::resume(&mut process.context) };
            let context = process.context;
            assert_eq!(context.cs & 3, 3, "std program did not run in ring 3");
            assert!(
                clock.now_millis() - start < 5_000,
                "std probe {mode} timed out"
            );
            if context.vector == arch::TIMER_VECTOR {
                continue;
            }
            assert_eq!(context.vector, 128, "std probe {mode} faulted: {context:?}");
            calls += 1;
            assert!(calls < 100_000, "std probe {mode} exceeded syscall budget");
            match syscall::dispatch(process, sockets, handles, clock, console) {
                syscall::Action::Exit(code) => {
                    assert_eq!(code, expected, "std probe {mode} exit code");
                    crate::memory::check_permissions();
                    writeln!(console, "Ring-3 std probe {mode}: passed (exit {code})").ok();
                    break;
                }
                syscall::Action::Continue | syscall::Action::Poll => {}
            }
        }
        // Force a recognizable dirty byte even if an early abort did not
        // allocate; check_memory must observe it cleared on the next restart.
        process
            .copy_to_user(abi::USER_HEAP_END - 1, &[0xa5])
            .unwrap();
    }
    if entropy {
        assert!(
            crate::timer::ticks() > ticks_before,
            "std program was never preempted"
        );
        writeln!(
            console,
            "Userspace std isolation and restart checks passed."
        )
        .ok();
    } else {
        writeln!(console, "Userspace std entropy refusal checks passed.").ok();
    }
    crate::exit_qemu(0x10);
}

fn check_memory(process: &mut Process) {
    crate::memory::check_permissions();
    let text = crate::memory::permissions(crate::userspace::USER_BASE).unwrap();
    assert!(text.user && text.executable && !text.writable);
    for address in (abi::USER_HEAP_BASE..abi::USER_HEAP_END).step_by(4096) {
        let page = crate::memory::permissions(address).expect("std heap page missing");
        assert!(page.user && page.writable && !page.executable);
    }
    for address in [abi::USER_HEAP_BASE - 1, abi::USER_HEAP_END] {
        assert!(
            crate::memory::permissions(address).is_none(),
            "std heap guard is mapped"
        );
        assert!(!process.validate_buffer(address, 1, false));
        assert!(!process.validate_buffer(address, 1, true));
    }
    let mut bytes = [0; 256];
    for address in (abi::USER_HEAP_BASE..abi::USER_HEAP_END).step_by(bytes.len()) {
        process.copy_from_user(address, &mut bytes).unwrap();
        assert!(
            bytes.iter().all(|&byte| byte == 0),
            "std heap survived restart"
        );
    }
}
