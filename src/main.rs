#![no_std]
#![no_main]

#[cfg(not(feature = "smoke-test"))]
#[path = "../abi.rs"]
mod abi;
#[cfg(not(feature = "smoke-test"))]
mod abuse;
#[cfg(not(feature = "smoke-test"))]
mod arch;
mod console;
#[cfg(not(feature = "smoke-test"))]
mod e1000;
#[cfg(not(feature = "smoke-test"))]
mod memory;
#[cfg(not(feature = "smoke-test"))]
mod net;
#[cfg(not(feature = "smoke-test"))]
mod pci;
#[cfg(not(feature = "smoke-test"))]
mod syscall;
#[cfg(not(feature = "smoke-test"))]
mod time;
#[cfg(not(feature = "smoke-test"))]
mod timer;
#[cfg(all(
    any(feature = "userspace-test", feature = "fuzz-test"),
    not(feature = "smoke-test")
))]
mod user_test;
#[cfg(not(feature = "smoke-test"))]
mod userspace;

use core::arch::{asm, global_asm};
use core::fmt::Write;
use core::panic::PanicInfo;

use console::Console;

global_asm!(include_str!("boot.S"));

const MULTIBOOT_MAGIC: u32 = 0x2bad_b002;
const IDENTITY_MAP_END: u32 = 1 << 30;

/// The fixed prefix of the Multiboot v1 information structure.
#[derive(Clone, Copy)]
#[repr(C)]
struct BootInfo {
    flags: u32,
    mem_lower_kib: u32,
    mem_upper_kib: u32,
}

#[unsafe(no_mangle)]
extern "C" fn kernel_main(magic: u32, info_addr: u32) -> ! {
    // The bootstrap starts just one CPU and leaves interrupts disabled. This
    // local console is consequently the only writer to the VGA buffer/UART.
    let mut console = Console::new();
    writeln!(console, "Rust kernel").ok();
    writeln!(console, "===========").ok();

    assert_eq!(magic, MULTIBOOT_MAGIC, "invalid Multiboot boot magic");
    assert!(
        info_addr != 0
            && info_addr.is_multiple_of(4)
            && info_addr <= IDENTITY_MAP_END - size_of::<BootInfo>() as u32,
        "boot information is outside the identity map"
    );
    // SAFETY: the trusted Multiboot loader supplies this aligned structure;
    // the range check above ensures its entire prefix is identity mapped.
    let info = unsafe { (info_addr as *const BootInfo).read() };

    writeln!(console, "CPU: x86-64 (long mode)").ok();
    writeln!(console, "Paging: 4 GiB identity mapped (PCI MMIO uncached)").ok();
    if info.flags & 1 != 0 {
        writeln!(
            console,
            "Memory: {} KiB conventional, {} KiB above 1 MiB",
            info.mem_lower_kib, info.mem_upper_kib
        )
        .ok();
    } else {
        writeln!(console, "Memory: size not provided by the bootloader").ok();
    }
    writeln!(console, "Kernel booted successfully.").ok();

    #[cfg(feature = "smoke-test")]
    {
        check_boot_state();
        writeln!(console, "Boot checks passed.").ok();
        exit_qemu(0x10);
    }

    #[cfg(not(feature = "smoke-test"))]
    {
        arch::init();
        let protection = memory::init();
        memory::check_permissions();
        writeln!(
            console,
            "Kernel pages: RX text, R/NX constants, RW/NX data; SMEP={} SMAP={}",
            protection.smep, protection.smap
        )
        .ok();
        net::run(&mut console);
    }
}

#[cfg(feature = "smoke-test")]
fn check_boot_state() {
    static mut BSS_PROBE: u64 = 0;
    static mut DATA_PROBE: u64 = 0x0123_4567_89ab_cdef;

    let cr0: u64;
    let cr4: u64;
    let efer_low: u32;
    // SAFETY: the bootstrap entered ring 0 on an x86-64 CPU with MSR support.
    // These reads only inspect the CPU state that it established.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!(
            "rdmsr",
            in("ecx") 0xc000_0080u32,
            out("eax") efer_low,
            out("edx") _,
            options(nomem, nostack, preserves_flags)
        );
        assert_eq!(core::ptr::addr_of!(BSS_PROBE).read_volatile(), 0);
        assert_eq!(
            core::ptr::addr_of!(DATA_PROBE).read_volatile(),
            0x0123_4567_89ab_cdef
        );
    }
    assert_ne!(cr0 & (1 << 31), 0, "paging is disabled");
    assert_ne!(cr4 & (1 << 5), 0, "PAE is disabled");
    assert_ne!(efer_low & (1 << 10), 0, "long mode is inactive");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Interrupts remain disabled and the previous console will never be used
    // again. Reinitializing here also makes early boot panics visible.
    let mut console = Console::new();
    writeln!(console, "KERNEL PANIC: {info}").ok();
    #[cfg(any(
        feature = "smoke-test",
        feature = "userspace-test",
        feature = "fuzz-test"
    ))]
    exit_qemu(0x11);
    #[cfg(not(any(
        feature = "smoke-test",
        feature = "userspace-test",
        feature = "fuzz-test"
    )))]
    halt();
}

#[cfg(any(
    feature = "smoke-test",
    feature = "userspace-test",
    feature = "fuzz-test"
))]
fn exit_qemu(code: u32) -> ! {
    // SAFETY: make test attaches QEMU's isa-debug-exit device at this port.
    // QEMU returns (code << 1) | 1 to the host, so success (0x10) becomes 33.
    unsafe {
        asm!("out dx, eax", in("dx") 0xf4u16, in("eax") code, options(nomem, nostack));
    }
    halt();
}

fn halt() -> ! {
    loop {
        // SAFETY: this kernel runs at ring 0; with interrupts disabled, HLT
        // stops consuming CPU until an NMI/reset.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
