#![no_std]
#![no_main]

#[cfg(not(feature = "smoke-test"))]
#[path = "../abi.rs"]
mod abi;
#[cfg(all(not(feature = "smoke-test"), feature = "userspace-test"))]
mod abuse;
#[cfg(not(feature = "smoke-test"))]
mod arch;
mod console;
#[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
mod device;
#[cfg(all(not(feature = "smoke-test"), feature = "userspace-test"))]
mod e1000;
#[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
mod iommu;
#[cfg(not(feature = "smoke-test"))]
mod memory;
#[cfg(all(not(feature = "smoke-test"), feature = "userspace-test"))]
#[path = "legacy_net.rs"]
mod net;
#[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
mod net;
#[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
#[path = "../userspace/network_config.rs"]
mod network_config;
#[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
mod nic;
#[cfg(not(feature = "smoke-test"))]
mod pci;
#[cfg_attr(feature = "smoke-test", allow(dead_code))]
mod platform;
#[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
mod setup;
#[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
mod setup_plan;
#[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
mod shell;
#[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
mod shell_input;
#[cfg(all(feature = "std-test", not(feature = "smoke-test")))]
mod std_test;
#[cfg(all(not(feature = "smoke-test"), feature = "userspace-test"))]
mod syscall;
#[cfg(not(feature = "smoke-test"))]
mod time;
#[cfg(not(feature = "smoke-test"))]
mod timer;
#[cfg(all(
    feature = "userspace-test",
    not(any(feature = "smoke-test", feature = "std-test"))
))]
mod user_test;
#[cfg(not(feature = "smoke-test"))]
mod userspace;

use core::arch::{asm, global_asm};
use core::fmt::Write;
use core::panic::PanicInfo;

use console::Console;

global_asm!(include_str!("boot.S"));

#[unsafe(no_mangle)]
extern "C" fn kernel_main(magic: u32, info_addr: u32) -> ! {
    // The bootstrap starts just one CPU and leaves interrupts disabled. This
    // local console is consequently the only writer to the VGA buffer/UART.
    let mut console = Console::new();
    writeln!(console, "Rust kernel").ok();
    writeln!(console, "===========").ok();

    let boot = platform::init(magic, info_addr).expect("boot platform validation");
    writeln!(console, "CPU: x86-64 (long mode)").ok();
    writeln!(console, "Paging: 4 GiB identity mapped (PCI MMIO uncached)").ok();
    writeln!(
        console,
        "Multiboot{}: {} memory regions; resident kernel {} KiB in available RAM",
        boot.version,
        boot.memory_regions,
        boot.kernel_bytes.div_ceil(1024)
    )
    .ok();
    if let Some(address) = boot.hpet {
        writeln!(
            console,
            "ACPI: validated firmware tables; HPET at {address:#x}"
        )
        .ok();
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
