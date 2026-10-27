//! Single-CPU preemption at 100 Hz: PIT for QEMU, calibrated xAPIC for the
//! experimental physical backend. HPET supplies independent elapsed time.
//! The kernel keeps IF clear; timer interrupts preempt only userspace.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::time::Clock;

pub const VECTOR: u64 = crate::arch::TIMER_VECTOR;
pub const FREQUENCY_HZ: u32 = 100;
#[cfg(not(feature = "baremetal"))]
pub const BACKEND: &str = "PIT";
#[cfg(feature = "baremetal")]
pub const BACKEND: &str = "xAPIC (HPET calibrated)";

#[cfg(not(feature = "baremetal"))]
const PIC_MASTER_COMMAND: u16 = 0x20;
const PIC_MASTER_DATA: u16 = 0x21;
#[cfg(not(feature = "baremetal"))]
const PIC_SLAVE_COMMAND: u16 = 0xa0;
const PIC_SLAVE_DATA: u16 = 0xa1;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
// traps.S accesses these aligned supervisor-only atomics after saving GPRs.
#[unsafe(no_mangle)]
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
static TIMER_APIC_EOI: AtomicU64 = AtomicU64::new(0);

/// Delivered ticks, not elapsed time: ticks can coalesce while IF is clear.
#[cfg(feature = "userspace-test")]
pub fn ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}

/// Install once on the bootstrap CPU, after the IDT and HPET are ready.
/// Other IRQ sources remain masked; the kernel uses no external device IRQs.
pub fn init(clock: &Clock) -> Result<(), &'static str> {
    let flags: u64;
    let cs: u16;
    // SAFETY: reading CS and RFLAGS does not alter execution state.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    assert_eq!(cs & 3, 0, "timer setup requires ring 0");
    assert_eq!(flags & (1 << 9), 0, "timer setup requires IF = 0");
    assert!(
        !INITIALIZED.swap(true, Ordering::Relaxed),
        "timer already installed"
    );
    // Do not depend on firmware's virtual-wire or PIC routing. Keep both
    // legacy controllers masked unless the PIT backend explicitly enables IRQ0.
    unsafe {
        write_port(PIC_MASTER_DATA, 0xff);
        write_port(PIC_SLAVE_DATA, 0xff);
    }
    #[cfg(feature = "baremetal")]
    {
        apic::init(clock)
    }
    #[cfg(not(feature = "baremetal"))]
    {
        let _ = clock;
        init_pit();
        Ok(())
    }
}

#[cfg(not(feature = "baremetal"))]
fn init_pit() {
    const PIT_CLOCK_HZ: u32 = 1_193_182;
    const DIVISOR: u16 = ((PIT_CLOCK_HZ + FREQUENCY_HZ / 2) / FREQUENCY_HZ) as u16;
    // SAFETY: fixed PC chipset ports, one CPU and IF clear. ICW1 selects
    // cascaded, edge-triggered controllers; ICW4 selects manual EOI/8086 mode.
    unsafe {
        write_port(PIC_MASTER_COMMAND, 0x11);
        write_port(PIC_SLAVE_COMMAND, 0x11);
        write_port(PIC_MASTER_DATA, VECTOR as u8);
        write_port(PIC_SLAVE_DATA, VECTOR as u8 + 8);
        write_port(PIC_MASTER_DATA, 1 << 2);
        write_port(PIC_SLAVE_DATA, 2);
        write_port(PIC_MASTER_DATA, 1);
        write_port(PIC_SLAVE_DATA, 1);
        write_port(PIC_MASTER_DATA, 0xff);
        write_port(PIC_SLAVE_DATA, 0xff);
        // Counter 0, low/high access, mode 2 rate generator, binary.
        write_port(0x43, 0x34);
        write_port(0x40, DIVISOR as u8);
        write_port(0x40, (DIVISOR >> 8) as u8);
        write_port(PIC_MASTER_DATA, 0xfe);
    }
}

unsafe fn write_port(port: u16, value: u8) {
    // SAFETY: callers use PC PIC/PIT ports at CPL 0. Port 0x80 supplies the
    // conventional delay for older chipsets.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
        asm!("out 0x80, al", in("al") 0u8, options(nomem, nostack, preserves_flags));
    }
}

#[cfg(feature = "baremetal")]
mod apic {
    use super::*;
    use core::arch::x86_64::__cpuid;
    use core::hint::spin_loop;
    use core::ptr::{read_volatile, write_volatile};

    const ID: usize = 0x20;
    const VERSION: usize = 0x30;
    const PRIORITY: usize = 0x80;
    const EOI: usize = 0xb0;
    const SPURIOUS: usize = 0xf0;
    const IN_SERVICE: usize = 0x100;
    const PENDING: usize = 0x200;
    const ERROR_STATUS: usize = 0x280;
    const CMCI: usize = 0x2f0;
    const TIMER: usize = 0x320;
    const THERMAL: usize = 0x330;
    const PERFORMANCE: usize = 0x340;
    const LINT0: usize = 0x350;
    const LINT1: usize = 0x360;
    const ERROR: usize = 0x370;
    const INITIAL_COUNT: usize = 0x380;
    const CURRENT_COUNT: usize = 0x390;
    const DIVIDE: usize = 0x3e0;
    const MASKED: u32 = 1 << 16;
    const PERIODIC: u32 = 1 << 17;
    const SOFTWARE_ENABLE: u32 = 1 << 8;
    const SAMPLE_MICROS: u64 = 20_000;
    const MAX_POLLS: usize = 2_000_000;

    pub(super) fn init(clock: &Clock) -> Result<(), &'static str> {
        let features = __cpuid(1);
        if features.edx & ((1 << 5) | (1 << 9)) != (1 << 5) | (1 << 9) {
            return Err("xAPIC timer requires CPUID APIC/MSR support");
        }
        let low: u32;
        let high: u32;
        // SAFETY: CPUID advertises APIC/MSR support and init checked CPL 0.
        unsafe {
            asm!("rdmsr", in("ecx") 0x1bu32, out("eax") low, out("edx") high,
                options(nomem, nostack, preserves_flags));
        }
        if low & (1 << 10) != 0 {
            return Err("x2APIC is not supported by the timer backend");
        }
        if low & ((1 << 8) | (1 << 11)) != (1 << 8) | (1 << 11) {
            return Err("xAPIC must be globally enabled on the bootstrap CPU");
        }
        let base = (low & 0xffff_f000) as usize;
        if high != 0 || low & 0x3ff != 0x100 || !(0x4000_0000..=0xffff_f000).contains(&base) {
            return Err("xAPIC base is outside the supported uncached 32-bit map");
        }
        // These whole 2 MiB windows lose their supervisor identity mapping in
        // process CR3s. EOI runs before switching back to the kernel CR3.
        if (crate::userspace::USER_BASE..crate::userspace::USER_END).contains(&(base as u64))
            || (crate::userspace::DEVICE_MMIO..crate::userspace::DEVICE_DMA + 0x20_0000)
                .contains(&(base as u64))
        {
            return Err("xAPIC base overlaps a process remapping window");
        }
        let version = read(base, VERSION);
        let maximum_lvt = (version >> 16) & 0xff;
        if !(0x10..=0x15).contains(&(version & 0xff)) || !(3..=6).contains(&maximum_lvt) {
            return Err("unsupported local APIC version or LVT layout");
        }
        if read(base, ID) >> 24 != features.ebx >> 24 {
            return Err("local APIC ID does not match the bootstrap CPU");
        }
        let result = configure(base, maximum_lvt, clock);
        if result.is_err() {
            // A failed calibration/readback must leave the local timer masked.
            write(base, TIMER, MASKED | VECTOR as u32);
            write(base, INITIAL_COUNT, 0);
            TIMER_APIC_EOI.store(0, Ordering::Release);
        }
        result
    }

    fn configure(base: usize, maximum_lvt: u32, clock: &Clock) -> Result<(), &'static str> {
        // A masked vector must still be legal and must not be the spurious
        // vector (255 has no EOI). Delivery mode/trigger bits are cleared.
        for register in [ERROR, TIMER, LINT0, LINT1] {
            write(base, register, MASKED | 254);
            if read(base, register) & MASKED == 0 {
                return Err("local APIC LVT mask was not accepted");
            }
        }
        for (minimum, register) in [(4, PERFORMANCE), (5, THERMAL), (6, CMCI)] {
            if maximum_lvt >= minimum {
                write(base, register, MASKED | 254);
                if read(base, register) & MASKED == 0 {
                    return Err("local APIC optional LVT mask was not accepted");
                }
            }
        }
        write(base, INITIAL_COUNT, 0);
        // Do not inherit an in-service/pending firmware interrupt. External
        // device routing is disabled separately before entering userspace.
        for index in 0..8 {
            if read(base, IN_SERVICE + index * 16) != 0 || read(base, PENDING + index * 16) != 0 {
                return Err("local APIC has pending firmware interrupts");
            }
        }
        write(base, PRIORITY, 0);
        write(
            base,
            SPURIOUS,
            SOFTWARE_ENABLE | crate::arch::SPURIOUS_VECTOR as u32,
        );
        if read(base, PRIORITY) & 0xff != 0
            || read(base, SPURIOUS) & 0x1ff != SOFTWARE_ENABLE | crate::arch::SPURIOUS_VECTOR as u32
        {
            return Err("local APIC software enable/priority readback failed");
        }
        write(base, ERROR_STATUS, 0);
        if read(base, ERROR_STATUS) != 0 {
            return Err("local APIC reports an initialization error");
        }
        // Divide the bus/crystal clock by 16; leave the timer masked while
        // calibrating two independent samples against the running HPET.
        write(base, DIVIDE, 3);
        if read(base, DIVIDE) & 0xb != 3 {
            return Err("local APIC divide configuration was not accepted");
        }
        let first = sample(base, clock)?;
        let second = sample(base, clock)?;
        if first.abs_diff(second) > first.max(second) / 8 {
            return Err("local APIC frequency was unstable during calibration");
        }
        let period = ((u64::from(first) + u64::from(second)) / 2) as u32;
        if period == 0 {
            return Err("local APIC calibrated period is zero");
        }
        #[cfg(feature = "userspace-test")]
        check_spurious_return();
        TIMER_APIC_EOI.store((base + EOI) as u64, Ordering::Release);
        write(base, TIMER, PERIODIC | VECTOR as u32);
        write(base, INITIAL_COUNT, period);
        if read(base, TIMER) & (MASKED | (3 << 17) | 0xff) != PERIODIC | VECTOR as u32
            || read(base, INITIAL_COUNT) != period
        {
            return Err("local APIC periodic timer readback failed");
        }
        Ok(())
    }

    fn sample(base: usize, clock: &Clock) -> Result<u32, &'static str> {
        write(base, INITIAL_COUNT, u32::MAX);
        let start = clock.now_micros();
        for _ in 0..MAX_POLLS {
            let Some(elapsed) = clock.now_micros().checked_sub(start) else {
                return Err("HPET moved backwards during local APIC calibration");
            };
            if elapsed >= SAMPLE_MICROS {
                let current = read(base, CURRENT_COUNT);
                write(base, INITIAL_COUNT, 0);
                if current == 0 || current == u32::MAX || elapsed > SAMPLE_MICROS * 5 {
                    return Err("local APIC timer failed to count during HPET calibration");
                }
                let counts = u64::from(u32::MAX - current);
                let period = (counts * 1_000_000 / u64::from(FREQUENCY_HZ) + elapsed / 2) / elapsed;
                return u32::try_from(period)
                    .ok()
                    .filter(|period| *period != 0)
                    .ok_or("local APIC calibrated period is out of range");
            }
            spin_loop();
        }
        Err("HPET stalled during bounded local APIC calibration")
    }

    #[cfg(feature = "userspace-test")]
    fn check_spurious_return() {
        let first: u64;
        let second: u64;
        let before: u64;
        let after: u64;
        // SAFETY: DPL0 gate 255 is installed, IF is clear, and its dedicated
        // path preserves the interrupted kernel frame without any EOI.
        unsafe {
            asm!("pushfq", "pop {before}", "int 0xff", "pushfq", "pop {after}",
                before = out(reg) before, after = out(reg) after,
                inlateout("rax") 0x1234_5678_9abc_def0u64 => first,
                inlateout("rdx") 0xfedc_ba98_7654_3210u64 => second);
        }
        assert_eq!(first, 0x1234_5678_9abc_def0);
        assert_eq!(second, 0xfedc_ba98_7654_3210);
        assert_eq!(before, after);
        crate::arch::check_spurious_context();
    }

    fn read(base: usize, register: usize) -> u32 {
        // SAFETY: IA32_APIC_BASE and the layout were validated before access;
        // all APIC registers are aligned 32-bit MMIO in supervisor UC pages.
        unsafe { read_volatile((base + register) as *const u32) }
    }

    fn write(base: usize, register: usize, value: u32) {
        // SAFETY: same validated UC mapping; only defined writable registers
        // and supported LVT entries are used, while IF remains clear.
        unsafe { write_volatile((base + register) as *mut u32, value) }
    }
}
