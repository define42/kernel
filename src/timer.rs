//! Legacy PC IRQ0 preemption at approximately 100 Hz.
//!
//! The kernel runs with IF clear. IRET enables interrupts only in userspace;
//! each IRQ0 interrupt returns control to the scheduler with IF clear again.
//! HPET continues to provide wall-clock deadlines independently of these ticks.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const VECTOR: u64 = crate::arch::TIMER_VECTOR;
pub const FREQUENCY_HZ: u32 = 100;
const PIT_CLOCK_HZ: u32 = 1_193_182;
const DIVISOR: u16 = ((PIT_CLOCK_HZ + FREQUENCY_HZ / 2) / FREQUENCY_HZ) as u16;
const PIC_MASTER_COMMAND: u16 = 0x20;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_COMMAND: u16 = 0xa0;
const PIC_SLAVE_DATA: u16 = 0xa1;
const PIT_COUNTER0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
// traps.S increments this with LOCK INC after saving every interrupted GPR.
#[unsafe(no_mangle)]
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Delivered IRQ0 ticks, not elapsed time: ticks can coalesce while IF is clear.
#[cfg(feature = "userspace-test")]
pub fn ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}

/// Configure IRQ0 after the IDT is installed and HPET legacy routing is off.
///
/// Called once on the sole bootstrap CPU. All other legacy IRQs remain masked;
/// the network driver uses polling and HPET uses no interrupt delivery.
pub fn init() {
    let flags: u64;
    let cs: u16;
    // SAFETY: these reads do not require a particular privilege level.
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

    // SAFETY: fixed PC chipset ports, one CPU and IF clear. ICW1 selects
    // cascaded, edge-triggered controllers; ICW4 selects 8086 mode and manual
    // EOI. Master IRQ2 is the slave cascade, which stays masked here.
    unsafe {
        write_port(PIC_MASTER_DATA, 0xff);
        write_port(PIC_SLAVE_DATA, 0xff);
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

        // Counter 0, low-byte/high-byte access, mode 2 rate generator, binary.
        write_port(PIT_COMMAND, 0x34);
        write_port(PIT_COUNTER0, DIVISOR as u8);
        write_port(PIT_COUNTER0, (DIVISOR >> 8) as u8);
        // Only IRQ0 becomes deliverable, once userspace is entered with IF=1.
        write_port(PIC_MASTER_DATA, 0xfe);
    }
}

unsafe fn write_port(port: u16, value: u8) {
    // SAFETY: callers supply the PC PIC/PIT ports and execute at CPL 0. The
    // conventional port-0x80 delay also supports older emulated chipsets.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
        asm!("out 0x80, al", in("al") 0u8, options(nomem, nostack, preserves_flags));
    }
}
