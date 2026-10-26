//! A polled HPET clock for QEMU's PC machine. No interrupts are required.

use core::hint::spin_loop;
use core::ptr::{read_volatile, write_volatile};

const HPET_BASE: usize = 0xfed0_0000;
const CAPABILITIES: usize = 0x000;
const CONFIGURATION: usize = 0x010;
const INTERRUPT_STATUS: usize = 0x020;
const MAIN_COUNTER: usize = 0x0f0;
const TIMER_CONFIGURATION: usize = 0x100;
const TIMER_STRIDE: usize = 0x020;
const COUNTER_64_BIT: u64 = 1 << 13;
const ENABLE: u64 = 1;
const FEMTOSECONDS_PER_MILLISECOND: u128 = 1_000_000_000_000;
const FEMTOSECONDS_PER_MICROSECOND: u64 = 1_000_000_000;

/// Owns the HPET main counter for the single-CPU kernel.
///
/// Initialize once during boot, before starting any users of elapsed time.
/// QEMU's PC HPET has a fixed address; other platforms require ACPI discovery.
pub struct Clock {
    period_femtoseconds: u64,
}

impl Clock {
    pub fn new() -> Result<Self, &'static str> {
        let capabilities = read_register(CAPABILITIES);
        if capabilities == u64::MAX || capabilities & 0xff == 0 {
            return Err("HPET is missing at 0xfed00000");
        }
        if capabilities & COUNTER_64_BIT == 0 {
            return Err("HPET requires a 64-bit main counter");
        }
        let period_femtoseconds = capabilities >> 32;
        // HPET 1.0a specifies a nonzero tick period of at most 100 ns.
        if period_femtoseconds == 0 || period_femtoseconds > 100_000_000 {
            return Err("HPET reports an invalid clock period");
        }

        // Stop the main counter and disable legacy PIT/RTC replacement.
        write_register(CONFIGURATION, 0);
        let timer_count = ((capabilities >> 8) & 0x1f) as usize + 1;
        for timer in 0..timer_count {
            // Clear all writable timer bits, including interrupt enable,
            // periodic mode and FSB interrupt delivery. Read-only bits ignore
            // writes; reserved bits must remain zero.
            write_register(TIMER_CONFIGURATION + timer * TIMER_STRIDE, 0);
        }
        write_register(INTERRUPT_STATUS, (1u64 << timer_count) - 1);
        write_register(MAIN_COUNTER, 0);
        write_register(CONFIGURATION, ENABLE);
        if read_register(CONFIGURATION) & ENABLE == 0 {
            return Err("HPET failed to enable its main counter");
        }

        let clock = Self {
            period_femtoseconds,
        };
        let first = clock.ticks();
        // Bound the probe so a disabled or broken timer cannot hang boot.
        for _ in 0..100_000 {
            if clock.ticks() != first {
                return Ok(clock);
            }
            spin_loop();
        }
        Err("HPET main counter is not advancing")
    }

    pub fn now_millis(&self) -> i64 {
        // Widen before multiplication. Even the largest supported period and
        // counter produce fewer than i64::MAX milliseconds.
        ((self.ticks() as u128 * self.period_femtoseconds as u128) / FEMTOSECONDS_PER_MILLISECOND)
            as i64
    }

    pub fn delay_micros(&self, microseconds: u32) {
        let femtoseconds = u64::from(microseconds) * FEMTOSECONDS_PER_MICROSECOND;
        let ticks = femtoseconds.div_ceil(self.period_femtoseconds);
        let start = self.ticks();
        while self.ticks().wrapping_sub(start) < ticks {
            spin_loop();
        }
    }

    fn ticks(&self) -> u64 {
        read_register(MAIN_COUNTER)
    }
}

fn read_register(offset: usize) -> u64 {
    // SAFETY: boot.S maps the fixed QEMU HPET page as uncacheable memory.
    // Callers use only aligned, architecturally defined 64-bit registers.
    unsafe { read_volatile((HPET_BASE + offset) as *const u64) }
}

fn write_register(offset: usize, value: u64) {
    // SAFETY: the HPET mapping is uncacheable and all offsets are aligned.
    // Clock::new runs on the only active CPU, before any other timer users.
    unsafe { write_volatile((HPET_BASE + offset) as *mut u64, value) }
}
