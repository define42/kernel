//! A polled ACPI-discovered HPET clock. No interrupts are required.

use core::hint::spin_loop;
use core::ptr::{read_volatile, write_volatile};

/// Independent fallback for short hardware initialization/teardown polls.
/// A stopped HPET must not make elapsed-time deadlines spin forever. This
/// bounds completed MMIO polls, not a physically hung bus transaction.
pub const MAX_POLL_ITERATIONS: usize = 10_000_000;

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
/// The platform parser validates its ACPI register block and uncached mapping.
pub struct Clock {
    base: usize,
    period_femtoseconds: u64,
}

impl Clock {
    pub fn new() -> Result<Self, &'static str> {
        let base = crate::platform::hpet_address()?;
        let capabilities = read_register(base, CAPABILITIES);
        if capabilities == u64::MAX || capabilities & 0xff == 0 {
            return Err("HPET is missing at its ACPI register address");
        }
        if capabilities & COUNTER_64_BIT == 0 {
            return Err("HPET requires a 64-bit main counter");
        }
        let period_femtoseconds = capabilities >> 32;
        // HPET 1.0a specifies a nonzero tick period of at most 100 ns.
        if period_femtoseconds == 0 || period_femtoseconds > 100_000_000 {
            return Err("HPET reports an invalid clock period");
        }

        // Preserve manufacturer/reserved configuration bits (HPET 1.0a
        // section 2.3.5), while stopping the counter and legacy replacement.
        let configuration = read_register(base, CONFIGURATION) & !3;
        write_register(base, CONFIGURATION, configuration);
        if read_register(base, CONFIGURATION) & 3 != 0 {
            return Err("HPET failed to stop or disable legacy replacement");
        }
        let timer_count = ((capabilities >> 8) & 0x1f) as usize + 1;
        let mut pending_level_interrupts = 0u64;
        for timer in 0..timer_count {
            let offset = TIMER_CONFIGURATION + timer * TIMER_STRIDE;
            let previous = read_register(base, offset);
            // Retain the firmware's valid route and edge/level selection.
            // Disable interrupt, FSB, periodic and value-set modes; reserved
            // timer bits require zero and capability bits ignore writes.
            let stopped = previous & ((1 << 1) | (0x1f << 9));
            write_register(base, offset, stopped);
            if read_register(base, offset) & ((1 << 2) | (1 << 14)) != 0 {
                return Err("HPET comparator interrupt failed to disable");
            }
            if previous & (1 << 1) != 0 {
                pending_level_interrupts |= 1 << timer;
            }
        }
        write_register(base, INTERRUPT_STATUS, pending_level_interrupts);
        write_register(base, MAIN_COUNTER, 0);
        write_register(base, CONFIGURATION, configuration | ENABLE);
        if read_register(base, CONFIGURATION) & 3 != ENABLE {
            return Err("HPET failed to enable its main counter without legacy replacement");
        }

        let clock = Self {
            base,
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

    #[cfg(feature = "baremetal")]
    pub fn now_micros(&self) -> u64 {
        ((self.ticks() as u128 * self.period_femtoseconds as u128)
            / FEMTOSECONDS_PER_MICROSECOND as u128) as u64
    }

    pub fn delay_micros(&self, microseconds: u32) -> Result<(), &'static str> {
        let femtoseconds = u64::from(microseconds) * FEMTOSECONDS_PER_MICROSECOND;
        let ticks = femtoseconds.div_ceil(self.period_femtoseconds);
        let start = self.ticks();
        for _ in 0..MAX_POLL_ITERATIONS {
            let elapsed = self
                .ticks()
                .checked_sub(start)
                .ok_or("HPET counter moved backwards during delay")?;
            if elapsed >= ticks {
                return Ok(());
            }
            spin_loop();
        }
        Err("HPET delay exceeded bounded polling budget")
    }

    fn ticks(&self) -> u64 {
        read_register(self.base, MAIN_COUNTER)
    }
}

fn read_register(base: usize, offset: usize) -> u64 {
    // SAFETY: platform discovery checked the whole HPET page is mapped uncached.
    // Callers use only aligned, architecturally defined 64-bit registers.
    unsafe { read_volatile((base + offset) as *const u64) }
}

fn write_register(base: usize, offset: usize, value: u64) {
    // SAFETY: the HPET mapping is uncacheable and all offsets are aligned.
    // Clock::new runs on the only active CPU, before any other timer users.
    unsafe { write_volatile((base + offset) as *mut u64, value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopped_counter_exhausts_delay_budget_instead_of_succeeding() {
        // Exercise the real volatile-read loop against a stable register bank.
        // No writer exists, so this cannot accidentally satisfy elapsed time.
        let registers = [0u64; MAIN_COUNTER / size_of::<u64>() + 1];
        let clock = Clock {
            base: registers.as_ptr() as usize,
            period_femtoseconds: 10_000_000,
        };
        assert_eq!(clock.delay_micros(0), Ok(()));
        assert_eq!(
            clock.delay_micros(1),
            Err("HPET delay exceeded bounded polling budget")
        );
    }
}
