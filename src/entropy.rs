//! Bounded CPU random-number access for network startup and restart.
//!
//! The CPU RNG is a platform trust dependency. This is not an entropy pool,
//! health-test implementation, or a claim of cryptographic certification.
//! In particular no clock, MAC address, or fixed seed is used as a fallback.

use core::arch::{
    asm,
    x86_64::{__cpuid, __cpuid_count},
};
use core::hint::spin_loop;

pub fn random_u64() -> Option<u64> {
    if __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & (1 << 18) != 0 {
        for _ in 0..100 {
            let value: u64;
            let ready: u8;
            // SAFETY: CPUID advertised RDSEED; CF must indicate success.
            unsafe {
                asm!("rdseed {value}", "setc {ready}", value = out(reg) value,
                     ready = out(reg_byte) ready, options(nomem, nostack));
            }
            if ready != 0 {
                return Some(value);
            }
            spin_loop();
        }
    }
    if __cpuid(1).ecx & (1 << 30) != 0 {
        for _ in 0..10 {
            let value: u64;
            let ready: u8;
            // SAFETY: CPUID advertised RDRAND. Never use a CF=0 result.
            unsafe {
                asm!("rdrand {value}", "setc {ready}", value = out(reg) value,
                     ready = out(reg_byte) ready, options(nomem, nostack));
            }
            if ready != 0 {
                return Some(value);
            }
            spin_loop();
        }
    }
    None
}
