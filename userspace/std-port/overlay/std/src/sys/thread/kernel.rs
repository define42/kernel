use crate::io;
use crate::num::NonZero;
use crate::sys::pal::{SYS_POLL, monotonic_millis, syscall};
use crate::time::Duration;

pub fn available_parallelism() -> io::Result<NonZero<usize>> {
    Ok(NonZero::new(1).unwrap())
}

pub fn yield_now() {
    let result = unsafe { syscall(SYS_POLL, 0, 0, 0) };
    assert_eq!(result, 0, "kernel yield failed");
}

pub fn sleep(duration: Duration) {
    if duration.is_zero() {
        return;
    }
    // Round up and add one clock quantum: SYS_NOW truncates to milliseconds,
    // so the first observed tick can occur less than one full millisecond away.
    let milliseconds = duration.as_nanos().div_ceil(1_000_000);
    let milliseconds = u64::try_from(milliseconds)
        .ok()
        .and_then(|value| value.checked_add(1))
        .expect("sleep duration overflow");
    let deadline = monotonic_millis()
        .checked_add(milliseconds)
        .expect("sleep deadline overflow");
    while monotonic_millis() < deadline {
        yield_now();
    }
}
