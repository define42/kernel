use crate::pin::Pin;
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::time::{Duration, Instant};

pub struct Parker {
    token: AtomicBool,
}

impl Parker {
    pub unsafe fn new_in_place(parker: *mut Self) {
        unsafe {
            parker.write(Self {
                token: AtomicBool::new(false),
            })
        };
    }

    pub unsafe fn park(self: Pin<&Self>) {
        while !self.token.swap(false, Ordering::Acquire) {
            crate::sys::thread::yield_now();
        }
    }

    pub unsafe fn park_timeout(self: Pin<&Self>, duration: Duration) {
        if self.token.swap(false, Ordering::Acquire) {
            return;
        }
        let deadline = Instant::now()
            .checked_add(duration)
            .expect("park deadline overflow");
        while Instant::now() < deadline {
            if self.token.swap(false, Ordering::Acquire) {
                return;
            }
            crate::sys::thread::yield_now();
        }
    }

    pub fn unpark(self: Pin<&Self>) {
        self.token.store(true, Ordering::Release);
    }
}
