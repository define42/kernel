use crate::sys::pal::{SYS_RANDOM_BYTES, syscall};

pub fn fill_bytes(bytes: &mut [u8]) {
    for chunk in bytes.chunks_mut(256) {
        let result = unsafe {
            syscall(
                SYS_RANDOM_BYTES,
                chunk.as_mut_ptr() as usize,
                chunk.len(),
                0,
            )
        };
        // HashMap must not silently fall back to predictable keys on entropy
        // failure. This interface cannot return an io::Error.
        assert_eq!(
            result,
            chunk.len() as isize,
            "kernel randomness unavailable"
        );
    }
}
