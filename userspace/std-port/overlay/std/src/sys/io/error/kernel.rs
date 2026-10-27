use crate::io::ErrorKind;

pub fn errno() -> i32 {
    // There is no libc errno cell; errors are returned directly by syscalls.
    0
}

pub fn is_interrupted(code: i32) -> bool {
    code == 4
}

pub fn decode_error_kind(code: i32) -> ErrorKind {
    match code {
        4 => ErrorKind::Interrupted,
        5 => ErrorKind::Other,
        9 => ErrorKind::InvalidInput,
        11 => ErrorKind::WouldBlock,
        12 => ErrorKind::OutOfMemory,
        13 => ErrorKind::PermissionDenied,
        14 | 22 => ErrorKind::InvalidInput,
        38 => ErrorKind::Unsupported,
        107 => ErrorKind::NotConnected,
        110 => ErrorKind::TimedOut,
        _ => ErrorKind::Uncategorized,
    }
}

pub fn error_string(code: i32) -> String {
    match code {
        0 => "no stored OS error (kernel returns errors directly)",
        4 => "interrupted",
        5 => "input/output error",
        9 => "bad file descriptor",
        11 => "operation would block",
        12 => "out of memory",
        13 => "permission denied",
        14 => "invalid userspace address",
        22 => "invalid argument",
        38 => "operation unsupported",
        107 => "socket not connected",
        110 => "operation timed out",
        _ => "unknown kernel error",
    }
    .to_owned()
}
