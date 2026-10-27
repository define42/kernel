use crate::ffi::{OsStr, OsString};
use crate::{fmt, io};

pub struct Env;

impl fmt::Debug for Env {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_map().finish()
    }
}

impl Iterator for Env {
    type Item = (OsString, OsString);

    fn next(&mut self) -> Option<Self::Item> {
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

pub fn env() -> Env {
    Env
}

pub fn getenv(_: &OsStr) -> Option<OsString> {
    None
}

pub unsafe fn setenv(_: &OsStr, _: &OsStr) -> io::Result<()> {
    Err(io::const_error!(
        io::ErrorKind::Unsupported,
        "kernel has no process environment"
    ))
}

pub unsafe fn unsetenv(_: &OsStr) -> io::Result<()> {
    Err(io::const_error!(
        io::ErrorKind::Unsupported,
        "kernel has no process environment"
    ))
}
