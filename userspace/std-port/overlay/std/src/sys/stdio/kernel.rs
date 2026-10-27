use crate::io;
use crate::sys::pal::{SYS_WRITE, syscall};

pub struct Stdin;
pub struct Stdout;
pub struct Stderr;

impl Stdin {
    pub const fn new() -> Self {
        Self
    }
}

impl io::Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            Ok(0)
        } else {
            Err(io::Error::UNSUPPORTED_PLATFORM)
        }
    }
}

impl Stdout {
    pub const fn new() -> Self {
        Self
    }
}

impl Stderr {
    pub const fn new() -> Self {
        Self
    }
}

fn write(fd: usize, buf: &[u8]) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    // A syscall has bounded copying and execution cost. Write::write_all handles
    // partial writes; WouldBlock remains visible rather than dropping output.
    let length = buf.len().min(512);
    let result = unsafe { syscall(SYS_WRITE, fd, buf.as_ptr() as usize, length) };
    if result < 0 {
        Err(io::Error::from_raw_os_error((-result) as i32))
    } else if result as usize > length {
        Err(io::const_error!(
            io::ErrorKind::InvalidData,
            "invalid kernel write result"
        ))
    } else {
        Ok(result as usize)
    }
}

impl io::Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write(1, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write(2, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub const STDIN_BUF_SIZE: usize = 0;

pub fn is_ebadf(err: &io::Error) -> bool {
    err.raw_os_error() == Some(9)
}

pub fn panic_output() -> Option<Stderr> {
    Some(Stderr::new())
}
