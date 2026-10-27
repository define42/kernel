use core::arch::asm;
use core::fmt;
use core::ptr::{read_volatile, write_volatile};

#[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
#[path = "serial_output.rs"]
mod serial_output;

const VGA_BUFFER: *mut u16 = 0xb8000 as *mut u16;
const WIDTH: usize = 80;
const HEIGHT: usize = 25;
const COLOR: u16 = 0x0f00;
const COM1: u16 = 0x3f8;

pub struct Console {
    row: usize,
    column: usize,
    // LSR reads clear UART errors, including reads made while polling TX.
    receive_error: bool,
    #[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
    defer_logs: bool,
    #[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
    logs: serial_output::Logs,
}

impl Console {
    /// Called only on the bootstrap CPU, with interrupts disabled.
    pub fn new() -> Self {
        // SAFETY: the PC machine provides a 16550 UART at COM1 and a VGA text
        // buffer at 0xb8000, within the bootstrap's identity mapping.
        unsafe {
            outb(COM1 + 1, 0x00); // Disable serial interrupts.
            outb(COM1 + 3, 0x80); // Enable the baud-rate divisor registers.
            outb(COM1, 0x01); // 115200 baud.
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x03); // 8 data bits, no parity, 1 stop bit.
            outb(COM1 + 2, 0xc7); // Enable/clear FIFOs.
            outb(COM1 + 4, 0x03); // Assert DTR and RTS.
            for cell in 0..WIDTH * HEIGHT {
                write_volatile(VGA_BUFFER.add(cell), COLOR | u16::from(b' '));
            }
        }
        Self {
            row: 0,
            column: 0,
            receive_error: false,
            #[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
            defer_logs: false,
            #[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
            logs: serial_output::Logs::new(),
        }
    }

    fn write_byte(&mut self, byte: u8) {
        #[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
        if self.defer_logs {
            if byte == b'\n' {
                self.logs.push(b'\r');
            }
            self.logs.push(byte);
            self.vga_byte(byte);
            return;
        }
        if byte == b'\n' {
            self.serial_byte(b'\r');
        }
        self.serial_byte(byte);
        self.vga_byte(byte);
    }

    fn vga_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.newline(),
            b'\r' => self.column = 0,
            8 => self.column = self.column.saturating_sub(1),
            byte => {
                if self.column == WIDTH {
                    self.newline();
                }
                let glyph = if byte.is_ascii_graphic() || byte == b' ' {
                    byte
                } else {
                    b'?'
                };
                // SAFETY: row and column are bounded by HEIGHT and WIDTH.
                unsafe {
                    write_volatile(
                        VGA_BUFFER.add(self.row * WIDTH + self.column),
                        COLOR | u16::from(glyph),
                    );
                }
                self.column += 1;
            }
        }
    }

    fn newline(&mut self) {
        self.column = 0;
        if self.row < HEIGHT - 1 {
            self.row += 1;
            return;
        }
        // SAFETY: all accesses stay inside the VGA text buffer. Forward copy
        // is safe because each source row is above the destination address.
        unsafe {
            for cell in 0..WIDTH * (HEIGHT - 1) {
                let value = read_volatile(VGA_BUFFER.add(cell + WIDTH));
                write_volatile(VGA_BUFFER.add(cell), value);
            }
            for cell in WIDTH * (HEIGHT - 1)..WIDTH * HEIGHT {
                write_volatile(VGA_BUFFER.add(cell), COLOR | u16::from(b' '));
            }
        }
    }

    fn serial_status(&mut self) -> u8 {
        // SAFETY: COM1 LSR, accessed only by the single bootstrap CPU with IF clear.
        let status = unsafe { inb(COM1 + 5) };
        self.receive_error |= status & 0x1e != 0;
        status
    }

    /// One nonblocking receive probe. Lost/corrupt bytes invalidate the line.
    #[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
    pub fn read_serial(&mut self) -> Option<Result<u8, ()>> {
        let status = self.serial_status();
        if status == 0xff {
            return None; // Unpopulated legacy port.
        }
        if core::mem::take(&mut self.receive_error) {
            if status & 1 != 0 {
                // SAFETY: consume the possibly damaged FIFO head.
                unsafe {
                    inb(COM1);
                }
            }
            return Some(Err(()));
        }
        if status & 1 == 0 {
            return None;
        }
        // SAFETY: LSR reports a byte in the receive FIFO.
        Some(Ok(unsafe { inb(COM1) }))
    }

    /// Let the shell arbitrate serial output. Asynchronous fmt::Write logs
    /// remain immediate on VGA, but wait in fixed storage for a response gap.
    #[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
    pub fn defer_serial_logs(&mut self) {
        self.defer_logs = true;
    }

    /// Drain logs only between shell responses, within the shared TX budget.
    /// Yield input after each complete log line even if later logs remain.
    /// False means the current bounded log line still owns serial framing.
    #[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
    pub fn drain_serial_logs(&mut self, budget: usize) -> bool {
        for _ in 0..budget {
            let Some(byte) = self.logs.peek() else { break };
            if !self.try_serial_byte(byte) {
                break;
            }
            self.logs.pop();
            if byte == b'\n' {
                return true;
            }
        }
        self.logs.is_empty()
    }

    /// Terminal test exit has no next scheduler pass to drain its final log.
    /// This is bounded by fixed queue storage and the existing per-byte wait;
    /// normal runtime never calls this blocking path.
    #[cfg(all(
        feature = "fuzz-test",
        not(any(feature = "smoke-test", feature = "userspace-test"))
    ))]
    pub fn flush_serial_logs_for_exit(&mut self) {
        for _ in 0..8192 {
            let Some(byte) = self.logs.peek() else { break };
            self.serial_byte(byte);
            self.logs.pop();
        }
    }

    /// Try one raw byte without waiting. The shell supplies CRLF explicitly.
    #[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
    pub fn try_write_serial(&mut self, byte: u8) -> bool {
        if !self.try_serial_byte(byte) {
            return false;
        }
        self.vga_byte(byte);
        true
    }

    #[cfg(not(any(feature = "smoke-test", feature = "userspace-test")))]
    fn try_serial_byte(&mut self, byte: u8) -> bool {
        let status = self.serial_status();
        if status == 0xff || status & 0x20 == 0 {
            return false;
        }
        // SAFETY: the UART transmit holding register is ready.
        unsafe {
            outb(COM1, byte);
        }
        true
    }

    fn serial_byte(&mut self, byte: u8) {
        // Bound the wait so a missing or faulty UART cannot freeze VGA output.
        for _ in 0..100_000 {
            let status = self.serial_status();
            if status == 0xff {
                return; // Missing COM1 must not delay every boot/VGA byte.
            }
            if status & 0x20 != 0 {
                // SAFETY: the UART transmit holding register is ready.
                unsafe {
                    outb(COM1, byte);
                }
                return;
            }
            core::hint::spin_loop();
        }
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

unsafe fn outb(port: u16, value: u8) {
    // SAFETY: callers must ensure the port is valid and we are at ring 0.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: callers must ensure the port is valid and we are at ring 0.
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags));
    }
    value
}
