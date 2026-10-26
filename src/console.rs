use core::arch::asm;
use core::fmt;
use core::ptr::{read_volatile, write_volatile};

const VGA_BUFFER: *mut u16 = 0xb8000 as *mut u16;
const WIDTH: usize = 80;
const HEIGHT: usize = 25;
const COLOR: u16 = 0x0f00;
const COM1: u16 = 0x3f8;

pub struct Console {
    row: usize,
    column: usize,
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
        Self { row: 0, column: 0 }
    }

    fn write_byte(&mut self, byte: u8) {
        if byte == b'\n' {
            Self::serial_byte(b'\r');
        }
        Self::serial_byte(byte);

        match byte {
            b'\n' => self.newline(),
            b'\r' => self.column = 0,
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

    fn serial_byte(byte: u8) {
        // Bound the wait so a missing or faulty UART cannot freeze VGA output.
        for _ in 0..100_000 {
            // SAFETY: these are the PC UART's line-status and transmit ports.
            unsafe {
                if inb(COM1 + 5) & 0x20 != 0 {
                    outb(COM1, byte);
                    return;
                }
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
