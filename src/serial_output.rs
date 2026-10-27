//! Fixed storage for asynchronous logs while the shell owns serial framing.

const CAPACITY: usize = 4096;
const MAX_LINE: usize = 512;
const LONG_LINE: &[u8] = b"\r\n[serial log line truncated]\r\n";
const PARTIAL_LINE: &[u8] = b"\r\n[serial log fragment ended]\r\n";
const OVERFLOW: &[u8] = b"\r\n[serial log overflow; output dropped]\r\n";

pub struct Logs {
    bytes: [u8; CAPACITY],
    head: usize,
    length: usize,
    overflow: bool,
    line_length: usize,
    discard_line: bool,
}
impl Logs {
    pub const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            head: 0,
            length: 0,
            overflow: false,
            line_length: 0,
            discard_line: false,
        }
    }

    /// Bound both storage and the time one newline-free writer can prevent
    /// the shell from accepting input. Loss is always visibly delimited.
    pub fn push(&mut self, byte: u8) {
        if self.overflow {
            return;
        }
        if self.discard_line {
            if byte == b'\n' {
                self.discard_line = false;
            }
            return;
        }
        if byte == b'\n' {
            self.line_length = 0;
        } else if self.line_length == MAX_LINE {
            self.line_length = 0;
            self.discard_line = true;
            self.marker(LONG_LINE);
            return;
        } else {
            self.line_length += 1;
        }
        self.push_raw(byte);
    }

    fn push_raw(&mut self, byte: u8) {
        if self.overflow {
            return;
        }
        if self.length == CAPACITY {
            self.overflow = true;
            return;
        }
        self.bytes[(self.head + self.length) % CAPACITY] = byte;
        self.length += 1;
    }

    fn marker(&mut self, marker: &[u8]) {
        for byte in marker {
            self.push_raw(*byte);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0 && !self.overflow && self.line_length == 0
    }

    /// Peeking is repeatable until pop acknowledges a successful UART write.
    pub fn peek(&mut self) -> Option<u8> {
        if self.length == 0 && self.overflow {
            self.overflow = false;
            self.line_length = 0;
            self.discard_line = false;
            self.marker(OVERFLOW);
        } else if self.length == 0 && self.line_length != 0 {
            // A writer that stops without a newline must not indefinitely own
            // framing. Close the fragment, then ignore its unfinished suffix.
            self.line_length = 0;
            self.discard_line = true;
            self.marker(PARTIAL_LINE);
        }
        (self.length != 0).then(|| self.bytes[self.head])
    }

    pub fn pop(&mut self) {
        assert!(self.length != 0);
        self.head = (self.head + 1) % CAPACITY;
        self.length -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_bytes_across_backpressure_and_ring_wrap() {
        let mut logs = Logs::new();
        for round in 0..6 {
            let mut bytes: Vec<_> = (0..CAPACITY - 7)
                .map(|index| (index + round) as u8)
                .collect();
            bytes.push(b'\n');
            for byte in &bytes {
                logs.push(*byte);
            }
            for byte in bytes {
                assert_eq!(logs.peek(), Some(byte));
                assert_eq!(
                    logs.peek(),
                    Some(byte),
                    "a failed UART write must retain the byte"
                );
                logs.pop();
            }
            assert!(logs.is_empty());
            assert_eq!(logs.peek(), None);
        }
    }

    #[test]
    fn overflowing_log_suffix_is_dropped_with_one_visible_marker() {
        let mut logs = Logs::new();
        for index in 0..CAPACITY + 100 {
            logs.push(if index % 64 == 63 { b'\n' } else { b'x' });
        }
        for index in 0..CAPACITY {
            assert_eq!(
                logs.peek(),
                Some(if index % 64 == 63 { b'\n' } else { b'x' })
            );
            logs.pop();
        }
        assert!(!logs.is_empty(), "overflow marker must remain pending");
        // Appends before the marker is queued must not hide the earlier loss.
        logs.push(b'y');
        for byte in OVERFLOW {
            assert_eq!(logs.peek(), Some(*byte));
            logs.pop();
        }
        assert!(logs.is_empty());
        logs.push(b'z');
        logs.push(b'\n');
        assert_eq!(logs.peek(), Some(b'z'));
        logs.pop();
        assert_eq!(logs.peek(), Some(b'\n'));
        logs.pop();
        assert!(logs.is_empty());
    }

    #[test]
    fn bounds_newline_free_logs_and_delimits_incomplete_fragments() {
        let mut logs = Logs::new();
        for _ in 0..MAX_LINE * 8 {
            logs.push(b'x');
        }
        let mut output = Vec::new();
        while let Some(byte) = logs.peek() {
            output.push(byte);
            logs.pop();
        }
        let mut expected = vec![b'x'; MAX_LINE];
        expected.extend_from_slice(LONG_LINE);
        assert_eq!(output, expected);
        assert!(logs.is_empty());
        logs.push(b'y'); // Still the discarded suffix of the overlong line.
        assert_eq!(logs.peek(), None);
        logs.push(b'\n');
        logs.push(b'z');
        assert_eq!(logs.peek(), Some(b'z'));
        logs.pop();
        for byte in PARTIAL_LINE {
            assert_eq!(logs.peek(), Some(*byte));
            logs.pop();
        }
        assert!(logs.is_empty());
    }
}
