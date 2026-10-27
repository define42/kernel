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

    /// Accept one byte from stdout/stderr without dropping any accepted data.
    /// Newlines use the console's CRLF convention. Unlike legacy best-effort
    /// logs, a long stream starts another visibly delimited fragment instead
    /// of losing its suffix, and a full queue reports backpressure.
    pub fn try_push_console(&mut self, byte: u8) -> bool {
        if self.overflow {
            return false;
        }
        let fragment = !self.discard_line && self.line_length == MAX_LINE && byte != b'\n';
        let needed = usize::from(byte == b'\n') + 1 + if fragment { PARTIAL_LINE.len() } else { 0 };
        if needed > CAPACITY - self.length {
            return false;
        }
        // A previous best-effort line may have been truncated, or peek() may
        // have closed an idle fragment. Its marker already delimited the loss;
        // this strict write is a new fragment and must never inherit discard.
        if self.discard_line || fragment {
            self.line_length = 0;
            self.discard_line = false;
        }
        if fragment {
            self.marker(PARTIAL_LINE);
        }
        if byte == b'\n' {
            self.push_raw(b'\r');
            self.line_length = 0;
        } else {
            self.line_length += 1;
        }
        self.push_raw(byte);
        true
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

    fn drain(logs: &mut Logs) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Some(byte) = logs.peek() {
            assert_eq!(logs.peek(), Some(byte), "peeking must not consume bytes");
            bytes.push(byte);
            logs.pop();
        }
        bytes
    }

    #[test]
    fn strict_console_preserves_invalid_utf8_and_nul() {
        let mut logs = Logs::new();
        for byte in [0xff, 0, 0xc3, b'(', b'\n'] {
            assert!(logs.try_push_console(byte));
        }
        assert_eq!(drain(&mut logs), [0xff, 0, 0xc3, b'(', b'\r', b'\n']);
        assert!(logs.is_empty());
    }

    #[test]
    fn strict_console_full_queue_reports_backpressure_without_loss() {
        let mut logs = Logs::new();
        for _ in 0..CAPACITY / 2 {
            assert!(logs.try_push_console(b'\n'));
        }
        assert!(!logs.try_push_console(b'x'));
        assert!(!logs.try_push_console(b'\n'));
        assert!(
            !logs.overflow,
            "a refused write must not mark accepted data lost"
        );
        assert_eq!(drain(&mut logs), b"\r\n".repeat(CAPACITY / 2));
        assert!(logs.try_push_console(b'y'));
        assert!(logs.try_push_console(b'\n'));
        assert_eq!(drain(&mut logs), b"y\r\n");
    }

    #[test]
    fn strict_console_crlf_is_accepted_atomically() {
        let mut logs = Logs::new();
        for _ in 0..CAPACITY / 2 - 1 {
            assert!(logs.try_push_console(b'\n'));
        }
        assert!(logs.try_push_console(b'x'));
        assert!(!logs.try_push_console(b'\n'));
        assert_eq!(logs.length, CAPACITY - 1);
        assert_eq!(logs.line_length, 1);
        assert!(logs.try_push_console(b'y'));
        let mut expected = b"\r\n".repeat(CAPACITY / 2 - 1);
        expected.extend_from_slice(b"xy");
        expected.extend_from_slice(PARTIAL_LINE);
        assert_eq!(drain(&mut logs), expected);
    }

    #[test]
    fn strict_console_delimits_long_lines_without_dropping_the_suffix() {
        let mut logs = Logs::new();
        for _ in 0..MAX_LINE * 2 + 3 {
            assert!(logs.try_push_console(b'x'));
        }
        assert!(logs.try_push_console(b'\n'));
        let mut expected = vec![b'x'; MAX_LINE];
        expected.extend_from_slice(PARTIAL_LINE);
        expected.extend_from_slice(&[b'x'; MAX_LINE]);
        expected.extend_from_slice(PARTIAL_LINE);
        expected.extend_from_slice(b"xxx\r\n");
        assert_eq!(drain(&mut logs), expected);
    }

    #[test]
    fn strict_console_restarts_after_legacy_discard_and_idle_fragment() {
        let mut logs = Logs::new();
        for _ in 0..MAX_LINE + 1 {
            logs.push(b'x');
        }
        assert!(logs.discard_line);
        assert!(logs.try_push_console(b'y'));
        assert!(logs.try_push_console(b'\n'));
        let mut expected = vec![b'x'; MAX_LINE];
        expected.extend_from_slice(LONG_LINE);
        expected.extend_from_slice(b"y\r\n");
        assert_eq!(drain(&mut logs), expected);
        assert!(logs.try_push_console(b'z'));
        let mut expected = vec![b'z'];
        expected.extend_from_slice(PARTIAL_LINE);
        assert_eq!(drain(&mut logs), expected);
        assert!(logs.discard_line);
        assert!(logs.try_push_console(b'q'));
        assert!(logs.try_push_console(b'\n'));
        assert_eq!(drain(&mut logs), b"q\r\n");
    }

    #[test]
    fn strict_console_waits_for_legacy_overflow_marker() {
        let mut logs = Logs::new();
        for _ in 0..CAPACITY + 1 {
            logs.push(b'\n');
        }
        assert!(!logs.try_push_console(b'x'));
        let mut expected = vec![b'\n'; CAPACITY];
        expected.extend_from_slice(OVERFLOW);
        assert_eq!(drain(&mut logs), expected);
        assert!(logs.try_push_console(b'x'));
        assert!(logs.try_push_console(b'\n'));
        assert_eq!(drain(&mut logs), b"x\r\n");
    }

    #[test]
    fn strict_console_keeps_bytes_across_ring_wrap() {
        let mut logs = Logs::new();
        for round in 0u8..200 {
            let mut expected = Vec::new();
            for _ in 0..20 {
                for _ in 0..31 {
                    // Exclude newline so each fragment's expected framing is
                    // independent of the arbitrary non-UTF-8 payload byte.
                    let byte = if round == b'\n' { 0xff } else { round };
                    assert!(logs.try_push_console(byte));
                    expected.push(byte);
                }
                assert!(logs.try_push_console(b'\n'));
                expected.extend_from_slice(b"\r\n");
            }
            assert_eq!(drain(&mut logs), expected);
        }
    }

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
