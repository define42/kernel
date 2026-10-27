//! Bounded ASCII line editing for the serial console, without allocation or I/O.
//!
//! A completed line remains available until the next byte is fed. Overflow or
//! corrupt input invalidates the entire line; editing cannot recover a prefix
//! into a command. Ctrl-C explicitly cancels either normal or discarded input.

pub const CAPACITY: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    None,
    Echo(u8),
    Erase,
    Line,
    Cancel,
    TooLong,
    Corrupt,
}

#[derive(Clone, Copy)]
enum Failure {
    None,
    TooLong,
    Corrupt,
}

pub struct Input {
    bytes: [u8; CAPACITY],
    length: usize,
    failure: Failure,
    completed: bool,
    skip_lf: bool,
}

impl Input {
    pub const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            length: 0,
            failure: Failure::None,
            completed: false,
            skip_lf: false,
        }
    }

    pub fn line(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// Cancel the current/completed line and restore a fresh input state.
    pub fn reset(&mut self) {
        self.clear_line();
        self.skip_lf = false;
    }

    /// A UART error makes the complete current line untrustworthy. Wait for
    /// an explicit line ending, even if the previous byte happened to be CR.
    pub fn corrupt(&mut self) {
        self.length = 0;
        self.failure = Failure::Corrupt;
        self.completed = false;
        self.skip_lf = false;
    }

    pub fn feed(&mut self, byte: u8) -> Event {
        if self.completed {
            self.clear_line();
        }
        if self.skip_lf {
            self.skip_lf = false;
            if byte == b'\n' {
                return Event::None;
            }
        }
        if byte == 3 {
            self.reset();
            return Event::Cancel;
        }
        if matches!(byte, b'\r' | b'\n') {
            self.completed = true;
            self.skip_lf = byte == b'\r';
            return match self.failure {
                Failure::None => Event::Line,
                Failure::TooLong => Event::TooLong,
                Failure::Corrupt => Event::Corrupt,
            };
        }
        // ESC starts terminal control sequences such as arrow keys. Reject
        // the entire line so their printable suffixes cannot become commands.
        // Unknown controls and non-ASCII bytes receive the same treatment.
        if !matches!(byte, 8 | 127 | b' '..=b'~') {
            self.corrupt();
            return Event::None;
        }
        if !matches!(self.failure, Failure::None) {
            return Event::None;
        }
        if matches!(byte, 8 | 127) {
            if self.length == 0 {
                return Event::None;
            }
            self.length -= 1;
            return Event::Erase;
        }
        if self.length == CAPACITY {
            self.length = 0;
            self.failure = Failure::TooLong;
            return Event::None;
        }
        self.bytes[self.length] = byte;
        self.length += 1;
        Event::Echo(byte)
    }

    fn clear_line(&mut self) {
        self.length = 0;
        self.failure = Failure::None;
        self.completed = false;
    }
}

impl Default for Input {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(input: &mut Input, bytes: &[u8]) {
        for &byte in bytes {
            assert_eq!(input.feed(byte), Event::Echo(byte));
        }
    }

    #[test]
    fn completed_line_retains_bytes_until_next_feed() {
        const EMPTY: Input = Input::new();
        let mut input = EMPTY;
        assert!(input.line().is_empty());
        text(&mut input, b"  status  ");
        assert_eq!(input.feed(b'\n'), Event::Line);
        assert_eq!(input.line(), b"  status  ");
        assert_eq!(input.line(), b"  status  ");
        assert_eq!(input.feed(b'h'), Event::Echo(b'h'));
        assert_eq!(input.line(), b"h");
    }

    #[test]
    fn cr_lf_and_crlf_submit_once_per_line_ending() {
        let mut input = Input::new();
        text(&mut input, b"one");
        assert_eq!(input.feed(b'\r'), Event::Line);
        assert_eq!(input.line(), b"one");
        assert_eq!(input.feed(b'\n'), Event::None);
        assert!(input.line().is_empty());
        text(&mut input, b"two");
        assert_eq!(input.feed(b'\n'), Event::Line);
        assert_eq!(input.line(), b"two");
        assert_eq!(input.feed(b'\r'), Event::Line); // An intentional empty line.
        assert!(input.line().is_empty());
        assert_eq!(input.feed(b'\r'), Event::Line);
        assert_eq!(input.feed(b'\n'), Event::None);
        text(&mut input, b"three");
        assert_eq!(input.feed(b'\r'), Event::Line);
        text(&mut input, b"four"); // CR need not be followed by LF.
        assert_eq!(input.feed(b'\n'), Event::Line);
        assert_eq!(input.line(), b"four");
    }

    #[test]
    fn backspace_and_delete_edit_without_erasing_the_prompt() {
        let mut input = Input::new();
        assert_eq!(input.feed(8), Event::None);
        assert_eq!(input.feed(127), Event::None);
        text(&mut input, b"halp");
        assert_eq!(input.feed(8), Event::Erase);
        assert_eq!(input.feed(127), Event::Erase);
        assert_eq!(input.feed(8), Event::Erase);
        text(&mut input, b"elp");
        assert_eq!(input.feed(b'\n'), Event::Line);
        assert_eq!(input.line(), b"help");
    }

    #[test]
    fn exactly_capacity_bytes_are_accepted_and_can_be_edited() {
        let mut input = Input::new();
        text(&mut input, &[b'x'; CAPACITY]);
        assert_eq!(input.line().len(), CAPACITY);
        assert_eq!(input.feed(8), Event::Erase);
        assert_eq!(input.feed(b'y'), Event::Echo(b'y'));
        assert_eq!(input.feed(b'\r'), Event::Line);
        assert_eq!(input.line().len(), CAPACITY);
        assert_eq!(input.line()[CAPACITY - 1], b'y');
        assert_eq!(input.feed(b'\n'), Event::None);
    }

    #[test]
    fn overflow_discards_entire_line_and_backspace_cannot_recover_it() {
        let mut input = Input::new();
        text(&mut input, &[b'x'; CAPACITY]);
        assert_eq!(input.feed(b'x'), Event::None);
        assert!(input.line().is_empty());
        for byte in [8, 127, b'h', b'e', b'l', b'p'] {
            assert_eq!(input.feed(byte), Event::None);
        }
        assert_eq!(input.feed(b'\r'), Event::TooLong);
        assert!(input.line().is_empty());
        assert_eq!(input.feed(b'\n'), Event::None);
        text(&mut input, b"help");
        assert_eq!(input.feed(b'\n'), Event::Line);
        assert_eq!(input.line(), b"help");
    }

    #[test]
    fn ctrl_c_cancels_normal_overflowed_and_corrupt_lines() {
        let mut input = Input::new();
        text(&mut input, b"discard");
        assert_eq!(input.feed(3), Event::Cancel);
        assert!(input.line().is_empty());
        text(&mut input, &[b'x'; CAPACITY]);
        assert_eq!(input.feed(b'x'), Event::None);
        assert_eq!(input.feed(3), Event::Cancel);
        input.corrupt();
        assert_eq!(input.feed(3), Event::Cancel);
        text(&mut input, b"help");
        assert_eq!(input.feed(b'\n'), Event::Line);
        assert_eq!(input.line(), b"help");
    }

    #[test]
    fn uart_corruption_discards_through_eol_and_recovers() {
        let mut input = Input::new();
        text(&mut input, b"sta");
        input.corrupt();
        assert!(input.line().is_empty());
        for byte in b"tus\x08\x7f" {
            assert_eq!(input.feed(*byte), Event::None);
        }
        assert_eq!(input.feed(b'\r'), Event::Corrupt);
        assert_eq!(input.feed(b'\n'), Event::None);
        text(&mut input, b"status");
        assert_eq!(input.feed(b'\n'), Event::Line);
        assert_eq!(input.line(), b"status");
    }

    #[test]
    fn uart_error_after_cr_is_not_hidden_by_crlf_suppression() {
        let mut input = Input::new();
        assert_eq!(input.feed(b'\r'), Event::Line);
        input.corrupt();
        assert_eq!(input.feed(b'\n'), Event::Corrupt);
        assert_eq!(input.feed(b'\n'), Event::Line);
    }

    #[test]
    fn escape_sequences_cannot_turn_into_commands() {
        let mut input = Input::new();
        for bytes in [b"\x1b[Ahelp\n".as_slice(), b"help\x1b[D\n", b"\x1bOArun\n"] {
            for &byte in &bytes[..bytes.len() - 1] {
                input.feed(byte);
            }
            assert_eq!(input.feed(b'\n'), Event::Corrupt);
            assert!(input.line().is_empty());
        }
        text(&mut input, b"help");
        assert_eq!(input.feed(b'\n'), Event::Line);
        assert_eq!(input.line(), b"help");
    }

    #[test]
    fn unknown_controls_and_non_ascii_invalidate_instead_of_splicing_commands() {
        for invalid in (0..=255u8).filter(|byte| !matches!(*byte, 3 | 8 | 10 | 13 | 32..=127)) {
            let mut input = Input::new();
            text(&mut input, b"re");
            assert_eq!(input.feed(invalid), Event::None);
            assert_eq!(input.feed(b'b'), Event::None);
            assert_eq!(input.feed(b'\n'), Event::Corrupt);
            assert!(input.line().is_empty());
        }
    }

    #[test]
    fn explicit_reset_clears_pending_completion_failure_and_crlf_state() {
        let mut input = Input::new();
        text(&mut input, b"old");
        assert_eq!(input.feed(b'\r'), Event::Line);
        input.reset();
        assert!(input.line().is_empty());
        assert_eq!(input.feed(b'\n'), Event::Line);
        input.corrupt();
        input.reset();
        text(&mut input, b"new");
        assert_eq!(input.feed(b'\n'), Event::Line);
        assert_eq!(input.line(), b"new");
    }
}
