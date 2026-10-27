//! COM1 diagnostics and validated NIC requests, polled with bounded work.

use core::fmt::{self, Write};

use crate::console::Console;
use crate::nic::{self, Action, Command, Status};
use crate::pci::Scanner;
use crate::shell_input::{CAPACITY, Event, Input};
use crate::time::Clock;

const PROMPT: &str = "kernel> ";
const OUTPUT_SIZE: usize = 4096;
// Every individual response fits this reserve: setup show has at most eight
// fixed-schema rows (each under 176 bytes including PCI and MAC), plus its
// wrapper and prompt. Stop consuming input before the queue fills, even when
// a terminal stops reading.
const RESPONSE_RESERVE: usize = 1792;

struct Output {
    bytes: [u8; OUTPUT_SIZE],
    head: usize,
    length: usize,
}
impl Output {
    const fn new() -> Self {
        Self {
            bytes: [0; OUTPUT_SIZE],
            head: 0,
            length: 0,
        }
    }
    fn available(&self) -> usize {
        OUTPUT_SIZE - self.length
    }
    fn drain(&mut self, console: &mut Console) -> usize {
        let mut sent = 0;
        for _ in 0..32 {
            if self.length == 0 || !console.try_write_serial(self.bytes[self.head]) {
                break;
            }
            self.head = (self.head + 1) % OUTPUT_SIZE;
            self.length -= 1;
            sent += 1;
        }
        sent
    }
}
impl Write for Output {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() > self.available() {
            return Err(fmt::Error);
        }
        for byte in text.bytes() {
            self.bytes[(self.head + self.length) % OUTPUT_SIZE] = byte;
            self.length += 1;
        }
        Ok(())
    }
}

struct Scan {
    cursor: Scanner,
    network_only: bool,
    count: u32,
}

pub struct Shell {
    input: Input,
    output: Output,
    scan: Option<Scan>,
    action: Option<Action>,
    awaiting: Option<&'static str>,
}
impl Shell {
    pub fn new() -> Self {
        let mut shell = Self {
            input: Input::new(),
            output: Output::new(),
            scan: None,
            action: None,
            awaiting: None,
        };
        shell
            .output
            .write_str("\r\nSerial console: COM1 115200 8N1. Type help.\r\n")
            .ok();
        shell.output.write_str(PROMPT).ok();
        shell
    }

    /// Call only on the bootstrap CPU, with kernel CR3 active and IF clear.
    /// Each pass handles at most 16 input bytes, 32 output bytes and 31 PCI
    /// configuration reads. No UART readiness waits or allocation occur here.
    pub fn poll(&mut self, console: &mut Console, now: Option<i64>, nic: Status) -> Option<Action> {
        console.defer_serial_logs();
        let sent = self.output.drain(console);
        // A complete response stays contiguous across scheduler passes. Only
        // its empty queue permits asynchronous logs onto the UART. Each log
        // line yields to input, so continuous logs cannot starve commands.
        if self.output.length == 0 && !console.drain_serial_logs(32 - sent) {
            return None;
        }
        if self.awaiting.is_some() {
            return None;
        }
        for _ in 0..16 {
            if self.output.available() < RESPONSE_RESERVE {
                break;
            }
            let Some(byte) = console.read_serial() else {
                break;
            };
            let byte = match byte {
                Ok(byte) => byte,
                Err(()) => {
                    self.input.corrupt();
                    continue;
                }
            };
            match self.input.feed(byte) {
                Event::None => {}
                Event::Echo(byte) => {
                    // Input accepts printable ASCII only.
                    self.output.write_char(char::from(byte)).ok();
                }
                Event::Erase => {
                    self.output.write_str("\x08 \x08").ok();
                }
                Event::Cancel => {
                    self.scan = None;
                    self.output.write_str("^C\r\n").ok();
                    self.output.write_str(PROMPT).ok();
                }
                Event::TooLong => {
                    write!(
                        self.output,
                        "\r\nLine too long (maximum {CAPACITY} bytes); discarded.\r\n"
                    )
                    .ok();
                    if self.scan.is_none() {
                        self.output.write_str(PROMPT).ok();
                    }
                }
                Event::Corrupt => {
                    self.output
                        .write_str("\r\nInvalid serial input; line discarded.\r\n")
                        .ok();
                    if self.scan.is_none() {
                        self.output.write_str(PROMPT).ok();
                    }
                }
                Event::Line => self.command(now, nic),
            }
            if let Some(action) = self.action.take() {
                // Reserve space for one completion before accepting more input.
                self.awaiting = Some(match action {
                    Action::Setup(_) => "Setup",
                    _ => "NIC",
                });
                return Some(action);
            }
        }
        if self.output.available() >= RESPONSE_RESERVE {
            self.scan_step();
        }
        None
    }

    pub fn complete_nic(&mut self, result: Result<&'static str, &'static str>) {
        let Some(label) = self.awaiting.take() else {
            return;
        };
        match result {
            Ok(message) => {
                write!(self.output, "{label}: {message}\r\n").ok();
            }
            Err(message) => {
                write!(self.output, "{label} error: {message}\r\n").ok();
            }
        }
        self.output.write_str(PROMPT).ok();
    }

    fn command(&mut self, now: Option<i64>, status: Status) {
        self.output.write_str("\r\n").ok();
        let line = self.input.line().trim_ascii();
        if self.scan.is_some() {
            if !line.is_empty() {
                self.output
                    .write_str("PCI scan in progress; Ctrl-C cancels.\r\n")
                    .ok();
            }
            return;
        }
        match line {
            b"" => {}
            b"help" => {
                self.output.write_str(
                    "help      Show commands\r\npci       List PCI devices (alias: lspci)\r\npci net   List network controllers\r\nuptime    Milliseconds since clock initialization\r\nnic       Show NIC status (nic show)\r\nnic list|select ethN  Choose NIC to configure\r\nnic set IP/PREFIX GATEWAY|none [echo on|off]\r\nnic up|down  Enable or stop selected NIC\r\nsetup     Configure interfaces with JSON (setup help)\r\nChanges last until reboot; setting an address closes its connections.\r\nCtrl-C cancels a line or PCI scan; Backspace edits.\r\n"
                ).ok();
            }
            b"pci" | b"lspci" | b"pci net" | b"lspci net" => {
                self.scan = Some(Scan {
                    cursor: Scanner::new(),
                    network_only: line.ends_with(b" net"),
                    count: 0,
                });
                self.output.write_str("PCI segment 0000 (firmware-assigned buses; read-only)\r\nBDF           VENDOR:DEVICE CLASS  BAR0(raw)  DESCRIPTION\r\n").ok();
                return;
            }
            b"uptime" => match now {
                Some(now) => {
                    write!(self.output, "Uptime: {now} ms\r\n").ok();
                }
                None => {
                    self.output
                        .write_str("Uptime unavailable: clock not initialized.\r\n")
                        .ok();
                }
            },
            _ if line.split(|b| b.is_ascii_whitespace()).next() == Some(b"setup") => {
                let value = line[b"setup".len()..].trim_ascii();
                match value {
                    b"" | b"help" => {
                        self.output.write_str(
                            "setup show  Read all interface settings as JSON\r\nsetup {\"system\":[{\"Interface\":\"eth0\",\"PCI\":\"0000:00:02.0\",\"MAC\":\"52:54:00:12:34:56\",\"IPv4\":\"10.0.2.15/24\",\"Gateway\":\"10.0.2.2\",\"Echo\":true,\"Enabled\":true}]}\r\nSelect by Interface or PCI; both must identify the same NIC.\r\nPCI identifies a device; MAC sets its unicast Ethernet address.\r\nOmitted settings stay unchanged; Gateway may be \"none\".\r\nChanges last until reboot. Maximum line: 2048 bytes.\r\n"
                        ).ok();
                    }
                    b"show" => self.setup_show(status),
                    _ => match crate::setup::parse(value) {
                        Ok(request) => {
                            self.action = Some(Action::Setup(request));
                            return;
                        }
                        Err(error) => {
                            write!(self.output, "Setup error: {error}\r\n").ok();
                        }
                    },
                }
            }
            _ if line.split(|b| b.is_ascii_whitespace()).next() == Some(b"nic") => {
                match nic::parse(line, status.config) {
                    Ok(Command::Show) => {
                        write!(
                            self.output,
                            "NIC: {}\r\nIPv4: {}.{}.{}.{}/{}\r\nGateway: ",
                            status.state.label(),
                            status.config.address[0],
                            status.config.address[1],
                            status.config.address[2],
                            status.config.address[3],
                            status.config.prefix
                        )
                        .ok();
                        if let Some(ip) = status.config.gateway {
                            write!(self.output, "{}.{}.{}.{}\r\n", ip[0], ip[1], ip[2], ip[3]).ok();
                        } else {
                            self.output.write_str("none\r\n").ok();
                        }
                        write!(
                            self.output,
                            "Echo: {}\r\nMAC: ",
                            if status.config.echo { "on" } else { "off" }
                        )
                        .ok();
                        if let Some(mac) = status.mac {
                            let bytes = mac.to_le_bytes();
                            write!(
                                self.output,
                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\r\n",
                                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                            )
                            .ok();
                        } else {
                            self.output.write_str("unavailable\r\n").ok();
                        }
                        if let Some((bus, device, function)) = status.bdf {
                            write!(
                                self.output,
                                "PCI: 0000:{bus:02x}:{device:02x}.{function}\r\n"
                            )
                            .ok();
                        } else {
                            self.output.write_str("PCI: unassigned\r\n").ok();
                        }
                        let link = match status.link_up {
                            Some(true) => "up",
                            Some(false) => "down",
                            None => "unknown",
                        };
                        write!(self.output, "Link: {link}\r\n").ok();
                        if let Some(index) = status.selected {
                            write!(self.output, "Interface: eth{index}\r\n").ok();
                        } else {
                            self.output.write_str("Interface: none\r\n").ok();
                        }
                    }
                    Ok(Command::List) => {
                        self.output.write_str("NIC interfaces:\r\n").ok();
                        let mut count = 0;
                        for (index, entry) in status.interfaces.iter().enumerate() {
                            if let Some(interface) = entry {
                                let (bus, device, function) = interface.bdf;
                                let selected = if status.selected == Some(index) {
                                    " selected"
                                } else {
                                    ""
                                };
                                let state = interface.state.label();
                                write!(self.output,
                                    "eth{index} 0000:{bus:02x}:{device:02x}.{function} 8086:100e {state}{selected}\r\n"
                                ).ok();
                                count += 1;
                            }
                        }
                        if count == 0 {
                            self.output.write_str("No selectable NICs. Use pci net to inspect detected devices.\r\n").ok();
                        } else {
                            self.output
                                .write_str(
                                    "nic select ethN changes the console selection only.\r\n",
                                )
                                .ok();
                        }
                    }
                    Ok(Command::Change(action)) => {
                        self.action = Some(action);
                        return;
                    }
                    Err(error) => {
                        write!(self.output, "NIC error: {error}\r\n").ok();
                    }
                }
            }
            _ => {
                self.output
                    .write_str("Unknown command. Type help.\r\n")
                    .ok();
            }
        }
        self.output.write_str(PROMPT).ok();
    }

    /// Format the scheduler's single snapshot without additional device reads.
    /// Canonical values are numbers, booleans and fixed ASCII labels, so no
    /// user-controlled string can inject a quote or an extra JSON member.
    fn setup_show(&mut self, status: Status) {
        self.output.write_str("{\"system\":[").ok();
        let mut first = true;
        for (index, interface) in status.interfaces.iter().enumerate() {
            let Some(interface) = interface else { continue };
            if !first {
                self.output.write_char(',').ok();
            }
            first = false;
            let config = interface.config;
            let (bus, device, function) = interface.bdf;
            write!(
                self.output,
                "{{\"Interface\":\"eth{index}\",\"PCI\":\"0000:{bus:02x}:{device:02x}.{function:x}\""
            )
            .ok();
            if let Some(mac) = interface.mac {
                let bytes = mac.to_le_bytes();
                write!(
                    self.output,
                    ",\"MAC\":\"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\"",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                )
                .ok();
            }
            write!(
                self.output,
                ",\"IPv4\":\"{}.{}.{}.{}/{}\",\"Gateway\":\"",
                config.address[0],
                config.address[1],
                config.address[2],
                config.address[3],
                config.prefix
            )
            .ok();
            if let Some(ip) = config.gateway {
                write!(self.output, "{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]).ok();
            } else {
                self.output.write_str("none").ok();
            }
            write!(
                self.output,
                "\",\"Echo\":{},\"Enabled\":{}}}",
                config.echo, interface.enabled
            )
            .ok();
        }
        self.output.write_str("]}\r\n").ok();
    }

    fn scan_step(&mut self) {
        let Some(scan) = self.scan.as_mut() else {
            return;
        };
        // At most 28 scanner reads plus class, header and BAR0 for one row.
        // Return after the first discovered function, even when filtered out.
        for _ in 0..28 {
            match scan.cursor.next_probe() {
                Some(None) => {}
                Some(Some(function)) => {
                    let class = function.class_code();
                    if scan.network_only && class >> 16 != 2 {
                        return;
                    }
                    let header = (function.read_u32(0x0c) >> 16) & 0x7f;
                    let bar = if header <= 1 {
                        function.read_u32(0x10)
                    } else {
                        0
                    };
                    let description = match (function.vendor_id(), function.device_id(), class >> 8)
                    {
                        (0x8086, 0x100e, _) => "Intel 82540EM / e1000 NIC",
                        (_, _, 0x0200) => "Ethernet controller",
                        (_, _, 0x0280) => "Network controller",
                        (_, _, 0x0600) => "Host bridge",
                        (_, _, 0x0601) => "ISA bridge",
                        (_, _, 0x0604) => "PCI bridge",
                        (_, _, 0x0106) => "SATA controller",
                        (_, _, 0x0300) => "VGA controller",
                        (_, _, 0x0c03) => "USB controller",
                        (_, _, 0x0c05) => "SMBus controller",
                        _ => "PCI device",
                    };
                    write!(
                        self.output,
                        "0000:{:02x}:{:02x}.{} {:04x}:{:04x}     {:06x} {:08x}   {}\r\n",
                        function.bus(),
                        function.device(),
                        function.function(),
                        function.vendor_id(),
                        function.device_id(),
                        class,
                        bar,
                        description
                    )
                    .ok();
                    scan.count += 1;
                    return;
                }
                None => {
                    write!(
                        self.output,
                        "{} PCI device(s). BAR0 is raw configuration, including flag bits.\r\n",
                        scan.count
                    )
                    .ok();
                    self.scan = None;
                    self.output.write_str(PROMPT).ok();
                    return;
                }
            }
        }
    }
}

/// Keep hardware diagnostics available when network startup fails closed.
pub fn run(console: &mut Console, clock: Option<&Clock>) -> ! {
    let mut shell = Shell::new();
    loop {
        if shell
            .poll(console, clock.map(Clock::now_millis), Status::unavailable())
            .is_some()
        {
            shell.complete_nic(Err(
                "Networking unavailable; startup requirements were not met.",
            ));
        }
        // UART IRQs are disabled: HLT would prevent input from waking us.
        core::hint::spin_loop();
    }
}
