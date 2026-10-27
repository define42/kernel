//! Exercise the real shell with deterministic, nonblocking UART/PCI endpoints.

#[path = "../src/serial_output.rs"]
mod serial_output;

mod console {
    use std::collections::VecDeque;

    use crate::serial_output::Logs;

    pub struct Console {
        pub input: VecDeque<Result<u8, ()>>,
        pub output: Vec<u8>,
        pub blocked: bool,
        pub reads: usize,
        pub writes: usize,
        pub deferred: bool,
        pub logs: Logs,
    }
    impl Default for Console {
        fn default() -> Self {
            Self {
                input: VecDeque::new(),
                output: Vec::new(),
                blocked: false,
                reads: 0,
                writes: 0,
                deferred: false,
                logs: Logs::new(),
            }
        }
    }
    impl Console {
        pub fn defer_serial_logs(&mut self) {
            self.deferred = true;
        }
        pub fn drain_serial_logs(&mut self, budget: usize) -> bool {
            for _ in 0..budget {
                let Some(byte) = self.logs.peek() else { break };
                if !self.try_write_serial(byte) {
                    break;
                }
                self.logs.pop();
                if byte == b'\n' {
                    return true;
                }
            }
            self.logs.is_empty()
        }
        pub fn log(&mut self, text: &[u8]) {
            assert!(self.deferred, "shell must own serial output first");
            for byte in text {
                if *byte == b'\n' {
                    self.logs.push(b'\r');
                }
                self.logs.push(*byte);
            }
        }

        pub fn enqueue(&mut self, bytes: &[u8]) {
            self.input.extend(bytes.iter().copied().map(Ok));
        }
        pub fn read_serial(&mut self) -> Option<Result<u8, ()>> {
            self.reads += 1;
            self.input.pop_front()
        }
        pub fn try_write_serial(&mut self, byte: u8) -> bool {
            self.writes += 1;
            if self.blocked {
                return false;
            }
            self.output.push(byte);
            true
        }
    }
}

mod pci {
    use std::cell::RefCell;

    #[derive(Clone, Copy)]
    pub struct Function {
        pub slot: u8,
        pub network: bool,
    }
    #[derive(Default)]
    struct Bus {
        probes: Vec<Option<Function>>,
        reads: usize,
        scans: usize,
    }
    thread_local! { static BUS: RefCell<Bus> = RefCell::new(Bus::default()); }

    pub fn install(probes: Vec<Option<Function>>) {
        BUS.with(|bus| {
            *bus.borrow_mut() = Bus {
                probes,
                ..Bus::default()
            }
        });
    }
    pub fn reads() -> usize {
        BUS.with(|bus| bus.borrow().reads)
    }
    pub fn scans() -> usize {
        BUS.with(|bus| bus.borrow().scans)
    }
    impl Function {
        pub fn bus(self) -> u8 {
            self.slot / 32
        }
        pub fn device(self) -> u8 {
            self.slot % 32
        }
        pub fn function(self) -> u8 {
            0
        }
        pub fn vendor_id(self) -> u16 {
            if self.network { 0x8086 } else { 0x1234 }
        }
        pub fn device_id(self) -> u16 {
            if self.network { 0x100e } else { 0x1111 }
        }
        pub fn class_code(self) -> u32 {
            BUS.with(|bus| bus.borrow_mut().reads += 1);
            if self.network { 0x020000 } else { 0x030000 }
        }
        pub fn read_u32(self, offset: u8) -> u32 {
            BUS.with(|bus| bus.borrow_mut().reads += 1);
            match offset {
                0x0c => 0,
                0x10 => 0xf0000000 + u32::from(self.slot) * 0x20000,
                _ => panic!("unexpected shell PCI read: {offset:#x}"),
            }
        }
    }
    pub struct Scanner {
        cursor: usize,
    }
    impl Scanner {
        pub fn new() -> Self {
            BUS.with(|bus| bus.borrow_mut().scans += 1);
            Self { cursor: 0 }
        }
        pub fn next_probe(&mut self) -> Option<Option<Function>> {
            BUS.with(|bus| {
                let mut bus = bus.borrow_mut();
                let probe = bus.probes.get(self.cursor).copied()?;
                bus.reads += 1;
                self.cursor += 1;
                Some(probe)
            })
        }
    }
}

#[allow(dead_code)]
mod time {
    pub struct Clock;
    impl Clock {
        pub fn now_millis(&self) -> i64 {
            0
        }
    }
}

#[path = "../userspace/network_config.rs"]
mod network_config;
#[allow(dead_code)]
#[path = "../src/nic.rs"]
mod nic;

#[allow(dead_code)]
#[path = "../src/setup.rs"]
mod setup;

#[allow(dead_code)]
#[path = "../src/shell.rs"]
mod shell;
#[path = "../src/shell_input.rs"]
mod shell_input;

use console::Console;
use network_config::NetworkConfig;
use nic::{Action, Interface, State, Status};
use shell::Shell;

const BANNER: &str = "\r\nSerial console: COM1 115200 8N1. Type help.\r\nkernel> ";
const HELP: &str = "help      Show commands\r\npci       List PCI devices (alias: lspci)\r\npci net   List network controllers\r\nuptime    Milliseconds since clock initialization\r\nnic       Show NIC status (nic show)\r\nnic list|select ethN  Choose NIC to configure\r\nnic set IP/PREFIX GATEWAY|none [echo on|off]\r\nnic up|down  Enable or stop selected NIC\r\nsetup     Configure interfaces with JSON (setup help)\r\nChanges last until reboot; setting an address closes its connections.\r\nCtrl-C cancels a line or PCI scan; Backspace edits.\r\n";

fn poll(shell: &mut Shell, console: &mut Console, now: Option<i64>) {
    assert_eq!(
        poll_status(shell, console, now, Status::unavailable()),
        None
    );
}

fn poll_status(
    shell: &mut Shell,
    console: &mut Console,
    now: Option<i64>,
    status: Status,
) -> Option<Action> {
    let before = (console.reads, console.writes, pci::reads());
    let action = shell.poll(console, now, status);
    assert!(console.reads - before.0 <= 16, "unbounded UART input work");
    assert!(
        console.writes - before.1 <= 32,
        "unbounded UART output work"
    );
    assert!(pci::reads() - before.2 <= 31, "unbounded PCI work");
    action
}

fn settle(shell: &mut Shell, console: &mut Console, now: Option<i64>) {
    let mut idle = 0;
    for _ in 0..10_000 {
        let before = (console.input.len(), console.output.len(), pci::reads());
        poll(shell, console, now);
        if before == (console.input.len(), console.output.len(), pci::reads()) {
            idle += 1;
            // A scan's completion can enqueue text without doing I/O; allow
            // the following pass to drain it before declaring the shell idle.
            if idle == 2 {
                assert!(console.input.is_empty());
                return;
            }
        } else {
            idle = 0;
        }
    }
    panic!("shell failed to settle within bounded host test");
}

#[test]
fn blocked_transmit_stops_input_and_scanning_then_resumes() {
    pci::install(
        (0..96)
            .map(|slot| {
                Some(pci::Function {
                    slot,
                    network: true,
                })
            })
            .collect(),
    );
    let mut shell = Shell::new();
    let mut console = Console {
        blocked: true,
        ..Console::default()
    };
    console.enqueue(b"pci\n");
    for _ in 0..100 {
        poll(&mut shell, &mut console, None);
    }
    assert!(
        pci::reads() > 0 && pci::reads() < 96 * 4,
        "scan must pause before completion"
    );
    assert!(console.output.is_empty());
    console.enqueue(b"help\n");
    let paused = (console.input.len(), console.reads, pci::reads());
    for _ in 0..100 {
        poll(&mut shell, &mut console, None);
    }
    assert_eq!(paused, (console.input.len(), console.reads, pci::reads()));
    console.blocked = false;
    settle(&mut shell, &mut console, None);
    let output = String::from_utf8(console.output).unwrap();
    assert_eq!(pci::scans(), 1);
    assert_eq!(pci::reads(), 96 * 4);
    assert_eq!(output.matches("Intel 82540EM / e1000 NIC\r\n").count(), 96);
    assert!(output.contains("PCI scan in progress; Ctrl-C cancels.\r\n"));
    assert!(output.ends_with(
        "96 PCI device(s). BAR0 is raw configuration, including flag bits.\r\nkernel> "
    ));
}

#[test]
fn queued_responses_survive_repeated_backpressure_and_ring_wrap() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let mut expected = String::from(BANNER);
    // Long commands and help responses repeatedly cross the 4096-byte
    // ring boundary and fill it near the response reserve. Compare the full
    // wire transcript so dropped fmt writes, duplication and reordering fail.
    for _ in 0..120 {
        console.enqueue(b"help\r\n");
        expected.push_str("help\r\n");
        expected.push_str(HELP);
        expected.push_str("kernel> ");
        console.enqueue(b"uptime\n");
        expected.push_str("uptime\r\nUptime: 9223372036854775807 ms\r\nkernel> ");
        console.enqueue(&[b'?'; shell_input::CAPACITY]);
        console.enqueue(b"\n");
        expected.push_str(&"?".repeat(shell_input::CAPACITY));
        expected.push_str("\r\nUnknown command. Type help.\r\nkernel> ");
        console.enqueue(&[b'x'; shell_input::CAPACITY + 1]);
        console.enqueue(b"\n");
        expected.push_str(&"x".repeat(shell_input::CAPACITY));
        expected.push_str("\r\nLine too long (maximum 2048 bytes); discarded.\r\nkernel> ");
    }
    for pass in 0..100_000 {
        console.blocked = pass % 13 < 8;
        poll(&mut shell, &mut console, Some(i64::MAX));
        assert!(
            console.output.len() <= expected.len(),
            "duplicated queued output"
        );
        if console.input.is_empty() && console.output.len() == expected.len() {
            break;
        }
    }
    console.blocked = false;
    settle(&mut shell, &mut console, Some(i64::MAX));
    assert!(expected.len() > 32 * 2048);
    assert_eq!(console.output, expected.as_bytes());
    assert_eq!(pci::scans(), 0);
}

#[test]
fn uart_error_prevents_command_execution_and_next_line_recovers() {
    pci::install(vec![
        Some(pci::Function {
            slot: 1,
            network: false,
        }),
        Some(pci::Function {
            slot: 2,
            network: true,
        }),
    ]);
    let mut shell = Shell::new();
    let mut console = Console::default();
    console.enqueue(b"pci");
    console.input.push_back(Err(()));
    console.enqueue(b"\r\nuptime\npci net\n");
    settle(&mut shell, &mut console, Some(42));
    let output = String::from_utf8(console.output).unwrap();
    assert_eq!(
        pci::scans(),
        1,
        "corrupted pci command must never create a scan"
    );
    assert_eq!(
        output
            .matches("Invalid serial input; line discarded.")
            .count(),
        1
    );
    assert!(output.contains("Uptime: 42 ms\r\n"));
    assert!(!output.contains("VGA controller"));
    assert_eq!(output.matches("Intel 82540EM / e1000 NIC").count(), 1);
    assert!(
        output.ends_with(
            "1 PCI device(s). BAR0 is raw configuration, including flag bits.\r\nkernel> "
        )
    );
}

#[test]
fn ctrl_c_cancels_active_scan_before_more_pci_probes() {
    pci::install(vec![None; 2000]);
    let mut shell = Shell::new();
    let mut console = Console::default();
    console.enqueue(b"pci\n");
    poll(&mut shell, &mut console, None);
    let scanned = pci::reads();
    assert_eq!(scanned, 28);
    console.enqueue(b"\x03help\nuptime\n");
    settle(&mut shell, &mut console, None);
    let output = String::from_utf8(console.output).unwrap();
    assert_eq!(
        pci::reads(),
        scanned,
        "cancelled scan performed another PCI read"
    );
    assert_eq!(pci::scans(), 1);
    assert!(output.contains("^C\r\nkernel> help\r\n"));
    assert!(output.contains(HELP));
    assert!(output.contains("Uptime unavailable: clock not initialized.\r\n"));
    assert!(!output.contains("PCI device(s)."));
    assert!(output.ends_with("kernel> "));
}

fn configured_status() -> Status {
    Status {
        selected: Some(0),
        interfaces: [
            Some(Interface {
                bdf: (0, 2, 0),
                state: State::Up,
                config: NetworkConfig::parse("10.0.2.15", "24", "10.0.2.2", "1").unwrap(),
                enabled: true,
                mac: Some(0x5634_1200_5452),
            }),
            Some(Interface {
                bdf: (0, 3, 0),
                state: State::Down,
                config: NetworkConfig::parse("192.168.1.5", "24", "none", "0").unwrap(),
                enabled: false,
                mac: Some(0x5734_1200_5452),
            }),
            None,
            None,
            None,
            None,
            None,
            None,
        ],
        config: NetworkConfig::parse("10.0.2.15", "24", "10.0.2.2", "1").unwrap(),
        state: State::Up,
        mac: Some(0x5634_1200_5452),
        bdf: Some((0, 2, 0)),
        link_up: Some(true),
    }
}

fn command_status(
    shell: &mut Shell,
    console: &mut Console,
    status: Status,
    line: &[u8],
) -> Option<Action> {
    console.enqueue(line);
    let mut requested = None;
    let mut idle = 0;
    for _ in 0..10_000 {
        let before = (console.input.len(), console.output.len());
        if let Some(action) = poll_status(shell, console, Some(42), status) {
            assert!(
                requested.is_none(),
                "one line requested more than one change"
            );
            requested = Some(action);
            shell.complete_nic(Ok("test completion"));
        }
        if before == (console.input.len(), console.output.len()) {
            idle += 1;
            if idle == 2 {
                assert!(console.input.is_empty());
                return requested;
            }
        } else {
            idle = 0;
        }
    }
    panic!("NIC command did not finish within bounded host test");
}

#[test]
fn nic_show_reads_one_complete_snapshot_without_requesting_a_change() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let mut status = configured_status();
    for (state, label) in [
        (State::Up, "up"),
        (State::Starting, "starting"),
        (State::Down, "down"),
        (State::Quarantined, "quarantined"),
    ] {
        status.state = state;
        console.output.clear();
        assert_eq!(
            command_status(&mut shell, &mut console, status, b"nic show\r"),
            None
        );
        let output = String::from_utf8(console.output.clone()).unwrap();
        assert!(output.contains(&format!("NIC: {label}\r\nIPv4: 10.0.2.15/24\r\nGateway: 10.0.2.2\r\nEcho: on\r\nMAC: 52:54:00:12:34:56\r\nPCI: 0000:00:02.0\r\nLink: up\r\n")));
        assert!(output.contains("Interface: eth0\r\n"));
        assert!(output.ends_with("kernel> "));
    }
    assert_eq!(
        pci::reads(),
        0,
        "status must not bypass the scheduler's snapshot"
    );
}

#[test]
fn nic_configuration_emits_one_complete_action_and_invalid_lines_emit_none() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let mut status = configured_status();
    let desired = NetworkConfig::parse("10.0.2.16", "24", "10.0.2.2", "0").unwrap();
    assert_eq!(
        command_status(
            &mut shell,
            &mut console,
            status,
            b"nic set 10.0.2.16/24 10.0.2.2 echo off\r\n"
        ),
        Some(Action::Set(desired))
    );
    status.config = desired;
    let without_gateway = NetworkConfig::parse("10.0.2.17", "24", "none", "0").unwrap();
    assert_eq!(
        command_status(
            &mut shell,
            &mut console,
            status,
            b"nic set 10.0.2.17/24 none\r"
        ),
        Some(Action::Set(without_gateway))
    );
    for line in [
        &b"nic set 10.0.2.0/24 10.0.2.2\r"[..],
        b"nic set 10.0.2.16/24 192.168.1.1\r",
        b"nic set 10.0.2.16/24 none echo maybe\r",
        b"nic set 10.0.2.16/24 none echo on extra\r",
    ] {
        console.output.clear();
        assert_eq!(command_status(&mut shell, &mut console, status, line), None);
        assert!(String::from_utf8_lossy(&console.output).contains("NIC error:"));
        assert_eq!(
            command_status(&mut shell, &mut console, status, b"nic\r"),
            None
        );
        let output = String::from_utf8_lossy(&console.output);
        assert!(output.contains("IPv4: 10.0.2.16/24\r\nGateway: 10.0.2.2\r\nEcho: off"));
    }
}

#[test]
fn nic_actions_wait_for_completion_before_consuming_another_command() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let status = configured_status();
    settle(&mut shell, &mut console, None);
    console.output.clear();
    console.enqueue(b"nic down\rnic up\r");
    assert_eq!(
        poll_status(&mut shell, &mut console, None, status),
        Some(Action::Down)
    );
    let waiting = (console.input.len(), console.reads);
    for _ in 0..100 {
        assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    }
    assert_eq!((console.input.len(), console.reads), waiting);
    assert!(!String::from_utf8_lossy(&console.output).contains("kernel> "));
    shell.complete_nic(Err("test refusal"));
    assert_eq!(
        poll_status(&mut shell, &mut console, None, status),
        Some(Action::Up)
    );
    shell.complete_nic(Ok("test restart"));
    shell.complete_nic(Ok("duplicate completion must be ignored"));
    settle(&mut shell, &mut console, None);
    assert_eq!(
        String::from_utf8_lossy(&console.output),
        "nic down\r\nNIC error: test refusal\r\nkernel> nic up\r\nNIC: test restart\r\nkernel> "
    );
}

#[test]
fn corrupt_and_overlong_nic_commands_never_request_hardware_changes() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let status = configured_status();
    console.enqueue(b"nic down");
    console.input.push_back(Err(()));
    console.enqueue(b"\r");
    assert_eq!(command_status(&mut shell, &mut console, status, b""), None);
    let mut overlong = b"nic down".to_vec();
    overlong.resize(shell_input::CAPACITY + 1, b' ');
    overlong.push(b'\r');
    assert_eq!(
        command_status(&mut shell, &mut console, status, &overlong),
        None
    );
    assert_eq!(
        command_status(&mut shell, &mut console, status, b"nic up\x1b[Ax\r"),
        None
    );
    let output = String::from_utf8_lossy(&console.output);
    assert_eq!(
        output
            .matches("Invalid serial input; line discarded.")
            .count(),
        2
    );
    assert_eq!(output.matches("Line too long").count(), 1);
    assert!(!output.contains("test completion"));
    assert_eq!(
        command_status(&mut shell, &mut console, status, b"nic down\r"),
        Some(Action::Down)
    );
}

#[test]
fn nic_list_reports_independent_states_and_console_selection() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let mut status = configured_status();
    status.selected = Some(1);
    assert_eq!(
        command_status(&mut shell, &mut console, status, b"nic list\r"),
        None
    );
    let output = String::from_utf8_lossy(&console.output);
    assert!(output.contains("eth0 0000:00:02.0 8086:100e up\r\n"));
    assert!(output.contains("eth1 0000:00:03.0 8086:100e down selected\r\n"));
    assert_eq!(output.matches(" selected\r\n").count(), 1);
    assert_eq!(pci::reads(), 0);
}

#[test]
fn nic_list_keeps_all_eight_entries_during_output_backpressure() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    settle(&mut shell, &mut console, None);
    console.output.clear();
    let mut status = configured_status();
    status.selected = Some(7);
    status.interfaces = core::array::from_fn(|index| {
        Some(Interface {
            bdf: (0, index as u8 + 2, 0),
            state: State::Quarantined,
            config: status.config,
            enabled: true,
            mac: None,
        })
    });
    for _ in 0..30 {
        console.enqueue(b"nic list\r");
    }
    console.blocked = true;
    for _ in 0..100 {
        assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    }
    assert!(
        !console.input.is_empty(),
        "list output must apply backpressure"
    );
    let paused = (console.input.len(), console.reads);
    for _ in 0..100 {
        assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    }
    assert_eq!((console.input.len(), console.reads), paused);
    console.blocked = false;
    assert_eq!(command_status(&mut shell, &mut console, status, b""), None);
    let output = String::from_utf8_lossy(&console.output);
    assert_eq!(output.matches("NIC interfaces:\r\n").count(), 30);
    for index in 0..nic::MAX_INTERFACES {
        let label = if index == 7 { " selected" } else { "" };
        let row = format!(
            "eth{index} 0000:00:{:02x}.0 8086:100e quarantined{label}\r\n",
            index + 2
        );
        assert_eq!(
            output.matches(&row).count(),
            30,
            "missing or duplicated interface row"
        );
    }
    assert_eq!(
        output
            .matches("nic select ethN changes the console selection only.\r\nkernel> ")
            .count(),
        30
    );
    assert_eq!(pci::reads(), 0, "nic list must use the captured inventory");
}

#[test]
fn nic_selection_emits_strict_indices_without_changing_the_status_snapshot() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let status = configured_status();
    for index in [0, 1, 7] {
        assert_eq!(
            command_status(
                &mut shell,
                &mut console,
                status,
                format!("nic select eth{index}\r").as_bytes()
            ),
            Some(Action::Select(index))
        );
    }
    for command in [
        &b"nic select\r"[..],
        b"nic select eth8\r",
        b"nic select eth01\r",
        b"nic select Eth1\r",
        b"nic select eth-1\r",
        b"nic select eth1 extra\r",
    ] {
        console.output.clear();
        assert_eq!(
            command_status(&mut shell, &mut console, status, command),
            None
        );
        assert!(String::from_utf8_lossy(&console.output).contains("NIC error:"));
        assert_eq!(
            command_status(&mut shell, &mut console, status, b"nic show\r"),
            None
        );
        let output = String::from_utf8_lossy(&console.output);
        assert!(output.contains("Interface: eth0\r\n"));
        assert!(output.contains("IPv4: 10.0.2.15/24\r\nGateway: 10.0.2.2\r\nEcho: on"));
    }
    console.output.clear();
    assert_eq!(
        command_status(
            &mut shell,
            &mut console,
            Status::unavailable(),
            b"nic list\r"
        ),
        None
    );
    assert!(
        String::from_utf8_lossy(&console.output)
            .contains("No selectable NICs. Use pci net to inspect detected devices.")
    );
}

#[test]
fn setup_show_reads_all_settings_from_one_snapshot() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let status = configured_status();
    assert_eq!(
        command_status(&mut shell, &mut console, status, b"setup show\r"),
        None
    );
    let output = String::from_utf8_lossy(&console.output);
    let json = r#"{"system":[{"Interface":"eth0","PCI":"0000:00:02.0","MAC":"52:54:00:12:34:56","IPv4":"10.0.2.15/24","Gateway":"10.0.2.2","Echo":true,"Enabled":true},{"Interface":"eth1","PCI":"0000:00:03.0","MAC":"52:54:00:12:34:57","IPv4":"192.168.1.5/24","Gateway":"none","Echo":false,"Enabled":false}]}"#;
    assert!(output.contains(&format!("\r\n{json}\r\nkernel> ")));
    assert!(setup::parse(json.as_bytes()).is_ok());
    assert_eq!(pci::reads(), 0);
    console.output.clear();
    assert_eq!(
        command_status(
            &mut shell,
            &mut console,
            Status::unavailable(),
            b"setup show\r"
        ),
        None
    );
    assert_eq!(
        String::from_utf8_lossy(&console.output),
        "setup show\r\n{\"system\":[]}\r\nkernel> "
    );
}

#[test]
fn setup_help_and_invalid_documents_do_not_request_changes() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let status = configured_status();
    for line in [b"setup\r".as_slice(), b"setup help\r"] {
        assert_eq!(command_status(&mut shell, &mut console, status, line), None);
        let output = String::from_utf8_lossy(&console.output);
        assert!(output.contains("setup show  Read all interface settings as JSON"));
        assert!(output.contains("\"IPv4\":\"10.0.2.15/24\""));
        assert!(output.contains("\"MAC\":\"52:54:00:12:34:56\""));
        assert!(output.contains("\"PCI\":\"0000:00:02.0\""));
        assert!(output.contains("Select by Interface or PCI; both must identify the same NIC."));
        assert!(output.contains("MAC sets its unicast Ethernet address."));
        assert!(output.contains("Changes last until reboot."));
        console.output.clear();
    }
    for json in [
        r#"{"system":[{"Interface":"eth0","IPv4":"IPv4","Gateway":"10.0.2.2"}]}"#,
        r#"{"system":[{"Interface":"eth0","Echo":false},{"Interface":"eth1","Echo":"on"}]}"#,
        r#"{"system":[{"Interface":"eth0","Enabled":false}]} trailing"#,
        r#"{"system":[{"Interface":"eth0","Enabled":false},{"Interface":"eth0","Enabled":true}]}"#,
        r#"{"system":[{"Interface":"eth0","Enabled":false}],"unknown":false}"#,
        "show extra",
        "help extra",
    ] {
        assert_eq!(
            command_status(
                &mut shell,
                &mut console,
                status,
                format!("setup {json}\r").as_bytes()
            ),
            None,
            "invalid document submitted a request: {json}"
        );
        assert!(String::from_utf8_lossy(&console.output).contains("Setup error:"));
        assert!(!String::from_utf8_lossy(&console.output).contains("test completion"));
        console.output.clear();
    }
}

#[test]
fn setup_submits_one_batch_and_waits_for_completion_before_reading_more() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    settle(&mut shell, &mut console, None);
    console.output.clear();
    let status = configured_status();
    let json = br#"{"system":[{"Interface":"eth1","IPv4":"192.168.1.6/24","Gateway":"none","Echo":true,"Enabled":true},{"Interface":"eth0","Echo":false}]}"#;
    let expected = Action::Setup(setup::parse(json).unwrap());
    console.enqueue(b"setup ");
    console.enqueue(json);
    console.enqueue(b"\rnic down\r");
    let mut submitted = None;
    for _ in 0..100 {
        submitted = poll_status(&mut shell, &mut console, None, status);
        if submitted.is_some() {
            break;
        }
    }
    assert_eq!(submitted, Some(expected));
    assert_eq!(console.input.len(), b"nic down\r".len());
    let waiting = (console.input.len(), console.reads);
    for _ in 0..100 {
        assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    }
    assert_eq!((console.input.len(), console.reads), waiting);
    assert!(!String::from_utf8_lossy(&console.output).contains("kernel> "));
    shell.complete_nic(Err("test setup refusal"));
    assert_eq!(
        poll_status(&mut shell, &mut console, None, status),
        Some(Action::Down)
    );
    shell.complete_nic(Ok("test down"));
    shell.complete_nic(Ok("duplicate completion must be ignored"));
    settle(&mut shell, &mut console, None);
    let output = String::from_utf8_lossy(&console.output);
    assert!(output.ends_with(
        "Setup error: test setup refusal\r\nkernel> nic down\r\nNIC: test down\r\nkernel> "
    ));
    console.output.clear();
    let line = format!("setup {}\r", core::str::from_utf8(json).unwrap());
    assert_eq!(
        command_status(&mut shell, &mut console, status, line.as_bytes()),
        Some(expected)
    );
    assert!(
        String::from_utf8_lossy(&console.output).ends_with("Setup: test completion\r\nkernel> ")
    );
}

#[test]
fn corrupt_or_overlong_setup_cannot_apply_a_valid_prefix() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let status = configured_status();
    let valid = br#"setup {"system":[{"Interface":"eth0","Enabled":false}]}"#;
    console.enqueue(valid);
    console.input.push_back(Err(()));
    console.enqueue(b"\r");
    assert_eq!(command_status(&mut shell, &mut console, status, b""), None);
    let mut overflow = valid.to_vec();
    overflow.resize(shell_input::CAPACITY + 1, b' ');
    overflow.extend_from_slice(b"\x08\x7f\r");
    assert_eq!(
        command_status(&mut shell, &mut console, status, &overflow),
        None
    );
    let output = String::from_utf8_lossy(&console.output);
    assert_eq!(
        output
            .matches("Invalid serial input; line discarded.")
            .count(),
        1
    );
    assert_eq!(
        output.matches("Line too long (maximum 2048 bytes)").count(),
        1
    );
    assert!(!output.contains("test completion"));
    let mut boundary = valid.to_vec();
    boundary.resize(shell_input::CAPACITY, b' ');
    boundary.push(b'\r');
    assert_eq!(
        command_status(&mut shell, &mut console, status, &boundary),
        Some(Action::Setup(
            setup::parse(&valid[b"setup ".len()..]).unwrap()
        ))
    );
}

#[test]
fn setup_show_keeps_eight_complete_rows_under_backpressure() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    settle(&mut shell, &mut console, None);
    console.output.clear();
    let mut status = configured_status();
    let config = NetworkConfig::parse("223.255.255.254", "30", "223.255.255.253", "0").unwrap();
    status.interfaces = core::array::from_fn(|index| {
        Some(Interface {
            bdf: (255, index as u8 + 24, 7),
            state: State::Down,
            config,
            enabled: false,
            mac: Some(u64::from_le_bytes([
                2,
                index as u8,
                255,
                255,
                255,
                255,
                0,
                0,
            ])),
        })
    });
    let rows: Vec<_> = (0..nic::MAX_INTERFACES).map(|index| format!(
        "{{\"Interface\":\"eth{index}\",\"PCI\":\"0000:ff:{:02x}.7\",\"MAC\":\"02:{index:02x}:ff:ff:ff:ff\",\"IPv4\":\"223.255.255.254/30\",\"Gateway\":\"223.255.255.253\",\"Echo\":false,\"Enabled\":false}}", index + 24
    )).collect();
    let json = format!("{{\"system\":[{}]}}", rows.join(","));
    assert!(setup::parse(json.as_bytes()).is_ok());
    let transcript = format!("setup show\r\n{json}\r\nkernel> ").repeat(30);
    for _ in 0..30 {
        console.enqueue(b"setup show\r");
    }
    console.blocked = true;
    for _ in 0..100 {
        assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    }
    assert!(
        !console.input.is_empty(),
        "JSON output must apply backpressure"
    );
    let paused = (console.input.len(), console.reads);
    for _ in 0..100 {
        assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    }
    assert_eq!((console.input.len(), console.reads), paused);
    console.blocked = false;
    assert_eq!(command_status(&mut shell, &mut console, status, b""), None);
    assert_eq!(console.output, transcript.as_bytes());
    assert_eq!(pci::reads(), 0);

    // The complete response is captured when the command is accepted. A
    // status change on later polls cannot splice two configurations together.
    console.output.clear();
    console.enqueue(b"setup show\r");
    assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    assert_eq!(
        command_status(&mut shell, &mut console, Status::unavailable(), b""),
        None
    );
    assert_eq!(
        console.output,
        format!("setup show\r\n{json}\r\nkernel> ").as_bytes()
    );
    let command = format!("setup {json}\r");
    assert!(command.len() > 128 && command.len() <= shell_input::CAPACITY);
    assert_eq!(
        command_status(&mut shell, &mut console, status, command.as_bytes()),
        Some(Action::Setup(setup::parse(json.as_bytes()).unwrap()))
    );
}

#[test]
fn setup_show_omits_unknown_mac_without_inventing_an_address() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let mut status = configured_status();
    status.interfaces[0].as_mut().unwrap().mac = None;
    status.interfaces[1] = None;
    assert_eq!(
        command_status(&mut shell, &mut console, status, b"setup show\r"),
        None
    );
    let output = String::from_utf8_lossy(&console.output);
    let json = r#"{"system":[{"Interface":"eth0","PCI":"0000:00:02.0","IPv4":"10.0.2.15/24","Gateway":"10.0.2.2","Echo":true,"Enabled":true}]}"#;
    assert!(output.contains(&format!("\r\n{json}\r\nkernel> ")));
    assert!(!output.contains("MAC"));
    assert_eq!(
        setup::parse(json.as_bytes()).unwrap().entries[0]
            .unwrap()
            .mac,
        None
    );
    assert_eq!(pci::reads(), 0);
}

#[test]
fn setup_accepts_pci_selected_mac_changes_as_one_validated_request() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let status = configured_status();
    let request = br#"setup {"system":[{"PCI":"0000:00:03.0","MAC":"02:54:00:12:34:59"}]}"#;
    let mut command = request.to_vec();
    command.push(b'\r');
    let Some(Action::Setup(parsed)) = command_status(&mut shell, &mut console, status, &command)
    else {
        panic!("PCI-selected MAC change must submit a setup action");
    };
    let update = parsed.entries[0].unwrap();
    assert_eq!(update.interface, None);
    assert_eq!(update.pci, Some((0, 0, 3, 0)));
    assert_eq!(update.mac, Some(0x5934_1200_5402));
    assert!(parsed.entries[1..].iter().all(Option::is_none));
    assert!(
        String::from_utf8_lossy(&console.output).ends_with("Setup: test completion\r\nkernel> ")
    );
    assert_eq!(pci::reads(), 0);
}

#[test]
fn asynchronous_logs_wait_until_the_setup_json_response_is_complete() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let status = configured_status();
    settle(&mut shell, &mut console, None);
    console.output.clear();
    console.enqueue(b"setup show\r");
    assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    console.log(b"e1000: link up\n");
    assert_eq!(command_status(&mut shell, &mut console, status, b""), None);
    let output = String::from_utf8_lossy(&console.output);
    let json = output
        .lines()
        .find(|line| line.starts_with(r#"{"system":"#))
        .unwrap();
    assert!(
        setup::parse(json.as_bytes()).is_ok(),
        "interleaved JSON: {output}"
    );
    assert!(output.ends_with("}\r\nkernel> e1000: link up\r\n"));
    assert_eq!(output.matches("e1000: link up").count(), 1);
}

#[test]
fn deferred_log_backpressure_and_overflow_do_not_split_the_next_response() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let status = configured_status();
    settle(&mut shell, &mut console, None);
    console.output.clear();
    console.blocked = true;
    console.log(&b"overflow line\n".repeat(1024));
    console.enqueue(b"setup show\r");
    let before = console.input.len();
    for _ in 0..100 {
        assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    }
    assert_eq!(console.input.len(), before);
    console.blocked = false;
    assert_eq!(command_status(&mut shell, &mut console, status, b""), None);
    let output = String::from_utf8_lossy(&console.output);
    assert!(output.starts_with("overflow line\r\nsetup show\r\n"));
    let json = output
        .lines()
        .find(|line| line.starts_with(r#"{"system":"#))
        .unwrap();
    assert!(setup::parse(json.as_bytes()).is_ok());
    assert!(output.contains("}\r\nkernel> "));
    assert_eq!(
        output
            .matches("[serial log overflow; output dropped]")
            .count(),
        1
    );
}

#[test]
fn deferred_logs_drain_while_a_nic_action_is_awaiting_completion() {
    pci::install(Vec::new());
    let mut shell = Shell::new();
    let mut console = Console::default();
    let status = configured_status();
    settle(&mut shell, &mut console, None);
    console.output.clear();
    console.enqueue(b"nic up\rhelp\r");
    assert_eq!(
        poll_status(&mut shell, &mut console, None, status),
        Some(Action::Up)
    );
    console.log(b"Service e1000 restarted\n");
    let pending = (console.input.len(), console.reads);
    for _ in 0..100 {
        assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
    }
    assert_eq!((console.input.len(), console.reads), pending);
    assert_eq!(console.output, b"nic up\r\nService e1000 restarted\r\n");
}

#[test]
fn continuous_log_writers_cannot_starve_setup_show() {
    for payload in [b"continuous service log\n".repeat(64), vec![b'x'; 64]] {
        pci::install(Vec::new());
        let mut shell = Shell::new();
        let mut console = Console::default();
        let status = configured_status();
        settle(&mut shell, &mut console, None);
        console.output.clear();
        console.enqueue(b"setup show\r");
        let mut completed = false;
        for _ in 0..200 {
            console.log(&payload);
            assert_eq!(poll_status(&mut shell, &mut console, None, status), None);
            if console
                .output
                .windows(b"}\r\nkernel> ".len())
                .any(|bytes| bytes == b"}\r\nkernel> ")
            {
                completed = true;
                break;
            }
        }
        assert!(completed, "continuous logging starved setup show");
        let output = String::from_utf8_lossy(&console.output);
        let json = output
            .lines()
            .find(|line| line.starts_with(r#"{"system":"#))
            .unwrap();
        assert!(
            setup::parse(json.as_bytes()).is_ok(),
            "interleaved JSON: {output}"
        );
    }
}
