//! Validated console requests for selecting and configuring network interfaces.

use crate::network_config::{CONFIG, NetworkConfig};

pub const MAX_INTERFACES: usize = 8;

// Keep the bounded eight-NIC request inline: this no-allocator kernel transfers
// one owned snapshot from the serial parser to the scheduler.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Set(NetworkConfig),
    Up,
    Down,
    Select(usize),
    Setup(crate::setup::Setup),
}

// Commands reuse the same fixed-size action without heap allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Show,
    List,
    Change(Action),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Unavailable,
    Up,
    Starting,
    Down,
    Quarantined,
}
impl State {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Up => "up",
            Self::Starting => "starting",
            Self::Down => "down",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Interface {
    pub bdf: (u8, u8, u8),
    /// Configured or last registered address, retained while administratively down.
    pub mac: Option<u64>,
    pub state: State,
    pub config: NetworkConfig,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub selected: Option<usize>,
    pub interfaces: [Option<Interface>; MAX_INTERFACES],
    pub config: NetworkConfig,
    pub state: State,
    pub mac: Option<u64>,
    pub bdf: Option<(u8, u8, u8)>,
    pub link_up: Option<bool>,
}
impl Status {
    pub const fn unavailable() -> Self {
        Self {
            selected: None,
            interfaces: [None; MAX_INTERFACES],
            config: CONFIG,
            state: State::Unavailable,
            mac: None,
            bdf: None,
            link_up: None,
        }
    }
}

const USAGE: &str =
    "Usage: nic [show|list|select ethN|up|down|set IP/PREFIX GATEWAY|none [echo on|off]]";

/// Parse the complete line before requesting any scheduler/hardware change.
/// There is no implicit subnet/gateway correction and no partial application.
pub fn parse(line: &[u8], current: NetworkConfig) -> Result<Command, &'static str> {
    let text = core::str::from_utf8(line).map_err(|_| USAGE)?;
    let mut words = text.split_ascii_whitespace();
    if words.next() != Some("nic") {
        return Err(USAGE);
    }
    match words.next() {
        None => Ok(Command::Show),
        Some("show") if words.next().is_none() => Ok(Command::Show),
        Some("list") if words.next().is_none() => Ok(Command::List),
        Some("select") => {
            let name = words.next().ok_or(USAGE)?.as_bytes();
            if words.next().is_some() {
                return Err(USAGE);
            }
            if name.len() != 4 || &name[..3] != b"eth" || !(b'0'..=b'7').contains(&name[3]) {
                return Err("Select an interface name from nic list (eth0 through eth7).");
            }
            Ok(Command::Change(Action::Select(usize::from(name[3] - b'0'))))
        }
        Some("up") if words.next().is_none() => Ok(Command::Change(Action::Up)),
        Some("down") if words.next().is_none() => Ok(Command::Change(Action::Down)),
        Some("set") => {
            let (address, prefix) = words.next().and_then(|s| s.split_once('/')).ok_or(USAGE)?;
            let gateway = words.next().ok_or(USAGE)?;
            let echo = match words.next() {
                None => {
                    if current.echo {
                        "1"
                    } else {
                        "0"
                    }
                }
                Some("echo") => match words.next() {
                    Some("on") => "1",
                    Some("off") => "0",
                    _ => return Err("Echo must be 'on' or 'off'."),
                },
                Some(_) => return Err(USAGE),
            };
            if words.next().is_some() {
                return Err(USAGE);
            }
            let config = NetworkConfig::parse(address, prefix, gateway, echo).map_err(|_| {
                "Invalid IPv4/prefix/gateway: use a unicast host address and a distinct gateway in the same subnet, or none."
            })?;
            Ok(Command::Change(Action::Set(config)))
        }
        _ => Err(USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_complete_configuration_and_preserves_unspecified_echo() {
        let current = NetworkConfig::parse("10.0.2.15", "24", "10.0.2.2", "0").unwrap();
        assert_eq!(parse(b" nic  show ", current), Ok(Command::Show));
        assert_eq!(
            parse(b"nic down", current),
            Ok(Command::Change(Action::Down))
        );
        assert_eq!(parse(b"nic up", current), Ok(Command::Change(Action::Up)));
        let expected = NetworkConfig::parse("192.168.1.5", "24", "192.168.1.1", "0").unwrap();
        assert_eq!(
            parse(b"nic set 192.168.1.5/24 192.168.1.1", current),
            Ok(Command::Change(Action::Set(expected)))
        );
        let expected = NetworkConfig::parse("192.168.1.5", "32", "none", "1").unwrap();
        assert_eq!(
            parse(b"nic set 192.168.1.5/32 none echo on", current),
            Ok(Command::Change(Action::Set(expected)))
        );
    }

    #[test]
    fn rejects_incomplete_extra_ambiguous_and_invalid_arguments() {
        for command in [
            "nic reset",
            "nic up now",
            "nic down ignored",
            "nic show extra",
            "nic set",
            "nic set 10.0.2.16 10.0.2.2",
            "nic set 10.0.2.16/24",
            "nic set 10.0.2.16/024 10.0.2.2",
            "nic set 10.0.2.16/0 none",
            "nic set 10.0.2.0/24 none",
            "nic set 10.0.2.255/24 none",
            "nic set 127.0.0.1/8 none",
            "nic set 224.0.0.1/24 none",
            "nic set 10.0.2.16/24 10.0.3.1",
            "nic set 10.0.2.16/24 10.0.2.16",
            "nic set 10.0.2.16/24 none echo",
            "nic set 10.0.2.16/24 none echo 1",
            "nic set 10.0.2.16/24 none echo on extra",
        ] {
            assert!(parse(command.as_bytes(), CONFIG).is_err(), "{command}");
        }
    }
}
