//! Bounded, allocation-free JSON updates for the trusted serial console.
//!
//! The schema is fixed and uses ASCII identifiers and values. JSON escapes,
//! including ASCII `\uXXXX`, are decoded before duplicate-key/name checks.
//! Parsing never changes live configuration; callers must resolve and preflight
//! every requested interface before applying any update.

use crate::network_config::NetworkConfig;
use crate::nic::MAX_INTERFACES;

pub const MAX_INPUT: usize = 2048;
const MAX_STRING: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setup {
    /// Packed requests in JSON array order; selectors are resolved during preflight.
    pub entries: [Option<Update>; MAX_INTERFACES],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Update {
    pub interface: Option<usize>,
    pub pci: Option<(u16, u8, u8, u8)>,
    pub mac: Option<u64>,
    pub address: Option<[u8; 4]>,
    pub prefix: Option<u8>,
    /// `None` preserves the gateway; `Some(None)` removes it.
    pub gateway: Option<Option<[u8; 4]>>,
    pub echo: Option<bool>,
    pub enabled: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub mac: Option<u64>,
    pub config: NetworkConfig,
    pub enabled: bool,
}

impl Update {
    /// Merge omitted fields with this interface's current settings, then apply
    /// the same address/subnet/gateway validation as the userspace ABI.
    pub fn resolve(
        self,
        current: NetworkConfig,
        admin_up: bool,
        current_mac: Option<u64>,
    ) -> Result<Target, &'static str> {
        let mac = self.mac.or(current_mac);
        if mac.is_some_and(|value| !valid_mac(value)) {
            return Err("Setup MAC must be a nonzero unicast 48-bit address.");
        }
        let config = NetworkConfig {
            address: self.address.unwrap_or(current.address),
            prefix: self.prefix.unwrap_or(current.prefix),
            gateway: self.gateway.unwrap_or(current.gateway),
            echo: self.echo.unwrap_or(current.echo),
        };
        let config = NetworkConfig::from_wire(config.to_wire()).map_err(|_| {
            "Invalid setup IPv4/prefix/gateway: use a unicast host and a distinct gateway in the same subnet, or null."
        })?;
        Ok(Target {
            mac,
            config,
            enabled: self.enabled.unwrap_or(admin_up),
        })
    }
}

/// Parse raw JSON (without the `setup` command word), with a fixed input, string,
/// and interface limit. No unknown keys, duplicates, or trailing data are
/// accepted. A partial update is validated against current settings by resolve.
pub fn parse(input: &[u8]) -> Result<Setup, &'static str> {
    if input.len() > MAX_INPUT {
        return Err("Setup JSON exceeds 2048 bytes.");
    }
    let mut parser = Parser { input, cursor: 0 };
    parser.expect(b'{')?;
    if parser.string()?.bytes() != b"system" {
        return Err("Setup requires a single top-level 'system' array.");
    }
    parser.expect(b':')?;
    parser.expect(b'[')?;
    if parser.consume(b']') {
        return Err("Setup system array must contain at least one interface update.");
    }
    let mut setup = Setup {
        entries: [None; MAX_INTERFACES],
    };
    let mut count = 0;
    loop {
        if count == MAX_INTERFACES {
            return Err("Setup supports at most eight interface updates.");
        }
        let update = parser.update()?;
        for previous in setup.entries[..count].iter().flatten() {
            if update.interface.is_some() && update.interface == previous.interface {
                return Err("Setup must not repeat an interface.");
            }
            if update.pci.is_some() && update.pci == previous.pci {
                return Err("Setup must not repeat a PCI device.");
            }
        }
        setup.entries[count] = Some(update);
        count += 1;
        if parser.consume(b']') {
            break;
        }
        parser.expect(b',')?;
    }
    parser.expect(b'}')?;
    parser.whitespace();
    if parser.cursor != input.len() {
        return Err("Unexpected data after setup JSON.");
    }
    Ok(setup)
}

struct JsonString {
    data: [u8; MAX_STRING],
    len: usize,
}
impl JsonString {
    fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
    fn text(&self) -> &str {
        // string() only emits ASCII bytes.
        core::str::from_utf8(self.bytes()).unwrap()
    }
}

struct Parser<'a> {
    input: &'a [u8],
    cursor: usize,
}
impl Parser<'_> {
    fn whitespace(&mut self) {
        while self
            .input
            .get(self.cursor)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.cursor += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        self.whitespace();
        if self.input.get(self.cursor) == Some(&expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), &'static str> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err("Malformed setup JSON.")
        }
    }

    fn byte(&mut self) -> Result<u8, &'static str> {
        let byte = *self
            .input
            .get(self.cursor)
            .ok_or("Incomplete setup JSON.")?;
        self.cursor += 1;
        Ok(byte)
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), &'static str> {
        self.whitespace();
        if self.input[self.cursor..].starts_with(literal) {
            self.cursor += literal.len();
            Ok(())
        } else {
            Err("Invalid setup JSON value type.")
        }
    }

    fn string(&mut self) -> Result<JsonString, &'static str> {
        self.expect(b'"')?;
        let mut value = JsonString {
            data: [0; MAX_STRING],
            len: 0,
        };
        loop {
            let byte = match self.byte()? {
                b'"' => return Ok(value),
                b'\\' => match self.byte()? {
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'/' => b'/',
                    b'b' => 8,
                    b'f' => 12,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'u' => {
                        let mut code = 0_u16;
                        for _ in 0..4 {
                            let digit = match self.byte()? {
                                byte @ b'0'..=b'9' => byte - b'0',
                                byte @ b'a'..=b'f' => byte - b'a' + 10,
                                byte @ b'A'..=b'F' => byte - b'A' + 10,
                                _ => return Err("Invalid setup JSON Unicode escape."),
                            };
                            code = (code << 4) | u16::from(digit);
                        }
                        if code > 0x7f {
                            return Err("Setup JSON identifiers and values must be ASCII.");
                        }
                        code as u8
                    }
                    _ => return Err("Invalid setup JSON string escape."),
                },
                byte @ 0x20..=0x7f => byte,
                _ => return Err("Setup JSON strings must contain escaped controls and ASCII."),
            };
            if value.len == MAX_STRING {
                return Err("Setup JSON string exceeds 32 bytes.");
            }
            value.data[value.len] = byte;
            value.len += 1;
        }
    }

    fn prefix(&mut self) -> Result<u8, &'static str> {
        self.whitespace();
        let start = self.cursor;
        while self.input.get(self.cursor).is_some_and(u8::is_ascii_digit) {
            self.cursor += 1;
        }
        parse_prefix(&self.input[start..self.cursor])
    }

    fn boolean(&mut self) -> Result<bool, &'static str> {
        self.whitespace();
        if self.input.get(self.cursor) == Some(&b't') {
            self.literal(b"true")?;
            Ok(true)
        } else {
            self.literal(b"false")?;
            Ok(false)
        }
    }

    fn update(&mut self) -> Result<Update, &'static str> {
        self.expect(b'{')?;
        let mut seen = 0_u8;
        let mut update = Update::default();
        let mut cidr = None;
        loop {
            let key = self.string()?;
            let field = match key.bytes() {
                b"Interface" => 0,
                b"IPv4" => 1,
                b"Prefix" => 2,
                b"Gateway" => 3,
                b"Echo" => 4,
                b"Enabled" => 5,
                b"MAC" => 6,
                b"PCI" => 7,
                _ => {
                    return Err(
                        "Unknown setup field; use Interface, PCI, MAC, IPv4, Prefix, Gateway, Echo, or Enabled.",
                    );
                }
            };
            if seen & (1 << field) != 0 {
                return Err("Setup must not repeat a field.");
            }
            seen |= 1 << field;
            self.expect(b':')?;
            match field {
                0 => {
                    let name = self.string()?;
                    let name = name.bytes();
                    if name.len() != 4 || &name[..3] != b"eth" || !(b'0'..=b'7').contains(&name[3])
                    {
                        return Err("Setup Interface must be eth0 through eth7.");
                    }
                    update.interface = Some(usize::from(name[3] - b'0'));
                }
                1 => {
                    let value = self.string()?;
                    let (address, prefix) = match value.text().split_once('/') {
                        Some((address, prefix)) => {
                            (address, Some(parse_prefix(prefix.as_bytes())?))
                        }
                        None => (value.text(), None),
                    };
                    update.address = Some(parse_address(address)?);
                    cidr = prefix;
                }
                2 => update.prefix = Some(self.prefix()?),
                3 => {
                    self.whitespace();
                    let gateway = if self.input.get(self.cursor) == Some(&b'n') {
                        self.literal(b"null")?;
                        None
                    } else {
                        let value = self.string()?;
                        if value.bytes() == b"none" {
                            None
                        } else {
                            Some(parse_address(value.text())?)
                        }
                    };
                    update.gateway = Some(gateway);
                }
                4 => update.echo = Some(self.boolean()?),
                5 => update.enabled = Some(self.boolean()?),
                6 => update.mac = Some(parse_mac(self.string()?.bytes())?),
                7 => update.pci = Some(parse_pci(self.string()?.bytes())?),
                _ => unreachable!(),
            }
            if self.consume(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        if update.interface.is_none() && update.pci.is_none() {
            return Err("Each setup update requires Interface or PCI.");
        }
        if seen & !(1 | (1 << 7)) == 0 {
            return Err("Each setup interface requires at least one setting.");
        }
        if let Some(cidr) = cidr {
            if update.prefix.is_some_and(|prefix| prefix != cidr) {
                return Err("Setup IPv4 CIDR and Prefix disagree.");
            }
            update.prefix = Some(cidr);
        }
        Ok(update)
    }
}

/// Packed little-endian Ethernet address: the first octet is the low byte.
pub const fn valid_mac(mac: u64) -> bool {
    mac != 0 && mac >> 48 == 0 && mac & 1 == 0
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_hex(bytes: &[u8]) -> Option<u16> {
    let mut value = 0;
    for byte in bytes {
        value = (value << 4) | u16::from(hex(*byte)?);
    }
    Some(value)
}

fn parse_mac(bytes: &[u8]) -> Result<u64, &'static str> {
    const ERROR: &str = "Setup MAC must be six hexadecimal octets, nonzero and unicast.";
    if bytes.len() != 17 {
        return Err(ERROR);
    }
    let mut mac = 0;
    for octet in 0..6 {
        let start = octet * 3;
        let value = parse_hex(&bytes[start..start + 2]).ok_or(ERROR)?;
        if octet < 5 && bytes[start + 2] != b':' {
            return Err(ERROR);
        }
        mac |= u64::from(value) << (octet * 8);
    }
    if !valid_mac(mac) {
        return Err(ERROR);
    }
    Ok(mac)
}

fn parse_pci(bytes: &[u8]) -> Result<(u16, u8, u8, u8), &'static str> {
    const ERROR: &str = "Setup PCI must be DDDD:BB:DD.F hexadecimal (device 00-1f, function 0-7).";
    if bytes.len() != 12 || bytes[4] != b':' || bytes[7] != b':' || bytes[10] != b'.' {
        return Err(ERROR);
    }
    let segment = parse_hex(&bytes[..4]).ok_or(ERROR)?;
    let bus = parse_hex(&bytes[5..7]).ok_or(ERROR)? as u8;
    let device = parse_hex(&bytes[8..10]).ok_or(ERROR)? as u8;
    let function = hex(bytes[11]).ok_or(ERROR)?;
    if device > 31 || function > 7 {
        return Err(ERROR);
    }
    Ok((segment, bus, device, function))
}

fn parse_prefix(bytes: &[u8]) -> Result<u8, &'static str> {
    if bytes.is_empty() || bytes.len() > 2 || bytes[0] == b'0' {
        return Err("Setup Prefix must be an integer from 1 to 32 without leading zeros.");
    }
    let mut value = 0;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err("Setup Prefix must be an integer from 1 to 32.");
        }
        value = value * 10 + byte - b'0';
    }
    if value > 32 {
        Err("Setup Prefix must be an integer from 1 to 32.")
    } else {
        Ok(value)
    }
}

fn parse_address(text: &str) -> Result<[u8; 4], &'static str> {
    // /32 with no gateway validates the address independently of the final
    // subnet. resolve() validates the merged configuration as a whole.
    NetworkConfig::parse(text, "32", "none", "0")
        .map(|config| config.address)
        .map_err(|_| "Setup IPv4 and Gateway must be unicast dotted-decimal addresses.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current() -> NetworkConfig {
        NetworkConfig::parse("10.0.2.15", "24", "10.0.2.2", "1").unwrap()
    }

    fn first(input: &[u8]) -> Update {
        parse(input).unwrap().entries[0].unwrap()
    }

    #[test]
    fn example_merges_address_gateway_and_preserves_other_settings() {
        let update =
            first(br#"{"system":[{"Interface":"eth0","IPv4":"10.0.2.16","Gateway":"10.0.2.2"}]}"#);
        let target = update.resolve(current(), true, None).unwrap();
        assert_eq!(target.config.address, [10, 0, 2, 16]);
        assert_eq!(target.config.prefix, 24);
        assert_eq!(target.config.gateway, Some([10, 0, 2, 2]));
        assert!(target.config.echo);
        assert!(target.enabled);
    }

    #[test]
    fn complete_config_cidr_flags_and_null_gateway() {
        let target = first(br#"{"system":[{"Enabled":false,"Interface":"eth0","Gateway":null,"IPv4":"192.168.50.10/32","Echo":false}]}"#)
            .resolve(current(), true, None).unwrap();
        assert_eq!(
            target.config,
            NetworkConfig::parse("192.168.50.10", "32", "none", "0").unwrap()
        );
        assert!(!target.enabled);
        let target = first(br#"{"system":[{"Interface":"eth0","Gateway":"none","Prefix":31,"IPv4":"10.0.2.0/31","Enabled":true}]}"#)
            .resolve(current(), false, None).unwrap();
        assert!(target.enabled);
        assert_eq!(target.config.prefix, 31);
        assert_eq!(target.config.gateway, None);
    }

    #[test]
    fn omitted_values_use_each_individual_current_configuration() {
        let update = first(br#"{"system":[{"Interface":"eth0","Echo":false}]}"#);
        for current in [
            current(),
            NetworkConfig::parse("192.168.50.10", "24", "none", "1").unwrap(),
        ] {
            for admin_up in [false, true] {
                let target = update.resolve(current, admin_up, None).unwrap();
                assert_eq!(target.config.address, current.address);
                assert_eq!(target.config.prefix, current.prefix);
                assert_eq!(target.config.gateway, current.gateway);
                assert!(!target.config.echo);
                assert_eq!(target.enabled, admin_up);
            }
        }
    }

    #[test]
    fn accepts_all_eight_interfaces_in_any_order() {
        let mut input = String::from("{\"system\":[");
        for index in (0..8).rev() {
            if index != 7 {
                input.push(',');
            }
            input.push_str(&format!("{{\"Interface\":\"eth{index}\",\"IPv4\":\"10.0.2.{}\",\"Prefix\":24,\"Gateway\":\"10.0.2.2\",\"Echo\":true,\"Enabled\":true}}", 15 + index));
        }
        input.push_str("]}");
        assert!(input.len() < MAX_INPUT);
        let setup = parse(input.as_bytes()).unwrap();
        for (index, update) in setup.entries.into_iter().enumerate() {
            let target = update.unwrap().resolve(current(), false, None).unwrap();
            assert_eq!(update.unwrap().interface, Some(7 - index));
            assert_eq!(target.config.address[3], 22 - index as u8);
            assert!(target.enabled);
        }
    }

    #[test]
    fn handles_json_whitespace_and_ascii_escapes_before_name_validation() {
        let update = first(b" \t\r\n{ \"syst\\u0065m\" : [ { \"Interf\\u0061ce\" : \"eth\\u0030\", \"IPv4\": \"10.0.2.16\\/24\" } ] } \r\n");
        assert_eq!(update.address, Some([10, 0, 2, 16]));
        assert_eq!(update.prefix, Some(24));
        assert!(
            parse(br#"{"system":[{"Interface":"eth0","Interf\u0061ce":"eth1","Echo":true}]}"#)
                .is_err()
        );
        assert!(parse(br#"{"system":[{"Interface":"eth0","Echo":true},{"Interface":"eth\u0030","Echo":false}]}"#).is_err());
    }

    #[test]
    fn rejects_every_truncation_and_trailing_non_whitespace() {
        let input = br#"{"system":[{"Interface":"eth0","IPv4":"10.0.2.16/24","Gateway":"10.0.2.2","Echo":false,"Enabled":true}]}"#;
        for end in 0..input.len() {
            assert!(parse(&input[..end]).is_err(), "truncated at {end}");
        }
        for trailing in ["{}", "false", ",", "x", "\0", "\u{000b}"] {
            let mut suffixed = input.to_vec();
            suffixed.extend_from_slice(trailing.as_bytes());
            assert!(parse(&suffixed).is_err(), "{trailing:?}");
        }
    }

    #[test]
    fn rejects_invalid_schema_duplicates_types_and_syntax() {
        for input in [
            "{}",
            "[]",
            "null",
            "{\"system\":[]}",
            "{\"system\":{}}",
            "{\"system\":[{}]}",
            r#"{"system":[{"Interface":"eth0"}]}"#,
            r#"{"system":[{"Echo":true}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":true}],"system":[]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":true}],"extra":1}"#,
            r#"{"System":[{"Interface":"eth0","Echo":true}]}"#,
            r#"{"system":[{"Interface":"eth0","echo":true}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":true,"Echo":false}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":true},{"Interface":"eth0","Echo":false}]}"#,
            r#"{"system":[{"Interface":"eth8","Echo":true}]}"#,
            r#"{"system":[{"Interface":"eth00","Echo":true}]}"#,
            r#"{"system":[{"Interface":"ETH0","Echo":true}]}"#,
            r#"{"system":[{"Interface":0,"Echo":true}]}"#,
            r#"{"system":[{"Interface":"eth0","IPv4":"IPv4"}]}"#,
            r#"{"system":[{"Interface":"eth0","IPv4":1234}]}"#,
            r#"{"system":[{"Interface":"eth0","IPv4":null}]}"#,
            r#"{"system":[{"Interface":"eth0","Gateway":false}]}"#,
            r#"{"system":[{"Interface":"eth0","Gateway":"null"}]}"#,
            r#"{"system":[{"Interface":"eth0","Gateway":"0.0.0.0"}]}"#,
            r#"{"system":[{"Interface":"eth0","Gateway":nullx}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":"true"}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":1}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":null}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":True}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":truefalse}]}"#,
            r#"{"system":[{"Interface":"eth0","Enabled":{}}]}"#,
            r#"{"system":[{"Interface":"eth0","Enabled":[]}]}"#,
            r#"{"system":[{"Interface":"eth0","Prefix":24.0}]}"#,
            r#"{"system":[{"Interface":"eth0","Prefix":2e1}]}"#,
            r#"{"system":[{"Interface":"eth0","Prefix":-1}]}"#,
            r#"{"system":[{"Interface":"eth0","Prefix":+24}]}"#,
            r#"{"system":[{"Interface":"eth0","Prefix":"24"}]}"#,
            r#"{"system":[{"Interface":"eth0","Prefix":024}]}"#,
            r#"{"system":[{"Interface":"eth0","Prefix":0}]}"#,
            r#"{"system":[{"Interface":"eth0","Prefix":33}]}"#,
            r#"{"system":[{"Interface":"eth0","Prefix":9999999999999999999999}]}"#,
            r#"{"system":[{"Interface":"eth0","IPv4":"10.0.2.16/024"}]}"#,
            r#"{"system":[{"Interface":"eth0","IPv4":"10.0.2.16/24/24"}]}"#,
            r#"{"system":[{"Interface":"eth0","IPv4":"10.0.2.16/24","Prefix":25}]}"#,
            r#"{"system":[{"Interface":"eth0","Prefix":25,"IPv4":"10.0.2.16/24"}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":true,}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":true},]}"#,
            r#"{'system':[{'Interface':'eth0','Echo':true}]}"#,
            r#"{"system":[{"Interface":"eth0" "Echo":true}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":/* comment */true}]}"#,
        ] {
            assert!(parse(input.as_bytes()).is_err(), "{input}");
        }
    }

    #[test]
    fn rejects_invalid_strings_and_input_limits_without_panicking() {
        for escaped in [
            r"eth\q0",
            r"eth\u00g0",
            r"eth\u0",
            r"eth\u0080",
            r"eth\uD800\uDC00",
            "eth\n0",
            "éth0",
            "eth\0",
            r"eth\t0",
            r#"eth\"0"#,
        ] {
            let input = format!("{{\"system\":[{{\"Interface\":\"{escaped}\",\"Echo\":true}}]}}");
            assert!(parse(input.as_bytes()).is_err(), "{escaped}");
        }
        let long_string = "a".repeat(MAX_STRING + 1);
        assert!(
            parse(
                format!("{{\"system\":[{{\"Interface\":\"{long_string}\",\"Echo\":true}}]}}")
                    .as_bytes()
            )
            .is_err()
        );
        let mut boundary = br#"{"system":[{"Interface":"eth0","Echo":true}]}"#.to_vec();
        boundary.resize(MAX_INPUT, b' ');
        assert!(parse(&boundary).is_ok());
        boundary.push(b' ');
        assert!(parse(&boundary).is_err());
        assert!(parse(&[b'['; MAX_INPUT]).is_err());
        let mut ninth = String::from("{\"system\":[");
        for index in 0..9 {
            if index != 0 {
                ninth.push(',');
            }
            ninth.push_str(&format!(
                "{{\"Interface\":\"eth{}\",\"Echo\":true}}",
                index % 8
            ));
        }
        ninth.push_str("]}");
        assert_eq!(
            parse(ninth.as_bytes()).unwrap_err(),
            "Setup supports at most eight interface updates."
        );
    }

    #[test]
    fn validates_final_subnet_gateway_relationship_including_preserved_fields() {
        for input in [
            br#"{"system":[{"Interface":"eth0","IPv4":"10.0.2.0"}]}"#.as_slice(),
            br#"{"system":[{"Interface":"eth0","IPv4":"10.0.2.255"}]}"#,
            br#"{"system":[{"Interface":"eth0","IPv4":"192.168.1.5"}]}"#,
            br#"{"system":[{"Interface":"eth0","Gateway":"10.0.3.1"}]}"#,
            br#"{"system":[{"Interface":"eth0","Gateway":"10.0.2.15"}]}"#,
            br#"{"system":[{"Interface":"eth0","Gateway":"10.0.2.0"}]}"#,
            br#"{"system":[{"Interface":"eth0","Prefix":32}]}"#,
        ] {
            assert!(
                first(input).resolve(current(), true, None).is_err(),
                "{input:?}"
            );
        }
        let target = first(
            br#"{"system":[{"Interface":"eth0","IPv4":"192.168.1.5","Gateway":"192.168.1.1"}]}"#,
        )
        .resolve(current(), true, None)
        .unwrap();
        assert_eq!(target.config.address, [192, 168, 1, 5]);
        assert_eq!(target.config.gateway, Some([192, 168, 1, 1]));
    }
    #[test]
    fn parses_mac_and_pci_selectors_and_preserves_omitted_mac() {
        let update = first(br#"{"system":[{"PCI":"00aB:Cd:1F.7","MAC":"02:AB:cd:12:34:56"}]}"#);
        assert_eq!(update.interface, None);
        assert_eq!(update.pci, Some((0xab, 0xcd, 0x1f, 7)));
        assert_eq!(update.mac, Some(0x5634_12cd_ab02));
        assert_eq!(
            update
                .resolve(current(), false, Some(0x5634_1200_5452))
                .unwrap()
                .mac,
            update.mac
        );
        let update =
            first(br#"{"system":[{"Interface":"eth0","PCI":"0000:00:02.0","Echo":false}]}"#);
        assert_eq!(update.interface, Some(0));
        assert_eq!(update.pci, Some((0, 0, 2, 0)));
        assert_eq!(
            update
                .resolve(current(), true, Some(0x5634_1200_5452))
                .unwrap()
                .mac,
            Some(0x5634_1200_5452)
        );
        assert_eq!(update.resolve(current(), false, None).unwrap().mac, None);
    }

    #[test]
    fn rejects_invalid_mac_or_pci_even_after_valid_updates() {
        for mac in [
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:01",
            "52:54:00:12:34",
            "52:54:00:12:34:56:78",
            "5:54:00:12:34:56",
            "52-54-00-12-34-56",
            "52:54:00:12:34:gg",
            " 52:54:00:12:34:56",
            "52:54:00:12:34:56 ",
            "52:54:00:12:34:0x",
        ] {
            let input = format!(
                r#"{{"system":[{{"Interface":"eth0","Echo":false}},{{"Interface":"eth1","MAC":"{mac}"}}]}}"#
            );
            assert!(parse(input.as_bytes()).is_err(), "{mac}");
        }
        for pci in [
            "00:02.0",
            "000:00:02.0",
            "00000:00:02.0",
            "0000:0:02.0",
            "0000:000:02.0",
            "0000:00:2.0",
            "0000:00:02.00",
            "0000:00:20.0",
            "0000:00:02.8",
            "0000:00:02.f",
            "0000:00:02.g",
            "0000-00-02.0",
            "0000:00:02:0",
            "0000:gg:02.0",
            " 0000:00:02.0",
            "0000:00:02.0 ",
        ] {
            let input = format!(
                r#"{{"system":[{{"Interface":"eth0","Echo":false}},{{"PCI":"{pci}","Enabled":true}}]}}"#
            );
            assert!(parse(input.as_bytes()).is_err(), "{pci}");
        }
        for input in [
            r#"{"system":[{"Interface":"eth0","MAC":null}]}"#,
            r#"{"system":[{"Interface":"eth0","MAC":123}]}"#,
            r#"{"system":[{"Interface":"eth0","MAC":true}]}"#,
            r#"{"system":[{"PCI":null,"Echo":false}]}"#,
            r#"{"system":[{"PCI":123,"Echo":false}]}"#,
            r#"{"system":[{"PCI":{},"Echo":false}]}"#,
            r#"{"system":[{"PCI":"0000:00:02.0"}]}"#,
            r#"{"system":[{"Interface":"eth0","PCI":"0000:00:02.0"}]}"#,
            r#"{"system":[{"MAC":"52:54:00:12:34:56"}]}"#,
            r#"{"system":[{"Interface":"eth0","MAC":"52:54:00:12:34:56","MAC":"52:54:00:12:34:57"}]}"#,
            r#"{"system":[{"PCI":"0000:00:02.0","PCI":"0000:00:03.0","Echo":false}]}"#,
            r#"{"system":[{"PCI":"0000:0a:02.0","Echo":false},{"PCI":"0000:0A:02.0","Echo":true}]}"#,
        ] {
            assert!(parse(input.as_bytes()).is_err(), "{input}");
        }
    }

    #[test]
    fn truncation_of_mac_pci_request_never_produces_partial_setup() {
        let input = br#"{"system":[{"Interface":"eth0","Echo":false},{"PCI":"0000:00:03.0","MAC":"02:11:22:33:44:55"}]}"#;
        for end in 0..input.len() {
            assert!(parse(&input[..end]).is_err(), "truncated at {end}");
        }
        assert_eq!(
            parse(input).unwrap().entries[1].unwrap().pci,
            Some((0, 0, 3, 0))
        );
    }
}
