//! Shared static IPv4 configuration validation and canonical runtime wire format.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    pub address: [u8; 4],
    pub prefix: u8,
    pub gateway: Option<[u8; 4]>,
    pub echo: bool,
}

#[allow(dead_code)] // The userspace service obtains the current value through IPC.
pub const CONFIG: NetworkConfig = match NetworkConfig::parse(
    setting(option_env!("KERNEL_IPV4"), "10.0.2.15"),
    setting(option_env!("KERNEL_PREFIX"), "24"),
    setting(option_env!("KERNEL_GATEWAY"), "10.0.2.2"),
    setting(option_env!("KERNEL_ECHO"), "1"),
) {
    Ok(config) => config,
    Err(message) => panic!("{}", message),
};

const fn setting(value: Option<&'static str>, default: &'static str) -> &'static str {
    match value {
        Some(value) => value,
        None => default,
    }
}

impl NetworkConfig {
    pub const fn parse(
        address: &str,
        prefix: &str,
        gateway: &str,
        echo: &str,
    ) -> Result<Self, &'static str> {
        let Some(address) = ipv4(address) else {
            return Err("KERNEL_IPV4 must be a unicast IPv4 address in dotted decimal");
        };
        let Some(prefix) = decimal(prefix.as_bytes()) else {
            return Err("KERNEL_PREFIX must be a decimal prefix length from 1 to 32");
        };
        let gateway = match gateway.as_bytes() {
            b"none" => None,
            _ => {
                let Some(address) = ipv4(gateway) else {
                    return Err("KERNEL_GATEWAY must be a unicast IPv4 address or 'none'");
                };
                Some(address)
            }
        };
        let echo = match echo.as_bytes() {
            b"1" => true,
            b"0" => false,
            _ => return Err("KERNEL_ECHO must be '0' (disabled) or '1' (enabled)"),
        };
        Self {
            address,
            prefix,
            gateway,
            echo,
        }
        .validate()
    }

    /// Canonical sixteen-byte ABI encoding. Runtime configurations originate
    /// from parse/from_wire; the wire representation has no padding or pointers.
    pub const fn to_wire(self) -> [u8; 16] {
        let gateway = match self.gateway {
            Some(address) => address,
            None => [0; 4],
        };
        [
            self.address[0],
            self.address[1],
            self.address[2],
            self.address[3],
            self.prefix,
            self.echo as u8,
            self.gateway.is_some() as u8,
            0,
            gateway[0],
            gateway[1],
            gateway[2],
            gateway[3],
            0,
            0,
            0,
            0,
        ]
    }

    #[allow(dead_code)] // The kernel encodes this format; the service decodes it.
    pub const fn from_wire(bytes: [u8; 16]) -> Result<Self, &'static str> {
        if bytes[5] > 1 || bytes[6] > 1 {
            return Err("network configuration flags must be zero or one");
        }
        if bytes[7] != 0 || bytes[12] != 0 || bytes[13] != 0 || bytes[14] != 0 || bytes[15] != 0 {
            return Err("network configuration reserved bytes must be zero");
        }
        let gateway = [bytes[8], bytes[9], bytes[10], bytes[11]];
        if bytes[6] == 0 && u32::from_be_bytes(gateway) != 0 {
            return Err("absent network gateway must have a zero address");
        }
        Self {
            address: [bytes[0], bytes[1], bytes[2], bytes[3]],
            prefix: bytes[4],
            gateway: if bytes[6] == 1 { Some(gateway) } else { None },
            echo: bytes[5] == 1,
        }
        .validate()
    }

    const fn validate(self) -> Result<Self, &'static str> {
        if !unicast(self.address) {
            return Err("KERNEL_IPV4 must be a unicast IPv4 address in dotted decimal");
        }
        if self.prefix == 0 || self.prefix > 32 {
            return Err("KERNEL_PREFIX must be a decimal prefix length from 1 to 32");
        }
        let mask = u32::MAX << (32 - self.prefix);
        let local = u32::from_be_bytes(self.address);
        if !host(local, mask, self.prefix) {
            return Err("KERNEL_IPV4 cannot be the subnet network or broadcast address");
        }
        if let Some(gateway) = self.gateway {
            if !unicast(gateway) {
                return Err("KERNEL_GATEWAY must be a unicast IPv4 address or 'none'");
            }
            let router = u32::from_be_bytes(gateway);
            if local == router {
                return Err("KERNEL_GATEWAY must differ from KERNEL_IPV4");
            }
            // smoltcp learns ARP neighbors only inside the local subnet. A
            // /32 therefore has no usable distinct default gateway here.
            if router & mask != local & mask || !host(router, mask, self.prefix) {
                return Err("KERNEL_GATEWAY must be a host in the configured subnet");
            }
        }
        Ok(self)
    }
}

const fn unicast(address: [u8; 4]) -> bool {
    address[0] != 0 && address[0] != 127 && address[0] < 224
}

const fn host(address: u32, mask: u32, prefix: u8) -> bool {
    prefix >= 31 || (address & !mask != 0 && address & !mask != !mask)
}

const fn decimal(bytes: &[u8]) -> Option<u8> {
    if bytes.is_empty() || bytes.len() > 3 || (bytes.len() > 1 && bytes[0] == b'0') {
        return None;
    }
    let mut value = 0_u16;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte < b'0' || byte > b'9' {
            return None;
        }
        value = value * 10 + (byte - b'0') as u16;
        index += 1;
    }
    if value <= 255 {
        Some(value as u8)
    } else {
        None
    }
}

const fn ipv4(text: &str) -> Option<[u8; 4]> {
    let bytes = text.as_bytes();
    let mut address = [0; 4];
    let mut octet = [0; 3];
    let mut digits = 0;
    let mut part = 0;
    let mut index = 0;
    while index <= bytes.len() {
        if index == bytes.len() || bytes[index] == b'.' {
            if part == 4 || digits == 0 {
                return None;
            }
            // Const slicing is not available on all supported Rust toolchains.
            let value = match digits {
                1 => decimal(&[octet[0]]),
                2 => decimal(&[octet[0], octet[1]]),
                _ => decimal(&octet),
            };
            let Some(value) = value else { return None };
            address[part] = value;
            part += 1;
            digits = 0;
        } else {
            if digits == 3 {
                return None;
            }
            octet[digits] = bytes[index];
            digits += 1;
        }
        index += 1;
    }
    if part != 4 || !unicast(address) {
        None
    } else {
        Some(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_public_address_with_echo_disabled() {
        assert_eq!(
            NetworkConfig::parse("10.0.2.15", "24", "10.0.2.2", "1"),
            Ok(NetworkConfig {
                address: [10, 0, 2, 15],
                prefix: 24,
                gateway: Some([10, 0, 2, 2]),
                echo: true,
            })
        );
        let config = NetworkConfig::parse("203.0.113.10", "24", "203.0.113.1", "0").unwrap();
        assert_eq!(config.address, [203, 0, 113, 10]);
        assert!(!config.echo);
        let _ = CONFIG; // Also require compile-time environment validation.
    }

    #[test]
    fn rejects_ambiguous_and_non_unicast_addresses() {
        for address in [
            "",
            "1.2.3",
            "1.2.3.4.5",
            "1..3.4",
            "1.2.3.256",
            "1.2.3.-1",
            "1.2.3.04",
            "1.2.3.4 ",
            "0.1.2.3",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                NetworkConfig::parse(address, "24", "none", "0").is_err(),
                "{address}"
            );
        }
        for prefix in ["", "0", "33", "024", "-1", "24 "] {
            assert!(NetworkConfig::parse("10.0.2.15", prefix, "none", "1").is_err());
        }
        for echo in ["", "true", "false", "2", "01"] {
            assert!(NetworkConfig::parse("10.0.2.15", "24", "none", echo).is_err());
        }
    }

    #[test]
    fn gateway_must_be_a_distinct_on_link_host() {
        for gateway in ["10.0.3.1", "10.0.2.15", "10.0.2.0", "10.0.2.255", "0.0.0.0"] {
            assert!(NetworkConfig::parse("10.0.2.15", "24", gateway, "0").is_err());
        }
        for address in ["10.0.2.0", "10.0.2.255"] {
            assert!(NetworkConfig::parse(address, "24", "none", "0").is_err());
        }
        assert!(NetworkConfig::parse("10.0.2.15", "24", "none", "0").is_ok());
    }

    #[test]
    fn point_to_point_prefix_has_two_hosts_and_host_prefix_has_no_gateway() {
        assert!(NetworkConfig::parse("10.0.2.0", "31", "10.0.2.1", "0").is_ok());
        assert!(NetworkConfig::parse("10.0.2.1", "31", "10.0.2.0", "0").is_ok());
        assert!(NetworkConfig::parse("10.0.2.15", "32", "none", "0").is_ok());
        assert!(NetworkConfig::parse("10.0.2.15", "32", "10.0.2.2", "0").is_err());
    }

    #[test]
    fn wire_layout_and_round_trips_are_canonical() {
        let configured = NetworkConfig::parse("192.168.50.10", "24", "192.168.50.1", "1").unwrap();
        assert_eq!(
            configured.to_wire(),
            [192, 168, 50, 10, 24, 1, 1, 0, 192, 168, 50, 1, 0, 0, 0, 0]
        );
        for (address, prefix, gateway, echo) in [
            ("10.0.2.15", "24", "10.0.2.2", "1"),
            ("192.168.50.10", "24", "none", "0"),
            ("10.0.2.0", "31", "10.0.2.1", "0"),
            ("10.0.2.15", "32", "none", "1"),
        ] {
            let config = NetworkConfig::parse(address, prefix, gateway, echo).unwrap();
            assert_eq!(NetworkConfig::from_wire(config.to_wire()), Ok(config));
        }
        const DECODED: Result<NetworkConfig, &str> = NetworkConfig::from_wire(CONFIG.to_wire());
        assert_eq!(DECODED, Ok(CONFIG));
    }

    #[test]
    fn wire_rejects_noncanonical_flags_reserved_bytes_and_absent_gateway_payload() {
        let valid = NetworkConfig::parse("10.0.2.15", "24", "none", "0")
            .unwrap()
            .to_wire();
        for position in [5, 6] {
            for invalid in 2..=255 {
                let mut bytes = valid;
                bytes[position] = invalid;
                assert!(NetworkConfig::from_wire(bytes).is_err());
            }
        }
        for position in [7, 12, 13, 14, 15, 8, 9, 10, 11] {
            let mut bytes = valid;
            bytes[position] = 1;
            assert!(
                NetworkConfig::from_wire(bytes).is_err(),
                "noncanonical byte {position}"
            );
        }
        let mut zero_gateway = valid;
        zero_gateway[6] = 1;
        assert!(NetworkConfig::from_wire(zero_gateway).is_err());
    }

    #[test]
    fn wire_uses_the_same_address_prefix_and_gateway_rules_as_text() {
        let valid = NetworkConfig::parse("10.0.2.15", "24", "none", "0")
            .unwrap()
            .to_wire();
        for prefix in 0..=255 {
            let mut bytes = valid;
            bytes[3] = 1; // A valid host in every supported prefix, including /30.
            bytes[4] = prefix;
            assert_eq!(
                NetworkConfig::from_wire(bytes).is_ok(),
                (1..=32).contains(&prefix)
            );
        }
        for address in [
            [0, 1, 2, 3],
            [127, 0, 0, 1],
            [224, 0, 0, 1],
            [255; 4],
            [10, 0, 2, 0],
            [10, 0, 2, 255],
        ] {
            let mut bytes = valid;
            bytes[..4].copy_from_slice(&address);
            assert!(NetworkConfig::from_wire(bytes).is_err());
        }
        for gateway in [
            [10, 0, 3, 1],
            [10, 0, 2, 15],
            [10, 0, 2, 0],
            [10, 0, 2, 255],
            [0; 4],
            [127, 0, 0, 1],
        ] {
            let mut bytes = valid;
            bytes[6] = 1;
            bytes[8..12].copy_from_slice(&gateway);
            assert!(NetworkConfig::from_wire(bytes).is_err());
        }
    }
}
