//! Pure preflight for one complete serial setup request. No hardware changes.
use crate::{nic, setup};

pub type Plan = [Option<setup::Target>; nic::MAX_INTERFACES];

/// Resolve every entry against its own current values before accepting any
/// changes. Only changed entries are returned, so replaying an exported setup
/// does not reset connections. Missing or quarantined interfaces reject all.
pub fn prepare(request: &setup::Setup, status: &nic::Status) -> Result<Plan, &'static str> {
    let mut plan = [None; nic::MAX_INTERFACES];
    let mut selected = [false; nic::MAX_INTERFACES];
    for update in request.entries.iter().flatten() {
        let by_name = if let Some(index) = update.interface {
            status
                .interfaces
                .get(index)
                .and_then(Option::as_ref)
                .ok_or("Unknown interface; use nic list.")?;
            Some(index)
        } else {
            None
        };
        let by_pci = if let Some((segment, bus, device, function)) = update.pci {
            if segment != 0 {
                return Err("Unknown PCI interface; use nic list.");
            }
            Some(
                status
                    .interfaces
                    .iter()
                    .position(|entry| {
                        entry.is_some_and(|interface| interface.bdf == (bus, device, function))
                    })
                    .ok_or("Unknown PCI interface; use nic list.")?,
            )
        } else {
            None
        };
        if let (Some(named), Some(pci)) = (by_name, by_pci)
            && named != pci
        {
            return Err("Setup Interface and PCI must identify the same device.");
        }
        let index = by_name
            .or(by_pci)
            .ok_or("Each setup update requires Interface or PCI.")?;
        if selected[index] {
            return Err("Setup must not target the same device more than once.");
        }
        selected[index] = true;
        let interface = status.interfaces[index].ok_or("Unknown interface; use nic list.")?;
        if matches!(
            interface.state,
            nic::State::Quarantined | nic::State::Unavailable
        ) {
            return Err("Setup cannot change an unavailable or quarantined interface.");
        }
        let target = update.resolve(interface.config, interface.enabled, interface.mac)?;
        if target.config != interface.config
            || target.enabled != interface.enabled
            || target.mac != interface.mac
        {
            plan[index] = Some(target);
        }
    }
    // Check the final configuration, including untouched and disabled devices.
    // This permits coordinated MAC swaps while rejecting aliases on any NIC.
    let mut final_macs = [None; nic::MAX_INTERFACES];
    for (index, interface) in status.interfaces.iter().enumerate() {
        let Some(interface) = interface else { continue };
        let mac = plan[index].map_or(interface.mac, |target| target.mac);
        if let Some(mac) = mac {
            if !setup::valid_mac(mac) {
                return Err("Setup MAC must be a nonzero unicast 48-bit address.");
            }
            if final_macs[..index].contains(&Some(mac)) {
                return Err("Setup MAC addresses must be unique across interfaces.");
            }
        }
        final_macs[index] = mac;
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_config::NetworkConfig;

    fn status() -> nic::Status {
        let mut status = nic::Status::unavailable();
        for (index, entry) in status.interfaces[..2].iter_mut().enumerate() {
            *entry = Some(nic::Interface {
                bdf: (0, index as u8 + 2, 0),
                state: nic::State::Up,
                config: NetworkConfig::parse("10.0.2.15", "24", "10.0.2.2", "1").unwrap(),
                enabled: true,
                mac: Some(0x5634_1200_5452 + ((index as u64) << 40)),
            });
        }
        status
    }

    #[test]
    fn rejects_missing_or_quarantined_later_interface_before_producing_plan() {
        let request = setup::parse(
            br#"{"system":[{"Interface":"eth0","Echo":false},{"Interface":"eth1","Echo":false}]}"#,
        )
        .unwrap();
        for state in [
            None,
            Some(nic::State::Quarantined),
            Some(nic::State::Unavailable),
        ] {
            let mut status = status();
            if let Some(state) = state {
                status.interfaces[1].as_mut().unwrap().state = state;
            } else {
                status.interfaces[1] = None;
            }
            assert!(prepare(&request, &status).is_err());
            assert!(status.interfaces[0].unwrap().config.echo);
        }
    }

    #[test]
    fn rejects_late_gateway_that_conflicts_with_preserved_address() {
        let request = setup::parse(br#"{"system":[{"Interface":"eth0","Echo":false},{"Interface":"eth1","Gateway":"10.0.3.1"}]}"#).unwrap();
        assert!(prepare(&request, &status()).is_err());
    }

    #[test]
    fn resolves_each_interfaces_own_defaults_and_omits_noops() {
        let mut status = status();
        let second = status.interfaces[1].as_mut().unwrap();
        second.config = NetworkConfig::parse("192.168.1.5", "16", "none", "0").unwrap();
        second.enabled = false;
        second.state = nic::State::Down;
        let request = setup::parse(br#"{"system":[{"Interface":"eth0","Echo":true},{"Interface":"eth1","IPv4":"192.168.1.6"}]}"#).unwrap();
        let plan = prepare(&request, &status).unwrap();
        assert!(plan[0].is_none());
        let target = plan[1].unwrap();
        assert_eq!(
            target.config,
            NetworkConfig::parse("192.168.1.6", "16", "none", "0").unwrap()
        );
        assert!(!target.enabled);
        assert_eq!(target.mac, status.interfaces[1].unwrap().mac);
        assert!(plan[2..].iter().all(Option::is_none));
    }
    #[test]
    fn resolves_pci_selectors_without_rebinding_interface_names() {
        let status = status();
        let request = setup::parse(br#"{"system":[{"PCI":"0000:00:03.0","Echo":false},{"Interface":"eth0","PCI":"0000:00:02.0","MAC":"02:ab:CD:12:34:56"}]}"#).unwrap();
        let plan = prepare(&request, &status).unwrap();
        assert_eq!(plan[0].unwrap().mac, Some(0x5634_12cd_ab02));
        assert_eq!(
            plan[0].unwrap().config,
            status.interfaces[0].unwrap().config
        );
        assert!(!plan[1].unwrap().config.echo);
        assert_eq!(plan[1].unwrap().mac, status.interfaces[1].unwrap().mac);
    }

    #[test]
    fn rejects_conflicts_missing_devices_and_alias_duplicates_including_noops() {
        let status = status();
        for json in [
            r#"{"system":[{"Interface":"eth0","PCI":"0000:00:03.0","Echo":false}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":false},{"PCI":"0000:00:04.0","Echo":false}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":false},{"PCI":"0001:00:03.0","Echo":false}]}"#,
            r#"{"system":[{"Interface":"eth0","Echo":false},{"PCI":"0000:00:02.0","Enabled":true}]}"#,
            r#"{"system":[{"PCI":"0000:00:02.0","Echo":true},{"Interface":"eth0","Echo":false}]}"#,
        ] {
            let request = setup::parse(json.as_bytes()).unwrap();
            assert!(prepare(&request, &status).is_err(), "{json}");
            assert!(status.interfaces[0].unwrap().config.echo);
            assert_eq!(status.interfaces[0].unwrap().mac, Some(0x5634_1200_5452));
        }
    }

    #[test]
    fn rejects_mac_collisions_with_changed_untouched_and_disabled_peers() {
        for enabled in [false, true] {
            let mut status = status();
            status.interfaces[1].as_mut().unwrap().enabled = enabled;
            for json in [
                r#"{"system":[{"Interface":"eth0","MAC":"52:54:00:12:34:57"}]}"#,
                r#"{"system":[{"Interface":"eth0","MAC":"02:00:00:00:00:01"},{"PCI":"0000:00:03.0","MAC":"02:00:00:00:00:01"}]}"#,
            ] {
                let request = setup::parse(json.as_bytes()).unwrap();
                assert!(prepare(&request, &status).is_err(), "{json}");
                assert_eq!(status.interfaces[0].unwrap().mac, Some(0x5634_1200_5452));
            }
        }
    }

    #[test]
    fn coordinated_mac_swap_and_replay_are_valid() {
        let mut status = status();
        let request = setup::parse(br#"{"system":[{"PCI":"0000:00:03.0","MAC":"52:54:00:12:34:56"},{"Interface":"eth0","MAC":"52:54:00:12:34:57"}]}"#).unwrap();
        let plan = prepare(&request, &status).unwrap();
        assert_eq!(plan[0].unwrap().mac, status.interfaces[1].unwrap().mac);
        assert_eq!(plan[1].unwrap().mac, status.interfaces[0].unwrap().mac);
        for (interface, target) in status.interfaces.iter_mut().zip(plan) {
            if let (Some(interface), Some(target)) = (interface, target) {
                interface.mac = target.mac;
            }
        }
        assert!(
            prepare(&request, &status)
                .unwrap()
                .iter()
                .all(Option::is_none)
        );
    }

    #[test]
    fn validates_raw_updates_at_preflight_boundary() {
        for mac in [0, 1, 0xffff_ffff_ffff, 0x1_0000_0000_0002] {
            let request = setup::Setup {
                entries: core::array::from_fn(|index| {
                    (index == 0).then_some(setup::Update {
                        interface: Some(0),
                        mac: Some(mac),
                        ..setup::Update::default()
                    })
                }),
            };
            assert!(prepare(&request, &status()).is_err());
        }
        let request = setup::Setup {
            entries: core::array::from_fn(|index| {
                (index == 0).then_some(setup::Update {
                    interface: Some(usize::MAX),
                    echo: Some(false),
                    ..setup::Update::default()
                })
            }),
        };
        assert!(prepare(&request, &status()).is_err());
    }
}
