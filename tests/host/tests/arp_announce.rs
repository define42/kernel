#[path = "../../../abi.rs"]
mod abi;
#[path = "../../../userspace/arp_announce.rs"]
mod arp_announce;

use arp_announce::Announcements;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, Ipv4Address,
};

fn new_announcement(now: i64) -> Announcements {
    Announcements::new(
        EthernetAddress([0x02, 0xab, 0xcd, 0x12, 0x34, 0x56]),
        Ipv4Address::new(10, 0, 2, 15),
        now,
    )
}

#[test]
fn announcement_is_broadcast_arp_request_with_configured_mac_and_address() {
    let mut announcement = new_announcement(0);
    let mut sent = false;
    announcement.poll(0, |bytes| {
        assert_eq!(bytes.len(), 42);
        let frame = EthernetFrame::new_checked(bytes).unwrap();
        assert_eq!(frame.dst_addr(), EthernetAddress::BROADCAST);
        assert_eq!(
            frame.src_addr(),
            EthernetAddress([0x02, 0xab, 0xcd, 0x12, 0x34, 0x56])
        );
        assert_eq!(frame.ethertype(), EthernetProtocol::Arp);
        assert_eq!(
            ArpRepr::parse(&ArpPacket::new_checked(frame.payload()).unwrap()).unwrap(),
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr: frame.src_addr(),
                source_protocol_addr: Ipv4Address::new(10, 0, 2, 15),
                target_hardware_addr: EthernetAddress([0; 6]),
                target_protocol_addr: Ipv4Address::new(10, 0, 2, 15),
            }
        );
        sent = true;
        Ok(())
    });
    assert!(sent);
}

#[test]
fn sends_exactly_two_announcements_with_two_second_spacing() {
    let mut announcement = new_announcement(10);
    let mut sent = Vec::new();
    for now in [9, 10, 10, 11, 1000, 2009, 2010, 2011, 4000, 6000] {
        announcement.poll(now, |_| {
            sent.push(now);
            Ok(())
        });
    }
    assert_eq!(sent, [10, 2010]);
}

#[test]
fn queue_full_uses_backoff_and_keeps_successes_two_seconds_apart() {
    let mut announcement = new_announcement(0);
    let mut attempted = Vec::new();
    for now in [0, 0, 1, 99, 100, 101, 2000, 2099, 2100, 2101] {
        announcement.poll(now, |_| {
            attempted.push(now);
            if now == 0 { Err(abi::EAGAIN) } else { Ok(()) }
        });
    }
    assert_eq!(attempted, [0, 100, 2100]);
}

#[test]
fn persistent_pressure_has_attempt_and_deadline_limits() {
    let mut announcement = new_announcement(0);
    let mut attempts = 0;
    for now in 0..=10_000 {
        announcement.poll(now, |_| {
            attempts += 1;
            Err(abi::EAGAIN)
        });
    }
    assert_eq!(attempts, 32);

    let mut announcement = new_announcement(0);
    let mut attempts = 0;
    for now in [0, 4999, 5000, 10_000] {
        announcement.poll(now, |_| {
            attempts += 1;
            Err(abi::EAGAIN)
        });
    }
    assert_eq!(attempts, 2);
}

#[test]
fn other_errors_stop_announcements_and_time_overflow_cannot_spin() {
    let mut announcement = new_announcement(0);
    let mut attempts = 0;
    for now in [0, 100, 2000, 4000] {
        announcement.poll(now, |_| {
            attempts += 1;
            Err(abi::EINVAL)
        });
    }
    assert_eq!(attempts, 1);

    let mut announcement = new_announcement(i64::MAX - 1);
    let mut attempts = 0;
    for now in [i64::MAX - 1, i64::MAX, i64::MAX] {
        announcement.poll(now, |_| {
            attempts += 1;
            Err(abi::EAGAIN)
        });
    }
    assert_eq!(attempts, 1);
}
