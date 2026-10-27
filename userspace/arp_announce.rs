//! Bounded startup announcements refresh neighbors after an IP or MAC change.
//! This is best-effort cache refresh, not IPv4 address conflict detection.

use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, Ipv4Address,
};

const ANNOUNCE_INTERVAL_MS: i64 = 2_000;
const RETRY_INTERVAL_MS: i64 = 100;
const DEADLINE_MS: i64 = 5_000;
const MAX_ATTEMPTS: u8 = 32;
const FRAME_SIZE: usize = 42;

pub struct Announcements {
    frame: [u8; FRAME_SIZE],
    next: i64,
    deadline: i64,
    remaining: u8,
    attempts: u8,
}

impl Announcements {
    pub fn new(mac: EthernetAddress, address: Ipv4Address, now: i64) -> Self {
        let mut bytes = [0; FRAME_SIZE];
        let mut frame = EthernetFrame::new_unchecked(&mut bytes[..]);
        frame.set_src_addr(mac);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_ethertype(EthernetProtocol::Arp);
        // RFC 5227 sections 1.1 and 2.3: an announcement is a broadcast
        // request with sender/target IPv4 equal and an all-zero target MAC.
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: mac,
            source_protocol_addr: address,
            target_hardware_addr: EthernetAddress([0; 6]),
            target_protocol_addr: address,
        }
        .emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
        Self {
            frame: bytes,
            next: now,
            deadline: now.saturating_add(DEADLINE_MS),
            remaining: 2,
            attempts: MAX_ATTEMPTS,
        }
    }

    /// At most one nonblocking enqueue attempt per call. Successful sends are
    /// spaced by two seconds. A full frame queue gets bounded, delayed retries;
    /// persistent pressure or any other error ends this startup-only operation.
    pub fn poll(&mut self, now: i64, send: impl FnOnce(&[u8]) -> Result<(), i64>) {
        if self.remaining == 0 || self.attempts == 0 {
            return;
        }
        if now >= self.deadline {
            self.remaining = 0;
            return;
        }
        if now < self.next {
            return;
        }
        self.attempts -= 1;
        match send(&self.frame) {
            Ok(()) => {
                self.remaining -= 1;
                self.next = now.saturating_add(ANNOUNCE_INTERVAL_MS);
            }
            Err(crate::abi::EAGAIN) => {
                self.next = now.saturating_add(RETRY_INTERVAL_MS);
            }
            Err(_) => self.remaining = 0,
        }
    }
}
