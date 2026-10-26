//! Bounded HTTP SYN admission and connection lifetime limits.
//!
//! This protects four socket slots, not link bandwidth. Call `refresh` before
//! each ingress packet; established traffic never spends admission tokens.

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket,
};

const SLOTS: usize = 4;
const SOURCES: usize = 32;
const PER_SOURCE_SLOTS: usize = 3;
const SOURCE_BURST: u32 = 32;
const SOURCE_RATE: u32 = 16;
const GLOBAL_BURST: u32 = 64;
const GLOBAL_RATE: u32 = 32;
const SOURCE_IDLE_MS: i64 = 30_000;
const HALF_OPEN_MS: i64 = 3000;
const LIFETIME_MS: i64 = 15_000;
const HTTP_PORT: u16 = 80;
const LOCAL_IP: IpAddress = IpAddress::Ipv4(Ipv4Address::new(10, 0, 2, 15));

#[derive(Clone, Copy)]
struct Bucket {
    // Thousandths of a token preserve fractional refill across frequent polls.
    credit: u32,
    updated: i64,
}

impl Bucket {
    const fn new(burst: u32, now: i64) -> Self {
        Self {
            credit: burst * 1000,
            updated: now,
        }
    }

    fn refill(&mut self, now: i64, rate: u32, burst: u32) {
        let elapsed = now.saturating_sub(self.updated);
        if elapsed <= 0 {
            return;
        }
        let capacity = burst * 1000;
        let elapsed = elapsed.min((capacity / rate) as i64) as u32;
        self.credit = (self.credit + elapsed * rate).min(capacity);
        self.updated = now;
    }
}

#[derive(Clone, Copy)]
struct Source {
    address: IpAddress,
    bucket: Bucket,
    last_seen: i64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Tuple {
    address: IpAddress,
    port: u16,
}

#[derive(Clone, Copy)]
struct Active {
    tuple: Tuple,
    started: i64,
    half_open: bool,
}

pub struct Guard {
    sources: [Option<Source>; SOURCES],
    active: [Option<Active>; SLOTS],
    global: Bucket,
}

impl Default for Guard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard {
    pub const fn new() -> Self {
        Self {
            sources: [None; SOURCES],
            active: [None; SLOTS],
            global: Bucket::new(GLOBAL_BURST, 0),
        }
    }

    pub fn refresh(&mut self, sockets: &SocketSet<'_>, handles: &[SocketHandle; SLOTS], now: i64) {
        for (index, handle) in handles.iter().enumerate() {
            let socket = sockets.get::<tcp::Socket>(*handle);
            let endpoint = socket.remote_endpoint().filter(|_| socket.is_active());
            self.active[index] = endpoint.map(|endpoint| {
                let tuple = Tuple {
                    address: endpoint.addr,
                    port: endpoint.port,
                };
                let started = self.active[index]
                    .filter(|previous| previous.tuple == tuple)
                    .map_or(now, |previous| previous.started);
                Active {
                    tuple,
                    started,
                    half_open: socket.state() == tcp::State::SynReceived,
                }
            });
        }
        self.expire_sources(now);
    }

    /// Abort expired connections, leaving listener rearming to the application.
    pub fn expire(
        &mut self,
        sockets: &mut SocketSet<'_>,
        handles: &[SocketHandle; SLOTS],
        now: i64,
    ) {
        self.refresh(sockets, handles, now);
        for (index, active) in self.active.iter_mut().enumerate() {
            if active.is_some_and(|connection| {
                let age = now.saturating_sub(connection.started);
                age >= LIFETIME_MS || (connection.half_open && age >= HALF_OPEN_MS)
            }) {
                sockets.get_mut::<tcp::Socket>(handles[index]).abort();
                *active = None;
            }
        }
    }

    pub fn allow(&mut self, frame: &[u8], now: i64) -> bool {
        let Ok(ethernet) = EthernetFrame::new_checked(frame) else {
            return true; // Let the stack reject malformed/unrelated packets.
        };
        if ethernet.ethertype() != EthernetProtocol::Ipv4 {
            return true;
        }
        let Ok(ip) = Ipv4Packet::new_checked(ethernet.payload()) else {
            return true;
        };
        if ip.version() != 4
            || IpAddress::Ipv4(ip.dst_addr()) != LOCAL_IP
            || ip.next_header() != IpProtocol::Tcp
            || ip.more_frags()
            || ip.frag_offset() != 0
        {
            // IPv4 reassembly is disabled; smoltcp rejects all fragments.
            return true;
        }
        let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else {
            return true;
        };
        if tcp.dst_port() != HTTP_PORT || !tcp.syn() || tcp.ack() || tcp.rst() || tcp.fin() {
            return true;
        }
        let address = IpAddress::Ipv4(ip.src_addr());
        if !address.is_unicast()
            || tcp.src_port() == 0
            || !ip.verify_checksum()
            || !tcp.verify_checksum(&address, &LOCAL_IP)
        {
            return false;
        }
        self.admit(
            Tuple {
                address,
                port: tcp.src_port(),
            },
            now,
        )
    }

    /// Find an existing connection for a validated HTTP packet. The caller
    /// may temporarily hide listeners so smoltcp dispatches to this tuple.
    pub fn matching_slot(&self, frame: &[u8]) -> Option<usize> {
        let ethernet = EthernetFrame::new_checked(frame).ok()?;
        if ethernet.ethertype() != EthernetProtocol::Ipv4 {
            return None;
        }
        let ip = Ipv4Packet::new_checked(ethernet.payload()).ok()?;
        if ip.version() != 4
            || IpAddress::Ipv4(ip.dst_addr()) != LOCAL_IP
            || ip.next_header() != IpProtocol::Tcp
            || ip.more_frags()
            || ip.frag_offset() != 0
            || !ip.verify_checksum()
        {
            return None;
        }
        let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
        let tuple = Tuple {
            address: IpAddress::Ipv4(ip.src_addr()),
            port: tcp.src_port(),
        };
        if tcp.dst_port() != HTTP_PORT || !tcp.verify_checksum(&tuple.address, &LOCAL_IP) {
            return None;
        }
        self.active
            .iter()
            .position(|entry| entry.is_some_and(|active| active.tuple == tuple))
    }

    fn admit(&mut self, tuple: Tuple, now: i64) -> bool {
        // Retransmissions belong to the existing connection, including while
        // closing, and must not be cut off by a later rate-limit decision.
        if self
            .active
            .iter()
            .flatten()
            .any(|active| active.tuple == tuple)
        {
            return true;
        }
        let occupied = self.active.iter().flatten().count();
        let from_source = self
            .active
            .iter()
            .flatten()
            .filter(|active| active.tuple.address == tuple.address)
            .count();
        if occupied == SLOTS || from_source >= PER_SOURCE_SLOTS {
            return false;
        }
        self.expire_sources(now);
        let existing = self
            .sources
            .iter()
            .position(|entry| entry.is_some_and(|source| source.address == tuple.address));
        let Some(index) = existing.or_else(|| self.sources.iter().position(Option::is_none)) else {
            // Never evict a recent source: cycling spoofed IPs must not reset
            // another source's exhausted bucket.
            return false;
        };
        let source = self.sources[index].get_or_insert(Source {
            address: tuple.address,
            bucket: Bucket::new(SOURCE_BURST, now),
            last_seen: now,
        });
        source.last_seen = now;
        source.bucket.refill(now, SOURCE_RATE, SOURCE_BURST);
        self.global.refill(now, GLOBAL_RATE, GLOBAL_BURST);
        if source.bucket.credit < 1000 || self.global.credit < 1000 {
            return false;
        }
        source.bucket.credit -= 1000;
        self.global.credit -= 1000;
        true
    }

    fn expire_sources(&mut self, now: i64) {
        for entry in &mut self.sources {
            let Some(source) = entry else { continue };
            if self
                .active
                .iter()
                .flatten()
                .any(|active| active.tuple.address == source.address)
            {
                source.last_seen = now;
            } else if now.saturating_sub(source.last_seen) >= SOURCE_IDLE_MS {
                *entry = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::EthernetAddress;

    fn tuple(source: u8, port: u16) -> Tuple {
        Tuple {
            address: IpAddress::v4(10, 0, 2, source),
            port,
        }
    }

    fn syn(source: u8, port: u16) -> [u8; 54] {
        let mut bytes = [0; 54];
        let mut ethernet = EthernetFrame::new_unchecked(&mut bytes[..]);
        ethernet.set_ethertype(EthernetProtocol::Ipv4);
        ethernet.set_src_addr(EthernetAddress([2, 0, 0, 0, 0, source]));
        ethernet.set_dst_addr(EthernetAddress([2, 0, 0, 0, 0, 15]));
        let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(40);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_src_addr(Ipv4Address::new(10, 0, 2, source));
        ip.set_dst_addr(Ipv4Address::new(10, 0, 2, 15));
        ip.fill_checksum();
        let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
        tcp.set_src_port(port);
        tcp.set_dst_port(HTTP_PORT);
        tcp.set_header_len(20);
        tcp.set_syn(true);
        tcp.fill_checksum(&tuple(source, port).address, &LOCAL_IP);
        bytes
    }

    #[test]
    fn source_refill_keeps_fractions_and_caps_bursts() {
        let mut guard = Guard::new();
        for port in 1..=SOURCE_BURST as u16 {
            assert!(guard.allow(&syn(2, port), 0));
        }
        assert!(!guard.allow(&syn(2, 100), 0));
        assert!(!guard.allow(&syn(2, 100), 62));
        assert!(guard.allow(&syn(2, 100), 63));
        assert!(!guard.allow(&syn(2, 101), 63));
        for port in 1..=SOURCE_BURST as u16 {
            assert!(guard.allow(&syn(2, port), 10_000));
        }
        assert!(!guard.allow(&syn(2, 100), 10_000));
    }

    #[test]
    fn global_budget_spans_sources_and_refills() {
        let mut guard = Guard::new();
        for source in [2, 3] {
            for port in 1..=SOURCE_BURST as u16 {
                assert!(guard.allow(&syn(source, port), 0));
            }
        }
        assert!(!guard.allow(&syn(4, 1), 0));
        assert!(!guard.allow(&syn(4, 1), 31));
        assert!(guard.allow(&syn(4, 1), 32));
    }

    #[test]
    fn source_table_does_not_evict_recent_or_active_entries() {
        let mut guard = Guard::new();
        for source in 1..=SOURCES as u8 {
            assert!(guard.allow(&syn(source, 1), 0));
        }
        assert!(!guard.allow(&syn(40, 1), SOURCE_IDLE_MS - 1));
        guard.active[0] = Some(Active {
            tuple: tuple(1, 1),
            started: 0,
            half_open: false,
        });
        assert!(guard.allow(&syn(40, 1), SOURCE_IDLE_MS));
        assert!(
            guard
                .sources
                .iter()
                .flatten()
                .any(|source| source.address == tuple(1, 1).address)
        );
        assert!(guard.allow(&syn(1, 1), SOURCE_IDLE_MS));
    }

    #[test]
    fn per_ip_limit_preserves_retransmits_and_other_sources() {
        let mut guard = Guard::new();
        for index in 0..3 {
            guard.active[index] = Some(Active {
                tuple: tuple(2, index as u16 + 1),
                started: 0,
                half_open: index == 0,
            });
        }
        guard.global.credit = 0;
        assert!(guard.allow(&syn(2, 1), 0));
        assert!(!guard.allow(&syn(2, 4), 1000));
        assert!(guard.allow(&syn(3, 4), 1000));
        guard.active[3] = Some(Active {
            tuple: tuple(3, 4),
            started: 1000,
            half_open: true,
        });
        assert!(!guard.allow(&syn(4, 5), 2000));
        assert!(guard.allow(&syn(3, 4), 2000));
    }

    #[test]
    fn invalid_checksums_do_not_spend_tokens_and_unrelated_traffic_passes() {
        let mut guard = Guard::new();
        let mut frame = syn(2, 1);
        frame[50] ^= 1; // TCP checksum.
        assert!(!guard.allow(&frame, 0));
        assert!(guard.sources.iter().all(Option::is_none));
        frame[37] = 81; // Another destination port is outside the policy.
        assert!(guard.allow(&frame, 0));
        for length in 0..54 {
            assert!(guard.allow(&frame[..length], 0));
        }
    }

    #[test]
    fn retransmitted_syn_cannot_be_stolen_by_an_earlier_listener() {
        use smoltcp::iface::{Config, Interface, SocketStorage};
        use smoltcp::phy::{self, DeviceCapabilities, Medium};
        use smoltcp::time::Instant;
        use smoltcp::wire::IpCidr;

        struct Device(Option<[u8; 54]>);
        struct Receive([u8; 54]);
        struct Transmit;
        impl phy::RxToken for Receive {
            fn consume<R, F>(self, f: F) -> R
            where
                F: FnOnce(&[u8]) -> R,
            {
                f(&self.0)
            }
        }
        impl phy::TxToken for Transmit {
            fn consume<R, F>(self, len: usize, f: F) -> R
            where
                F: FnOnce(&mut [u8]) -> R,
            {
                f(&mut [0; 1514][..len])
            }
        }
        impl phy::Device for Device {
            type RxToken<'a> = Receive;
            type TxToken<'a> = Transmit;
            fn receive(&mut self, _: Instant) -> Option<(Receive, Transmit)> {
                Some((Receive(self.0.take()?), Transmit))
            }
            fn transmit(&mut self, _: Instant) -> Option<Transmit> {
                Some(Transmit)
            }
            fn capabilities(&self) -> DeviceCapabilities {
                let mut caps = DeviceCapabilities::default();
                caps.medium = Medium::Ethernet;
                caps.max_transmission_unit = 1514;
                caps
            }
        }

        let mut device = Device(None);
        let config = Config::new(EthernetAddress([2, 0, 0, 0, 0, 15]).into());
        let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
        interface.update_ip_addrs(|addresses| {
            addresses.push(IpCidr::new(LOCAL_IP, 24)).unwrap();
        });
        let mut rx = [[0; 128]; SLOTS];
        let mut tx = [[0; 128]; SLOTS];
        let mut storage = [const { SocketStorage::EMPTY }; SLOTS];
        let mut sockets = SocketSet::new(&mut storage[..]);
        let mut handles = [SocketHandle::default(); SLOTS];
        for (index, (rx, tx)) in rx.iter_mut().zip(tx.iter_mut()).enumerate() {
            handles[index] = sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(&mut rx[..]),
                tcp::SocketBuffer::new(&mut tx[..]),
            ));
        }
        sockets
            .get_mut::<tcp::Socket>(handles[1])
            .listen(HTTP_PORT)
            .unwrap();
        let frame = syn(2, 12_345);
        device.0 = Some(frame);
        interface.poll_ingress_single(Instant::from_millis(0), &mut device, &mut sockets);
        assert_eq!(
            sockets.get::<tcp::Socket>(handles[1]).state(),
            tcp::State::SynReceived
        );
        for index in [0, 2, 3] {
            sockets
                .get_mut::<tcp::Socket>(handles[index])
                .listen(HTTP_PORT)
                .unwrap();
        }

        // Control: upstream's first-match dispatch gives this retransmission
        // to the earlier listener and creates a duplicate tuple.
        device.0 = Some(frame);
        interface.poll_ingress_single(Instant::from_millis(1), &mut device, &mut sockets);
        assert_eq!(
            sockets.get::<tcp::Socket>(handles[0]).state(),
            tcp::State::SynReceived
        );
        sockets.get_mut::<tcp::Socket>(handles[0]).abort();
        sockets
            .get_mut::<tcp::Socket>(handles[0])
            .listen(HTTP_PORT)
            .unwrap();

        let mut guard = Guard::new();
        guard.global.credit = 0;
        for now in 2..5 {
            guard.refresh(&sockets, &handles, now);
            assert_eq!(guard.matching_slot(&frame), Some(1));
            assert!(guard.allow(&frame, now));
            let mut suspended = [false; SLOTS];
            for (index, handle) in handles.iter().enumerate() {
                let socket = sockets.get_mut::<tcp::Socket>(*handle);
                if socket.is_listening() {
                    socket.abort();
                    suspended[index] = true;
                }
            }
            device.0 = Some(frame);
            interface.poll_ingress_single(Instant::from_millis(now), &mut device, &mut sockets);
            for (index, handle) in handles.iter().enumerate() {
                if suspended[index] {
                    sockets
                        .get_mut::<tcp::Socket>(*handle)
                        .listen(HTTP_PORT)
                        .unwrap();
                }
            }
            assert!(sockets.get::<tcp::Socket>(handles[0]).is_listening());
            assert_eq!(
                sockets.get::<tcp::Socket>(handles[1]).state(),
                tcp::State::SynReceived
            );
            assert_eq!(
                handles
                    .iter()
                    .filter(|handle| sockets.get::<tcp::Socket>(**handle).is_active())
                    .count(),
                1
            );
        }
        assert_eq!(guard.global.credit, 0);
    }
}
