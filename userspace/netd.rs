//! Isolated Ethernet/ARP/IPv4/ICMP/TCP service. The kernel transports opaque
//! frames and bounded RPC messages; all protocol state belongs to this process.
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../abi.rs"]
mod abi;
#[path = "../src/abuse.rs"]
mod abuse;
mod arp_announce;
mod heap;
mod net_syscall;
mod network_config;

use core::arch::asm;
use core::fmt::{self, Write};
use core::panic::PanicInfo;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address};

use network_config::NetworkConfig;

const FRAME_SIZE: usize = 1514;
const ECHO_BUFFER_SIZE: usize = 16 * 1024;
const ECHO_PORT: u16 = 1234;
const RPC_BATCH: usize = 8;

struct Buffers {
    echo_receive: [u8; ECHO_BUFFER_SIZE],
    echo_transmit: [u8; ECHO_BUFFER_SIZE],
    http_receive: [[u8; abi::SOCKET_BUFFER_SIZE]; abi::SOCKET_COUNT],
    http_transmit: [[u8; abi::SOCKET_BUFFER_SIZE]; abi::SOCKET_COUNT],
}

// These process-private buffers live in BSS, not on the user stack. Keep echo
// buffers allocated so runtime configuration can enable it on a later restart.
static mut BUFFERS: Buffers = Buffers {
    echo_receive: [0; ECHO_BUFFER_SIZE],
    echo_transmit: [0; ECHO_BUFFER_SIZE],
    http_receive: [[0; abi::SOCKET_BUFFER_SIZE]; abi::SOCKET_COUNT],
    http_transmit: [[0; abi::SOCKET_BUFFER_SIZE]; abi::SOCKET_COUNT],
};

struct EthernetDevice {
    receive_buffer: [u8; FRAME_SIZE],
    pending_receive: Option<usize>,
    guard: abuse::Guard,
}

impl EthernetDevice {
    fn prepare(&mut self, now: Instant) -> bool {
        self.pending_receive = None;
        let Ok(length) = net_syscall::receive_frame(&mut self.receive_buffer) else {
            return false;
        };
        let frame = &self.receive_buffer[..length];
        if !self.guard.allow(frame, now.total_millis()) {
            return false;
        }
        self.pending_receive = Some(length);
        self.guard.matching_slot(frame).is_some()
    }
}

struct ReceiveToken<'a>(&'a [u8]);
struct TransmitToken;

impl phy::Device for EthernetDevice {
    type RxToken<'a> = ReceiveToken<'a>;
    type TxToken<'a> = TransmitToken;

    fn receive(&mut self, _: Instant) -> Option<(ReceiveToken<'_>, TransmitToken)> {
        let length = self.pending_receive.take()?;
        Some((ReceiveToken(&self.receive_buffer[..length]), TransmitToken))
    }

    fn transmit(&mut self, _: Instant) -> Option<TransmitToken> {
        Some(TransmitToken)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = FRAME_SIZE;
        caps.max_burst_size = Some(1);
        caps
    }
}

impl phy::RxToken for ReceiveToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.0)
    }
}

impl phy::TxToken for TransmitToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = [0; FRAME_SIZE];
        let result = f(&mut frame[..len]);
        // The bounded kernel queue can fill while this process is preempted.
        // Treat that as packet loss; TCP retransmits and ARP retries normally.
        let _ = net_syscall::send_frame(&frame[..len]);
        result
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(mode: u64, _seed: u64, _iterations: u64) -> ! {
    // SAFETY: the loader supplies a fresh private heap and allocator state on
    // every entry. This process has not allocated or started any user threads.
    assert!(
        unsafe { heap::init() },
        "userspace heap initialization failed"
    );
    let code_segment: u16;
    // SAFETY: CS is readable at every privilege level.
    unsafe {
        asm!("mov {segment:x}, cs", segment = out(reg) code_segment, options(nomem, nostack, preserves_flags));
    }
    assert_eq!(code_segment & 3, 3, "network service must run in ring 3");
    net_syscall::log("Userspace network service: CPL=3\n");
    if mode == 1 {
        check_ipc_boundaries();
    }
    // Fetch on every process start/restart. A failed or malformed response
    // cannot silently reuse a compiled or stale network configuration.
    let network = match net_syscall::network_config() {
        Ok(config) => config,
        Err(error) => {
            writeln!(
                Logger,
                "Network configuration unavailable: {error}; refusing startup"
            )
            .ok();
            net_syscall::exit(1);
        }
    };
    // Every interface, including supervisor restarts, receives a fresh
    // hardware-backed seed. Clock values and fixed test seeds are not fallback
    // entropy. smoltcp's internal PRNG remains non-cryptographic.
    let seed = match net_syscall::random_seed() {
        Ok(seed) => seed,
        Err(error) => {
            writeln!(
                Logger,
                "Network entropy unavailable: {error}; refusing startup"
            )
            .ok();
            net_syscall::exit(1);
        }
    };
    let mac = loop {
        match net_syscall::mac() {
            Ok(mac) => break EthernetAddress(mac),
            Err(abi::EAGAIN) => net_syscall::poll(),
            Err(error) => panic!("network MAC unavailable: {error}"),
        }
    };
    let mut device = EthernetDevice {
        receive_buffer: [0; FRAME_SIZE],
        pending_receive: None,
        guard: abuse::Guard::for_address(Ipv4Address::from(network.address)),
    };
    let mut config = Config::new(mac.into());
    config.random_seed = seed;
    let mut interface = Interface::new(
        config,
        &mut device,
        Instant::from_millis(net_syscall::now_millis()),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(
                Ipv4Address::from(network.address).into(),
                network.prefix,
            ))
            .unwrap();
    });
    if let Some(gateway) = network.gateway {
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::from(gateway))
            .unwrap();
    }

    // SAFETY: _start is entered once in this single-threaded process. The
    // supervisor restores this process's private image on every restart.
    let buffers = unsafe { &mut *core::ptr::addr_of_mut!(BUFFERS) };
    let mut storage = [const { SocketStorage::EMPTY }; 1 + abi::SOCKET_COUNT];
    let mut sockets = SocketSet::new(&mut storage[..]);
    let echo_handle = if network.echo {
        let mut echo = tcp::Socket::new(
            tcp::SocketBuffer::new(&mut buffers.echo_receive[..]),
            tcp::SocketBuffer::new(&mut buffers.echo_transmit[..]),
        );
        echo.set_timeout(Some(Duration::from_secs(30)));
        echo.set_keep_alive(Some(Duration::from_secs(10)));
        echo.listen(ECHO_PORT).unwrap();
        Some(sockets.add(echo))
    } else {
        None
    };
    let mut handles = [SocketHandle::default(); abi::SOCKET_COUNT];
    for (index, (receive, transmit)) in buffers
        .http_receive
        .iter_mut()
        .zip(buffers.http_transmit.iter_mut())
        .enumerate()
    {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(&mut receive[..]),
            tcp::SocketBuffer::new(&mut transmit[..]),
        );
        socket.set_timeout(Some(Duration::from_secs(10)));
        handles[index] = sockets.add(socket);
    }
    let mut echo_buffer = [0; 2048];
    let mut request = abi::Request {
        id: 0,
        operation: 0,
        handle: 0,
        argument: 0,
        length: 0,
        data: [0; abi::SOCKET_BUFFER_SIZE],
    };
    let mut reply = abi::Reply {
        id: 0,
        result: 0,
        length: 0,
        data: [0; abi::SOCKET_BUFFER_SIZE],
    };
    let mut reply_pending = false;
    let mut reply_probe = if mode == 1 {
        ReplyProbe::Waiting
    } else {
        ReplyProbe::Disabled
    };

    let address = Ipv4Address::from(network.address);
    match network.gateway {
        Some(gateway) => writeln!(
            Logger,
            "IPv4: {address}/{}, gateway {}",
            network.prefix,
            Ipv4Address::from(gateway)
        )
        .ok(),
        None => writeln!(
            Logger,
            "IPv4: {address}/{}, no default gateway",
            network.prefix
        )
        .ok(),
    };
    if network.echo {
        writeln!(Logger, "TCP echo listening on {address}:{ECHO_PORT}").ok();
    } else {
        net_syscall::log("TCP echo disabled\n");
    }
    let mut announcements =
        arp_announce::Announcements::new(mac, address, net_syscall::now_millis());
    net_syscall::log("Polling network.\n");
    loop {
        let now = Instant::from_millis(net_syscall::now_millis());
        announcements.poll(now.total_millis(), net_syscall::send_frame);
        device
            .guard
            .expire(&mut sockets, &handles, now.total_millis());
        interface.poll_maintenance(now);
        let existing_http = device.prepare(now);
        let mut suspended = [false; abi::SOCKET_COUNT];
        if existing_http {
            // Preserve active-tuple priority over earlier free listeners.
            // RPCs are handled only after all listeners are restored.
            for (index, handle) in handles.iter().enumerate() {
                let socket = sockets.get_mut::<tcp::Socket>(*handle);
                if socket.is_listening() {
                    socket.abort();
                    suspended[index] = true;
                }
            }
        }
        interface.poll_ingress_single(now, &mut device, &mut sockets);
        for (index, handle) in handles.iter().enumerate() {
            if suspended[index] {
                sockets
                    .get_mut::<tcp::Socket>(*handle)
                    .listen(abi::HTTP_PORT)
                    .unwrap();
            }
        }
        if let Some(handle) = echo_handle {
            poll_echo(sockets.get_mut::<tcp::Socket>(handle), &mut echo_buffer);
        }
        service_requests(
            &mut sockets,
            &handles,
            &mut request,
            &mut reply,
            &mut reply_pending,
            &mut reply_probe,
        );
        interface.poll_egress(now, &mut device, &mut sockets);
        net_syscall::poll();
    }
}

/// Deliberately invalid calls are bounded and cannot consume a normal web RPC.
fn check_ipc_boundaries() {
    let mut canary = [0xa5_u8; 64];
    let address = canary.as_mut_ptr() as u64;
    let request_size = size_of::<abi::Request>() as u64;
    let reply_size = size_of::<abi::Reply>() as u64;
    let readonly = _start as *const () as u64;
    // SAFETY: denied capabilities and invalid ranges must be rejected by the
    // kernel before access. Calls with valid buffers keep those buffers live.
    unsafe {
        for invalid in [0, 0x10_0000, readonly, abi::DRIVER_DMA] {
            assert_eq!(
                net_syscall::raw(abi::SYS_RANDOM, invalid, 8, 0),
                abi::EFAULT
            );
        }
        for length in [0, 7, 9, u64::MAX] {
            assert_eq!(
                net_syscall::raw(abi::SYS_RANDOM, address, length, 0),
                abi::EINVAL
            );
        }
        assert_eq!(
            net_syscall::raw(abi::SYS_RANDOM, address, 8, 1),
            abi::EINVAL
        );
        for invalid in [
            0,
            0x10_0000,
            readonly,
            abi::DRIVER_MMIO,
            abi::DRIVER_DMA,
            0x401f_fff8,
            u64::MAX - 7,
        ] {
            assert_eq!(
                net_syscall::raw(abi::SYS_NET_CONFIG, invalid, abi::NET_CONFIG_SIZE as u64, 0),
                abi::EFAULT
            );
        }
        for length in [0, 15, 17, u64::MAX] {
            assert_eq!(
                net_syscall::raw(abi::SYS_NET_CONFIG, address, length, 0),
                abi::EINVAL
            );
        }
        assert_eq!(
            net_syscall::raw(abi::SYS_NET_CONFIG, address, abi::NET_CONFIG_SIZE as u64, 1),
            abi::EINVAL
        );
        for operation in [
            abi::SYS_DRIVER_READY,
            abi::SYS_DRIVER_RX,
            abi::SYS_DRIVER_TX,
            abi::SYS_MAC_REGISTER,
            abi::SYS_STATE,
            abi::SYS_RECV,
            abi::SYS_SEND,
            abi::SYS_CLOSE,
            abi::SYS_ABORT,
            abi::SYS_LISTEN,
        ] {
            assert_eq!(net_syscall::raw(operation, 0, 0, 0), abi::EACCES);
        }
        for invalid in [0, 0x10_0000, abi::DRIVER_MMIO, abi::DRIVER_DMA] {
            assert_eq!(
                net_syscall::raw(abi::SYS_FRAME_RECV, invalid, 64, 0),
                abi::EFAULT
            );
            assert_eq!(
                net_syscall::raw(abi::SYS_FRAME_SEND, invalid, 14, 0),
                abi::EFAULT
            );
        }
        assert_eq!(
            net_syscall::raw(abi::SYS_FRAME_RECV, readonly, 64, 0),
            abi::EFAULT
        );
        for too_large in [abi::MAX_FRAME_SIZE as u64 + 1, u64::MAX] {
            assert_eq!(
                net_syscall::raw(abi::SYS_FRAME_RECV, address, too_large, 0),
                abi::EINVAL
            );
            assert_eq!(
                net_syscall::raw(abi::SYS_FRAME_SEND, address, too_large, 0),
                abi::EINVAL
            );
        }
        assert_eq!(
            net_syscall::raw(abi::SYS_FRAME_SEND, address, 13, 0),
            abi::EINVAL
        );
        for operation in [abi::SYS_NET_REQUEST, abi::SYS_NET_REPLY] {
            let size = if operation == abi::SYS_NET_REQUEST {
                request_size
            } else {
                reply_size
            };
            assert_eq!(net_syscall::raw(operation, 0, size, 0), abi::EFAULT);
            assert_eq!(net_syscall::raw(operation, 0x10_0000, size, 0), abi::EFAULT);
            assert_eq!(
                net_syscall::raw(operation, address, size - 1, 0),
                abi::EINVAL
            );
            assert_eq!(
                net_syscall::raw(operation, address, u64::MAX, 0),
                abi::EINVAL
            );
        }
        assert_eq!(
            net_syscall::raw(abi::SYS_NET_REQUEST, readonly, request_size, 0),
            abi::EFAULT
        );
    }
    let mut forged = abi::Reply::new();
    for id in [0, u64::MAX] {
        for length in [0, abi::SOCKET_BUFFER_SIZE as u64 + 1, u64::MAX] {
            forged.id = id;
            forged.length = length;
            forged.result = if length == 0 { 0 } else { i64::MAX };
            let error = net_syscall::reply(&forged).expect_err("forged reply was accepted");
            assert!(matches!(error, abi::EAGAIN | abi::EINVAL));
        }
    }
    assert!(
        canary.iter().all(|byte| *byte == 0xa5),
        "IPC probe overwrote its canary"
    );
    // The successful getter writes exactly its sixteen-byte output, even
    // when the surrounding writable user allocation is larger.
    unsafe {
        assert_eq!(
            net_syscall::raw(
                abi::SYS_NET_CONFIG,
                address + 8,
                abi::NET_CONFIG_SIZE as u64,
                0
            ),
            0
        );
    }
    assert!(
        canary[..8]
            .iter()
            .chain(&canary[24..])
            .all(|byte| *byte == 0xa5)
    );
    let wire: [u8; abi::NET_CONFIG_SIZE] = canary[8..24].try_into().unwrap();
    let config = NetworkConfig::from_wire(wire).expect("invalid kernel network configuration");
    assert_eq!(config.to_wire(), wire);
    net_syscall::log("Network IPC validation checks passed.\n");
}

fn poll_echo(socket: &mut tcp::Socket<'_>, buffer: &mut [u8]) {
    if socket.state() == tcp::State::Closed {
        socket.listen(ECHO_PORT).unwrap();
    }
    if socket.can_recv() && socket.can_send() {
        let available = socket.send_capacity() - socket.send_queue();
        let limit = available.min(buffer.len());
        let received = socket.recv_slice(&mut buffer[..limit]).unwrap();
        let sent = socket.send_slice(&buffer[..received]).unwrap();
        assert_eq!(sent, received);
    }
    if socket.state() == tcp::State::CloseWait && !socket.can_recv() {
        socket.close();
    }
}

enum ReplyProbe {
    Disabled,
    Waiting,
    AwaitingAcceptance,
}

fn service_requests(
    sockets: &mut SocketSet<'_>,
    handles: &[SocketHandle; abi::SOCKET_COUNT],
    request: &mut abi::Request,
    reply: &mut abi::Reply,
    reply_pending: &mut bool,
    reply_probe: &mut ReplyProbe,
) {
    for _ in 0..RPC_BATCH {
        if *reply_pending {
            match net_syscall::reply(reply) {
                Ok(()) => {
                    *reply_pending = false;
                    if matches!(reply_probe, ReplyProbe::AwaitingAcceptance) {
                        net_syscall::log("Pending RPC reply validation checks passed.\n");
                        *reply_probe = ReplyProbe::Disabled;
                    }
                }
                Err(abi::EAGAIN) => return,
                Err(error) => {
                    assert!(
                        !matches!(reply_probe, ReplyProbe::AwaitingAcceptance),
                        "valid RPC reply rejected after probes: {error}"
                    );
                    // A restarted web process may have canceled this request.
                    *reply_pending = false;
                }
            }
        }
        match net_syscall::request(request) {
            Ok(()) => {
                reply.id = request.id;
                reply.length = 0;
                reply.result = handle_request(sockets, handles, request, reply);
                if matches!(reply_probe, ReplyProbe::Waiting) {
                    check_pending_reply(request, reply);
                    *reply_probe = ReplyProbe::AwaitingAcceptance;
                }
                *reply_pending = true;
            }
            Err(abi::EAGAIN) => return,
            Err(error) => panic!("network request queue failed: {error}"),
        }
    }
}

/// Execute the real request once, reject bad metadata against its live ID, then
/// retain the original reply for normal delivery. Every rejection must leave
/// that same request pending; the following probe/valid reply checks this too.
fn check_pending_reply(request: &abi::Request, reply: &mut abi::Reply) {
    let original = (reply.id, reply.result, reply.length);
    let rejected = |reply: &abi::Reply| {
        assert_eq!(
            net_syscall::reply(reply),
            Err(abi::EINVAL),
            "malformed reply changed a live RPC"
        );
    };
    reply.id = request.id.wrapping_add(1);
    rejected(reply);
    reply.id = original.0;
    reply.length = abi::SOCKET_BUFFER_SIZE as u64 + 1;
    rejected(reply);
    reply.length = original.2;
    match request.operation {
        abi::SYS_STATE => {
            for invalid in [
                7,
                1 << 10,
                ((abi::SOCKET_BUFFER_SIZE as i64 + 1) << abi::SEND_QUEUE_SHIFT),
            ] {
                reply.result = invalid;
                rejected(reply);
            }
        }
        abi::SYS_SEND | abi::SYS_RECV => {
            reply.result = request.length as i64 + 1;
            reply.length = if request.operation == abi::SYS_RECV {
                reply.result as u64
            } else {
                0
            };
            rejected(reply);
            reply.length = 0;
        }
        abi::SYS_CLOSE | abi::SYS_ABORT | abi::SYS_LISTEN => {
            reply.result = 1;
            rejected(reply);
        }
        _ => panic!("unexpected operation in pending RPC probe"),
    }
    reply.result = abi::EFAULT; // Not an allowed result for any broker-issued operation.
    reply.length = 0;
    rejected(reply);
    (reply.id, reply.result, reply.length) = original;
}

fn handle_request(
    sockets: &mut SocketSet<'_>,
    handles: &[SocketHandle; abi::SOCKET_COUNT],
    request: &abi::Request,
    reply: &mut abi::Reply,
) -> i64 {
    let Some(handle) = usize::try_from(request.handle)
        .ok()
        .and_then(|index| handles.get(index))
    else {
        return abi::EBADF;
    };
    let socket = sockets.get_mut::<tcp::Socket>(*handle);
    match request.operation {
        abi::SYS_STATE => {
            let state = match socket.state() {
                tcp::State::Closed => abi::CLOSED,
                tcp::State::Listen => abi::LISTEN,
                tcp::State::SynReceived => abi::SYN_RECEIVED,
                tcp::State::Established => abi::ESTABLISHED,
                tcp::State::CloseWait => abi::CLOSE_WAIT,
                tcp::State::TimeWait => abi::TIME_WAIT,
                _ => abi::CLOSING,
            };
            (state
                | if socket.can_recv() { abi::CAN_RECV } else { 0 }
                | if socket.can_send() { abi::CAN_SEND } else { 0 }
                | ((socket.send_queue() as u64) << abi::SEND_QUEUE_SHIFT)) as i64
        }
        abi::SYS_CLOSE => {
            socket.close();
            0
        }
        abi::SYS_ABORT => {
            socket.abort();
            0
        }
        abi::SYS_LISTEN => {
            if request.argument != abi::HTTP_PORT as u64 {
                abi::EACCES
            } else if socket.listen(abi::HTTP_PORT).is_ok() {
                0
            } else {
                abi::EINVAL
            }
        }
        abi::SYS_RECV | abi::SYS_SEND => transfer(socket, request, reply),
        _ => abi::ENOSYS,
    }
}

fn transfer(socket: &mut tcp::Socket<'_>, request: &abi::Request, reply: &mut abi::Reply) -> i64 {
    if request.length > abi::SOCKET_BUFFER_SIZE as u64 {
        return abi::EINVAL;
    }
    let length = request.length as usize;
    if length == 0 {
        return 0;
    }
    if request.operation == abi::SYS_RECV {
        if !socket.can_recv() {
            return if socket.may_recv() {
                abi::EAGAIN
            } else {
                abi::ENOTCONN
            };
        }
        match socket.recv_slice(&mut reply.data[..length]) {
            Ok(count) => {
                reply.length = count as u64;
                count as i64
            }
            Err(_) => abi::ENOTCONN,
        }
    } else {
        if !socket.can_send() {
            return if socket.may_send() {
                abi::EAGAIN
            } else {
                abi::ENOTCONN
            };
        }
        socket
            .send_slice(&request.data[..length])
            .map_or(abi::ENOTCONN, |count| count as i64)
    }
}

struct Logger;

impl Write for Logger {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        net_syscall::log(text);
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    writeln!(Logger, "Network service panic: {info}").ok();
    net_syscall::exit(1);
}
