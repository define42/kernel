//! Ethernet/ARP/IPv4/ICMP and TCP using smoltcp, without a heap or interrupts.

use core::fmt::Write;

use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

use crate::console::Console;
use crate::e1000::{E1000, MAX_FRAME_SIZE};
use crate::time::Clock;
use crate::{abi, userspace::Process};
#[cfg(not(feature = "userspace-test"))]
use crate::{arch, syscall};

const FRAME_SIZE: usize = MAX_FRAME_SIZE; // Includes the 14-byte Ethernet header.
const SOCKET_BUFFER_SIZE: usize = 16 * 1024;
const ECHO_PORT: u16 = 1234;
const HTTP_CONNECTIONS: usize = abi::SOCKET_COUNT;
const USER_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/webserver.elf"));

/// Owns the NIC and a CPU-only copy of the most recently received frame.
struct EthernetDevice {
    nic: E1000,
    receive_buffer: [u8; FRAME_SIZE],
}

struct ReceiveToken<'a>(&'a [u8]);
struct TransmitToken<'a>(&'a mut E1000);

impl phy::Device for EthernetDevice {
    type RxToken<'a> = ReceiveToken<'a>;
    type TxToken<'a> = TransmitToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Reserve capacity for a possible immediate ARP/ICMP/TCP response before
        // taking ownership of an RX packet. Holding the token borrows the NIC
        // exclusively, so nobody else can consume that TX slot in the meantime.
        if !self.nic.can_transmit() {
            return None;
        }
        let len = self.nic.receive(&mut self.receive_buffer)?;
        Some((
            ReceiveToken(&self.receive_buffer[..len]),
            TransmitToken(&mut self.nic),
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.nic
            .can_transmit()
            .then_some(TransmitToken(&mut self.nic))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = FRAME_SIZE;
        caps.max_burst_size = Some(63); // One of the 64 TX slots stays unused.
        // The default requires software generation/verification of checksums.
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

impl phy::TxToken for TransmitToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = [0; FRAME_SIZE];
        let result = f(&mut frame[..len]);
        // Capacity was reserved when this token was created, and smoltcp
        // respects the advertised MTU. Failure indicates a driver invariant bug.
        self.0
            .transmit(&frame[..len])
            .expect("reserved e1000 TX slot");
        result
    }
}

pub fn run(console: &mut Console) -> ! {
    let clock = match Clock::new() {
        Ok(clock) => clock,
        Err(error) => {
            writeln!(console, "Network clock unavailable: {error}").ok();
            crate::halt();
        }
    };
    let nic = match E1000::init(&clock) {
        Ok(nic) => nic,
        Err(error) => {
            writeln!(console, "Network unavailable: {error}").ok();
            crate::halt();
        }
    };
    let mac = EthernetAddress(nic.mac_address());
    writeln!(
        console,
        "e1000: MAC {mac}, link {}",
        if nic.link_up() { "up" } else { "down" }
    )
    .ok();
    let mut device = EthernetDevice {
        nic,
        receive_buffer: [0; FRAME_SIZE],
    };
    let mut config = Config::new(mac.into());
    // Vary TCP sequence numbers across boots. This is a timing seed, not a
    // cryptographic entropy source; the kernel currently targets local QEMU use.
    // SAFETY: all supported x86-64 CPUs provide the RDTSC instruction at ring 0.
    config.random_seed = unsafe { core::arch::x86_64::_rdtsc() } ^ clock.now_millis() as u64;
    let mut interface = Interface::new(
        config,
        &mut device,
        Instant::from_millis(clock.now_millis()),
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::v4(10, 0, 2, 15), 24))
            .unwrap();
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 2, 2))
        .unwrap();

    // Fixed storage stays on this function's stack forever. No allocator is
    // needed, and no socket/DMA buffer can outlive its backing storage.
    let mut receive_buffer = [0; SOCKET_BUFFER_SIZE];
    let mut transmit_buffer = [0; SOCKET_BUFFER_SIZE];
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(&mut receive_buffer[..]),
        tcp::SocketBuffer::new(&mut transmit_buffer[..]),
    );
    socket.set_timeout(Some(Duration::from_secs(30)));
    socket.set_keep_alive(Some(Duration::from_secs(10)));
    socket.listen(ECHO_PORT).unwrap();
    let mut http_receive_buffers = [[0; abi::SOCKET_BUFFER_SIZE]; HTTP_CONNECTIONS];
    let mut http_transmit_buffers = [[0; abi::SOCKET_BUFFER_SIZE]; HTTP_CONNECTIONS];
    let mut storage = [const { SocketStorage::EMPTY }; 1 + HTTP_CONNECTIONS];
    let mut sockets = SocketSet::new(&mut storage[..]);
    let echo_handle = sockets.add(socket);
    #[cfg(not(feature = "userspace-test"))]
    let mut echo_buffer = [0; 2048];
    let mut http_handles = [echo_handle; HTTP_CONNECTIONS];
    for (index, (receive, transmit)) in http_receive_buffers
        .iter_mut()
        .zip(http_transmit_buffers.iter_mut())
        .enumerate()
    {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(&mut receive[..]),
            tcp::SocketBuffer::new(&mut transmit[..]),
        );
        socket.set_timeout(Some(Duration::from_secs(10)));
        http_handles[index] = sockets.add(socket);
    }

    writeln!(console, "IPv4: 10.0.2.15/24, gateway 10.0.2.2").ok();
    writeln!(console, "TCP echo listening on 10.0.2.15:1234").ok();
    writeln!(
        console,
        "Host: connect to 127.0.0.1:5555 (make run default)"
    )
    .ok();
    writeln!(console, "Web: http://127.0.0.1:8080/ (make run default)").ok();
    writeln!(console, "Polling network. Use Ctrl-a x to exit QEMU.").ok();

    let mut process = Process::load(USER_IMAGE).expect("load userspace ELF");
    writeln!(
        console,
        "Userspace: isolated RX/R/RW pages, NX stack, guarded stack"
    )
    .ok();
    #[cfg(feature = "userspace-test")]
    crate::user_test::run(&mut process, &mut sockets, &http_handles, &clock, console);

    #[cfg(not(feature = "userspace-test"))]
    run_process(
        console,
        &clock,
        &mut device,
        &mut interface,
        &mut sockets,
        echo_handle,
        &http_handles,
        &mut process,
        &mut echo_buffer,
    );
}

#[cfg(not(feature = "userspace-test"))]
#[allow(clippy::too_many_arguments)]
fn run_process(
    console: &mut Console,
    clock: &Clock,
    device: &mut EthernetDevice,
    interface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    echo_handle: smoltcp::iface::SocketHandle,
    http_handles: &[smoltcp::iface::SocketHandle; HTTP_CONNECTIONS],
    process: &mut Process,
    echo_buffer: &mut [u8],
) -> ! {
    let mut running = true;
    loop {
        let now = Instant::from_millis(clock.now_millis());
        // Handle the application between packets: a reset/last ACK and a new
        // SYN may already be queued together. Rearm the listener before that
        // SYN, and give TX/timers time even under continuous incoming traffic.
        interface.poll_maintenance(now);
        interface.poll_ingress_single(now, device, sockets);
        let socket = sockets.get_mut::<tcp::Socket>(echo_handle);
        if socket.state() == tcp::State::Closed {
            socket.listen(ECHO_PORT).unwrap();
        }
        if socket.can_recv() && socket.can_send() {
            // Only dequeue bytes that fit in TX. Otherwise a slow reader could
            // cause echoed data to be lost when the send buffer fills up.
            let available = socket.send_capacity() - socket.send_queue();
            let limit = available.min(echo_buffer.len());
            let received = socket.recv_slice(&mut echo_buffer[..limit]).unwrap();
            let sent = socket.send_slice(&echo_buffer[..received]).unwrap();
            assert_eq!(sent, received);
        }
        // A peer FIN may arrive with unread bytes. Drain and enqueue all of
        // them first; smoltcp then sends queued data before our own FIN.
        if socket.state() == tcp::State::CloseWait && !socket.can_recv() {
            socket.close();
        }
        interface.poll_egress(now, device, sockets);
        while running {
            // SAFETY: one process, one CPU, IF=0. Its loader-owned pages are
            // disjoint from this supervisor stack and the descriptor tables.
            unsafe { arch::resume(&mut process.context) };
            if process.context.vector != 128 {
                writeln!(
                    console,
                    "Userspace fault: vector={} error={:#x} rip={:#x} address={:#x}",
                    process.context.vector,
                    process.context.error_code,
                    process.context.rip,
                    process.context.cr2
                )
                .ok();
                running = false;
            } else {
                match syscall::dispatch(process, sockets, http_handles, clock, console) {
                    syscall::Action::Poll => break,
                    syscall::Action::Continue => continue,
                    syscall::Action::Exit(code) => {
                        writeln!(console, "Userspace exited: {code}").ok();
                        running = false;
                    }
                }
            }
            for handle in http_handles {
                sockets.get_mut::<tcp::Socket>(*handle).abort();
            }
            writeln!(
                console,
                "Web process stopped; kernel TCP echo remains available."
            )
            .ok();
        }
        // Interrupts are disabled, so HLT here would prevent future RX/timers.
        core::hint::spin_loop();
    }
}
