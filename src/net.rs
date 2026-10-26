//! Polled NIC/TCP with timer-preempted userspace and bounded syscall batches.

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
#[cfg(not(any(feature = "userspace-test", feature = "fuzz-test")))]
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
    guard: crate::abuse::Guard,
    pending_receive: Option<usize>,
}

impl EthernetDevice {
    /// Preload one admitted frame before smoltcp borrows the socket set.
    fn prepare(&mut self, timestamp: Instant) -> bool {
        self.pending_receive = None;
        if !self.nic.can_transmit() {
            return false;
        }
        let Some(len) = self.nic.receive(&mut self.receive_buffer) else {
            return false;
        };
        let frame = &self.receive_buffer[..len];
        if !self.guard.allow(frame, timestamp.total_millis()) {
            return false;
        }
        self.pending_receive = Some(len);
        self.guard.matching_slot(frame).is_some()
    }
}

struct ReceiveToken<'a>(&'a [u8]);
struct TransmitToken<'a>(&'a mut E1000);

impl phy::Device for EthernetDevice {
    type RxToken<'a> = ReceiveToken<'a>;
    type TxToken<'a> = TransmitToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // prepare() reserved a TX slot; no NIC operation occurs between
        // preparing this frame and consuming it through poll_ingress_single.
        let len = self.pending_receive.take()?;
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
    crate::timer::init();
    writeln!(console, "Timer: PIT 100 Hz; preemptive user scheduling").ok();
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
        guard: crate::abuse::Guard::new(),
        pending_receive: None,
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
    #[cfg(not(any(feature = "userspace-test", feature = "fuzz-test")))]
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

    device
        .guard
        .expire(&mut sockets, &http_handles, clock.now_millis());
    // Exercise the normal ingress path before test-only process runners take
    // over. HTTP sockets are still closed, so no listener suspension is needed.
    let initial_poll = Instant::from_millis(clock.now_millis());
    device.prepare(initial_poll);
    interface.poll_ingress_single(initial_poll, &mut device, &mut sockets);
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
    crate::memory::check_permissions();
    writeln!(
        console,
        "Userspace: isolated RX/R/RW pages, NX stack, guarded stack"
    )
    .ok();
    #[cfg(feature = "fuzz-test")]
    crate::user_test::fuzz_run(&mut process, &mut sockets, &http_handles, &clock, console);
    #[cfg(all(feature = "userspace-test", not(feature = "fuzz-test")))]
    crate::user_test::run(&mut process, &mut sockets, &http_handles, &clock, console);

    #[cfg(not(any(feature = "userspace-test", feature = "fuzz-test")))]
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

#[cfg(not(any(feature = "userspace-test", feature = "fuzz-test")))]
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
    #[cfg(feature = "preemption-test")]
    let mut phase = {
        process.restart(13);
        writeln!(console, "Preemption test: busy loop").ok();
        0u8
    };
    #[cfg(feature = "preemption-test")]
    let started = clock.now_millis();
    #[cfg(feature = "preemption-test")]
    let mut timer_returns = 0u64;
    #[cfg(feature = "preemption-test")]
    let mut budget_returns = 0u64;
    loop {
        let now = Instant::from_millis(clock.now_millis());
        // Handle the application between packets: a reset/last ACK and a new
        // SYN may already be queued together. Rearm the listener before that
        // SYN, and give TX/timers time even under continuous incoming traffic.
        device
            .guard
            .expire(sockets, http_handles, now.total_millis());
        device
            .guard
            .refresh(sockets, http_handles, now.total_millis());
        interface.poll_maintenance(now);
        let existing_http = device.prepare(now);
        let mut suspended = [false; HTTP_CONNECTIONS];
        if existing_http {
            // smoltcp dispatches to the first matching socket. Hide listeners
            // for this single packet so an earlier free slot cannot steal a
            // later connection's retransmitted SYN. Kernel IF=0 throughout;
            // userspace cannot observe the temporary listener suspension.
            for (index, handle) in http_handles.iter().enumerate() {
                let socket = sockets.get_mut::<tcp::Socket>(*handle);
                if socket.is_listening() {
                    socket.abort();
                    suspended[index] = true;
                }
            }
        }
        interface.poll_ingress_single(now, device, sockets);
        for (index, handle) in http_handles.iter().enumerate() {
            if suspended[index] {
                sockets
                    .get_mut::<tcp::Socket>(*handle)
                    .listen(abi::HTTP_PORT)
                    .unwrap();
            }
        }
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
        let mut calls = 0;
        let slice_started = clock.now_millis();
        while running {
            // SAFETY: one process, one CPU; kernel IF=0, user IF=1. Its loader-owned pages are
            // disjoint from this supervisor stack and the descriptor tables.
            unsafe { arch::resume(&mut process.context) };
            if process.context.vector == crate::timer::VECTOR {
                #[cfg(feature = "preemption-test")]
                {
                    timer_returns += 1;
                }
                break;
            }
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
                    syscall::Action::Continue => {
                        calls += 1;
                        // A process making only short syscalls cannot starve
                        // NIC work by spending most of its time with IF clear.
                        if calls >= 64 || clock.now_millis() - slice_started >= 10 {
                            #[cfg(feature = "preemption-test")]
                            {
                                budget_returns += 1;
                            }
                            break;
                        }
                        continue;
                    }
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
        #[cfg(feature = "preemption-test")]
        {
            let elapsed = clock.now_millis() - started;
            if phase == 0 && elapsed >= 12_000 {
                assert!(timer_returns >= 10, "busy process was not preempted");
                process.restart(14);
                phase = 1;
                writeln!(console, "Preemption test: syscall loop").ok();
            }
            if phase == 1 && elapsed >= 15_000 {
                assert!(budget_returns >= 10, "syscall budget was not enforced");
                phase = 2;
                writeln!(console, "Preemption fairness checks passed.").ok();
            }
        }
        // Kernel IF is clear; keep polling when no process is runnable.
        core::hint::spin_loop();
    }
}
