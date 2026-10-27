//! Scheduling and bounded IPC only: all Ethernet/TCP/HTTP processing is ring 3.
use crate::{
    abi, arch,
    console::Console,
    device::Device,
    network_config::{CONFIG, NetworkConfig},
    nic,
    time::Clock,
    userspace::{self, Process},
};
use core::fmt::Write;

const WEB: usize = 0;
const NETWORK: usize = 1;
const DRIVER: usize = 2;
const NAMES: [&str; 3] = ["web", "network", "driver"];
const IMAGES: [&[u8]; 3] = [
    include_bytes!(concat!(env!("OUT_DIR"), "/webserver.elf")),
    include_bytes!(concat!(env!("OUT_DIR"), "/netd.elf")),
    include_bytes!(concat!(env!("OUT_DIR"), "/nic-driver.elf")),
];
const QUEUE_SIZE: usize = 16;
const RPC_TIMEOUT: i64 = 2000;

struct FrameQueue {
    frames: [[u8; abi::MAX_FRAME_SIZE]; QUEUE_SIZE],
    lengths: [usize; QUEUE_SIZE],
    head: usize,
    count: usize,
}
impl FrameQueue {
    const fn new() -> Self {
        Self {
            frames: [[0; abi::MAX_FRAME_SIZE]; QUEUE_SIZE],
            lengths: [0; QUEUE_SIZE],
            head: 0,
            count: 0,
        }
    }
    fn clear(&mut self) {
        self.head = 0;
        self.count = 0;
    }
    fn push(&mut self, process: &Process, address: u64, length: u64) -> i64 {
        if !(14..=abi::MAX_FRAME_SIZE as u64).contains(&length) {
            return abi::EINVAL;
        }
        if !process.validate_buffer(address, length as usize, false) {
            return abi::EFAULT;
        }
        if self.count == QUEUE_SIZE {
            return abi::EAGAIN;
        }
        let tail = (self.head + self.count) % QUEUE_SIZE;
        if process
            .copy_from_user(address, &mut self.frames[tail][..length as usize])
            .is_err()
        {
            return abi::EFAULT;
        }
        self.lengths[tail] = length as usize;
        self.count += 1;
        length as i64
    }
    fn pop(&mut self, process: &mut Process, address: u64, capacity: u64) -> i64 {
        if capacity > abi::MAX_FRAME_SIZE as u64 {
            return abi::EINVAL;
        }
        if !process.validate_buffer(address, capacity as usize, true) {
            return abi::EFAULT;
        }
        if self.count == 0 {
            return abi::EAGAIN;
        }
        let length = self.lengths[self.head];
        if capacity < length as u64 {
            return abi::EINVAL;
        }
        if process
            .copy_to_user(address, &self.frames[self.head][..length])
            .is_err()
        {
            return abi::EFAULT;
        }
        self.head = (self.head + 1) % QUEUE_SIZE;
        self.count -= 1;
        length as i64
    }
}
struct Channels {
    rx: FrameQueue,
    tx: FrameQueue,
}
static mut CHANNELS: [Channels; nic::MAX_INTERFACES] = [const {
    Channels {
        rx: FrameQueue::new(),
        tx: FrameQueue::new(),
    }
}; nic::MAX_INTERFACES];

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Runnable,
    Blocked,
    Restart(i64),
    Disabled,
}
struct Task {
    process: Process,
    state: State,
    failures: u32,
    log_epoch: i64,
    log_bytes: usize,
    last_yield: i64,
}
struct Pending {
    request: abi::Request,
    delivered: bool,
    address: u64,
    started: i64,
}
struct Broker {
    pending: Option<Pending>,
    next_id: u64,
    mac: Option<u64>,
    // Administrative address survives resets; `mac` above gates service readiness.
    configured_mac: Option<u64>,
    config: NetworkConfig,
    admin_up: bool,
    quarantined: bool,
}
impl Broker {
    fn new() -> Self {
        Self {
            pending: None,
            next_id: 1,
            mac: None,
            configured_mac: None,
            config: CONFIG,
            admin_up: true,
            quarantined: false,
        }
    }
    fn request(&mut self, process: &Process, now: i64) -> Result<(), i64> {
        let c = process.context;
        if c.rdi >= abi::SOCKET_COUNT as u64 {
            return Err(abi::EBADF);
        }
        if c.rax == abi::SYS_LISTEN && c.rsi != abi::HTTP_PORT as u64 {
            return Err(abi::EACCES);
        }
        let transfer = c.rax == abi::SYS_SEND || c.rax == abi::SYS_RECV;
        if transfer {
            if c.rdx > abi::SOCKET_BUFFER_SIZE as u64 {
                return Err(abi::EINVAL);
            }
            if !process.validate_buffer(c.rsi, c.rdx as usize, c.rax == abi::SYS_RECV) {
                return Err(abi::EFAULT);
            }
            if c.rdx == 0 {
                return Err(0);
            }
        }
        if self.pending.is_some() {
            return Err(abi::EAGAIN);
        }
        let mut request = abi::Request::new();
        request.id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("RPC generation exhausted");
        request.operation = c.rax;
        request.handle = c.rdi;
        request.argument = if c.rax == abi::SYS_LISTEN { c.rsi } else { 0 };
        request.length = if transfer { c.rdx } else { 0 };
        if c.rax == abi::SYS_SEND {
            process
                .copy_from_user(c.rsi, &mut request.data[..c.rdx as usize])
                .map_err(|_| abi::EFAULT)?;
        }
        self.pending = Some(Pending {
            request,
            delivered: false,
            address: c.rsi,
            started: now,
        });
        Ok(())
    }
    fn deliver(&mut self, process: &mut Process, address: u64, length: u64) -> i64 {
        if length != size_of::<abi::Request>() as u64 {
            return abi::EINVAL;
        }
        if !process.validate_buffer(address, length as usize, true) {
            return abi::EFAULT;
        }
        let Some(pending) = self.pending.as_mut().filter(|p| !p.delivered) else {
            return abi::EAGAIN;
        };
        // SAFETY: Request contains initialized integers/bytes and no padding.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&pending.request as *const abi::Request).cast::<u8>(),
                size_of::<abi::Request>(),
            )
        };
        if process.copy_to_user(address, bytes).is_err() {
            return abi::EFAULT;
        }
        pending.delivered = true;
        0
    }
    fn reply(&mut self, tasks: &mut [Task; 3], address: u64, length: u64) -> i64 {
        if length != size_of::<abi::Reply>() as u64 {
            return abi::EINVAL;
        }
        let mut reply = abi::Reply::new();
        // SAFETY: every bit pattern is valid for Reply's integer/byte fields.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                (&mut reply as *mut abi::Reply).cast::<u8>(),
                size_of::<abi::Reply>(),
            )
        };
        if tasks[NETWORK]
            .process
            .copy_from_user(address, bytes)
            .is_err()
        {
            return abi::EFAULT;
        }
        let Some(pending) = self.pending.as_ref() else {
            return abi::EAGAIN;
        };
        if !pending.delivered
            || reply.id != pending.request.id
            || tasks[WEB].state != State::Blocked
        {
            return abi::EINVAL;
        }
        let scalar_valid = match pending.request.operation {
            abi::SYS_STATE => {
                reply.result >= 0
                    && (reply.result as u64 & abi::STATE_MASK) <= abi::TIME_WAIT
                    && reply.result as u64 & 0xfc00 == 0
                    && (reply.result as u64 >> abi::SEND_QUEUE_SHIFT)
                        <= abi::SOCKET_BUFFER_SIZE as u64
            }
            abi::SYS_CLOSE | abi::SYS_ABORT => reply.result == 0,
            abi::SYS_LISTEN => reply.result == 0 || reply.result == abi::EINVAL,
            abi::SYS_SEND | abi::SYS_RECV => {
                reply.result >= 0 || matches!(reply.result, abi::EAGAIN | abi::ENOTCONN)
            }
            _ => false,
        };
        if !scalar_valid {
            return abi::EINVAL;
        }
        let receiving = pending.request.operation == abi::SYS_RECV;
        if reply.length > abi::SOCKET_BUFFER_SIZE as u64
            || (receiving
                && reply.result >= 0
                && (reply.result as u64 != reply.length || reply.length > pending.request.length))
            || (!receiving && reply.length != 0)
            || (reply.result < 0 && reply.length != 0)
            || (pending.request.operation == abi::SYS_SEND
                && reply.result > pending.request.length as i64)
        {
            return abi::EINVAL;
        }
        if receiving
            && reply.result > 0
            && tasks[WEB]
                .process
                .copy_to_user(pending.address, &reply.data[..reply.length as usize])
                .is_err()
        {
            return abi::EFAULT;
        }
        tasks[WEB].process.context.rax = reply.result as u64;
        tasks[WEB].state = State::Runnable;
        self.pending = None;
        0
    }
}

#[path = "entropy.rs"]
mod entropy;

pub fn run(console: &mut Console) -> ! {
    if entropy::random_u64().is_none() {
        writeln!(
            console,
            "Hardware entropy unavailable; refusing network startup."
        )
        .ok();
        crate::shell::run(console, None);
    }
    let clock = match Clock::new() {
        Ok(clock) => clock,
        Err(error) => {
            writeln!(
                console,
                "Clock unavailable: {error}; refusing network startup."
            )
            .ok();
            crate::shell::run(console, None);
        }
    };
    if let Err(error) = crate::timer::init(&clock) {
        writeln!(
            console,
            "Preemption unavailable: {error}; refusing network startup."
        )
        .ok();
        crate::shell::run(console, Some(&clock));
    }
    writeln!(
        console,
        "Timer: {} 100 Hz; preemptive service scheduling",
        crate::timer::BACKEND
    )
    .ok();
    let devices = match Device::discover(&clock) {
        Ok(devices) => devices,
        Err(error) => {
            writeln!(
                console,
                "Network isolation unavailable: {error}; refusing device access."
            )
            .ok();
            crate::shell::run(console, Some(&clock));
        }
    };
    let mut groups: [Option<Group<'_>>; nic::MAX_INTERFACES] =
        [const { None }; nic::MAX_INTERFACES];
    for (index, device) in devices.into_iter().enumerate() {
        let Some(mut device) = device else { continue };
        let mut tasks = core::array::from_fn(|role| Task {
            process: Process::load_slot(IMAGES[role], index * 3 + role).expect("load service ELF"),
            state: State::Runnable,
            failures: 0,
            log_epoch: 0,
            log_bytes: 0,
            last_yield: 0,
        });
        device
            .configure(&mut tasks[DRIVER].process)
            .expect("configure isolated NIC");
        driver_context(&mut tasks[DRIVER].process, &device, None);
        groups[index] = Some(Group {
            tasks,
            broker: Broker::new(),
            device,
        });
    }
    #[cfg(feature = "isolation-test")]
    {
        let first = groups[0].as_mut().expect("first interface");
        let [web, network, driver] = &mut first.tasks;
        userspace::check_isolation(&mut web.process, &mut network.process, &mut driver.process);
        writeln!(
            console,
            "Process address-space and SIMD isolation checks passed."
        )
        .ok();
        first.device.stop().expect("stop device for mapping probe");
        // SAFETY: all services are stopped and this device's DMA revoke completed.
        unsafe { userspace::check_device_unmapping(&mut driver.process) };
        first
            .device
            .configure(&mut driver.process)
            .expect("restore driver mappings");
        writeln!(console, "Revoked driver MMIO/DMA mappings fault at CPL3.").ok();
        let (first, rest) = groups.split_at_mut(1);
        if let Some(second) = rest[0].as_mut() {
            let [a, b, c] = &mut first[0].as_mut().expect("first interface").tasks;
            let [d, e, f] = &mut second.tasks;
            // SAFETY: neither configured driver has started bus mastering yet.
            unsafe {
                userspace::check_interface_isolation(
                    [&mut a.process, &mut b.process, &mut c.process],
                    [&mut d.process, &mut e.process, &mut f.process],
                )
            };
            writeln!(
                console,
                "Cross-interface process and DMA memory isolation checks passed."
            )
            .ok();
        }
        for group in groups.iter_mut().flatten() {
            driver_context(
                &mut group.tasks[DRIVER].process,
                &group.device,
                group.broker.configured_mac,
            );
        }
    }
    userspace::activate_kernel();
    crate::memory::check_permissions();
    writeln!(
        console,
        "Isolation: three address spaces per NIC; private IPC and VT-d DMA domains"
    )
    .ok();
    // SAFETY: single scheduler/CPU with IF clear; queues are supervisor-only.
    let all_channels = unsafe { &mut *core::ptr::addr_of_mut!(CHANNELS) };
    #[cfg(feature = "fuzz-test")]
    let (mut fuzz_calls, mut fuzz_preemptions) = (0u64, 0u64);
    #[cfg(feature = "fuzz-test")]
    let fuzz_iterations: u64 = env!("KERNEL_FUZZ_ITERATIONS")
        .parse()
        .expect("fuzz iterations");
    #[cfg(feature = "fuzz-test")]
    {
        let tasks = &mut groups[0].as_mut().expect("first interface").tasks;
        let seed: u64 = env!("KERNEL_FUZZ_SEED").parse().expect("fuzz seed");
        tasks[WEB].process.restart(15);
        tasks[WEB].process.context.rsi = seed;
        tasks[WEB].process.context.rdx = fuzz_iterations;
        writeln!(
            console,
            "Syscall fuzz: seed={seed} iterations={fuzz_iterations}"
        )
        .ok();
    }
    #[cfg(feature = "preemption-test")]
    let (mut phase, mut timer_returns, mut budget_returns) = (0, 0u64, 0u64);
    #[cfg(feature = "preemption-test")]
    groups[0].as_mut().expect("first interface").tasks[WEB]
        .process
        .restart(13);
    #[cfg(feature = "preemption-test")]
    writeln!(console, "Preemption test: busy loop").ok();
    #[cfg(feature = "isolation-test")]
    let mut test_phase = 0;
    #[cfg(feature = "isolation-test")]
    let mut test_driver_mode = 0;
    #[cfg(feature = "isolation-test")]
    {
        let tasks = &mut groups[0].as_mut().expect("first interface").tasks;
        tasks[DRIVER].process.context.rcx = if option_env!("KERNEL_IR_PROBE") == Some("1") {
            6
        } else {
            1
        };
        tasks[NETWORK].process.context.rdi = 1;
    }
    let mut shell = crate::shell::Shell::new();
    let first_run = clock.now_millis();
    for group in groups.iter_mut().flatten() {
        for task in &mut group.tasks {
            task.last_yield = first_run;
        }
    }
    let mut selected = 0;
    let mut global_quarantine = false;
    #[cfg(feature = "isolation-test")]
    // SAFETY: mapped supervisor text. Volatile reads verify that forbidden
    // NIC writes did not alter the actual target bytes despite CPU caching.
    let dma_canary =
        unsafe { core::ptr::read_volatile(abi::KERNEL_PROBE_ADDRESS as *const [u8; 64]) };
    'schedule: loop {
        if !global_quarantine
            && groups
                .iter()
                .flatten()
                .any(|group| group.device.global_faulted())
        {
            // Block every requester before any per-NIC reset/drain can wait.
            for group in groups.iter_mut().flatten() {
                if let Err(error) = group.device.block_dma() {
                    writeln!(console, "Shared failure: {error}").ok();
                }
            }
            for (index, group) in groups.iter_mut().enumerate() {
                let Some(group) = group else { continue };
                let _ = group.device.stop();
                quarantine(
                    &mut group.tasks,
                    &mut group.broker,
                    &mut all_channels[index],
                );
            }
            global_quarantine = true;
            writeln!(console, "All NICs quarantined after shared VT-d failure.").ok();
        }
        for index in 0..nic::MAX_INTERFACES {
            // No administrative mutation may follow a shared unit failure.
            if !global_quarantine
                && groups
                    .iter()
                    .flatten()
                    .any(|group| group.device.global_faulted())
            {
                continue 'schedule;
            }
            if let Some(action) = shell.poll(
                console,
                Some(clock.now_millis()),
                nic_status(&groups, selected),
            ) {
                let result = if let nic::Action::Select(target) = action {
                    if groups.get(target).is_some_and(Option::is_some) {
                        selected = target;
                        Ok("selected for console configuration; networking unchanged")
                    } else {
                        Err("Unknown interface; use nic list.")
                    }
                } else if let nic::Action::Setup(setup) = action {
                    apply_setup(&setup, &mut groups, all_channels, clock.now_millis())
                } else {
                    let group = groups[selected].as_mut().expect("selected interface");
                    apply_nic(
                        action,
                        &mut group.tasks,
                        &mut group.broker,
                        &mut all_channels[selected],
                        &mut group.device,
                        clock.now_millis(),
                    )
                };
                shell.complete_nic(result);
            }
            let Some(Group {
                tasks,
                broker,
                device,
            }) = groups[index].as_mut()
            else {
                continue;
            };
            let channels = &mut all_channels[index];
            let now = clock.now_millis();
            if tasks[DRIVER].state == State::Runnable && device.faulted() {
                if let Some(fault) = device.fault() {
                    writeln!(
                        console,
                        "Contained NIC DMA fault: address={:#x} source={:#x} reason={} write={}",
                        fault.address, fault.source, fault.reason, fault.write
                    )
                    .ok();
                } else {
                    writeln!(console, "Contained NIC DMA fault: fault status overflow").ok();
                }
                #[cfg(feature = "isolation-test")]
                if index == 0 {
                    match test_phase {
                        0 => {
                            let fault = device.fault().expect("read DMA fault record");
                            if option_env!("KERNEL_IR_PROBE") == Some("1") {
                                assert_eq!(
                                    fault.reason, 0x22,
                                    "nonpresent interrupt-remapping entry"
                                );
                                writeln!(
                                    console,
                                    "Nonpresent interrupt-remapping entry blocked NIC MSI."
                                )
                                .ok();
                            } else {
                                assert_eq!(fault.address, abi::KERNEL_PROBE_ADDRESS);
                                assert!(!fault.write);
                            }
                            test_phase = 1;
                        }
                        2 => {
                            let fault = device.fault().expect("write DMA fault record");
                            assert_eq!(fault.address, abi::KERNEL_PROBE_ADDRESS);
                            assert!(fault.write);
                            // SAFETY: same mapped text as the pre-probe snapshot.
                            assert_eq!(
                                unsafe {
                                    core::ptr::read_volatile(
                                        abi::KERNEL_PROBE_ADDRESS as *const [u8; 64],
                                    )
                                },
                                dma_canary
                            );
                            test_phase = 3;
                        }
                        10 if option_env!("KERNEL_IR_PROBE") == Some("1") => {
                            let fault = device.fault().expect("interrupt-remapping fault record");
                            assert_eq!(fault.reason, 0x22);
                            writeln!(console, "NIC interrupt-aperture containment passed.").ok();
                            writeln!(
                                console,
                                "QEMU compatibility-format interrupts remain unverified."
                            )
                            .ok();
                            test_phase = 11;
                        }
                        13 => {
                            let fault = device.fault().expect("cross-interface DMA fault record");
                            assert_eq!(fault.address, device.peer_iova().expect("peer DMA window"));
                            assert!(fault.write);
                            writeln!(console, "Cross-interface DMA write blocked by VT-d.").ok();
                            test_phase = 14;
                        }
                        _ => panic!("unexpected DMA fault in isolation test"),
                    }
                }
                restart_group(DRIVER, tasks, broker, channels, device, now, console);
            }
            if broker
                .pending
                .as_ref()
                .is_some_and(|p| now - p.started >= RPC_TIMEOUT)
            {
                writeln!(
                    console,
                    "Network RPC deadline expired; restarting network services"
                )
                .ok();
                restart_group(NETWORK, tasks, broker, channels, device, now, console);
            }
            for slot in [DRIVER, NETWORK] {
                if tasks[slot].state == State::Runnable && now - tasks[slot].last_yield >= 2000 {
                    writeln!(console, "Service {} heartbeat expired", NAMES[slot]).ok();
                    restart_group(slot, tasks, broker, channels, device, now, console);
                }
            }
            for slot in [DRIVER, NETWORK, WEB] {
                if let State::Restart(at) = tasks[slot].state {
                    if now < at {
                        continue;
                    }
                    tasks[slot].process.restart(0);
                    #[cfg(feature = "isolation-test")]
                    if index == 0 && slot == NETWORK {
                        tasks[slot].process.context.rdi = 1;
                    }
                    if slot == DRIVER {
                        if let Err(error) = device.configure(&mut tasks[slot].process) {
                            let _ = device.stop();
                            quarantine(tasks, broker, channels);
                            writeln!(
                                console,
                                "Networking quarantined after device setup failure: {error}"
                            )
                            .ok();
                            continue;
                        }
                        driver_context(&mut tasks[slot].process, device, broker.configured_mac);
                        #[cfg(feature = "isolation-test")]
                        if index == 0 {
                            tasks[slot].process.context.rcx = test_driver_mode;
                            test_driver_mode = 0;
                        }
                    }
                    tasks[slot].state = State::Runnable;
                    tasks[slot].last_yield = now;
                    writeln!(console, "Service {} restarted", NAMES[slot]).ok();
                }
                if tasks[slot].state != State::Runnable {
                    continue;
                }
                let started = clock.now_millis();
                for call_count in 0..64 {
                    // A failure during a previous grant/revoke must stop all
                    // requesters before another userspace service can run.
                    if device.global_faulted() {
                        continue 'schedule;
                    }
                    tasks[slot].process.activate();
                    // SAFETY: this task owns its CR3 and private backing. All
                    // privileged state stays supervisor-only across the switch.
                    unsafe { arch::resume(&mut tasks[slot].process.context) };
                    tasks[slot].process.save_extended_state();
                    userspace::activate_kernel();
                    let context = tasks[slot].process.context;
                    #[cfg(feature = "fuzz-test")]
                    if index == 0 && slot == WEB {
                        if context.vector == crate::timer::VECTOR {
                            fuzz_preemptions += 1;
                        } else {
                            assert_eq!(context.vector, 128, "fuzz process fault: {context:?}");
                            fuzz_calls += 1;
                            if fuzz_calls.is_multiple_of(16384) {
                                writeln!(console, "Syscall fuzz progress: calls={fuzz_calls}").ok();
                            }
                            if context.rax == abi::SYS_EXIT {
                                assert_eq!(context.rdi, 0, "syscall fuzz failed");
                                assert!(fuzz_calls >= fuzz_iterations);
                                crate::memory::check_permissions();
                                writeln!(console, "Syscall fuzz passed: calls={fuzz_calls} preemptions={fuzz_preemptions}").ok();
                                console.flush_serial_logs_for_exit();
                                crate::exit_qemu(0x10);
                            }
                        }
                    }
                    if context.vector == crate::timer::VECTOR {
                        #[cfg(feature = "preemption-test")]
                        if index == 0 && slot == WEB {
                            timer_returns += 1;
                        }
                        break;
                    }
                    if context.vector != 128 || context.rax == abi::SYS_EXIT {
                        #[cfg(feature = "isolation-test")]
                        if index == 0 {
                            match (test_phase, slot) {
                                (4, WEB) => {
                                    assert_eq!(context.vector, 6, "IPC probe must reach UD2");
                                    test_phase = 5;
                                }
                                (6, NETWORK) => {
                                    assert_eq!(context.vector, 14);
                                    test_phase = 7;
                                }
                                (8, DRIVER) => {
                                    assert_eq!(context.vector, 6);
                                    test_phase = 9;
                                }
                                (10, DRIVER) => {
                                    assert_eq!(
                                        (context.vector, context.rax, context.rdi),
                                        (128, abi::SYS_EXIT, 0)
                                    );
                                    writeln!(console, "NIC interrupt-aperture containment passed.")
                                        .ok();
                                    if option_env!("KERNEL_IR_PROBE") == Some("1") {
                                        writeln!(
                                    console,
                                    "QEMU compatibility-format interrupts remain unverified."
                                )
                                .ok();
                                    }
                                    test_phase = 11;
                                }
                                _ => panic!(
                                    "unexpected service failure in isolation test: phase={test_phase} slot={slot} {context:?}"
                                ),
                            }
                        }
                        writeln!(
                            console,
                            "Service {} stopped: vector={} result={} rip={:#x} address={:#x}",
                            NAMES[slot], context.vector, context.rdi, context.rip, context.cr2
                        )
                        .ok();
                        restart_group(
                            slot,
                            tasks,
                            broker,
                            channels,
                            device,
                            clock.now_millis(),
                            console,
                        );
                        break;
                    }
                    let result = dispatch(slot, tasks, broker, channels, device, &clock, console);
                    tasks[slot].process.context.rax = result as u64;
                    if tasks[slot].state != State::Runnable || context.rax == abi::SYS_POLL {
                        break;
                    }
                    if call_count == 63 || clock.now_millis() - started >= 10 {
                        #[cfg(feature = "preemption-test")]
                        if index == 0 && slot == WEB {
                            budget_returns += 1;
                        }
                        break;
                    }
                }
            }
            #[cfg(feature = "preemption-test")]
            if index == 0 && phase == 0 && now >= 12_000 {
                assert!(timer_returns >= 10, "busy process was not preempted");
                tasks[WEB].process.restart(14);
                phase = 1;
                writeln!(console, "Preemption test: syscall loop").ok();
            } else if index == 0 && phase == 1 && now >= 15_000 {
                assert!(
                    budget_returns >= 10,
                    "syscall process did not yield its budget"
                );
                phase = 2;
                writeln!(console, "Preemption fairness checks passed.").ok();
            }
            #[cfg(feature = "isolation-test")]
            if index == 0 {
                match test_phase {
                    1 if now >= 2000 && broker.mac.is_some() => {
                        tasks[DRIVER].failures = 0;
                        restart_group(DRIVER, tasks, broker, channels, device, now, console);
                        test_driver_mode = 5;
                        test_phase = 2;
                    }
                    3 if now >= 4000 && broker.mac.is_some() => {
                        writeln!(console, "DMA containment and driver recovery passed.").ok();
                        broker.pending = None;
                        tasks[WEB].process.restart(16);
                        tasks[WEB].state = State::Runnable;
                        test_phase = 4;
                    }
                    5 if now >= 6000 => {
                        tasks[NETWORK].process.context.rip = 0;
                        test_phase = 6;
                    }
                    7 if now >= 8000 => {
                        tasks[DRIVER].failures = 0;
                        restart_group(DRIVER, tasks, broker, channels, device, now, console);
                        test_driver_mode = 2;
                        test_phase = 8;
                    }
                    9 if now >= 10000 && broker.mac.is_some() => {
                        tasks[DRIVER].failures = 0;
                        restart_group(DRIVER, tasks, broker, channels, device, now, console);
                        test_driver_mode = 4;
                        test_phase = 10;
                    }
                    11 if now >= 14_000 && broker.mac.is_some() => {
                        if device.peer_iova().is_some() {
                            tasks[DRIVER].failures = 0;
                            restart_group(DRIVER, tasks, broker, channels, device, now, console);
                            test_driver_mode = 7;
                            test_phase = 13;
                        } else {
                            writeln!(console, "Service isolation and recovery checks passed.").ok();
                            test_phase = 12;
                        }
                    }
                    14 if now >= 16_000 && broker.mac.is_some() => {
                        writeln!(console, "Cross-interface DMA fault recovery passed.").ok();
                        writeln!(console, "Service isolation and recovery checks passed.").ok();
                        test_phase = 12;
                    }
                    12 if now >= 19_000
                        && device.peer_iova().is_some()
                        && option_env!("KERNEL_SHARED_FAULT_PROBE") == Some("1") =>
                    {
                        writeln!(console, "Injecting synthetic shared VT-d failure.").ok();
                        device.inject_shared_failure();
                        test_phase = 15;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn driver_context(process: &mut Process, device: &Device<'_>, mac: Option<u64>) {
    process.context.rdi = abi::DRIVER_MMIO;
    process.context.rsi = abi::DRIVER_DMA;
    process.context.rdx = device.iova();
    // Sixth System V argument: zero requests the EEPROM address on first start.
    process.context.r9 = mac.unwrap_or(0);
    #[cfg(feature = "isolation-test")]
    {
        process.context.r8 = device.peer_iova().unwrap_or(0);
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch(
    slot: usize,
    tasks: &mut [Task; 3],
    broker: &mut Broker,
    channels: &mut Channels,
    device: &mut Device<'_>,
    clock: &Clock,
    console: &mut Console,
) -> i64 {
    let c = tasks[slot].process.context;
    let (a, b, d) = (c.rdi, c.rsi, c.rdx);
    match c.rax {
        abi::SYS_POLL => {
            tasks[slot].last_yield = clock.now_millis();
            0
        }
        abi::SYS_NOW => clock.now_millis(),
        abi::SYS_LOG => {
            if b > abi::MAX_LOG as u64 {
                return abi::EINVAL;
            }
            let task = &mut tasks[slot];
            let now = clock.now_millis();
            if now - task.log_epoch >= 1000 {
                task.log_epoch = now;
                task.log_bytes = 0;
            }
            if task.log_bytes + b as usize > 4096 {
                return abi::EAGAIN;
            }
            let mut buffer = [0u8; abi::MAX_LOG];
            if task
                .process
                .copy_from_user(a, &mut buffer[..b as usize])
                .is_err()
            {
                return abi::EFAULT;
            }
            match core::str::from_utf8(&buffer[..b as usize]) {
                Ok(message) => {
                    task.log_bytes += b as usize;
                    console.write_str(message).ok();
                    b as i64
                }
                Err(_) => abi::EINVAL,
            }
        }
        abi::SYS_STATE
        | abi::SYS_RECV
        | abi::SYS_SEND
        | abi::SYS_CLOSE
        | abi::SYS_ABORT
        | abi::SYS_LISTEN => {
            if slot != WEB {
                return abi::EACCES;
            }
            let _ = d;
            match broker.request(&tasks[slot].process, clock.now_millis()) {
                Ok(()) => {
                    tasks[slot].state = State::Blocked;
                    0
                }
                Err(error) => error,
            }
        }
        abi::SYS_FRAME_RECV if slot == NETWORK => channels.rx.pop(&mut tasks[slot].process, a, b),
        abi::SYS_FRAME_SEND if slot == NETWORK => channels.tx.push(&tasks[slot].process, a, b),
        abi::SYS_DRIVER_RX if slot == DRIVER => channels.rx.push(&tasks[slot].process, a, b),
        abi::SYS_DRIVER_TX if slot == DRIVER => channels.tx.pop(&mut tasks[slot].process, a, b),
        abi::SYS_NET_REQUEST if slot == NETWORK => broker.deliver(&mut tasks[slot].process, a, b),
        abi::SYS_NET_REPLY if slot == NETWORK => broker.reply(tasks, a, b),
        abi::SYS_DRIVER_READY if slot == DRIVER => device.start().map_or(abi::EIO, |_| 0),
        abi::SYS_MAC if slot == NETWORK => broker.mac.map_or(abi::EAGAIN, |mac| mac as i64),
        abi::SYS_NET_CONFIG if slot == NETWORK => {
            if b != abi::NET_CONFIG_SIZE as u64 || d != 0 {
                return abi::EINVAL;
            }
            tasks[slot]
                .process
                .copy_to_user(a, &broker.config.to_wire())
                .map_or(abi::EFAULT, |_| 0)
        }
        abi::SYS_MAC_REGISTER if slot == DRIVER => {
            if !crate::setup::valid_mac(a)
                || broker.configured_mac.is_some_and(|expected| expected != a)
            {
                return abi::EINVAL;
            }
            if device.running() || broker.mac.is_some() {
                return abi::EACCES;
            }
            broker.configured_mac = Some(a);
            broker.mac = Some(a);
            0
        }
        abi::SYS_RANDOM if slot == NETWORK => {
            if b != 8 || d != 0 {
                return abi::EINVAL;
            }
            if !tasks[slot].process.validate_buffer(a, 8, true) {
                return abi::EFAULT;
            }
            match entropy::random_u64() {
                Some(value) => tasks[slot]
                    .process
                    .copy_to_user(a, &value.to_le_bytes())
                    .map_or(abi::EFAULT, |_| 0),
                None => abi::EIO,
            }
        }
        abi::SYS_FRAME_RECV..=abi::SYS_NET_CONFIG => abi::EACCES,
        _ => abi::ENOSYS,
    }
}

struct Group<'a> {
    tasks: [Task; 3],
    broker: Broker,
    device: Device<'a>,
}

fn group_state(group: &Group<'_>) -> nic::State {
    let Group {
        tasks,
        broker,
        device,
    } = group;
    if broker.quarantined {
        nic::State::Quarantined
    } else if !broker.admin_up {
        nic::State::Down
    } else if device.running()
        && broker.mac.is_some()
        && tasks
            .iter()
            .all(|task| matches!(task.state, State::Runnable | State::Blocked))
    {
        nic::State::Up
    } else {
        nic::State::Starting
    }
}

fn nic_status(groups: &[Option<Group<'_>>; nic::MAX_INTERFACES], selected: usize) -> nic::Status {
    let group = groups[selected].as_ref().expect("selected interface");
    nic::Status {
        selected: Some(selected),
        interfaces: core::array::from_fn(|index| {
            groups[index].as_ref().map(|group| nic::Interface {
                bdf: group.device.bdf(),
                mac: group.broker.configured_mac,
                state: group_state(group),
                config: group.broker.config,
                enabled: group.broker.admin_up,
            })
        }),
        config: group.broker.config,
        state: group_state(group),
        mac: group.broker.mac,
        bdf: Some(group.device.bdf()),
        link_up: Some(group.device.link_up()),
    }
}

fn quarantine(tasks: &mut [Task; 3], broker: &mut Broker, channels: &mut Channels) {
    for task in tasks {
        task.state = State::Disabled;
    }
    broker.pending = None;
    broker.mac = None;
    broker.admin_up = false;
    broker.quarantined = true;
    channels.rx.clear();
    channels.tx.clear();
}

/// Apply one preflighted batch without running userspace between entries.
/// Validation has no side effects. Hardware teardown failure retains old
/// configurations and quarantines changed interfaces; no pool is reused then.
fn apply_setup(
    request: &crate::setup::Setup,
    groups: &mut [Option<Group<'_>>; nic::MAX_INTERFACES],
    channels: &mut [Channels; nic::MAX_INTERFACES],
    now: i64,
) -> Result<&'static str, &'static str> {
    let snapshot = nic_status(groups, 0);
    let plan = crate::setup_plan::prepare(request, &snapshot)?;
    if plan.iter().all(Option::is_none) {
        return Ok("unchanged");
    }
    let mut failed = false;
    // Disable all affected services and block all affected active requesters
    // before the first reset/drain wait. Unlisted and unchanged peers stay live.
    for (index, target) in plan.iter().enumerate() {
        if target.is_none() {
            continue;
        }
        let group = groups[index].as_mut().expect("preflighted interface");
        for task in &mut group.tasks {
            task.state = State::Disabled;
        }
        group.broker.pending = None;
        group.broker.mac = None;
        group.broker.admin_up = false;
        channels[index].rx.clear();
        channels[index].tx.clear();
        if snapshot.interfaces[index].unwrap().enabled && group.device.block_dma().is_err() {
            failed = true;
        }
    }
    let mut shared_failed = false;
    for (index, target) in plan.iter().enumerate() {
        if target.is_none() || !snapshot.interfaces[index].unwrap().enabled {
            continue;
        }
        if groups[index].as_mut().unwrap().device.stop().is_err() {
            failed = true;
        }
        if !shared_failed
            && groups
                .iter()
                .flatten()
                .any(|group| group.device.global_faulted())
        {
            // A shared-unit failure cannot wait for the remaining resets before
            // stopping unlisted peers. The outer scheduler quarantines all.
            for group in groups.iter_mut().flatten() {
                let _ = group.device.block_dma();
            }
            shared_failed = true;
            failed = true;
        }
    }
    if failed {
        for (index, target) in plan.iter().enumerate() {
            if target.is_some() {
                let group = groups[index].as_mut().unwrap();
                quarantine(&mut group.tasks, &mut group.broker, &mut channels[index]);
            }
        }
        return Err("Device teardown failed; changed interfaces quarantined, settings retained.");
    }
    // Publish only after every required teardown succeeded. Startup remains
    // supervised by the existing per-NIC configure/READY/recovery checks.
    for (index, target) in plan.iter().enumerate() {
        let Some(target) = target else { continue };
        let group = groups[index].as_mut().unwrap();
        group.broker.config = target.config;
        group.broker.configured_mac = target.mac;
        group.broker.admin_up = target.enabled;
        if target.enabled {
            for task in &mut group.tasks {
                task.state = State::Restart(now);
            }
        }
    }
    Ok("settings applied; changed enabled interfaces restarting")
}

/// Console changes run only in the kernel scheduler, with every process stopped.
/// A live change replaces all three service images and the NIC rings so no old
/// socket, ARP/admission state, RPC, or queued frame survives the transition.
fn apply_nic(
    action: nic::Action,
    tasks: &mut [Task; 3],
    broker: &mut Broker,
    channels: &mut Channels,
    device: &mut Device<'_>,
    now: i64,
) -> Result<&'static str, &'static str> {
    if let nic::Action::Set(config) = action {
        // Action is kernel-owned, but validate public fields again at this
        // boundary so future callers cannot bypass the console parser.
        NetworkConfig::from_wire(config.to_wire()).map_err(|_| "Invalid network configuration.")?;
    }
    // Administrative focus is handled before borrowing this individual group.
    if matches!(action, nic::Action::Select(_) | nic::Action::Setup(_)) {
        return Err("interface selection belongs to the console");
    }
    if broker.quarantined {
        return Err("NIC is quarantined; reboot is required.");
    }
    match action {
        nic::Action::Set(config) if config == broker.config => return Ok("unchanged"),
        nic::Action::Set(config) if !broker.admin_up => {
            broker.config = config;
            return Ok("configuration saved while down");
        }
        nic::Action::Up if broker.admin_up => return Ok("unchanged"),
        nic::Action::Down if !broker.admin_up => return Ok("unchanged"),
        _ => {}
    }
    // Disable scheduling before teardown. Even if reset/invalidation fails,
    // every service remains stopped and the pinned DMA pool is never reused.
    for task in tasks.iter_mut() {
        task.state = State::Disabled;
    }
    broker.pending = None;
    broker.mac = None;
    broker.admin_up = false;
    channels.rx.clear();
    channels.tx.clear();
    if let Err(error) = device.stop() {
        quarantine(tasks, broker, channels);
        return Err(error);
    }
    if let nic::Action::Set(config) = action {
        // Publish only after successful reset and DMA revocation. A failed
        // transition therefore retains the previously authoritative config.
        broker.config = config;
    }
    if action == nic::Action::Down {
        return Ok("down");
    }
    broker.admin_up = true;
    for task in tasks {
        // Preserve crash counters, log rate limits and monotonic RPC IDs.
        // An explicit administrative restart replaces any pending backoff
        // deadline with immediate recovery, without clearing quarantine.
        task.state = State::Restart(now);
    }
    Ok(match action {
        nic::Action::Set(_) => "configuration applied; connections reset",
        _ => "up; services starting",
    })
}

#[allow(clippy::too_many_arguments)]
fn restart_group(
    failed: usize,
    tasks: &mut [Task; 3],
    broker: &mut Broker,
    channels: &mut Channels,
    device: &mut Device<'_>,
    now: i64,
    console: &mut Console,
) {
    if !broker.admin_up || broker.quarantined {
        return;
    }
    broker.pending = None;
    channels.rx.clear();
    channels.tx.clear();
    let delay = 100 * (1i64 << tasks[failed].failures.min(6));
    tasks[failed].failures = tasks[failed].failures.saturating_add(1);
    if failed == DRIVER {
        if let Err(error) = device.stop() {
            quarantine(tasks, broker, channels);
            writeln!(
                console,
                "Networking quarantined after DMA teardown failure: {error}"
            )
            .ok();
            return;
        }
        broker.mac = None;
        tasks[DRIVER].state = State::Restart(now + delay);
    }
    for task in &mut tasks[..=NETWORK] {
        task.state = State::Restart(now + delay);
    }
    writeln!(
        console,
        "Service restart scheduled in {delay} ms; kernel remains running"
    )
    .ok();
}
