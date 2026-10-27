//! Scheduling and bounded IPC only: all Ethernet/TCP/HTTP processing is ring 3.
use crate::{
    abi, arch,
    console::Console,
    device::Device,
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
static mut CHANNELS: Channels = Channels {
    rx: FrameQueue::new(),
    tx: FrameQueue::new(),
};

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
}
impl Broker {
    fn new() -> Self {
        Self {
            pending: None,
            next_id: 1,
            mac: None,
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

pub fn run(console: &mut Console) -> ! {
    let clock = Clock::new().expect("HPET clock");
    crate::timer::init();
    writeln!(console, "Timer: PIT 100 Hz; preemptive service scheduling").ok();
    let mut device = match Device::new(&clock) {
        Ok(device) => device,
        Err(error) => {
            writeln!(
                console,
                "Network isolation unavailable: {error}; refusing device access."
            )
            .ok();
            crate::halt();
        }
    };
    let mut tasks = core::array::from_fn(|slot| Task {
        process: Process::load_slot(IMAGES[slot], slot).expect("load service ELF"),
        state: State::Runnable,
        failures: 0,
        log_epoch: 0,
        log_bytes: 0,
        last_yield: 0,
    });
    device
        .configure(&mut tasks[DRIVER].process)
        .expect("configure isolated NIC");
    #[cfg(feature = "isolation-test")]
    {
        let (web, rest) = tasks.split_at_mut(1);
        let (network, driver) = rest.split_at_mut(1);
        userspace::check_isolation(
            &mut web[0].process,
            &mut network[0].process,
            &mut driver[0].process,
        );
        writeln!(
            console,
            "Process address-space and SIMD isolation checks passed."
        )
        .ok();
    }
    driver_context(&mut tasks[DRIVER].process);
    userspace::activate_kernel();
    crate::memory::check_permissions();
    writeln!(
        console,
        "Isolation: three address spaces; bounded IPC; NIC DMA restricted by VT-d"
    )
    .ok();
    // SAFETY: this is the only scheduler on the single boot CPU. Neither user
    // mappings nor DMA mappings expose these queues, and kernel IF stays clear.
    let channels = unsafe { &mut *core::ptr::addr_of_mut!(CHANNELS) };
    let mut broker = Broker::new();
    #[cfg(feature = "fuzz-test")]
    let (mut fuzz_calls, mut fuzz_preemptions) = (0u64, 0u64);
    #[cfg(feature = "fuzz-test")]
    let fuzz_iterations: u64 = env!("KERNEL_FUZZ_ITERATIONS")
        .parse()
        .expect("fuzz iterations");
    #[cfg(feature = "fuzz-test")]
    {
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
    tasks[WEB].process.restart(13);
    #[cfg(feature = "preemption-test")]
    writeln!(console, "Preemption test: busy loop").ok();
    #[cfg(feature = "isolation-test")]
    let mut test_phase = 0;
    #[cfg(feature = "isolation-test")]
    let mut test_driver_mode = 0;
    #[cfg(feature = "isolation-test")]
    {
        tasks[DRIVER].process.context.rcx = 1;
        tasks[NETWORK].process.context.rdi = 1;
    }
    let first_run = clock.now_millis();
    for task in &mut tasks {
        task.last_yield = first_run;
    }
    #[cfg(feature = "isolation-test")]
    // SAFETY: mapped supervisor text. Volatile reads verify that forbidden
    // NIC writes did not alter the actual target bytes despite CPU caching.
    let dma_canary = unsafe { core::ptr::read_volatile(0x100000 as *const [u8; 64]) };
    loop {
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
            {
                match test_phase {
                    0 => {
                        let fault = device.fault().expect("read DMA fault record");
                        assert_eq!(fault.address, 0x100000);
                        assert!(!fault.write);
                        test_phase = 1;
                    }
                    2 => {
                        let fault = device.fault().expect("write DMA fault record");
                        assert_eq!(fault.address, 0x100000);
                        assert!(fault.write);
                        // SAFETY: same mapped text as the pre-probe snapshot.
                        assert_eq!(
                            unsafe { core::ptr::read_volatile(0x100000 as *const [u8; 64]) },
                            dma_canary
                        );
                        test_phase = 3;
                    }
                    _ => panic!("unexpected DMA fault in isolation test"),
                }
            }
            restart_group(
                DRIVER,
                &mut tasks,
                &mut broker,
                channels,
                &mut device,
                now,
                console,
            );
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
            restart_group(
                NETWORK,
                &mut tasks,
                &mut broker,
                channels,
                &mut device,
                now,
                console,
            );
        }
        for slot in [DRIVER, NETWORK] {
            if tasks[slot].state == State::Runnable && now - tasks[slot].last_yield >= 2000 {
                writeln!(console, "Service {} heartbeat expired", NAMES[slot]).ok();
                restart_group(
                    slot,
                    &mut tasks,
                    &mut broker,
                    channels,
                    &mut device,
                    now,
                    console,
                );
            }
        }
        for slot in [DRIVER, NETWORK, WEB] {
            if let State::Restart(at) = tasks[slot].state {
                if now < at {
                    continue;
                }
                tasks[slot].process.restart(0);
                #[cfg(feature = "isolation-test")]
                if slot == NETWORK {
                    tasks[slot].process.context.rdi = 1;
                }
                if slot == DRIVER {
                    if let Err(error) = device.configure(&mut tasks[slot].process) {
                        let _ = device.stop();
                        for task in &mut tasks {
                            task.state = State::Disabled;
                        }
                        writeln!(
                            console,
                            "Networking quarantined after device setup failure: {error}"
                        )
                        .ok();
                        continue;
                    }
                    driver_context(&mut tasks[slot].process);
                    #[cfg(feature = "isolation-test")]
                    {
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
                tasks[slot].process.activate();
                // SAFETY: this task owns its CR3 and private backing. All
                // privileged state stays supervisor-only across the switch.
                unsafe { arch::resume(&mut tasks[slot].process.context) };
                tasks[slot].process.save_extended_state();
                userspace::activate_kernel();
                let context = tasks[slot].process.context;
                #[cfg(feature = "fuzz-test")]
                if slot == WEB {
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
                            crate::exit_qemu(0x10);
                        }
                    }
                }
                if context.vector == crate::timer::VECTOR {
                    #[cfg(feature = "preemption-test")]
                    if slot == WEB {
                        timer_returns += 1;
                    }
                    break;
                }
                if context.vector != 128 || context.rax == abi::SYS_EXIT {
                    #[cfg(feature = "isolation-test")]
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
                            writeln!(console, "NIC interrupt-aperture containment passed.").ok();
                            test_phase = 11;
                        }
                        _ => panic!(
                            "unexpected service failure in isolation test: phase={test_phase} slot={slot} {context:?}"
                        ),
                    }
                    writeln!(
                        console,
                        "Service {} stopped: vector={} result={} rip={:#x} address={:#x}",
                        NAMES[slot], context.vector, context.rdi, context.rip, context.cr2
                    )
                    .ok();
                    restart_group(
                        slot,
                        &mut tasks,
                        &mut broker,
                        channels,
                        &mut device,
                        clock.now_millis(),
                        console,
                    );
                    break;
                }
                let result = dispatch(
                    slot,
                    &mut tasks,
                    &mut broker,
                    channels,
                    &mut device,
                    &clock,
                    console,
                );
                tasks[slot].process.context.rax = result as u64;
                if tasks[slot].state != State::Runnable || context.rax == abi::SYS_POLL {
                    break;
                }
                if call_count == 63 || clock.now_millis() - started >= 10 {
                    #[cfg(feature = "preemption-test")]
                    if slot == WEB {
                        budget_returns += 1;
                    }
                    break;
                }
            }
        }
        #[cfg(feature = "preemption-test")]
        if phase == 0 && now >= 12_000 {
            assert!(timer_returns >= 10, "busy process was not preempted");
            tasks[WEB].process.restart(14);
            phase = 1;
            writeln!(console, "Preemption test: syscall loop").ok();
        } else if phase == 1 && now >= 15_000 {
            assert!(
                budget_returns >= 10,
                "syscall process did not yield its budget"
            );
            phase = 2;
            writeln!(console, "Preemption fairness checks passed.").ok();
        }
        #[cfg(feature = "isolation-test")]
        match test_phase {
            1 if now >= 2000 && broker.mac.is_some() => {
                tasks[DRIVER].failures = 0;
                restart_group(
                    DRIVER,
                    &mut tasks,
                    &mut broker,
                    channels,
                    &mut device,
                    now,
                    console,
                );
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
                restart_group(
                    DRIVER,
                    &mut tasks,
                    &mut broker,
                    channels,
                    &mut device,
                    now,
                    console,
                );
                test_driver_mode = 2;
                test_phase = 8;
            }
            9 if now >= 10000 && broker.mac.is_some() => {
                tasks[DRIVER].failures = 0;
                restart_group(
                    DRIVER,
                    &mut tasks,
                    &mut broker,
                    channels,
                    &mut device,
                    now,
                    console,
                );
                test_driver_mode = 4;
                test_phase = 10;
            }
            11 if now >= 14_000 && broker.mac.is_some() => {
                writeln!(console, "Service isolation and recovery checks passed.").ok();
                test_phase = 12;
            }
            _ => {}
        }
    }
}

fn driver_context(process: &mut Process) {
    process.context.rdi = abi::DRIVER_MMIO;
    process.context.rsi = abi::DRIVER_DMA;
    process.context.rdx = abi::DRIVER_IOVA;
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
        abi::SYS_MAC_REGISTER if slot == DRIVER => {
            if a >> 48 != 0 || a == 0 || a == 0xffff_ffff_ffff || a & 1 != 0 {
                return abi::EINVAL;
            }
            broker.mac = Some(a);
            0
        }
        abi::SYS_FRAME_RECV..=abi::SYS_MAC_REGISTER => abi::EACCES,
        _ => abi::ENOSYS,
    }
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
    broker.pending = None;
    channels.rx.clear();
    channels.tx.clear();
    let delay = 100 * (1i64 << tasks[failed].failures.min(6));
    tasks[failed].failures = tasks[failed].failures.saturating_add(1);
    if failed == DRIVER {
        if let Err(error) = device.stop() {
            for task in tasks {
                task.state = State::Disabled;
            }
            broker.mac = None;
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
