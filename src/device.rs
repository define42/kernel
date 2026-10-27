//! Kernel-owned PCI assignment and DMA lifetime, without packet processing.
//! The ring-3 e1000 driver owns MMIO programming and all Ethernet operations.

#[cfg(not(feature = "baremetal"))]
use core::arch::asm;
use core::arch::x86_64::__cpuid;
use core::ptr::{addr_of_mut, read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{
    iommu::{Fault, Iommu},
    pci,
    time::{Clock, MAX_POLL_ITERATIONS},
    userspace::Process,
};

pub const MMIO_VIRTUAL: u64 = 0x5000_0000;
pub const DMA_VIRTUAL: u64 = 0x5020_0000;
pub const DMA_LENGTH: usize = 0x41000;
const BAR_LENGTH: usize = 128 * 1024;
const MAX_NICS: usize = crate::nic::MAX_INTERFACES;

#[repr(C, align(4096))]
struct Pool([u8; DMA_LENGTH]);
static mut DMA: [Pool; MAX_NICS] = [const { Pool([0; DMA_LENGTH]) }; MAX_NICS];
static CLAIMED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct Candidate {
    function: pci::Function,
    mmio: usize,
}

pub struct Device<'a> {
    clock: &'a Clock,
    function: pci::Function,
    mmio: usize,
    pool_index: usize,
    #[cfg(feature = "isolation-test")]
    count: usize,
    iommu: Iommu<'a>,
    configured: bool,
    started: bool,
}

impl<'a> Device<'a> {
    pub fn discover(clock: &'a Clock) -> Result<[Option<Self>; MAX_NICS], &'static str> {
        if CLAIMED.swap(true, Ordering::AcqRel) {
            return Err("isolated device initialization already attempted");
        }
        let (inventory, count) = inventory()?;
        // PCI INTx stays disabled. VT-d's interrupt aperture is separate from
        // DMA translation, so a malicious RX descriptor could synthesize an
        // MSI. The default QEMU backend requires an absent local APIC. The
        // experimental physical backend instead requires Intel interrupt
        // remapping and refuses known hypervisors with unverified MSI handling.
        require_supported_interrupt_platform()?;
        for candidate in inventory[..count].iter().flatten() {
            candidate.function.prepare_memory();
            if candidate.function.bus_master_enabled() {
                return Err("PCI bus mastering could not be disabled");
            }
            reset(candidate.mmio, clock)?;
        }
        let assignments = core::array::from_fn(|index| {
            inventory[index].map(|candidate| {
                // SAFETY: each inventoried NIC exclusively owns its array slot;
                // every pool is aligned, disjoint and permanently pinned.
                let physical = unsafe { addr_of_mut!(DMA[index]) as u64 };
                (candidate.function, physical, DMA_LENGTH)
            })
        });
        let mut domains = Iommu::new(clock, assignments, cfg!(feature = "baremetal"))?;
        Ok(core::array::from_fn(|index| {
            inventory[index].map(|candidate| Self {
                clock,
                function: candidate.function,
                mmio: candidate.mmio,
                pool_index: index,
                #[cfg(feature = "isolation-test")]
                count,
                iommu: domains[index]
                    .take()
                    .expect("inventoried NIC has a DMA domain"),
                configured: false,
                started: false,
            })
        }))
    }

    pub fn configure(&mut self, process: &mut Process) -> Result<(), &'static str> {
        if process.interface_index() != self.pool_index {
            return Err("driver process belongs to another NIC interface");
        }
        if self.configured || self.started || self.function.bus_master_enabled() {
            return Err("cannot remap a running or configured device");
        }
        self.iommu.ensure_revoked()?;
        // SAFETY: this NIC's driver is stopped by the scheduler, its bus
        // mastering is disabled and its old DMA context was drained/revoked.
        // Other NICs keep their separate mappings, DMA pools and contexts.
        unsafe { process.unmap_devices()? };
        self.iommu.grant()?;
        // SAFETY: bus mastering is disabled and the previous run was reset and
        // drained before revoke. This allocation is permanently pinned, has no
        // kernel objects, and is never recycled for unrelated process memory.
        unsafe {
            let pool = addr_of_mut!(DMA[self.pool_index]);
            write_bytes(pool.cast::<u8>(), 0, DMA_LENGTH);
            process.map_device(MMIO_VIRTUAL, self.mmio as u64, BAR_LENGTH, true)?;
            process.map_device(DMA_VIRTUAL, pool as u64, DMA_LENGTH, false)?;
        }
        self.configured = true;
        Ok(())
    }

    pub fn start(&mut self) -> Result<(), &'static str> {
        if !self.configured || self.started {
            return Err("driver READY is invalid for this device state");
        }
        if self.iommu.faulted() {
            return Err("VT-d fault before driver READY");
        }
        // The kernel trusts no ring addresses programmed by the user driver:
        // the IOMMU enforces the fixed pool regardless of device registers.
        if self.function.bus_master_enabled() {
            return Err("PCI bus mastering was enabled before driver READY");
        }
        self.iommu.verify_assignment()?;
        self.function.enable_bus_master();
        if !self.function.bus_master_enabled() {
            return Err("PCI bus mastering could not be enabled");
        }
        self.started = true;
        Ok(())
    }

    /// Immediate first phase of global quarantine: block every requester
    /// before any per-device reset/drain wait can delay stopping its peers.
    /// Even on error, the caller must still attempt full `stop` on every NIC.
    pub fn block_dma(&mut self) -> Result<(), &'static str> {
        self.function.disable_bus_master();
        self.started = false;
        if self.function.bus_master_enabled() {
            return Err("PCI bus mastering could not be disabled");
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), &'static str> {
        let block_result = self.block_dma();
        self.configured = false;
        // Always revoke, including if reset fails. The pool remains pinned even
        // on failure; callers must fail closed instead of resuming the driver.
        let reset_result = reset(self.mmio, self.clock);
        let revoke_result = self.iommu.revoke();
        if self.function.bus_master_enabled() {
            return Err("PCI DMA remains enabled during teardown");
        }
        block_result.and(reset_result).and(revoke_result)
    }

    pub fn iova(&self) -> u64 {
        self.iommu.iova()
    }

    /// A different interface's IOVA window, deliberately absent from this
    /// device's domain. Used by the isolation test to verify peer containment.
    #[cfg(feature = "isolation-test")]
    pub fn peer_iova(&self) -> Option<u64> {
        (self.count > 1).then(|| Iommu::iova_for((self.pool_index + 1) % self.count))
    }

    /// An unattributable/shared-unit failure must quarantine every interface.
    pub fn global_faulted(&self) -> bool {
        self.iommu.global_faulted()
    }

    /// Kernel-only isolation-test hook; no userspace or console API exposes it.
    #[cfg(feature = "isolation-test")]
    pub fn inject_shared_failure(&self) {
        self.iommu.inject_shared_failure();
    }

    /// Read-only identity/status used by the kernel console. No PCI writes,
    /// BAR probing, or ownership changes are exposed through these methods.
    pub fn bdf(&self) -> (u8, u8, u8) {
        (
            self.function.bus(),
            self.function.device(),
            self.function.function(),
        )
    }

    pub fn link_up(&self) -> bool {
        // SAFETY: STATUS is a read-only register in the validated BAR mapping;
        // unlike ICR, reading it does not acknowledge or alter device state.
        unsafe { read_volatile((self.mmio + 8) as *const u32) & (1 << 1) != 0 }
    }

    pub fn running(&self) -> bool {
        self.started
    }

    pub fn faulted(&self) -> bool {
        self.iommu.faulted()
    }
    pub fn fault(&self) -> Option<Fault> {
        self.iommu.fault()
    }
}

/// Disable DMA on every matching function, including unsupported/excess
/// devices, before returning any error. Only fixed 82540EM root-bus endpoints
/// without multifunction aliases are eligible for userspace assignment.
fn inventory() -> Result<([Option<Candidate>; MAX_NICS], usize), &'static str> {
    let mut candidates: [Option<Candidate>; MAX_NICS] = [None; MAX_NICS];
    let mut count = 0;
    let mut first_error = None;
    let mut fatal_error = None;
    let mut scanner = pci::Scanner::new();
    while let Some(probe) = scanner.next_probe() {
        let Some(function) = probe else { continue };
        if function.vendor_id() != 0x8086 || function.device_id() != 0x100e {
            continue;
        }
        function.disable_bus_master();
        if function.bus_master_enabled() {
            fatal_error.get_or_insert("PCI bus mastering could not be disabled");
            continue;
        }
        let candidate = validate_candidate(function);
        let candidate = match candidate {
            Ok(candidate) => candidate,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
        };
        let register_page = match Iommu::register_page(function) {
            Ok(base) => base,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
        };
        if overlaps(candidate.mmio, BAR_LENGTH, register_page, 4096) {
            fatal_error.get_or_insert("e1000 BAR overlaps the VT-d register page");
            continue;
        }
        if count == MAX_NICS {
            fatal_error.get_or_insert("more than eight assignable e1000 NICs are unsupported");
            continue;
        }
        candidates[count] = Some(candidate);
        count += 1;
    }
    if let Some(error) = fatal_error {
        return Err(error);
    }
    if count == 0 {
        return Err(first_error.unwrap_or("Intel 82540EM e1000 NIC not found"));
    }
    // Check aliases against every matching NIC, including excluded functions:
    // disabling bus mastering does not disable their CPU MMIO decoding. BAR
    // sizing writes are unnecessary because 82540EM's BAR0 is fixed at 128 KiB.
    let mut scanner = pci::Scanner::new();
    while let Some(probe) = scanner.next_probe() {
        let Some(function) = probe else { continue };
        if function.vendor_id() != 0x8086 || function.device_id() != 0x100e {
            continue;
        }
        let bar = function.read_u32(0x10);
        if bar & 7 != 0 {
            continue;
        }
        let mmio = (bar & !0xf) as usize;
        for candidate in candidates[..count].iter().flatten() {
            if function.bus() == candidate.function.bus()
                && function.devfn() == candidate.function.devfn()
            {
                continue;
            }
            if overlaps(mmio, BAR_LENGTH, candidate.mmio, BAR_LENGTH) {
                return Err("e1000 BARs overlap; independent NIC assignment is unsafe");
            }
        }
    }
    Ok((candidates, count))
}

fn validate_candidate(function: pci::Function) -> Result<Candidate, &'static str> {
    if function.bus() != 0 {
        return Err("isolated e1000 must be directly on PCI root bus 0");
    }
    let header = (function.read_u32(0x0c) >> 16) as u8;
    if function.function() != 0 || header != 0 || function.class_code() != 0x020000 {
        return Err("isolated e1000 requires a single-function type-zero Ethernet endpoint");
    }
    let bar = function.read_u32(0x10);
    if bar & 7 != 0 {
        return Err("isolated e1000 BAR0 must be a 32-bit memory BAR");
    }
    let mmio = (bar & !0xf) as usize;
    if !(0x4000_0000..=(1usize << 32) - BAR_LENGTH).contains(&mmio)
        || !mmio.is_multiple_of(BAR_LENGTH)
    {
        return Err("e1000 BAR0 is outside the uncached aligned MMIO region");
    }
    Ok(Candidate { function, mmio })
}

fn overlaps(left: usize, left_length: usize, right: usize, right_length: usize) -> bool {
    // BARs and DRHD pages are below 4 GiB; these additions cannot overflow usize.
    left < right + right_length && right < left + left_length
}

fn reset(mmio: usize, clock: &Clock) -> Result<(), &'static str> {
    // SAFETY: caller owns the validated uncached BAR and has stopped DMA.
    unsafe {
        write_volatile((mmio + 0xd8) as *mut u32, u32::MAX);
        write_volatile((mmio + 0x100) as *mut u32, 0);
        write_volatile((mmio + 0x400) as *mut u32, 0);
        read_volatile((mmio + 8) as *const u32);
    }
    clock.delay_micros(10_000)?;
    // SAFETY: CTRL is the first register in the assigned BAR.
    unsafe {
        let control = read_volatile(mmio as *const u32);
        write_volatile(mmio as *mut u32, control | (1 << 26));
    }
    let deadline = clock.now_millis() + 100;
    let mut polls = MAX_POLL_ITERATIONS;
    // SAFETY: read the reset bit from the same validated register.
    while unsafe { read_volatile(mmio as *const u32) } & (1 << 26) != 0 {
        if clock.now_millis() >= deadline || polls == 0 {
            return Err("e1000 lifecycle reset timed out or clock stopped");
        }
        polls -= 1;
        core::hint::spin_loop();
    }
    clock.delay_micros(10_000)?;
    // QEMU's software reset self-clears CTRL.RST but leaves ring/filter state;
    // leave both engines disabled and interrupts masked explicitly.
    unsafe {
        write_volatile((mmio + 0xd8) as *mut u32, u32::MAX);
        write_volatile((mmio + 0x100) as *mut u32, 0);
        write_volatile((mmio + 0x400) as *mut u32, 0);
        read_volatile((mmio + 0xc0) as *const u32);
    }
    Ok(())
}

#[cfg(not(feature = "baremetal"))]
fn require_supported_interrupt_platform() -> Result<(), &'static str> {
    // QEMU delivers NMI/INIT MSI even to a globally disabled APIC. Requiring
    // CPUID.APIC absent corresponds to -smp 1 -cpu max,-apic: no local APIC
    // device exists at all. Merely clearing IA32_APIC_BASE is insufficient.
    if __cpuid(1).edx & (1 << 9) != 0 {
        return Err("isolated NIC requires QEMU -smp 1 -cpu max,-apic (MSI containment)");
    }
    let low: u32;
    let high: u32;
    // SAFETY: this driver-assignment backend specifically targets QEMU TCG,
    // whose IA32_APIC_BASE read is defined even without an APIC object.
    // cpu_get_apic_base(NULL) returns only the BSP bit. This also rejects an
    // APIC hidden by CPUID masking but instantiated by an SMP configuration.
    unsafe {
        asm!("rdmsr", in("ecx") 0x1bu32, out("eax") low, out("edx") high,
             options(nomem, nostack, preserves_flags));
    }
    if low != 0x100 || high != 0 {
        return Err("QEMU has a hidden local APIC; interrupt aperture cannot be isolated");
    }
    Ok(())
}

#[cfg(feature = "baremetal")]
fn require_supported_interrupt_platform() -> Result<(), &'static str> {
    // This opt-in port trusts the processor/firmware platform, not an emulated
    // acknowledgment. In particular QEMU advertises IRES/CFIS but its VT-d
    // compatibility MSI path bypasses the deny policy. Never use baremetal as
    // a switch to bypass the development backend's APIC guard in a VM.
    let features = __cpuid(1);
    if features.ecx & (1 << 31) != 0 {
        return Err(
            "hardware isolation refuses hypervisors: compatible MSI blocking is unverified",
        );
    }
    let vendor = __cpuid(0);
    if vendor.ebx != u32::from_le_bytes(*b"Genu")
        || vendor.edx != u32::from_le_bytes(*b"ineI")
        || vendor.ecx != u32::from_le_bytes(*b"ntel")
    {
        return Err("experimental hardware isolation requires an Intel processor");
    }
    if features.edx & (1 << 9) == 0 {
        return Err("experimental hardware isolation requires a real local APIC");
    }
    // No device DMA is enabled here. Iommu::new must still establish the empty
    // IR table, complete IEC invalidation, acknowledge IRES=1/CFIS=0 and enable
    // second-level translation; start() rechecks before enabling bus mastering.
    Ok(())
}
