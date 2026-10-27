//! A deliberately narrow legacy VT-d assignment implementation.
//!
//! Legacy root/context tables, three-level 39-bit second-level translation,
//! Up to eight root-bus NICs have distinct domains and pinned DMA allocations.
//! Every unassigned requester and every other IOVA is denied. The single-CPU
//! kernel serializes table/register updates. No identity/pass-through domain.
//! Optional interrupt remapping installs an immutable, entirely nonpresent
//! table and blocks compatibility-format requests. The hardware port remains
//! experimental: QEMU does not implement compatibility-format blocking.
//! Register definitions and ordering: Intel VT-d Rev. 4.0, sections 5.1.4,
//! 6.5.2, 6.7, 9 and 11; https://cdrdv2-public.intel.com/671081/vt-directed-io-spec.pdf.

use core::arch::{asm, x86_64::__cpuid};
use core::ptr::{addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering, fence};

use crate::{
    pci::Function,
    time::{Clock, MAX_POLL_ITERATIONS},
};

pub const DMA_IOVA: u64 = crate::abi::DRIVER_IOVA;
const PAGE: usize = 4096;
const MAX_DOMAINS: usize = crate::nic::MAX_INTERFACES;
const DOMAIN_STRIDE: u64 = crate::abi::DRIVER_IOVA_STRIDE;
const CAP: usize = 0x08;
const ECAP: usize = 0x10;
const GCMD: usize = 0x18;
const GSTS: usize = 0x1c;
const RTADDR: usize = 0x20;
const CCMD: usize = 0x28;
const FSTS: usize = 0x34;
const FECTL: usize = 0x38;
const IQH: usize = 0x80;
const IQT: usize = 0x88;
const IQA: usize = 0x90;
const IECTL: usize = 0xa0;
const IRTA: usize = 0xb8;
const TE: u32 = 1 << 31;
const SRTP: u32 = 1 << 30;
const QIE: u32 = 1 << 26;
const IRE: u32 = 1 << 25;
const SIRTP: u32 = 1 << 24;
const CFI: u32 = 1 << 23;
const PERSISTENT_COMMANDS: u32 = TE | QIE | IRE | CFI;
const BUSY: u64 = 1 << 63;
const ROOT_SIZE: usize = 256 * 2;

#[repr(C, align(4096))]
struct DomainTables {
    pdpt: [u64; 512],
    directory: [u64; 512],
    pages: [u64; 512],
}

impl DomainTables {
    const ZERO: Self = Self {
        pdpt: [0; 512],
        directory: [0; 512],
        pages: [0; 512],
    };
}

#[repr(C, align(4096))]
struct Tables {
    root: [u64; ROOT_SIZE],
    context: [u64; ROOT_SIZE],
    domains: [DomainTables; MAX_DOMAINS],
    interrupts: [u64; 512],  // 256 nonpresent 128-bit IRTEs.
    queue: [u64; 512],       // 256 128-bit invalidation descriptors.
    completion: [u32; 1024], // A dedicated page, never granted to a device.
}

static CLAIMED: AtomicBool = AtomicBool::new(false);
// Shared-unit command/verification failures cannot be recovered per interface.
static FAILED: AtomicBool = AtomicBool::new(false);
static mut TABLES: Tables = Tables {
    root: [0; ROOT_SIZE],
    context: [0; ROOT_SIZE],
    domains: [const { DomainTables::ZERO }; MAX_DOMAINS],
    interrupts: [0; 512],
    queue: [0; 512],
    completion: [0; 1024],
};

const _: () = {
    assert!(size_of::<DomainTables>() == 3 * PAGE);
    assert!(size_of::<Tables>() == (5 + 3 * MAX_DOMAINS) * PAGE);
    assert!(align_of::<Tables>() == PAGE);
    assert!(MAX_DOMAINS == crate::abi::MAX_NIC_INTERFACES);
    assert!(MAX_DOMAINS <= 8);
    assert!(core::mem::offset_of!(Tables, domains).is_multiple_of(PAGE));
    assert!(core::mem::offset_of!(Tables, interrupts).is_multiple_of(PAGE));
    assert!(core::mem::offset_of!(Tables, queue).is_multiple_of(PAGE));
    assert!(core::mem::offset_of!(Tables, completion).is_multiple_of(PAGE));
};

#[derive(Clone, Copy, Debug)]
pub struct Fault {
    pub address: u64,
    pub source: u16,
    pub reason: u8,
    pub write: bool,
}

pub struct Iommu<'a> {
    clock: &'a Clock,
    base: usize,
    context_index: usize,
    domain_index: usize,
    physical: u64,
    length: usize,
    requesters: [Option<u16>; MAX_DOMAINS],
    iotlb: usize,
    fault_base: usize,
    fault_count: usize,
    granted: bool,
    // Unlike `!granted`, this proves the previous context-cache/IOTLB
    // invalidation and read/write drain completed successfully.
    revoked: bool,
    interrupt_remapping: bool,
}

impl<'a> Iommu<'a> {
    /// Initialize the shared remapping hardware once, with every context
    /// absent. Each returned owner may grant/revoke only its immutable slot.
    pub fn new(
        clock: &'a Clock,
        assignments: [Option<(Function, u64, usize)>; MAX_DOMAINS],
        require_interrupt_remapping: bool,
    ) -> Result<[Option<Self>; MAX_DOMAINS], &'static str> {
        if CLAIMED.swap(true, Ordering::AcqRel) {
            return Err("VT-d initialization already attempted");
        }
        let (function, physical, length) = assignments[0].ok_or("no VT-d assignments")?;
        let description = discover_dmar(function)?;
        for (index, assignment) in assignments.iter().enumerate() {
            let Some((function, physical, length)) = *assignment else {
                continue;
            };
            if function.bus() != 0 || function.bus_master_enabled() {
                return Err("isolated e1000 must be a stopped root-bus function");
            }
            if !physical.is_multiple_of(PAGE as u64)
                || length == 0
                || !length.is_multiple_of(PAGE)
                || length > DOMAIN_STRIDE as usize
                || physical
                    .checked_add(length as u64)
                    .is_none_or(|end| end > (1 << 30))
            {
                return Err("invalid pinned VT-d DMA pool");
            }
            if discover_dmar(function)?.base != description.base {
                return Err("NICs are covered by different VT-d remapping units");
            }
            for previous in assignments[..index].iter().flatten() {
                if previous.0.devfn() == function.devfn()
                    || (physical < previous.1 + previous.2 as u64
                        && previous.1 < physical + length as u64)
                {
                    return Err("VT-d requester or DMA pool assignments overlap");
                }
            }
        }
        // CLFLUSH publishes tables even when ECAP.C is clear, as in QEMU.
        let cpu = __cpuid(1);
        let cache_line = ((cpu.ebx >> 8) & 0xff) as usize * 8;
        if cpu.edx & (1 << 19) == 0
            || !(8..=PAGE).contains(&cache_line)
            || !cache_line.is_power_of_two()
        {
            return Err("VT-d table publication requires a valid CLFLUSH line size");
        }
        let base = description.base;
        let cap = read64(base, CAP);
        let ecap = read64(base, ECAP);
        if cap == u64::MAX || cap & (1 << 9) == 0 {
            return Err("VT-d does not support 39-bit second-level translation");
        }
        if cap & ((1 << 54) | (1 << 55)) != (1 << 54) | (1 << 55) {
            return Err("VT-d read/write draining is unavailable");
        }
        if cap & (1 << 4) != 0 {
            return Err("VT-d write-buffer flushing platform is unsupported");
        }
        if read32(base, GSTS) & (TE | (1 << 28) | QIE | IRE) != 0 {
            return Err(
                "VT-d firmware translation/queued invalidation/interrupt remapping is active",
            );
        }
        let supports_interrupt_remapping = ecap & (1 << 3) != 0;
        if require_interrupt_remapping
            && (!description.interrupt_remapping || !supports_interrupt_remapping)
        {
            return Err(
                "hardware NIC isolation requires firmware-declared VT-d interrupt remapping",
            );
        }
        if supports_interrupt_remapping != description.interrupt_remapping {
            return Err("DMAR and VT-d disagree about interrupt-remapping support");
        }
        let iotlb = (((ecap >> 8) & 0x3ff) * 16 + 8) as usize;
        let fault_base = (((cap >> 24) & 0x3ff) * 16) as usize;
        let fault_count = (((cap >> 40) & 0xff) + 1) as usize;
        if iotlb < 0x80
            || iotlb + 8 > PAGE
            || fault_base < 0x80
            || fault_base + fault_count * 16 > PAGE
        {
            return Err("VT-d register layout exceeds the validated MMIO page");
        }
        let mut unit = Self {
            clock,
            base,
            context_index: function.devfn() as usize * 2,
            domain_index: 0,
            physical,
            length,
            requesters: assignments.map(|assignment| assignment.map(|item| item.0.devfn() as u16)),
            iotlb,
            fault_base,
            fault_count,
            granted: false,
            revoked: false,
            interrupt_remapping: false,
        };
        // SAFETY: single initialization owns these permanent supervisor
        // tables. No requester is present and every NIC has bus mastering off.
        // Domains share only the root/context tables; each has disjoint paging
        // structures and maps only its own pinned pool at a unique IOVA range.
        unsafe {
            addr_of_mut!(TABLES.root[0]).write(addr_of_mut!(TABLES.context) as u64 | 1);
            for (index, assignment) in assignments.iter().enumerate() {
                let Some((_, physical, length)) = *assignment else {
                    continue;
                };
                addr_of_mut!(TABLES.domains[index].pdpt[0])
                    .write(addr_of_mut!(TABLES.domains[index].directory) as u64 | 3);
                addr_of_mut!(
                    TABLES.domains[index].directory[(Self::iova_for(index) >> 21) as usize]
                )
                .write(addr_of_mut!(TABLES.domains[index].pages) as u64 | 3);
                for page in 0..length / PAGE {
                    addr_of_mut!(TABLES.domains[index].pages[page])
                        .write((physical + (page * PAGE) as u64) | 3);
                }
            }
        }
        publish_tables();
        write32(base, FECTL, 1 << 31); // Faults are polled, never MSI-delivered.
        unit.clear_faults();
        // SAFETY: the root is a page-aligned field in the exclusively owned tables.
        write64(base, RTADDR, unsafe { addr_of_mut!(TABLES.root) as u64 });
        unit.command(SRTP, true)?;
        unit.invalidate()?;
        if supports_interrupt_remapping {
            unit.enable_interrupt_deny(ecap)?;
        }
        unit.command(TE, true)?;
        unit.verify_assignment()?;
        // All contexts are absent. A final global invalidation with read/write
        // draining establishes acknowledged revocation for every returned owner.
        unit.revoke()?;
        Ok(core::array::from_fn(|index| {
            assignments[index].map(|(function, physical, length)| Self {
                clock,
                base,
                context_index: function.devfn() as usize * 2,
                domain_index: index,
                physical,
                length,
                requesters: unit.requesters,
                iotlb,
                fault_base,
                fault_count,
                granted: false,
                revoked: true,
                interrupt_remapping: unit.interrupt_remapping,
            })
        }))
    }

    pub const fn iova_for(index: usize) -> u64 {
        DMA_IOVA + index as u64 * DOMAIN_STRIDE
    }

    pub fn iova(&self) -> u64 {
        Self::iova_for(self.domain_index)
    }

    /// Verify the hardware state again before the kernel enables PCI DMA.
    /// IRES/CFIS are architectural acknowledgments, not proof of an emulator's
    /// implementation: Device rejects APIC-equipped hypervisors separately.
    pub fn verify_assignment(&self) -> Result<(), &'static str> {
        if FAILED.load(Ordering::Acquire) {
            return Err("VT-d shared unit is quarantined after a command or verification failure");
        }
        let status = read32(self.base, GSTS);
        if status & TE == 0 || status & QIE != 0 {
            return fail_unit("VT-d translation/invalidation state changed unexpectedly");
        }
        if self.interrupt_remapping && status & (IRE | CFI) != IRE {
            return fail_unit("VT-d interrupt-remapping deny policy is not active");
        }
        self.verify_domain()
    }

    /// Check that peer IOVA windows and every non-pool page remain absent.
    /// These tables are supervisor-only, pinned, and never device-writable.
    fn verify_domain(&self) -> Result<(), &'static str> {
        let index = self.domain_index;
        let directory_index = (self.iova() >> 21) as usize;
        // SAFETY: this immutable requester owns exactly this context slot.
        let context_valid = unsafe {
            let low = addr_of_mut!(TABLES.context[self.context_index]).read_volatile();
            let high = addr_of_mut!(TABLES.context[self.context_index + 1]).read_volatile();
            if self.granted {
                low == addr_of_mut!(TABLES.domains[index].pdpt) as u64 | 1
                    && high == (((index + 1) as u64) << 8) | 1
            } else {
                low == 0
            }
        };
        if !context_valid {
            return fail_unit("VT-d requester context changed unexpectedly");
        }
        for entry in 0..512 {
            // SAFETY: the immutable domain slot belongs to this owner. The
            // CPU alone writes these tables and all updates are serialized.
            let valid = unsafe {
                let pdpt = addr_of_mut!(TABLES.domains[index].pdpt[entry]).read_volatile();
                let directory =
                    addr_of_mut!(TABLES.domains[index].directory[entry]).read_volatile();
                let page = addr_of_mut!(TABLES.domains[index].pages[entry]).read_volatile();
                let expected_pdpt = if entry == 0 {
                    addr_of_mut!(TABLES.domains[index].directory) as u64 | 3
                } else {
                    0
                };
                let expected_directory = if entry == directory_index {
                    addr_of_mut!(TABLES.domains[index].pages) as u64 | 3
                } else {
                    0
                };
                let expected_page = if entry < self.length / PAGE {
                    (self.physical + (entry * PAGE) as u64) | 3
                } else {
                    0
                };
                pdpt == expected_pdpt && directory == expected_directory && page == expected_page
            };
            if !valid {
                return fail_unit("VT-d private domain page tables changed unexpectedly");
            }
        }
        Ok(())
    }

    fn enable_interrupt_deny(&mut self, ecap: u64) -> Result<(), &'static str> {
        if ecap & (1 << 1) == 0 {
            return Err("VT-d interrupt isolation requires queued invalidation");
        }
        // Intel 6.5.2: finish register invalidations before switching interfaces.
        self.wait64(CCMD, BUSY, 0)?;
        self.wait64(self.iotlb, BUSY, 0)?;
        self.command(CFI, false)?;
        write32(self.base, IECTL, 1 << 31); // Completion is polled, never MSI.
        write64(self.base, IQT, 0);
        // SAFETY: these supervisor pages are permanently pinned and are never
        // present in the assigned DMA domain or any process's user mappings.
        write64(self.base, IQA, unsafe { addr_of_mut!(TABLES.queue) as u64 });
        self.command(QIE, true)?;
        // SIZE=7 gives 2^(7+1)=256 entries. EIME remains zero; clearing CFI is
        // required even without x2APIC. Every IRTE has Present=0 and FPD=0.
        write64(self.base, IRTA, unsafe {
            addr_of_mut!(TABLES.interrupts) as u64 | 7
        });
        self.command(SIRTP, true)?;
        // Intel 6.7: invalidate the old IEC after installing IRTA. A queue-head
        // advance only acknowledges fetching; a status-write wait descriptor
        // proves completion and drains earlier remapped interrupt requests.
        unsafe {
            addr_of_mut!(TABLES.completion[0]).write_volatile(0);
            addr_of_mut!(TABLES.queue[0]).write(4); // Global IEC, G=0.
            addr_of_mut!(TABLES.queue[1]).write(0);
            addr_of_mut!(TABLES.queue[2]).write(5 | (1 << 5) | (1 << 6) | (1 << 32));
            addr_of_mut!(TABLES.queue[3]).write(addr_of_mut!(TABLES.completion[0]) as u64);
        }
        publish_tables();
        write64(self.base, IQT, 32);
        let deadline = self.clock.now_millis() + 100;
        let mut polls = MAX_POLL_ITERATIONS;
        // SAFETY: only this initialization writes the completion word; hardware
        // performs an architecturally coherent DWORD status write (6.5.2.8).
        while unsafe { addr_of_mut!(TABLES.completion[0]).read_volatile() } != 1 {
            if read32(self.base, FSTS) & 0x70 != 0 {
                return Err("VT-d interrupt-entry invalidation failed");
            }
            if self.clock.now_millis() >= deadline || polls == 0 {
                return Err("VT-d interrupt-entry invalidation timed out or clock stopped");
            }
            polls -= 1;
            core::hint::spin_loop();
        }
        fence(Ordering::SeqCst);
        self.wait64(IQH, u64::MAX, 32)?;
        if read32(self.base, FSTS) & 0x70 != 0 {
            return Err("VT-d interrupt-entry invalidation reported an error");
        }
        // The queue is empty and its last completed command is a wait. Intel
        // 6.5.2 permits disabling it now. Our immutable deny table never needs
        // another IEC invalidation; DMA uses the existing register interface.
        self.command(QIE, false)?;
        self.wait64(IQH, u64::MAX, 0)?;
        write64(self.base, IQT, 0);
        self.command(IRE, true)?;
        self.command(CFI, false)?;
        if read32(self.base, GSTS) & (IRE | CFI) != IRE {
            return Err("VT-d did not acknowledge blocking compatibility interrupts");
        }
        self.interrupt_remapping = true;
        Ok(())
    }

    // Serialize each GCMD field update and preserve persistent state. Reusing
    // bare TE/SRTP writes after IRE was enabled would silently reopen MSI DMA.
    fn command(&self, bit: u32, enabled: bool) -> Result<(), &'static str> {
        let current = read32(self.base, GSTS) & PERSISTENT_COMMANDS;
        let command = if enabled {
            current | bit
        } else {
            current & !bit
        };
        write32(self.base, GCMD, command);
        self.wait32(GSTS, bit, if enabled { bit } else { 0 })
    }

    /// Validate firmware coverage before hardware changes; Device also checks
    /// that no admitted NIC BAR aliases this protected register page.
    pub fn register_page(function: Function) -> Result<usize, &'static str> {
        if function.bus() != 0 {
            return Err("isolated e1000 must be on root PCI bus 0 (no requester aliases)");
        }
        Ok(discover_dmar(function)?.base)
    }

    pub fn ensure_revoked(&self) -> Result<(), &'static str> {
        if self.granted || !self.revoked {
            return Err("VT-d reassignment requires an acknowledged revoke and DMA drain");
        }
        self.verify_assignment()
    }

    pub fn grant(&mut self) -> Result<(), &'static str> {
        if self.granted {
            return Ok(());
        }
        self.ensure_revoked()?;
        self.revoked = false;
        if self.global_faulted() || self.fault().is_some() {
            return Err("VT-d fault records remain before domain grant");
        }
        // SAFETY: context slot belongs exclusively to the assigned root-bus
        // function; high word is its unique domain ID and AGAW=1 (39 bits), TT=0. Publish
        // Present last. DMA is stopped during changes by the Device owner.
        unsafe {
            addr_of_mut!(TABLES.context[self.context_index + 1])
                .write_volatile((((self.domain_index + 1) as u64) << 8) | 1);
            addr_of_mut!(TABLES.context[self.context_index])
                .write_volatile(addr_of_mut!(TABLES.domains[self.domain_index].pdpt) as u64 | 1);
        }
        publish_tables();
        self.invalidate()?;
        self.granted = true;
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), &'static str> {
        self.revoked = false;
        // SAFETY: the caller disabled bus mastering and reset the device. The
        // allocation persists forever even if hardware fails to acknowledge.
        unsafe { addr_of_mut!(TABLES.context[self.context_index]).write_volatile(0) };
        publish_tables();
        self.granted = false;
        self.invalidate()?;
        self.clear_own_faults();
        self.revoked = true;
        Ok(())
    }

    pub fn faulted(&self) -> bool {
        self.global_faulted() || self.fault().is_some()
    }

    /// PPF (bit 1) describes pending primary records and is source-attributable.
    /// Overflow, invalidation errors, or an unknown requester lose attribution
    /// and therefore require the scheduler to quarantine every interface.
    pub fn global_faulted(&self) -> bool {
        if FAILED.load(Ordering::Acquire) || read32(self.base, FSTS) & 0x7d != 0 {
            return true;
        }
        for index in 0..self.fault_count {
            if let Some(fault) = self.fault_at(index)
                && !self.requesters.contains(&Some(fault.source))
            {
                return true;
            }
        }
        false
    }

    /// Test only: exercise the scheduler's shared-unit quarantine using the
    /// same irreversible latch as an invalidation/verification failure. This
    /// does not write hardware registers or simulate a hardware timeout.
    #[cfg(feature = "isolation-test")]
    pub fn inject_shared_failure(&self) {
        let _ = fail_unit::<()>("isolation test injected a shared VT-d failure");
    }

    pub fn fault(&self) -> Option<Fault> {
        (0..self.fault_count)
            .filter_map(|index| self.fault_at(index))
            .find(|fault| fault.source == (self.context_index / 2) as u16)
    }

    fn fault_at(&self, index: usize) -> Option<Fault> {
        let offset = self.fault_base + index * 16;
        let high = read64(self.base, offset + 8);
        (high & BUSY != 0).then(|| Fault {
            address: read64(self.base, offset) & !0xfff,
            source: high as u16,
            reason: (high >> 32) as u8,
            write: high & (1 << 62) == 0,
        })
    }

    fn clear_own_faults(&self) {
        for index in 0..self.fault_count {
            if self
                .fault_at(index)
                .is_some_and(|fault| fault.source == (self.context_index / 2) as u16)
            {
                write64(self.base, self.fault_base + index * 16 + 8, BUSY);
            }
        }
        // Do not clear global status or another NIC's fault record. Lost fault
        // attribution must remain visible even while an unrelated NIC stops.
    }

    fn clear_faults(&self) {
        for index in 0..self.fault_count {
            write64(self.base, self.fault_base + index * 16 + 8, BUSY);
        }
        // Clear only the architecturally writable overflow/error bits.
        write32(self.base, FSTS, 0x7d);
    }

    fn invalidate(&self) -> Result<(), &'static str> {
        write64(self.base, CCMD, BUSY | (1 << 61));
        self.wait64(CCMD, BUSY, 0)?;
        if read64(self.base, CCMD) & (3 << 59) != 1 << 59 {
            return fail_unit("VT-d global context invalidation was not acknowledged");
        }
        // Global IOTLB invalidation, drain both DMA reads and writes.
        write64(
            self.base,
            self.iotlb,
            BUSY | (1 << 60) | (1 << 49) | (1 << 48),
        );
        self.wait64(self.iotlb, BUSY, 0)?;
        if read64(self.base, self.iotlb) & (3 << 57) != 1 << 57 {
            return fail_unit("VT-d global IOTLB invalidation was not acknowledged");
        }
        Ok(())
    }

    fn wait32(&self, offset: usize, mask: u32, value: u32) -> Result<(), &'static str> {
        let deadline = self.clock.now_millis() + 100;
        let mut polls = MAX_POLL_ITERATIONS;
        while read32(self.base, offset) & mask != value {
            if self.clock.now_millis() >= deadline || polls == 0 {
                return fail_unit("VT-d register command timed out or clock stopped");
            }
            polls -= 1;
            core::hint::spin_loop();
        }
        Ok(())
    }

    fn wait64(&self, offset: usize, mask: u64, value: u64) -> Result<(), &'static str> {
        let deadline = self.clock.now_millis() + 100;
        let mut polls = MAX_POLL_ITERATIONS;
        while read64(self.base, offset) & mask != value {
            if self.clock.now_millis() >= deadline || polls == 0 {
                return fail_unit("VT-d invalidation timed out or clock stopped");
            }
            polls -= 1;
            core::hint::spin_loop();
        }
        Ok(())
    }
}

fn fail_unit<T>(error: &'static str) -> Result<T, &'static str> {
    FAILED.store(true, Ordering::Release);
    Err(error)
}

fn publish_tables() {
    let start = addr_of_mut!(TABLES).cast::<u8>();
    fence(Ordering::SeqCst);
    // CPUID reports the CLFLUSH granule in units of eight bytes. A fixed
    // 64-byte stride would skip cache lines on a supported 32-byte CPU.
    let cache_line = ((__cpuid(1).ebx >> 8) & 0xff) as usize * 8;
    for offset in (0..size_of::<Tables>()).step_by(cache_line) {
        // SAFETY: CLFLUSH support is checked above; all lines belong to the
        // permanent supervisor table allocation. No user can edit the tables.
        unsafe {
            asm!("clflush [{}]", in(reg) start.add(offset), options(nostack, preserves_flags))
        };
    }
    fence(Ordering::SeqCst);
}

fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: validated uncached DRHD page; all private offsets are aligned.
    unsafe { read_volatile((base + offset) as *const u32) }
}
fn read64(base: usize, offset: usize) -> u64 {
    // SAFETY: as read32, with aligned 64-bit architectural registers.
    unsafe { read_volatile((base + offset) as *const u64) }
}
fn write32(base: usize, offset: usize, value: u32) {
    // SAFETY: one CPU serializes domain owners on the validated shared register page.
    unsafe { write_volatile((base + offset) as *mut u32, value) }
}
fn write64(base: usize, offset: usize, value: u64) {
    // SAFETY: one CPU serializes domain owners on the validated shared register page.
    unsafe { write_volatile((base + offset) as *mut u64, value) }
}

struct Dmar {
    base: usize,
    interrupt_remapping: bool,
}

fn discover_dmar(function: Function) -> Result<Dmar, &'static str> {
    // Shared platform discovery validates the boot memory map, RSDP/root, SDT
    // checksums and full physical ranges before exposing an immutable slice.
    let dmar = crate::platform::acpi_table(*b"DMAR")?
        .ok_or("ACPI DMAR missing; an enabled Intel VT-d unit is required")?;
    if dmar.len() < 48 {
        return Err("truncated ACPI DMAR");
    }
    let mut unit = None;
    let mut offset = 48;
    while offset < dmar.len() {
        if dmar.len() - offset < 4 {
            return Err("truncated DMAR subtable");
        }
        let kind = u16_at(dmar, offset)?;
        let size = u16_at(dmar, offset + 2)? as usize;
        if size < 4 || size > dmar.len() - offset {
            return Err("invalid DMAR subtable length");
        }
        let entry = &dmar[offset..offset + size];
        if kind == 0 {
            if size < 16 || unit.is_some() || u16_at(entry, 6)? != 0 {
                return Err("VT-d requires exactly one segment-zero DRHD");
            }
            let flags = entry[4];
            if flags & !1 != 0 {
                return Err("unsupported DRHD flags");
            }
            let mut covers_nic = flags & 1 != 0;
            let mut scope = 16;
            while scope < size {
                if size - scope < 6 {
                    return Err("truncated DRHD device scope");
                }
                let scope_type = entry[scope];
                let scope_length = entry[scope + 1] as usize;
                if scope_length < 6
                    || scope_length > size - scope
                    || !(scope_length - 6).is_multiple_of(2)
                {
                    return Err("invalid DRHD device scope length");
                }
                // Root-bus-only assignment deliberately rejects bridge aliases.
                if scope_type == 1
                    && scope_length == 8
                    && entry[scope + 5] == function.bus()
                    && entry[scope + 6] == function.devfn() >> 3
                    && entry[scope + 7] == function.devfn() & 7
                {
                    covers_nic = true;
                }
                scope += scope_length;
            }
            if !covers_nic {
                return Err("DRHD does not cover the assigned e1000 function");
            }
            let base = u64_at(entry, 8)?;
            if !(0x4000_0000..=0xffff_f000).contains(&base) || !base.is_multiple_of(4096) {
                return Err("DRHD MMIO is outside the uncached identity map");
            }
            unit = Some(base as usize);
        } else if kind == 1 {
            return Err("DMAR reserved-memory DMA regions are unsupported");
        }
        offset += size;
    }
    Ok(Dmar {
        base: unit.ok_or("ACPI DMAR contains no supported remapping unit")?,
        interrupt_remapping: dmar[37] & 1 != 0,
    })
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, &'static str> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or("truncated DMAR integer")?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}
fn u64_at(data: &[u8], offset: usize) -> Result<u64, &'static str> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or("truncated DMAR integer")?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}
