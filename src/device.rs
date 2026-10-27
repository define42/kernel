//! Kernel-owned PCI assignment and DMA lifetime, without packet processing.
//! The ring-3 e1000 driver owns MMIO programming and all Ethernet operations.

use core::arch::{asm, x86_64::__cpuid};
use core::ptr::{addr_of_mut, read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{
    iommu::{Fault, Iommu},
    pci,
    time::Clock,
    userspace::Process,
};

pub const MMIO_VIRTUAL: u64 = 0x5000_0000;
pub const DMA_VIRTUAL: u64 = 0x5020_0000;
pub const DMA_LENGTH: usize = 0x41000;
const BAR_LENGTH: usize = 128 * 1024;

#[repr(C, align(4096))]
struct Pool([u8; DMA_LENGTH]);
static mut DMA: Pool = Pool([0; DMA_LENGTH]);
static CLAIMED: AtomicBool = AtomicBool::new(false);

pub struct Device<'a> {
    clock: &'a Clock,
    function: pci::Function,
    mmio: usize,
    iommu: Iommu<'a>,
    configured: bool,
    started: bool,
}

impl<'a> Device<'a> {
    pub fn new(clock: &'a Clock) -> Result<Self, &'static str> {
        if CLAIMED.swap(true, Ordering::AcqRel) {
            return Err("isolated device initialization already attempted");
        }
        let function = pci::find(0x8086, 0x100e).ok_or("Intel 82540EM e1000 NIC not found")?;
        function.prepare_memory();
        if function.bus_master_enabled() {
            return Err("PCI bus mastering could not be disabled");
        }
        if function.bus() != 0 {
            return Err("isolated e1000 must be directly on PCI root bus 0");
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
        // PCI INTx stays disabled. VT-d's interrupt aperture is separate from
        // DMA translation, so a malicious RX descriptor could synthesize an
        // MSI. This one-CPU PIC/PIT platform therefore disables the local APIC
        // by requiring a QEMU CPU with no APIC device (-cpu max,-apic).
        // Future APIC use requires real interrupt-remapping isolation first.
        require_no_local_apic()?;
        reset(mmio, clock)?;
        let iommu = Iommu::new(clock, function, addr_of_mut!(DMA) as u64, DMA_LENGTH)?;
        Ok(Self {
            clock,
            function,
            mmio,
            iommu,
            configured: false,
            started: false,
        })
    }

    pub fn configure(&mut self, process: &mut Process) -> Result<(), &'static str> {
        if self.started || self.function.bus_master_enabled() {
            return Err("cannot remap a running device");
        }
        self.iommu.grant()?;
        // SAFETY: bus mastering is disabled and the previous run was reset and
        // drained before revoke. This allocation is permanently pinned, has no
        // kernel objects, and is never recycled for unrelated process memory.
        unsafe {
            write_bytes(addr_of_mut!(DMA).cast::<u8>(), 0, DMA_LENGTH);
            process.map_device(MMIO_VIRTUAL, self.mmio as u64, BAR_LENGTH, true)?;
            process.map_device(DMA_VIRTUAL, addr_of_mut!(DMA) as u64, DMA_LENGTH, false)?;
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
        self.function.enable_bus_master();
        if !self.function.bus_master_enabled() {
            return Err("PCI bus mastering could not be enabled");
        }
        self.started = true;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), &'static str> {
        self.function.disable_bus_master();
        self.started = false;
        self.configured = false;
        // Always revoke, including if reset fails. The pool remains pinned even
        // on failure; callers must fail closed instead of resuming the driver.
        let reset_result = reset(self.mmio, self.clock);
        let revoke_result = self.iommu.revoke();
        if self.function.bus_master_enabled() {
            return Err("PCI DMA remains enabled during teardown");
        }
        reset_result.and(revoke_result)
    }

    pub fn faulted(&self) -> bool {
        self.iommu.faulted()
    }
    pub fn fault(&self) -> Option<Fault> {
        self.iommu.fault()
    }
}

fn reset(mmio: usize, clock: &Clock) -> Result<(), &'static str> {
    // SAFETY: caller owns the validated uncached BAR and has stopped DMA.
    unsafe {
        write_volatile((mmio + 0xd8) as *mut u32, u32::MAX);
        write_volatile((mmio + 0x100) as *mut u32, 0);
        write_volatile((mmio + 0x400) as *mut u32, 0);
        read_volatile((mmio + 8) as *const u32);
    }
    clock.delay_micros(10_000);
    // SAFETY: CTRL is the first register in the assigned BAR.
    unsafe {
        let control = read_volatile(mmio as *const u32);
        write_volatile(mmio as *mut u32, control | (1 << 26));
    }
    let deadline = clock.now_millis() + 100;
    // SAFETY: read the reset bit from the same validated register.
    while unsafe { read_volatile(mmio as *const u32) } & (1 << 26) != 0 {
        if clock.now_millis() >= deadline {
            return Err("e1000 lifecycle reset timed out");
        }
        core::hint::spin_loop();
    }
    clock.delay_micros(10_000);
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

fn require_no_local_apic() -> Result<(), &'static str> {
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
