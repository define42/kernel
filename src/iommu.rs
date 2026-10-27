//! A deliberately narrow VT-d assignment implementation for QEMU q35.
//!
//! Legacy root/context tables, three-level 39-bit second-level translation,
//! one root-bus NIC, one permanently pinned DMA allocation. Every unassigned
//! requester and every other IOVA is denied. No identity/pass-through domain.
//! Register definitions: QEMU hw/i386/intel_iommu_internal.h and Intel VT-d
//! architecture sections 9 (translation structures) and 10 (registers).

use core::arch::{asm, x86_64::__cpuid};
use core::ptr::{addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering, fence};

use crate::{pci::Function, time::Clock};

pub const DMA_IOVA: u64 = 0x1000_0000;
const PAGE: usize = 4096;
const CAP: usize = 0x08;
const ECAP: usize = 0x10;
const GCMD: usize = 0x18;
const GSTS: usize = 0x1c;
const RTADDR: usize = 0x20;
const CCMD: usize = 0x28;
const FSTS: usize = 0x34;
const FECTL: usize = 0x38;
const TE: u32 = 1 << 31;
const SRTP: u32 = 1 << 30;
const BUSY: u64 = 1 << 63;
const ROOT_SIZE: usize = 256 * 2;

#[repr(C, align(4096))]
struct Tables {
    root: [u64; ROOT_SIZE],
    context: [u64; ROOT_SIZE],
    pdpt: [u64; 512],
    directory: [u64; 512],
    pages: [u64; 512],
}

static CLAIMED: AtomicBool = AtomicBool::new(false);
static mut TABLES: Tables = Tables {
    root: [0; ROOT_SIZE],
    context: [0; ROOT_SIZE],
    pdpt: [0; 512],
    directory: [0; 512],
    pages: [0; 512],
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
    iotlb: usize,
    fault_base: usize,
    fault_count: usize,
    granted: bool,
}

impl<'a> Iommu<'a> {
    pub fn new(
        clock: &'a Clock,
        function: Function,
        physical: u64,
        length: usize,
    ) -> Result<Self, &'static str> {
        if CLAIMED.swap(true, Ordering::AcqRel) {
            return Err("VT-d initialization already attempted");
        }
        if function.bus() != 0 {
            return Err("isolated e1000 must be on root PCI bus 0 (no requester aliases)");
        }
        if !physical.is_multiple_of(PAGE as u64)
            || length == 0
            || !length.is_multiple_of(PAGE)
            || length > 2 * 1024 * 1024
            || physical
                .checked_add(length as u64)
                .is_none_or(|end| end > (1 << 30))
        {
            return Err("invalid pinned VT-d DMA pool");
        }
        // CLFLUSH publishes tables even when ECAP.C is clear, as in QEMU.
        if __cpuid(1).edx & (1 << 19) == 0 {
            return Err("VT-d table publication requires CLFLUSH");
        }
        let base = discover_dmar(function)?;
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
        if read32(base, GSTS) & (TE | (1 << 26) | (1 << 25)) != 0 {
            return Err(
                "VT-d firmware translation/queued invalidation/interrupt remapping is active",
            );
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
            iotlb,
            fault_base,
            fault_count,
            granted: false,
        };
        // SAFETY: single initialization owns permanently allocated supervisor
        // tables. Bus mastering is disabled before entering this constructor.
        // Only the pinned pool receives leaf mappings; neither user/kernel
        // executable memory nor the CPU/IOMMU page tables are mapped for DMA.
        unsafe {
            addr_of_mut!(TABLES.root[0]).write(addr_of_mut!(TABLES.context) as u64 | 1);
            addr_of_mut!(TABLES.pdpt[0]).write(addr_of_mut!(TABLES.directory) as u64 | 3);
            addr_of_mut!(TABLES.directory[(DMA_IOVA >> 21) as usize])
                .write(addr_of_mut!(TABLES.pages) as u64 | 3);
            for page in 0..length / PAGE {
                addr_of_mut!(TABLES.pages[page]).write((physical + (page * PAGE) as u64) | 3);
            }
        }
        publish_tables();
        write32(base, FECTL, 1 << 31); // Faults are polled, never MSI-delivered.
        unit.clear_faults();
        // SAFETY: the root is a page-aligned field in the exclusively owned tables.
        write64(base, RTADDR, unsafe { addr_of_mut!(TABLES.root) as u64 });
        write32(base, GCMD, SRTP);
        unit.wait32(GSTS, SRTP, SRTP)?;
        unit.invalidate()?;
        write32(base, GCMD, TE);
        unit.wait32(GSTS, TE, TE)?;
        unit.grant()?;
        Ok(unit)
    }

    pub fn grant(&mut self) -> Result<(), &'static str> {
        if self.granted {
            return Ok(());
        }
        self.clear_faults();
        // SAFETY: context slot belongs exclusively to the assigned root-bus
        // function; high word is domain 1 and AGAW=1 (39 bits), TT=0. Publish
        // Present last. DMA is stopped during changes by the Device owner.
        unsafe {
            addr_of_mut!(TABLES.context[self.context_index + 1]).write_volatile((1 << 8) | 1);
            addr_of_mut!(TABLES.context[self.context_index])
                .write_volatile(addr_of_mut!(TABLES.pdpt) as u64 | 1);
        }
        publish_tables();
        self.invalidate()?;
        self.granted = true;
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), &'static str> {
        // SAFETY: the caller disabled bus mastering and reset the device. The
        // allocation persists forever even if hardware fails to acknowledge.
        unsafe { addr_of_mut!(TABLES.context[self.context_index]).write_volatile(0) };
        publish_tables();
        self.granted = false;
        self.invalidate()?;
        self.clear_faults();
        Ok(())
    }

    pub fn faulted(&self) -> bool {
        read32(self.base, FSTS) & 0x7f != 0 || self.fault().is_some()
    }

    pub fn fault(&self) -> Option<Fault> {
        for index in 0..self.fault_count {
            let offset = self.fault_base + index * 16;
            let high = read64(self.base, offset + 8);
            if high & BUSY != 0 {
                return Some(Fault {
                    address: read64(self.base, offset) & !0xfff,
                    source: high as u16,
                    reason: (high >> 32) as u8,
                    write: high & (1 << 62) == 0,
                });
            }
        }
        None
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
            return Err("VT-d global context invalidation was not acknowledged");
        }
        // Global IOTLB invalidation, drain both DMA reads and writes.
        write64(
            self.base,
            self.iotlb,
            BUSY | (1 << 60) | (1 << 49) | (1 << 48),
        );
        self.wait64(self.iotlb, BUSY, 0)?;
        if read64(self.base, self.iotlb) & (3 << 57) != 1 << 57 {
            return Err("VT-d global IOTLB invalidation was not acknowledged");
        }
        Ok(())
    }

    fn wait32(&self, offset: usize, mask: u32, value: u32) -> Result<(), &'static str> {
        let deadline = self.clock.now_millis() + 100;
        while read32(self.base, offset) & mask != value {
            if self.clock.now_millis() >= deadline {
                return Err("VT-d register command timed out");
            }
            core::hint::spin_loop();
        }
        Ok(())
    }

    fn wait64(&self, offset: usize, mask: u64, value: u64) -> Result<(), &'static str> {
        let deadline = self.clock.now_millis() + 100;
        while read64(self.base, offset) & mask != value {
            if self.clock.now_millis() >= deadline {
                return Err("VT-d invalidation timed out");
            }
            core::hint::spin_loop();
        }
        Ok(())
    }
}

fn publish_tables() {
    let start = addr_of_mut!(TABLES).cast::<u8>();
    fence(Ordering::SeqCst);
    for offset in (0..size_of::<Tables>()).step_by(64) {
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
    // SAFETY: the unique Iommu owns its validated register page.
    unsafe { write_volatile((base + offset) as *mut u32, value) }
}
fn write64(base: usize, offset: usize, value: u64) {
    // SAFETY: the unique Iommu owns its validated register page.
    unsafe { write_volatile((base + offset) as *mut u64, value) }
}

/// QEMU SeaBIOS places the RSDP in the ACPI BIOS search area. Deliberately
/// avoid the BDA/EBDA pointer at 0x40e: the hardened kernel unmaps page zero.
fn discover_dmar(function: Function) -> Result<usize, &'static str> {
    let mut root = None;
    for address in (0xe0000..0x100000).step_by(16) {
        if bytes(address, 8)? != b"RSD PTR " || checksum(address, 20)? != 0 {
            continue;
        }
        let revision = bytes(address + 15, 1)?[0];
        let rsdt = u32_at(address + 16)? as usize;
        if revision >= 2 {
            let length = u32_at(address + 20)? as usize;
            if !(36..=4096).contains(&length) || checksum(address, length)? != 0 {
                return Err("invalid ACPI RSDP extended checksum");
            }
            let xsdt = u64_at(address + 24)?;
            if xsdt != 0 && xsdt < (1 << 30) {
                root = Some((xsdt as usize, 8));
                break;
            }
        }
        root = Some((rsdt, 4));
        break;
    }
    let (root, stride) = root.ok_or("ACPI RSDP not found; q35 SeaBIOS is required")?;
    let root_length = table(root, if stride == 8 { b"XSDT" } else { b"RSDT" })?;
    if !(root_length - 36).is_multiple_of(stride) {
        return Err("invalid ACPI root table entry count");
    }
    let mut dmar = None;
    for offset in (36..root_length).step_by(stride) {
        let address = if stride == 8 {
            u64_at(root + offset)?
        } else {
            u32_at(root + offset)? as u64
        };
        if address >= (1 << 30) {
            return Err("ACPI table is outside mapped low RAM");
        }
        if bytes(address as usize, 4)? == b"DMAR" && dmar.replace(address as usize).is_some() {
            return Err("multiple ACPI DMAR tables are unsupported");
        }
    }
    let dmar =
        dmar.ok_or("ACPI DMAR missing; add -machine q35 -device intel-iommu,intremap=off")?;
    let length = table(dmar, b"DMAR")?;
    if length < 48 {
        return Err("truncated ACPI DMAR");
    }
    let mut unit = None;
    let mut offset = 48;
    while offset < length {
        if offset + 4 > length {
            return Err("truncated DMAR subtable");
        }
        let kind = u16_at(dmar + offset)?;
        let size = u16_at(dmar + offset + 2)? as usize;
        if size < 4 || size > length - offset {
            return Err("invalid DMAR subtable length");
        }
        if kind == 0 {
            if size < 16 || unit.is_some() || u16_at(dmar + offset + 6)? != 0 {
                return Err("VT-d requires exactly one segment-zero DRHD");
            }
            let flags = bytes(dmar + offset + 4, 1)?[0];
            if flags & !1 != 0 {
                return Err("unsupported DRHD flags");
            }
            let mut covers_nic = flags & 1 != 0;
            let mut scope = 16;
            while scope < size {
                if size - scope < 6 {
                    return Err("truncated DRHD device scope");
                }
                let scope_address = dmar + offset + scope;
                let scope_type = bytes(scope_address, 1)?[0];
                let scope_length = bytes(scope_address + 1, 1)?[0] as usize;
                if scope_length < 6
                    || scope_length > size - scope
                    || !(scope_length - 6).is_multiple_of(2)
                {
                    return Err("invalid DRHD device scope length");
                }
                // QEMU may list every root endpoint instead of INCLUDE_ALL.
                // Root-bus-only assignment deliberately rejects bridge aliases.
                if scope_type == 1
                    && scope_length == 8
                    && bytes(scope_address + 5, 1)?[0] == function.bus()
                    && bytes(scope_address + 6, 1)?[0] == function.devfn() >> 3
                    && bytes(scope_address + 7, 1)?[0] == function.devfn() & 7
                {
                    covers_nic = true;
                }
                scope += scope_length;
            }
            if !covers_nic {
                return Err("DRHD does not cover the assigned e1000 function");
            }
            let base = u64_at(dmar + offset + 8)?;
            if !(0x4000_0000..=0xffff_f000).contains(&base) || !base.is_multiple_of(4096) {
                return Err("DRHD MMIO is outside the uncached identity map");
            }
            unit = Some(base as usize);
        } else if kind == 1 {
            return Err("DMAR reserved-memory DMA regions are unsupported");
        }
        offset += size;
    }
    unit.ok_or("ACPI DMAR contains no supported remapping unit")
}

fn table(address: usize, signature: &[u8; 4]) -> Result<usize, &'static str> {
    if bytes(address, 4)? != signature {
        return Err("ACPI table signature mismatch");
    }
    let length = u32_at(address + 4)? as usize;
    if !(36..=1024 * 1024).contains(&length) || checksum(address, length)? != 0 {
        return Err("ACPI table length/checksum is invalid");
    }
    Ok(length)
}

fn bytes(address: usize, length: usize) -> Result<&'static [u8], &'static str> {
    if address < PAGE
        || address
            .checked_add(length)
            .is_none_or(|end| end > (1 << 30))
    {
        return Err("ACPI read is outside mapped firmware/RAM");
    }
    // SAFETY: the trusted QEMU BIOS supplied these immutable ACPI tables and
    // BIOS scan range. The complete byte range is inside supervisor identity
    // mappings, excluding the unmapped null page; it is never user-writable.
    Ok(unsafe { core::slice::from_raw_parts(address as *const u8, length) })
}
fn checksum(address: usize, length: usize) -> Result<u8, &'static str> {
    Ok(bytes(address, length)?
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte)))
}
fn u16_at(address: usize) -> Result<u16, &'static str> {
    Ok(u16::from_le_bytes(bytes(address, 2)?.try_into().unwrap()))
}
fn u32_at(address: usize) -> Result<u32, &'static str> {
    Ok(u32::from_le_bytes(bytes(address, 4)?.try_into().unwrap()))
}
fn u64_at(address: usize) -> Result<u64, &'static str> {
    Ok(u64::from_le_bytes(bytes(address, 8)?.try_into().unwrap()))
}
