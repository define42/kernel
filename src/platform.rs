//! Validated Multiboot memory maps and ACPI discovery before page zero is removed.
//!
//! The loader and firmware remain trusted. Every pointer is bounded to the low
//! identity map before dereferencing; firmware SDTs must also be covered by
//! reserved/ACPI memory, never kernel or available RAM. No allocator is used.
//! Formats: GNU Multiboot 1/2 specifications, ACPI 6.5 section 5.2, HPET 1.0a.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, Ordering};

const MULTIBOOT1: u32 = 0x2bad_b002;
const MULTIBOOT2: u32 = 0x36d7_6289;
const RAM_MAP_END: u64 = 1 << 30;
const MAX_BOOT_BYTES: usize = 1024 * 1024;
const MAX_REGIONS: usize = 256;
const MAX_TABLES: usize = 128;
const SDT_HEADER: usize = 36;

#[derive(Clone, Copy, Debug, Default)]
struct Region {
    start: u64,
    end: u64,
    kind: u32,
}

struct MemoryMap {
    regions: [Region; MAX_REGIONS],
    count: usize,
}

impl MemoryMap {
    const fn new() -> Self {
        Self {
            regions: [Region {
                start: 0,
                end: 0,
                kind: 0,
            }; MAX_REGIONS],
            count: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.len() < 20 || self.count == MAX_REGIONS {
            return Err("truncated memory map or too many regions");
        }
        let start = u64_at(bytes, 0)?;
        let length = u64_at(bytes, 8)?;
        let end = start.checked_add(length).ok_or("memory region overflows")?;
        if length == 0 {
            return Err("empty memory map region");
        }
        self.regions[self.count] = Region {
            start,
            end,
            kind: u32_at(bytes, 16)?,
        };
        self.count += 1;
        Ok(())
    }

    fn multiboot1(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut map = Self::new();
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            let length = u32_at(bytes, cursor)? as usize;
            if length < 20 {
                return Err("Multiboot1 memory map entry is too short");
            }
            let start = cursor.checked_add(4).ok_or("memory map offset overflows")?;
            let end = start
                .checked_add(length)
                .ok_or("memory map length overflows")?;
            map.push(
                bytes
                    .get(start..end)
                    .ok_or("truncated Multiboot1 memory map")?,
            )?;
            cursor = end;
        }
        if map.count == 0 {
            return Err("empty Multiboot memory map");
        }
        Ok(map)
    }

    fn multiboot2(bytes: &[u8], stride: usize) -> Result<Self, &'static str> {
        if stride < 24 || !stride.is_multiple_of(8) || !bytes.len().is_multiple_of(stride) {
            return Err("invalid Multiboot2 memory map entry size");
        }
        let mut map = Self::new();
        for entry in bytes.chunks_exact(stride) {
            map.push(entry)?;
        }
        if map.count == 0 {
            return Err("empty Multiboot memory map");
        }
        Ok(map)
    }

    /// Coverage may span adjacent/overlapping entries, but an overlapping
    /// forbidden entry always wins. Never infer usable RAM from mem_upper.
    fn covers(&self, start: u64, end: u64, firmware: bool) -> bool {
        if start >= end {
            return false;
        }
        let allowed = |kind| {
            if firmware {
                matches!(kind, 2..=4)
            } else {
                kind == 1
            }
        };
        if self.regions[..self.count]
            .iter()
            .any(|r| r.start < end && r.end > start && !allowed(r.kind))
        {
            return false;
        }
        let mut cursor = start;
        while cursor < end {
            let next = self.regions[..self.count]
                .iter()
                .filter(|r| allowed(r.kind) && r.start <= cursor && r.end > cursor)
                .map(|r| r.end)
                .max()
                .unwrap_or(cursor);
            if next == cursor {
                return false;
            }
            cursor = next;
        }
        true
    }
}

#[derive(Clone, Copy)]
struct KernelRange {
    start: u64,
    end: u64,
}

impl KernelRange {
    fn overlaps(self, start: u64, end: u64) -> bool {
        start < self.end && end > self.start
    }
}

struct BootData<'a> {
    map: MemoryMap,
    rsdp: Option<&'a [u8]>,
}

fn parse_multiboot2(bytes: &[u8]) -> Result<BootData<'_>, &'static str> {
    let total = u32_at(bytes, 0)? as usize;
    if !(16..=MAX_BOOT_BYTES).contains(&total) || total != bytes.len() || !total.is_multiple_of(8) {
        return Err("invalid Multiboot2 total size");
    }
    let mut cursor = 8usize;
    let mut map = None;
    let mut old_rsdp = None;
    let mut new_rsdp = None;
    let mut ended = false;
    while cursor < total {
        let kind = u32_at(bytes, cursor)?;
        let size = u32_at(bytes, cursor + 4)? as usize;
        if size < 8 {
            return Err("Multiboot2 tag is too short");
        }
        let end = cursor
            .checked_add(size)
            .ok_or("Multiboot2 tag size overflows")?;
        let tag = bytes.get(cursor..end).ok_or("truncated Multiboot2 tag")?;
        match kind {
            0 => {
                if size != 8 || end != total {
                    return Err("invalid Multiboot2 end tag");
                }
                ended = true;
                break;
            }
            6 => {
                if map.is_some() || size < 16 {
                    return Err("duplicate/truncated Multiboot2 memory map");
                }
                // Future map versions retain the first 24 bytes of each entry.
                map = Some(MemoryMap::multiboot2(&tag[16..], u32_at(tag, 8)? as usize)?);
            }
            14 => {
                if old_rsdp.replace(&tag[8..]).is_some() {
                    return Err("duplicate ACPI 1 RSDP tag");
                }
                parse_rsdp(&tag[8..])?;
            }
            15 => {
                if new_rsdp.replace(&tag[8..]).is_some() {
                    return Err("duplicate ACPI 2 RSDP tag");
                }
                if tag.get(23).is_none_or(|revision| *revision < 2) {
                    return Err("invalid ACPI 2 RSDP tag");
                }
                parse_rsdp(&tag[8..])?;
            }
            18 => return Err("EFI boot services must be terminated before kernel entry"),
            _ => {}
        }
        cursor = end.checked_add(7).ok_or("Multiboot2 alignment overflows")? & !7;
        if cursor > total {
            return Err("truncated Multiboot2 tag padding");
        }
    }
    if !ended {
        return Err("Multiboot2 end tag is missing");
    }
    Ok(BootData {
        map: map.ok_or("Multiboot memory map is required")?,
        rsdp: new_rsdp.or(old_rsdp),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Root {
    address: u64,
    stride: usize,
}

fn checksum(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0
}

fn parse_rsdp(bytes: &[u8]) -> Result<Root, &'static str> {
    let prefix = bytes.get(..20).ok_or("truncated ACPI RSDP")?;
    if &prefix[..8] != b"RSD PTR " || !checksum(prefix) {
        return Err("invalid ACPI RSDP signature/checksum");
    }
    let rsdt = u32_at(prefix, 16)? as u64;
    if prefix[15] >= 2 {
        let length = u32_at(bytes, 20)? as usize;
        if !(36..=4096).contains(&length)
            || !checksum(bytes.get(..length).ok_or("truncated extended RSDP")?)
        {
            return Err("invalid ACPI RSDP extended length/checksum");
        }
        let xsdt = u64_at(bytes, 24)?;
        if xsdt != 0 {
            return Ok(Root {
                address: xsdt,
                stride: 8,
            });
        }
    } else if prefix[15] != 0 {
        return Err("unsupported ACPI RSDP revision");
    }
    if rsdt == 0 {
        return Err("ACPI root address is zero");
    }
    Ok(Root {
        address: rsdt,
        stride: 4,
    })
}

fn validate_sdt(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() < SDT_HEADER
        || bytes.len() > MAX_BOOT_BYTES
        || u32_at(bytes, 4)? as usize != bytes.len()
        || !checksum(bytes)
    {
        return Err("invalid ACPI SDT length/checksum");
    }
    Ok(())
}

fn parse_hpet(bytes: &[u8]) -> Result<usize, &'static str> {
    validate_sdt(bytes)?;
    if bytes.len() < 56 || &bytes[..4] != b"HPET" {
        return Err("truncated ACPI HPET table");
    }
    // Some PC firmware leaves GAS width unspecified (zero); otherwise this
    // driver requires its native 64-bit register access description. HPET
    // 1.0a reserves the fourth GAS byte; newer GAS uses it as access size.
    if bytes[40] != 0
        || !matches!(bytes[41], 0 | 64)
        || bytes[42] != 0
        || !matches!(bytes[43], 0 | 4)
    {
        return Err("HPET requires a supported system-memory register block");
    }
    let address = u64_at(bytes, 44)?;
    // All MMIO above 1 GiB is already mapped UC. Below it, changing cache
    // attributes would require a separate mapping and cache synchronization.
    if !(RAM_MAP_END..=0xffff_f000).contains(&address) || !address.is_multiple_of(4096) {
        return Err("HPET MMIO lies outside the uncached identity map");
    }
    Ok(address as usize)
}

struct State {
    map: MemoryMap,
    kernel: KernelRange,
    root: Option<Root>,
    hpet: Option<usize>,
}
static CLAIMED: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static mut STATE: Option<State> = None;

pub struct BootSummary {
    pub version: u8,
    pub memory_regions: usize,
    pub kernel_bytes: u64,
    pub hpet: Option<usize>,
}

/// Runs once on the bootstrap CPU, before memory::init unmaps the BIOS data
/// area. The boot loader must have exited firmware boot services.
pub fn init(magic: u32, info_address: u32) -> Result<BootSummary, &'static str> {
    if CLAIMED.swap(true, Ordering::AcqRel) {
        return Err("platform already initialized");
    }
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    let kernel = KernelRange {
        start: addr_of!(__kernel_start) as u64,
        end: addr_of!(__kernel_end) as u64,
    };
    if kernel.start < 0x10_0000 || kernel.start >= kernel.end || kernel.end > RAM_MAP_END {
        return Err("resident kernel is outside mapped RAM");
    }
    let address = info_address as u64;
    let (version, boot) = match magic {
        MULTIBOOT1 => {
            if !address.is_multiple_of(4) {
                return Err("unaligned Multiboot1 information");
            }
            let info = physical_bytes(address, 52, kernel)?;
            if u32_at(info, 0)? & (1 << 6) == 0 {
                return Err("Multiboot memory map is required");
            }
            let length = u32_at(info, 44)? as usize;
            if length > MAX_BOOT_BYTES {
                return Err("Multiboot memory map is too large");
            }
            let bytes = physical_bytes(u32_at(info, 48)? as u64, length, kernel)?;
            (
                1,
                BootData {
                    map: MemoryMap::multiboot1(bytes)?,
                    rsdp: None,
                },
            )
        }
        MULTIBOOT2 => {
            if !address.is_multiple_of(8) {
                return Err("unaligned Multiboot2 information");
            }
            let prefix = physical_bytes(address, 8, kernel)?;
            let size = u32_at(prefix, 0)? as usize;
            if !(16..=MAX_BOOT_BYTES).contains(&size) {
                return Err("invalid Multiboot2 information size");
            }
            (2, parse_multiboot2(physical_bytes(address, size, kernel)?)?)
        }
        _ => return Err("invalid Multiboot boot magic"),
    };
    if !boot.map.covers(kernel.start, kernel.end, false) {
        #[cfg(not(test))]
        {
            use core::fmt::Write;
            let mut console = crate::console::Console::new();
            writeln!(
                console,
                "Boot RAM conflict: kernel [{:#x}, {:#x})",
                kernel.start, kernel.end
            )
            .ok();
            for region in &boot.map.regions[..boot.map.count] {
                writeln!(
                    console,
                    "  memory [{:#x}, {:#x}) type {}",
                    region.start, region.end, region.kind
                )
                .ok();
            }
        }
        return Err("entire resident kernel including BSS must be backed by available RAM");
    }
    let mut state = State {
        map: boot.map,
        kernel,
        root: None,
        hpet: None,
    };
    if !cfg!(feature = "smoke-test") {
        let root = match boot.rsdp {
            Some(copy) => parse_rsdp(copy)?,
            None => discover_bios_rsdp(kernel)?,
        };
        state.root = Some(root);
        state.validate_root()?;
        let hpet = state
            .acpi_table(*b"HPET")?
            .ok_or("ACPI HPET table is required")?;
        state.hpet = Some(parse_hpet(hpet)?);
    }
    let summary = BootSummary {
        version,
        memory_regions: state.map.count,
        kernel_bytes: kernel.end - kernel.start,
        hpet: state.hpet,
    };
    // SAFETY: one-time bootstrap initialization, published before any reader.
    unsafe {
        addr_of_mut!(STATE).write(Some(state));
    }
    READY.store(true, Ordering::Release);
    Ok(summary)
}

fn state() -> Result<&'static State, &'static str> {
    if !READY.load(Ordering::Acquire) {
        return Err("platform discovery has not completed");
    }
    // SAFETY: READY publishes the fully initialized immutable static object.
    unsafe { (&*addr_of!(STATE)).as_ref().ok_or("platform state missing") }
}

pub fn hpet_address() -> Result<usize, &'static str> {
    state()?.hpet.ok_or("HPET has not been discovered")
}

/// Entire immutable SDT, including its 36-byte header. Duplicates fail closed;
/// the reserved firmware memory remains pinned for the lifetime of the kernel.
#[cfg_attr(feature = "userspace-test", allow(dead_code))]
pub fn acpi_table(signature: [u8; 4]) -> Result<Option<&'static [u8]>, &'static str> {
    state()?.acpi_table(signature)
}

impl State {
    fn firmware_bytes(&self, address: u64, length: usize) -> Result<&'static [u8], &'static str> {
        let end = address
            .checked_add(length as u64)
            .ok_or("ACPI range overflows")?;
        if !self.map.covers(address, end, true) {
            return Err("ACPI table is outside reserved firmware memory");
        }
        physical_bytes(address, length, self.kernel)
    }

    fn table(&self, address: u64) -> Result<&'static [u8], &'static str> {
        let prefix = self.firmware_bytes(address, SDT_HEADER)?;
        let length = u32_at(prefix, 4)? as usize;
        if !(SDT_HEADER..=MAX_BOOT_BYTES).contains(&length) {
            return Err("invalid ACPI SDT length");
        }
        let bytes = self.firmware_bytes(address, length)?;
        validate_sdt(bytes)?;
        Ok(bytes)
    }

    fn root_table(&self) -> Result<(&'static [u8], usize), &'static str> {
        let root = self.root.ok_or("ACPI root has not been discovered")?;
        let bytes = self.table(root.address)?;
        let expected = if root.stride == 8 { b"XSDT" } else { b"RSDT" };
        if &bytes[..4] != expected
            || !(bytes.len() - SDT_HEADER).is_multiple_of(root.stride)
            || (bytes.len() - SDT_HEADER) / root.stride > MAX_TABLES
        {
            return Err("invalid ACPI root signature/entry count");
        }
        Ok((bytes, root.stride))
    }

    fn validate_root(&self) -> Result<(), &'static str> {
        let (root, stride) = self.root_table()?;
        for entry in root[SDT_HEADER..].chunks_exact(stride) {
            self.table(if stride == 8 {
                u64_at(entry, 0)?
            } else {
                u32_at(entry, 0)? as u64
            })?;
        }
        Ok(())
    }

    fn acpi_table(&self, signature: [u8; 4]) -> Result<Option<&'static [u8]>, &'static str> {
        let (root, stride) = self.root_table()?;
        let mut found = None;
        for entry in root[SDT_HEADER..].chunks_exact(stride) {
            let bytes = self.table(if stride == 8 {
                u64_at(entry, 0)?
            } else {
                u32_at(entry, 0)? as u64
            })?;
            if bytes[..4] == signature && found.replace(bytes).is_some() {
                return Err("duplicate requested ACPI table");
            }
        }
        Ok(found)
    }
}

fn physical_bytes(
    address: u64,
    length: usize,
    kernel: KernelRange,
) -> Result<&'static [u8], &'static str> {
    let end = address
        .checked_add(length as u64)
        .ok_or("physical read overflows")?;
    if address < 4096 || length == 0 || end > RAM_MAP_END || kernel.overlaps(address, end) {
        return Err("boot/firmware pointer is outside mapped low memory or overlaps kernel");
    }
    // SAFETY: a trusted boot loader/firmware supplies these pointers. The
    // complete range is supervisor identity mapped and disjoint from kernel
    // allocations. Firmware table readers additionally require reserved RAM.
    Ok(unsafe { core::slice::from_raw_parts(address as *const u8, length) })
}

fn discover_bios_rsdp(kernel: KernelRange) -> Result<Root, &'static str> {
    // SAFETY: only called before page zero is unmapped; x86 BIOS data area.
    let ebda = u64::from(unsafe { (0x40e as *const u16).read_volatile() }) << 4;
    if (0x80000..=0x9fc00).contains(&ebda)
        && let Some(root) = scan_rsdp(ebda, ebda + 1024, kernel)?
    {
        return Ok(root);
    }
    scan_rsdp(0xe0000, 0x100000, kernel)?.ok_or("ACPI RSDP not supplied or found in EBDA/BIOS")
}

fn scan_rsdp(start: u64, end: u64, kernel: KernelRange) -> Result<Option<Root>, &'static str> {
    for address in (start..end).step_by(16) {
        if address + 20 > end {
            break;
        }
        let prefix = physical_bytes(address, 20, kernel)?;
        if &prefix[..8] != b"RSD PTR " || !checksum(prefix) {
            continue;
        }
        let length = if prefix[15] >= 2 {
            if address + 24 > end {
                return Err("RSDP crosses BIOS search boundary");
            }
            u32_at(physical_bytes(address, 24, kernel)?, 20)? as usize
        } else {
            20
        };
        if !(20..=4096).contains(&length) || address + length as u64 > end {
            return Err("RSDP extends outside BIOS search area");
        }
        return Ok(Some(parse_rsdp(physical_bytes(address, length, kernel)?)?));
    }
    Ok(None)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    let end = offset.checked_add(4).ok_or("field offset overflows")?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or("truncated 32-bit field")?
            .try_into()
            .unwrap(),
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, &'static str> {
    let end = offset.checked_add(8).ok_or("field offset overflows")?;
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or("truncated 64-bit field")?
            .try_into()
            .unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(start: u64, length: u64, kind: u32) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&start.to_le_bytes());
        entry.extend_from_slice(&length.to_le_bytes());
        entry.extend_from_slice(&kind.to_le_bytes());
        entry.extend_from_slice(&0u32.to_le_bytes());
        entry
    }

    fn mb1(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for entry in entries {
            bytes.extend_from_slice(&(entry.len() as u32).to_le_bytes());
            bytes.extend_from_slice(entry);
        }
        bytes
    }

    fn finish_checksum(bytes: &mut [u8], offset: usize) {
        bytes[offset] = 0;
        bytes[offset] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)));
    }

    fn rsdp(revision: u8) -> Vec<u8> {
        let mut bytes = vec![0; if revision >= 2 { 36 } else { 20 }];
        bytes[..8].copy_from_slice(b"RSD PTR ");
        bytes[15] = revision;
        bytes[16..20].copy_from_slice(&0x7ff0000u32.to_le_bytes());
        if revision >= 2 {
            bytes[20..24].copy_from_slice(&36u32.to_le_bytes());
            bytes[24..32].copy_from_slice(&0x7ff1000u64.to_le_bytes());
        }
        finish_checksum(&mut bytes[..20], 8);
        if revision >= 2 {
            finish_checksum(&mut bytes, 32);
        }
        bytes
    }

    fn tag(bytes: &mut Vec<u8>, kind: u32, payload: &[u8]) {
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u32 + 8).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().next_multiple_of(8), 0);
    }

    fn mb2(extra: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = vec![0; 8];
        let mut map = Vec::new();
        map.extend_from_slice(&24u32.to_le_bytes());
        map.extend_from_slice(&0u32.to_le_bytes());
        map.extend_from_slice(&region(0x100000, 0x1f00000, 1));
        tag(&mut bytes, 6, &map);
        for (kind, payload) in extra {
            tag(&mut bytes, *kind, payload);
        }
        tag(&mut bytes, 0, &[]);
        let length = bytes.len() as u32;
        bytes[..4].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    #[test]
    fn mb1_extended_unsorted_entries_cover_entire_kernel() {
        let mut extended = region(0x100000, 0x100000, 1);
        extended.extend_from_slice(&[0x55; 8]);
        let bytes = mb1(&[region(0x200000, 0x600000, 1), extended]);
        let map = MemoryMap::multiboot1(&bytes).unwrap();
        assert!(map.covers(0x100000, 0x800000, false));
        assert!(!map.covers(0x100000, 0x800001, false));
    }

    #[test]
    fn kernel_coverage_rejects_reserved_overlap_holes_and_bss_shortfall() {
        let map = MemoryMap::multiboot1(&mb1(&[
            region(0x100000, 0x700000, 1),
            region(0x400000, 4096, 2),
        ]))
        .unwrap();
        assert!(!map.covers(0x100000, 0x800000, false));
        let map = MemoryMap::multiboot1(&mb1(&[
            region(0x100000, 0x100000, 1),
            region(0x300000, 0x100000, 1),
        ]))
        .unwrap();
        assert!(!map.covers(0x100000, 0x400000, false));
        assert!(!map.covers(0x100000, 0x200001, false));
    }

    #[test]
    fn firmware_tables_require_reserved_or_acpi_coverage() {
        let map = MemoryMap::multiboot1(&mb1(&[
            region(0x100000, 0x100000, 1),
            region(0x200000, 4096, 2),
            region(0x201000, 4096, 3),
            region(0x202000, 4096, 4),
            region(0x203000, 4096, 5),
        ]))
        .unwrap();
        assert!(map.covers(0x200000, 0x203000, true));
        assert!(!map.covers(0x100000, 0x100024, true));
        assert!(!map.covers(0x202000, 0x203001, true));
    }

    #[test]
    fn mb1_rejects_every_truncation_and_overflowing_or_empty_ranges() {
        let valid = mb1(&[region(0x100000, 0x100000, 1)]);
        for length in 0..valid.len() {
            assert!(MemoryMap::multiboot1(&valid[..length]).is_err());
        }
        assert!(MemoryMap::multiboot1(&mb1(&[region(u64::MAX - 8, 16, 1)])).is_err());
        assert!(MemoryMap::multiboot1(&mb1(&[region(0x100000, 0, 1)])).is_err());
        let mut short = valid;
        short[..4].copy_from_slice(&19u32.to_le_bytes());
        assert!(MemoryMap::multiboot1(&short).is_err());
    }

    #[test]
    fn map_capacity_and_multiboot2_entry_sizes_are_bounded() {
        let entries = region(0x100000, 4096, 1).repeat(MAX_REGIONS + 1);
        assert!(MemoryMap::multiboot2(&entries, 24).is_err());
        for stride in [0, 16, 20, 23, 25, usize::MAX] {
            assert!(MemoryMap::multiboot2(&region(0x100000, 4096, 1), stride).is_err());
        }
        assert!(MemoryMap::multiboot2(&[0; 23], 24).is_err());
    }

    #[test]
    fn multiboot2_prefers_valid_extended_rsdp_and_ignores_unknown_tags() {
        let bytes = mb2(&[(7, vec![1, 2, 3]), (14, rsdp(0)), (15, rsdp(2))]);
        let parsed = parse_multiboot2(&bytes).unwrap();
        assert!(parsed.map.covers(0x100000, 0x2000000, false));
        assert_eq!(
            parse_rsdp(parsed.rsdp.unwrap()).unwrap(),
            Root {
                address: 0x7ff1000,
                stride: 8
            }
        );
    }

    #[test]
    fn multiboot2_rejects_duplicate_map_and_live_efi_services() {
        let valid = mb2(&[]);
        assert!(parse_multiboot2(&mb2(&[(6, valid[16..48].to_vec())])).is_err());
        assert!(parse_multiboot2(&mb2(&[(18, vec![])])).is_err());
        assert!(parse_multiboot2(&mb2(&[(14, rsdp(0)), (14, rsdp(0))])).is_err());
    }

    #[test]
    fn multiboot2_rejects_every_truncation_missing_end_and_bad_tag_size() {
        let valid = mb2(&[(15, rsdp(2))]);
        for length in 0..valid.len() {
            assert!(parse_multiboot2(&valid[..length]).is_err());
        }
        let mut missing = valid.clone();
        missing.truncate(missing.len() - 8);
        let length = missing.len() as u32;
        missing[..4].copy_from_slice(&length.to_le_bytes());
        assert!(parse_multiboot2(&missing).is_err());
        for bad_size in [0u32, 7, u32::MAX] {
            let mut bytes = valid.clone();
            bytes[12..16].copy_from_slice(&bad_size.to_le_bytes());
            assert!(parse_multiboot2(&bytes).is_err());
        }
    }

    #[test]
    fn rsdp_validates_both_checksums_and_extended_length() {
        let valid = rsdp(2);
        for length in 0..valid.len() {
            assert!(parse_rsdp(&valid[..length]).is_err());
        }
        let mut broken = valid.clone();
        broken[10] ^= 1;
        assert!(parse_rsdp(&broken).is_err());
        broken = valid.clone();
        broken[30] ^= 1;
        assert!(parse_rsdp(&broken).is_err());
        broken = valid;
        broken[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_rsdp(&broken).is_err());
        assert_eq!(parse_rsdp(&rsdp(0)).unwrap().stride, 4);
    }

    fn hpet() -> Vec<u8> {
        let mut bytes = vec![0; 56];
        bytes[..4].copy_from_slice(b"HPET");
        bytes[4..8].copy_from_slice(&56u32.to_le_bytes());
        bytes[44..52].copy_from_slice(&0xfed00000u64.to_le_bytes());
        finish_checksum(&mut bytes, 9);
        bytes
    }

    #[test]
    fn hpet_rejects_bad_checksum_io_space_and_cached_or_unmapped_addresses() {
        let valid = hpet();
        assert_eq!(parse_hpet(&valid).unwrap(), 0xfed00000);
        for length in 0..valid.len() {
            assert!(parse_hpet(&valid[..length]).is_err());
        }
        let mut bad = valid.clone();
        bad[9] ^= 1;
        assert!(parse_hpet(&bad).is_err());
        for (field, value) in [(40, 1), (41, 32), (42, 1), (43, 3)] {
            bad = valid.clone();
            bad[field] = value;
            finish_checksum(&mut bad, 9);
            assert!(parse_hpet(&bad).is_err());
        }
        for address in [0u64, 0x200000, 0xfed00001, 0x1_0000_0000, u64::MAX] {
            bad = valid.clone();
            bad[44..52].copy_from_slice(&address.to_le_bytes());
            finish_checksum(&mut bad, 9);
            assert!(parse_hpet(&bad).is_err());
        }
    }

    #[test]
    fn physical_range_rejects_null_overflow_and_kernel_aliases_without_dereference() {
        let kernel = KernelRange {
            start: 0x100000,
            end: 0x800000,
        };
        for (address, length) in [
            (0, 1),
            (4095, 1),
            (RAM_MAP_END - 8, 16),
            (u64::MAX, 2),
            (0x100000, 4096),
            (0xff000, 8192),
            (4096, 0),
        ] {
            assert!(physical_bytes(address, length, kernel).is_err());
        }
    }
}
