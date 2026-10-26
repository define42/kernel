//! One isolated ELF process with timer-preempted user execution.
//!
//! Only this process's 2 MiB virtual window has user-accessible leaf entries.
//! Its physical backing stays accessible through the supervisor identity map,
//! which the kernel uses for checked copies and for resetting the process.

use core::arch::{asm, x86_64::__cpuid};
use core::marker::PhantomData;
use core::ptr::{addr_of_mut, copy_nonoverlapping, read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::Context;

pub const USER_BASE: u64 = 0x4000_0000;
pub const USER_END: u64 = 0x4020_0000;
pub const STACK_BOTTOM: u64 = USER_END - 64 * 1024;
const STACK_GUARD: u64 = STACK_BOTTOM - PAGE_SIZE as u64;
const REGION_SIZE: usize = (USER_END - USER_BASE) as usize;
const PAGE_SIZE: usize = 4096;
const PAGE_COUNT: usize = REGION_SIZE / PAGE_SIZE;
const MAX_SEGMENTS: usize = 16;

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const NO_EXECUTE: u64 = 1 << 63;
const PF_EXECUTE: u32 = 1;
const PF_WRITE: u32 = 2;
const PF_READ: u32 = 4;

#[repr(C, align(4096))]
struct Backing([u8; REGION_SIZE]);
#[repr(C, align(4096))]
struct PageTable([u64; PAGE_COUNT]);

static mut BACKING: Backing = Backing([0; REGION_SIZE]);
static mut PAGE_TABLE: PageTable = PageTable([0; PAGE_COUNT]);
static CLAIMED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    static mut boot_pml4: [u64; 512];
    static mut boot_pdpt: [u64; 512];
    static mut boot_page_directory: [u64; 2048];
}

#[derive(Clone, Copy)]
struct Segment {
    address: u64,
    offset: usize,
    file_size: usize,
    memory_size: usize,
    flags: u32,
}

impl Segment {
    const EMPTY: Self = Self {
        address: 0,
        offset: 0,
        file_size: 0,
        memory_size: 0,
        flags: 0,
    };

    fn first_page(self) -> usize {
        (self.address - USER_BASE) as usize / PAGE_SIZE
    }

    fn end_page(self) -> usize {
        self.first_page() + self.memory_size.div_ceil(PAGE_SIZE)
    }
}

pub struct Process {
    pub context: Context,
    image: &'static [u8],
    entry: u64,
    segments: [Segment; MAX_SEGMENTS],
    segment_count: usize,
    // Page tables and resume state belong to the single boot CPU.
    _single_cpu: PhantomData<*mut ()>,
}

impl Process {
    pub fn load(image: &'static [u8]) -> Result<Self, &'static str> {
        let (entry, segments, segment_count) = parse_elf(image)?;
        // Long mode requires CPUID, checked by the bootstrap.
        let extended = __cpuid(0x8000_0000);
        if extended.eax < 0x8000_0001 || __cpuid(0x8000_0001).edx & (1 << 20) == 0 {
            return Err("CPU does not support execute-disable pages");
        }
        let backing = addr_of_mut!(BACKING).cast::<u8>() as u64;
        let table = addr_of_mut!(PAGE_TABLE).cast::<u64>() as u64;
        if backing + REGION_SIZE as u64 > USER_BASE || table + PAGE_SIZE as u64 > USER_BASE {
            return Err("userspace backing is outside supervisor RAM");
        }
        CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "only one userspace process is supported")?;

        let mut process = Self {
            context: Context::user(entry, USER_END - 8, 0),
            image,
            entry,
            segments,
            segment_count,
            _single_cpu: PhantomData,
        };
        // SAFETY: CLAIMED gives this process exclusive ownership of the static
        // storage. The CPU has not entered userspace and interrupts are off.
        unsafe { process.install_mapping() };
        process.restart(0);
        Ok(process)
    }

    /// Restore initialized data, clear BSS and stack, and reset all registers.
    /// The caller must have regained control from `arch::resume` first.
    pub fn restart(&mut self, arg: u64) {
        let backing = addr_of_mut!(BACKING).cast::<u8>();
        // SAFETY: this process exclusively owns BACKING, and no user code runs
        // concurrently while this single CPU runs kernel code with IF clear. Ranges were
        // validated before the process was constructed.
        unsafe {
            write_bytes(backing, 0, REGION_SIZE);
            for segment in &self.segments[..self.segment_count] {
                copy_nonoverlapping(
                    self.image.as_ptr().add(segment.offset),
                    backing.add((segment.address - USER_BASE) as usize),
                    segment.file_size,
                );
            }
        }
        self.context = Context::user(self.entry, USER_END - 8, arg);
    }

    /// Check every touched page, including permissions for output buffers.
    pub fn validate_buffer(&self, address: u64, len: usize, write: bool) -> bool {
        let Some(end) = address.checked_add(len as u64) else {
            return false;
        };
        if address < USER_BASE || end > USER_END {
            return false;
        }
        if len == 0 {
            return true;
        }
        let first = ((address - USER_BASE) / PAGE_SIZE as u64) as usize;
        let last = ((end - 1 - USER_BASE) / PAGE_SIZE as u64) as usize;
        let required = PRESENT | USER | if write { WRITABLE } else { 0 };
        let table = addr_of_mut!(PAGE_TABLE).cast::<u64>();
        (first..=last).all(|page| {
            // SAFETY: the bounds above constrain the index to this process's
            // page table. Only the kernel writes it, before the process starts.
            unsafe { read_volatile(table.add(page)) & required == required }
        })
    }

    pub fn copy_from_user(&self, address: u64, dst: &mut [u8]) -> Result<(), &'static str> {
        if !self.validate_buffer(address, dst.len(), false) {
            return Err("invalid userspace source buffer");
        }
        // SAFETY: checked user pages have backing at the corresponding offset.
        // This supervisor alias cannot fault on user permissions. Safe kernel
        // slices cannot alias our private static backing.
        unsafe {
            copy_nonoverlapping(
                addr_of_mut!(BACKING)
                    .cast::<u8>()
                    .add((address - USER_BASE) as usize),
                dst.as_mut_ptr(),
                dst.len(),
            );
        }
        Ok(())
    }

    pub fn copy_to_user(&mut self, address: u64, src: &[u8]) -> Result<(), &'static str> {
        if !self.validate_buffer(address, src.len(), true) {
            return Err("invalid userspace destination buffer");
        }
        // SAFETY: as above; validation also requires writable user leaf pages.
        unsafe {
            copy_nonoverlapping(
                src.as_ptr(),
                addr_of_mut!(BACKING)
                    .cast::<u8>()
                    .add((address - USER_BASE) as usize),
                src.len(),
            );
        }
        Ok(())
    }

    unsafe fn install_mapping(&self) {
        let backing = addr_of_mut!(BACKING).cast::<u8>() as u64;
        let table = addr_of_mut!(PAGE_TABLE).cast::<u64>();
        // SAFETY: all static tables are page aligned in supervisor RAM. The
        // bootstrap's first four PDPT entries cover 4 GiB with 2 MiB leaves.
        // Replacing PDE 512 only changes [1 GiB, 1 GiB + 2 MiB). Setting U/S
        // on its ancestors does not expose other supervisor leaf entries.
        unsafe {
            write_bytes(table, 0, PAGE_COUNT);
            for segment in &self.segments[..self.segment_count] {
                let mut flags = PRESENT | USER;
                if segment.flags & PF_WRITE != 0 {
                    flags |= WRITABLE;
                }
                if segment.flags & PF_EXECUTE == 0 {
                    flags |= NO_EXECUTE;
                }
                for page in segment.first_page()..segment.end_page() {
                    write_volatile(
                        table.add(page),
                        (backing + (page * PAGE_SIZE) as u64) | flags,
                    );
                }
            }
            for page in ((STACK_BOTTOM - USER_BASE) as usize / PAGE_SIZE)..PAGE_COUNT {
                write_volatile(
                    table.add(page),
                    (backing + (page * PAGE_SIZE) as u64) | PRESENT | USER | WRITABLE | NO_EXECUTE,
                );
            }

            let efer_low: u32;
            let efer_high: u32;
            asm!(
                "rdmsr", in("ecx") 0xc000_0080u32,
                out("eax") efer_low, out("edx") efer_high,
                options(nomem, nostack, preserves_flags)
            );
            asm!(
                "wrmsr", in("ecx") 0xc000_0080u32,
                in("eax") efer_low | (1 << 11), in("edx") efer_high,
                options(nomem, nostack, preserves_flags)
            );
            let pml4 = addr_of_mut!(boot_pml4).cast::<u64>();
            let pdpt = addr_of_mut!(boot_pdpt).cast::<u64>();
            let directory = addr_of_mut!(boot_page_directory).cast::<u64>();
            write_volatile(pml4, read_volatile(pml4) | USER);
            write_volatile(pdpt.add(1), read_volatile(pdpt.add(1)) | USER);
            write_volatile(directory.add(512), table as u64 | PRESENT | WRITABLE | USER);

            let cr0: u64;
            asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
            asm!("mov cr0, {}", in(reg) cr0 | (1 << 16), options(nostack, preserves_flags));
            let cr3: u64;
            asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
            // Flush the former huge-page translation and updated ancestors.
            asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
        }
    }
}

fn parse_elf(image: &[u8]) -> Result<(u64, [Segment; MAX_SEGMENTS], usize), &'static str> {
    if image.len() < 64
        || &image[..7] != b"\x7fELF\x02\x01\x01"
        || u16_at(image, 16)? != 2
        || u16_at(image, 18)? != 62
        || u32_at(image, 20)? != 1
        || u16_at(image, 52)? != 64
        || u16_at(image, 54)? != 56
    {
        return Err("userspace image must be a static ELF64 x86-64 executable");
    }
    let entry = u64_at(image, 24)?;
    let phoff = usize::try_from(u64_at(image, 32)?).map_err(|_| "ELF offset overflow")?;
    let count = usize::from(u16_at(image, 56)?);
    if count == 0 || count > MAX_SEGMENTS {
        return Err("invalid ELF program header count");
    }
    let table_end = phoff
        .checked_add(count * 56)
        .ok_or("ELF program header overflow")?;
    if table_end > image.len() {
        return Err("ELF program headers exceed image");
    }
    let mut segments = [Segment::EMPTY; MAX_SEGMENTS];
    let mut segment_count = 0;
    let mut executable_entry = false;
    for index in 0..count {
        let header = phoff + index * 56;
        let kind = u32_at(image, header)?;
        let flags = u32_at(image, header + 4)?;
        if kind == 2 || kind == 3 {
            return Err("dynamic userspace executables are unsupported");
        }
        if kind == 0x6474_e551 && flags & PF_EXECUTE != 0 {
            return Err("executable userspace stacks are forbidden");
        }
        if kind != 1 {
            continue;
        }
        let address = u64_at(image, header + 16)?;
        let offset =
            usize::try_from(u64_at(image, header + 8)?).map_err(|_| "ELF offset overflow")?;
        let file_size =
            usize::try_from(u64_at(image, header + 32)?).map_err(|_| "ELF file size overflow")?;
        let memory_size =
            usize::try_from(u64_at(image, header + 40)?).map_err(|_| "ELF memory size overflow")?;
        let alignment = u64_at(image, header + 48)?;
        if flags & !(PF_READ | PF_WRITE | PF_EXECUTE) != 0
            || flags & PF_READ == 0
            || flags & (PF_WRITE | PF_EXECUTE) == (PF_WRITE | PF_EXECUTE)
        {
            return Err("invalid ELF segment permissions");
        }
        if alignment != PAGE_SIZE as u64
            || !address.is_multiple_of(PAGE_SIZE as u64)
            || !offset.is_multiple_of(PAGE_SIZE)
        {
            return Err("ELF load segments must be page aligned");
        }
        let file_end = offset
            .checked_add(file_size)
            .ok_or("ELF segment file overflow")?;
        let memory_end = address
            .checked_add(memory_size as u64)
            .ok_or("ELF segment memory overflow")?;
        if file_size > memory_size || file_end > image.len() {
            return Err("ELF segment exceeds its backing image");
        }
        if address < USER_BASE || memory_end > STACK_GUARD {
            return Err("ELF segment exceeds userspace image window");
        }
        if memory_size == 0 {
            continue;
        }
        let segment = Segment {
            address,
            offset,
            file_size,
            memory_size,
            flags,
        };
        for previous in &segments[..segment_count] {
            if segment.first_page() < previous.end_page()
                && previous.first_page() < segment.end_page()
            {
                return Err("ELF segments share a page");
            }
        }
        if flags & PF_EXECUTE != 0 && entry >= address && entry < address + file_size as u64 {
            executable_entry = true;
        }
        segments[segment_count] = segment;
        segment_count += 1;
    }
    if !executable_entry {
        return Err("ELF entry is outside executable file bytes");
    }
    Ok((entry, segments, segment_count))
}

fn bytes_at<const N: usize>(image: &[u8], offset: usize) -> Result<[u8; N], &'static str> {
    let end = offset.checked_add(N).ok_or("ELF field offset overflow")?;
    image
        .get(offset..end)
        .ok_or("ELF field exceeds image")?
        .try_into()
        .map_err(|_| "ELF field has the wrong size")
}

fn u16_at(image: &[u8], offset: usize) -> Result<u16, &'static str> {
    Ok(u16::from_le_bytes(bytes_at(image, offset)?))
}
fn u32_at(image: &[u8], offset: usize) -> Result<u32, &'static str> {
    Ok(u32::from_le_bytes(bytes_at(image, offset)?))
}
fn u64_at(image: &[u8], offset: usize) -> Result<u64, &'static str> {
    Ok(u64::from_le_bytes(bytes_at(image, offset)?))
}
