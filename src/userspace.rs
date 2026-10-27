//! Fixed, isolated ELF processes with timer-preempted user execution.
//!
//! Each process has its own CR3, private physical backing, and identical user
//! virtual window. Supervisor mappings are shared. Only the driver capability
//! receives extra device mappings; checked IPC/syscall copies never accept them.

use core::arch::{asm, x86_64::__cpuid};
use core::marker::PhantomData;
use core::ptr::{
    addr_of, addr_of_mut, copy_nonoverlapping, read_volatile, write_bytes, write_volatile,
};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::Context;

pub const USER_BASE: u64 = 0x4000_0000;
pub const USER_END: u64 = 0x4020_0000;
pub const STACK_BOTTOM: u64 = USER_END - 64 * 1024;
pub const PROCESS_COUNT: usize = 3;
pub const DRIVER_SLOT: usize = 2;
pub const DEVICE_MMIO: u64 = 0x5000_0000;
pub const DEVICE_DMA: u64 = 0x5020_0000;
#[cfg_attr(
    any(feature = "userspace-test", feature = "fuzz-test"),
    allow(dead_code)
)]
const MMIO_LENGTH: usize = 128 * 1024;
const STACK_GUARD: u64 = STACK_BOTTOM - PAGE_SIZE as u64;
const REGION_SIZE: usize = (USER_END - USER_BASE) as usize;
const PAGE_SIZE: usize = 4096;
const PAGE_COUNT: usize = REGION_SIZE / PAGE_SIZE;
const MAX_SEGMENTS: usize = 16;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
#[cfg_attr(
    any(feature = "userspace-test", feature = "fuzz-test"),
    allow(dead_code)
)]
const UNCACHED: u64 = (1 << 3) | (1 << 4);
const NO_EXECUTE: u64 = 1 << 63;
const PF_EXECUTE: u32 = 1;
const PF_WRITE: u32 = 2;
const PF_READ: u32 = 4;

// FXSAVE64 covers x87/MMX, MXCSR, and XMM0..15. OSXSAVE stays clear, so
// userspace cannot execute AVX/XSAVE instructions with unsaved wider state.
#[repr(C, align(16))]
struct ExtendedState([u8; 512]);

impl ExtendedState {
    const fn clean() -> Self {
        let mut bytes = [0; 512];
        bytes[0] = 0x7f; // x87 control word: masked exceptions, extended precision.
        bytes[1] = 0x03;
        bytes[24] = 0x80; // MXCSR = 0x1f80, masked exceptions, nearest rounding.
        bytes[25] = 0x1f;
        Self(bytes)
    }
}

static KERNEL_EXTENDED_STATE: ExtendedState = ExtendedState::clean();
static EXTENDED_READY: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct DeviceMapping {
    physical: u64,
    length: usize,
}

impl DeviceMapping {
    const EMPTY: Self = Self {
        physical: 0,
        length: 0,
    };
}

// Every table starts on a page boundary: the backing is 2 MiB and every table
// is exactly 4 KiB. Metadata follows the tables in a separate supervisor page.
#[repr(C, align(4096))]
struct Storage {
    backing: [u8; REGION_SIZE],
    pml4: [u64; PAGE_COUNT],
    pdpt: [u64; PAGE_COUNT],
    directory: [u64; PAGE_COUNT],
    user: [u64; PAGE_COUNT],
    mmio: [u64; PAGE_COUNT],
    dma: [u64; PAGE_COUNT],
    devices: [DeviceMapping; 2],
    extended: ExtendedState,
}

impl Storage {
    const EMPTY: Self = Self {
        backing: [0; REGION_SIZE],
        pml4: [0; PAGE_COUNT],
        pdpt: [0; PAGE_COUNT],
        directory: [0; PAGE_COUNT],
        user: [0; PAGE_COUNT],
        mmio: [0; PAGE_COUNT],
        dma: [0; PAGE_COUNT],
        devices: [DeviceMapping::EMPTY; 2],
        // Keep the whole multi-megabyte allocation in BSS; restart installs
        // the clean nonzero control words before the process can be resumed.
        extended: ExtendedState([0; 512]),
    };
}

static mut STORAGE: [Storage; PROCESS_COUNT] = [const { Storage::EMPTY }; PROCESS_COUNT];
static CLAIMED: [AtomicBool; PROCESS_COUNT] = [const { AtomicBool::new(false) }; PROCESS_COUNT];

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
    slot: usize,
    image: &'static [u8],
    entry: u64,
    segments: [Segment; MAX_SEGMENTS],
    segment_count: usize,
    // Page tables and resume state belong to the single boot CPU.
    _single_cpu: PhantomData<*mut ()>,
}

impl Process {
    /// Compatibility entry for the web process and original isolation tests.
    #[cfg(feature = "userspace-test")]
    pub fn load(image: &'static [u8]) -> Result<Self, &'static str> {
        Self::load_slot(image, 0)
    }

    /// Load a process into its fixed slot and activate its address space.
    /// Slots 0, 1, and 2 belong to the web, network, and driver processes.
    pub fn load_slot(image: &'static [u8], slot: usize) -> Result<Self, &'static str> {
        if slot >= PROCESS_COUNT {
            return Err("invalid process slot");
        }
        let (entry, segments, segment_count) = parse_elf(image)?;
        let extended = __cpuid(0x8000_0000);
        if extended.eax < 0x8000_0001 || __cpuid(0x8000_0001).edx & (1 << 20) == 0 {
            return Err("CPU does not support execute-disable pages");
        }
        initialize_extended_state()?;
        let storage = storage(slot);
        if storage as u64 + size_of::<Storage>() as u64 > USER_BASE {
            return Err("process storage is outside supervisor RAM");
        }
        CLAIMED[slot]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "process slot is already occupied")?;

        let mut process = Self {
            context: Context::user(entry, USER_END - 8, 0),
            slot,
            image,
            entry,
            segments,
            segment_count,
            _single_cpu: PhantomData,
        };
        // SAFETY: this process exclusively owns its claimed storage. It has
        // never run, and the sole CPU keeps IF clear during kernel operations.
        unsafe { process.install_mapping() };
        process.restart(0);
        process.activate();
        Ok(process)
    }

    /// Install this process's private CR3 before `arch::resume`.
    pub fn activate(&self) {
        // SAFETY: all roots share the same resident supervisor mappings, so
        // the current kernel stack and this object survive the CR3 change.
        unsafe {
            switch_root(addr_of!((*storage(self.slot)).pml4) as u64);
            restore_extended(addr_of!((*storage(self.slot)).extended));
        }
    }

    /// Save all user x87/MMX/SSE state immediately after `arch::resume`.
    /// The kernel target emits no floating-point/SIMD instructions, so saving
    /// before `activate_kernel` preserves the exact state at the user trap.
    #[cfg_attr(
        any(feature = "userspace-test", feature = "fuzz-test"),
        allow(dead_code)
    )]
    pub fn save_extended_state(&mut self) {
        // SAFETY: the slot belongs to this process and remains resident.
        let root = unsafe { addr_of!((*storage(self.slot)).pml4) as u64 };
        assert_eq!(active_root(), root, "save user state before switching CR3");
        // SAFETY: this process owns the aligned supervisor-only image. The
        // scheduler calls this for the process whose registers are live.
        unsafe {
            asm!("fxsave64 [{}]", in(reg) addr_of_mut!((*storage(self.slot)).extended),
                options(nostack, preserves_flags));
        }
    }

    /// Restore initialized data, clear BSS and stack, and reset all registers.
    /// Device mappings and the currently selected CR3 are not changed.
    pub fn restart(&mut self, arg: u64) {
        let backing = self.backing();
        // SAFETY: only this process owns its backing. No user code runs while
        // this single CPU executes kernel code with IF clear. ELF ranges were
        // validated when the process was constructed.
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
        // Reset extended registers too, including physical x87 register bytes
        // whose tags are empty, so process restarts cannot retain old secrets.
        unsafe {
            copy_nonoverlapping(
                addr_of!(KERNEL_EXTENDED_STATE),
                addr_of_mut!((*storage(self.slot)).extended),
                1,
            );
            if active_root() == addr_of!((*storage(self.slot)).pml4) as u64 {
                restore_extended(addr_of!(KERNEL_EXTENDED_STATE));
            }
        }
        self.context = Context::user(self.entry, USER_END - 8, arg);
    }

    /// Map the resources assigned exclusively to the driver process.
    ///
    /// # Safety
    /// The physical interval must belong exclusively to this driver as device
    /// MMIO or a DMA allocation, with no live Rust references aliasing it. The
    /// caller must configure DMA isolation before allowing untrusted driver
    /// execution. Mapping arbitrary kernel RAM would violate kernel isolation.
    /// Call on the boot CPU with IF clear, before resuming the driver.
    #[cfg_attr(
        any(feature = "userspace-test", feature = "fuzz-test"),
        allow(dead_code)
    )]
    pub unsafe fn map_device(
        &mut self,
        virtual_addr: u64,
        physical: u64,
        length: usize,
        uncached: bool,
    ) -> Result<(), &'static str> {
        if self.slot != DRIVER_SLOT {
            return Err("device mappings require the driver slot");
        }
        if length == 0
            || !length.is_multiple_of(PAGE_SIZE)
            || !physical.is_multiple_of(PAGE_SIZE as u64)
        {
            return Err("device ranges must contain aligned whole pages");
        }
        let Some(end) = physical.checked_add(length as u64) else {
            return Err("device physical range overflow");
        };
        let index = match virtual_addr {
            DEVICE_MMIO
                if length == MMIO_LENGTH
                    && uncached
                    && physical >= USER_BASE
                    && end <= 1u64 << 32 =>
            {
                0
            }
            DEVICE_DMA
                if length <= REGION_SIZE
                    && !uncached
                    && physical >= 0x100000
                    && end <= USER_BASE =>
            {
                1
            }
            _ => return Err("unsupported driver device mapping"),
        };
        let store = storage(self.slot);
        // SAFETY: exclusive process storage and caller-owned physical pages.
        // Each fixed virtual interval occupies its own 2 MiB PDE. Unused PTEs
        // remain absent; mappings are one-shot and cannot overlap ELF pages.
        unsafe {
            let existing = addr_of!((*store).devices)
                .cast::<DeviceMapping>()
                .add(index)
                .read();
            if existing.length != 0 {
                return if existing.physical == physical && existing.length == length {
                    Ok(()) // The same exclusive resource may be reconfigured after restart.
                } else {
                    Err("driver resource is already mapped differently")
                };
            }
            let table = if index == 0 {
                addr_of_mut!((*store).mmio).cast::<u64>()
            } else {
                addr_of_mut!((*store).dma).cast::<u64>()
            };
            let flags =
                PRESENT | WRITABLE | USER | NO_EXECUTE | if uncached { UNCACHED } else { 0 };
            for page in 0..length / PAGE_SIZE {
                write_volatile(
                    table.add(page),
                    (physical + (page * PAGE_SIZE) as u64) | flags,
                );
            }
            let pde = ((virtual_addr >> 21) & 511) as usize;
            write_volatile(
                addr_of_mut!((*store).directory).cast::<u64>().add(pde),
                table as u64 | PRESENT | WRITABLE | USER | NO_EXECUTE,
            );
            addr_of_mut!((*store).devices)
                .cast::<DeviceMapping>()
                .add(index)
                .write(DeviceMapping { physical, length });
            // Flush only when this process is active; a future CR3 switch will
            // flush the translation if another process is currently selected.
            let root = addr_of!((*store).pml4) as u64;
            if active_root() == root {
                switch_root(root);
            }
        }
        Ok(())
    }

    /// Check only private user pages; device ranges are never copy buffers.
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
        let table = self.user_table();
        (first..=last).all(|page| {
            // SAFETY: range checks constrain the index to this process's PT.
            unsafe { read_volatile(table.add(page)) & required == required }
        })
    }

    pub fn copy_from_user(&self, address: u64, dst: &mut [u8]) -> Result<(), &'static str> {
        if !self.validate_buffer(address, dst.len(), false) {
            return Err("invalid userspace source buffer");
        }
        // SAFETY: validated pages have private backing at this offset. Safe
        // kernel slices cannot alias the private static storage of a process.
        unsafe {
            copy_nonoverlapping(
                self.backing().add((address - USER_BASE) as usize),
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
        // SAFETY: validation also requires writable user leaves; the active
        // process need not be this one because copies use supervisor aliases.
        unsafe {
            copy_nonoverlapping(
                src.as_ptr(),
                self.backing().add((address - USER_BASE) as usize),
                src.len(),
            );
        }
        Ok(())
    }

    fn backing(&self) -> *mut u8 {
        // SAFETY: load_slot validated the slot and claims it exclusively.
        unsafe { addr_of_mut!((*storage(self.slot)).backing).cast::<u8>() }
    }

    fn user_table(&self) -> *mut u64 {
        // SAFETY: as above; the field is exactly one page and is page aligned.
        unsafe { addr_of_mut!((*storage(self.slot)).user).cast::<u64>() }
    }

    unsafe fn install_mapping(&self) {
        let store = storage(self.slot);
        let backing = self.backing() as u64;
        let table = self.user_table();
        // SAFETY: this is the sole owner of newly claimed static storage. The
        // supervisor map is copied from the immutable boot root, never from a
        // previously active process. Only PDPT1 gets a private directory.
        unsafe {
            let pml4 = addr_of_mut!((*store).pml4).cast::<u64>();
            let pdpt = addr_of_mut!((*store).pdpt).cast::<u64>();
            let directory = addr_of_mut!((*store).directory).cast::<u64>();
            copy_nonoverlapping(addr_of!(boot_pml4).cast::<u64>(), pml4, PAGE_COUNT);
            copy_nonoverlapping(addr_of!(boot_pdpt).cast::<u64>(), pdpt, PAGE_COUNT);
            copy_nonoverlapping(
                addr_of!(boot_page_directory).cast::<u64>().add(PAGE_COUNT),
                directory,
                PAGE_COUNT,
            );
            write_volatile(pml4, pdpt as u64 | PRESENT | WRITABLE | USER);
            write_volatile(pdpt.add(1), directory as u64 | PRESENT | WRITABLE | USER);
            write_volatile(directory, table as u64 | PRESENT | WRITABLE | USER);
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
            // memory::init already enables NXE/WP; assert that before using NX.
            let efer: u32;
            let cr0: u64;
            asm!("rdmsr", in("ecx") 0xc000_0080u32, out("eax") efer, out("edx") _,
                options(nomem, nostack, preserves_flags));
            asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
            assert_ne!(
                efer & (1 << 11),
                0,
                "memory protection must precede process loading"
            );
            assert_ne!(
                cr0 & (1 << 16),
                0,
                "supervisor write protection is disabled"
            );
        }
    }
}

/// Return to the boot address space, which contains no user-accessible pages.
#[cfg_attr(
    any(feature = "userspace-test", feature = "fuzz-test"),
    allow(dead_code)
)]
pub fn activate_kernel() {
    // SAFETY: boot tables remain resident and share every supervisor mapping.
    unsafe {
        switch_root(addr_of!(boot_pml4) as u64);
        if EXTENDED_READY.load(Ordering::Acquire) {
            restore_extended(addr_of!(KERNEL_EXTENDED_STATE));
        }
    }
}

fn initialize_extended_state() -> Result<(), &'static str> {
    let features = __cpuid(1).edx;
    let required = (1 << 24) | (1 << 25) | (1 << 26); // FXSR, SSE, SSE2.
    if features & required != required {
        return Err("CPU must support FXSAVE and SSE2 context switching");
    }
    if !EXTENDED_READY.swap(true, Ordering::AcqRel) {
        // SAFETY: one boot CPU, kernel IF clear, before any userspace starts.
        // Preserve paging protections while enabling only the state we save.
        unsafe {
            let cr0: u64;
            let cr4: u64;
            asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
            let cr0 = (cr0 | (1 << 1) | (1 << 5)) & !((1 << 2) | (1 << 3));
            asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
            asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            let cr4 = (cr4 | (1 << 9) | (1 << 10)) & !(1 << 18);
            asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
            restore_extended(addr_of!(KERNEL_EXTENDED_STATE));
        }
    }
    Ok(())
}

unsafe fn restore_extended(state: *const ExtendedState) {
    // SAFETY: callers supply an aligned, initialized supervisor state image.
    // FXRSTOR does not require a live x87 stack and clears stale XMM contents.
    unsafe {
        asm!("fxrstor64 [{}]", in(reg) state, options(readonly, nostack, preserves_flags));
    }
}

fn storage(slot: usize) -> *mut Storage {
    assert!(slot < PROCESS_COUNT);
    // SAFETY: the checked index points into static process storage.
    unsafe { addr_of_mut!(STORAGE).cast::<Storage>().add(slot) }
}

pub(crate) fn active_root() -> u64 {
    let root: u64;
    // SAFETY: called only in ring 0 on the boot CPU.
    unsafe {
        asm!("mov {}, cr3", out(reg) root, options(nomem, nostack, preserves_flags));
    }
    root & ADDRESS
}

unsafe fn switch_root(root: u64) {
    // SAFETY: caller supplies a resident root sharing all active kernel memory.
    unsafe {
        asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
    }
}

pub(crate) fn slot_for_root(root: u64) -> Option<usize> {
    (0..PROCESS_COUNT).find(|&slot| {
        CLAIMED[slot].load(Ordering::Acquire)
            // SAFETY: slot lies within static storage; no field is dereferenced.
            && unsafe { addr_of!((*storage(slot)).pml4) as u64 == root }
    })
}

/// Audit helpers intentionally return only table identities and allowed page
/// ownership, never mutable references into another process's private RAM.
pub(crate) fn expected_pdpt(root: u64) -> Option<u64> {
    if root == addr_of!(boot_pml4) as u64 {
        return Some(addr_of!(boot_pdpt) as u64);
    }
    let slot = slot_for_root(root)?;
    // SAFETY: validated, claimed process storage.
    Some(unsafe { addr_of!((*storage(slot)).pdpt) as u64 })
}

pub(crate) fn expected_directory(root: u64, index: usize) -> Option<u64> {
    if index >= 4 {
        return None;
    }
    if root != addr_of!(boot_pml4) as u64 && index == 1 {
        let slot = slot_for_root(root)?;
        // SAFETY: validated, claimed process storage.
        return Some(unsafe { addr_of!((*storage(slot)).directory) as u64 });
    }
    expected_pdpt(root)?;
    // SAFETY: four consecutive page directories are reserved by the bootstrap.
    Some(unsafe {
        addr_of!(boot_page_directory)
            .cast::<u64>()
            .add(index * PAGE_COUNT) as u64
    })
}

pub(crate) fn allowed_user_page(
    root: u64,
    address: u64,
    physical: u64,
    writable: bool,
    executable: bool,
) -> bool {
    let Some(slot) = slot_for_root(root) else {
        return false;
    };
    let store = storage(slot);
    // SAFETY: only the kernel modifies metadata, with user execution stopped.
    unsafe {
        if (USER_BASE..USER_END).contains(&address) {
            return physical == addr_of!((*store).backing) as u64 + address - USER_BASE;
        }
        if slot != DRIVER_SLOT || !writable || executable {
            return false;
        }
        for (index, base) in [DEVICE_MMIO, DEVICE_DMA].into_iter().enumerate() {
            let mapping = addr_of!((*store).devices)
                .cast::<DeviceMapping>()
                .add(index)
                .read();
            if address >= base && address - base < mapping.length as u64 {
                return physical == mapping.physical + address - base;
            }
        }
    }
    false
}

/// Exercise real ring-3 memory and extended-register isolation, then restore
/// all three ELF images and initial contexts. Device mappings survive intact.
/// The boot test calls this after assigning the driver's resources, before
/// giving any process its service startup arguments.
#[cfg(feature = "isolation-test")]
pub fn check_isolation(web: &mut Process, network: &mut Process, driver: &mut Process) {
    let mut processes = [web, network, driver];
    let address = STACK_BOTTOM;
    let mut roots = [0; PROCESS_COUNT];
    let mut physical = [0; PROCESS_COUNT];
    for (index, process) in processes.iter_mut().enumerate() {
        assert_eq!(
            process.slot, index,
            "isolation check requires all three slots"
        );
        process.restart(0);
        process
            .copy_to_user(address, &(0x1234_5678u64 + index as u64).to_le_bytes())
            .unwrap();
        process.activate();
        crate::memory::check_permissions();
        roots[index] = active_root();
        physical[index] = crate::memory::permissions(address).unwrap().physical;
        assert_eq!(
            crate::memory::permissions(DEVICE_MMIO).unwrap().user,
            index == DRIVER_SLOT
        );
        assert_eq!(
            crate::memory::permissions(DEVICE_DMA).unwrap().user,
            index == DRIVER_SLOT
        );
        assert!(!process.validate_buffer(DEVICE_MMIO, 1, false));
        assert!(!process.validate_buffer(DEVICE_DMA, 1, true));
    }
    for first in 0..PROCESS_COUNT {
        for second in first + 1..PROCESS_COUNT {
            assert_ne!(roots[first], roots[second], "process roots alias");
            assert_ne!(
                physical[first], physical[second],
                "private user pages alias"
            );
        }
    }
    // MOV RAX,[RDI]; INT80; UD2. The first pass reads each private virtual page;
    // the second must fault on another process's supervisor physical alias.
    const READ: &[u8] = &[0x48, 0x8b, 0x07, 0xcd, 0x80, 0x0f, 0x0b];
    for (index, process) in processes.iter_mut().enumerate() {
        let context = run_isolation_probe(process, READ, address);
        assert_eq!(context.vector, 128);
        assert_eq!(context.rax, 0x1234_5678 + index as u64);
        let other = physical[(index + 1) % PROCESS_COUNT];
        let context = run_isolation_probe(process, READ, other);
        assert_eq!(context.vector, 14, "cross-process physical read must fault");
        assert_eq!(context.error_code & 5, 5);
        assert_eq!(context.cr2, other);
    }

    // Load distinct XMM0/XMM15, x87 ST0/control word, and MXCSR values from
    // private memory, saving their exact state on each user trap.
    const LOAD_FP: &[u8] = &[
        0xf3, 0x0f, 0x6f, 0x07, // movdqu xmm0,[rdi]
        0xf3, 0x44, 0x0f, 0x6f, 0x7f, 0x10, // movdqu xmm15,[rdi+16]
        0xdd, 0x47, 0x20, // fld qword [rdi+32]
        0xd9, 0x6f, 0x28, // fldcw [rdi+40]
        0x0f, 0xae, 0x57, 0x2c, // ldmxcsr [rdi+44]
        0xcd, 0x80, 0x0f, 0x0b,
    ];
    const STORE_FP: &[u8] = &[
        0xf3, 0x0f, 0x7f, 0x07, // movdqu [rdi],xmm0
        0xf3, 0x44, 0x0f, 0x7f, 0x7f, 0x10, // movdqu [rdi+16],xmm15
        0xdd, 0x57, 0x20, // fst qword [rdi+32]
        0xd9, 0x7f, 0x28, // fnstcw [rdi+40]
        0x0f, 0xae, 0x5f, 0x2c, // stmxcsr [rdi+44]
        0xcd, 0x80, 0x0f, 0x0b,
    ];
    let mut expected = [[0u8; 48]; PROCESS_COUNT];
    for (index, process) in processes.iter_mut().enumerate() {
        let input = &mut expected[index];
        input[..16].fill(0x11 + index as u8);
        input[16..32].fill(0x91 + index as u8);
        let value = [
            0x3ff0_0000_0000_0000u64,
            0x4000_0000_0000_0000,
            0x4010_0000_0000_0000,
        ][index];
        input[32..40].copy_from_slice(&value.to_le_bytes());
        input[40..42].copy_from_slice(&(0x037fu16 | ((index as u16) << 10)).to_le_bytes());
        input[44..48].copy_from_slice(&(0x1f80u32 | ((index as u32) << 13)).to_le_bytes());
        process.copy_to_user(address + 128, input).unwrap();
        assert_eq!(
            run_isolation_probe(process, LOAD_FP, address + 128).vector,
            128
        );
        check_kernel_extended_state();
    }
    for index in [2, 0, 1, 2, 1, 0] {
        let process = &mut processes[index];
        assert_eq!(
            run_isolation_probe(process, STORE_FP, address + 256).vector,
            128
        );
        let mut actual = [0; 48];
        process.copy_from_user(address + 256, &mut actual).unwrap();
        assert_eq!(
            actual, expected[index],
            "extended registers crossed process boundary"
        );
        check_kernel_extended_state();
    }
    // VZEROUPPER must #UD: wider AVX state is deliberately not enabled/saved.
    let context = run_isolation_probe(processes[0], &[0xc5, 0xf8, 0x77, 0xcd, 0x80], 0);
    assert_eq!(context.vector, 6, "AVX must remain unavailable");
    for process in processes {
        process.restart(0);
    }
    activate_kernel();
    crate::memory::check_permissions();
    check_kernel_extended_state();
}

#[cfg(feature = "isolation-test")]
fn run_isolation_probe(process: &mut Process, code: &[u8], argument: u64) -> Context {
    assert!(
        process.segments[..process.segment_count]
            .iter()
            .any(|segment| {
                segment.flags & PF_EXECUTE != 0
                    && process.entry >= segment.address
                    && process.entry + code.len() as u64
                        <= segment.address + segment.file_size as u64
            }),
        "ELF entry has insufficient executable bytes for isolation probe"
    );
    // SAFETY: test code replaces only this process's executable backing while
    // it is stopped; restart restores the original embedded ELF afterwards.
    unsafe {
        copy_nonoverlapping(
            code.as_ptr(),
            process.backing().add((process.entry - USER_BASE) as usize),
            code.len(),
        );
    }
    process.context = Context::user(process.entry, USER_END - 8, argument);
    for _ in 0..1000 {
        process.activate();
        // SAFETY: the process owns its mappings; IDT/TSS and timer are ready.
        unsafe {
            crate::arch::resume(&mut process.context);
        }
        process.save_extended_state();
        activate_kernel();
        if process.context.vector != crate::arch::TIMER_VECTOR {
            return process.context;
        }
    }
    panic!("isolation probe made no progress");
}

#[cfg(feature = "isolation-test")]
fn check_kernel_extended_state() {
    let mut state = ExtendedState::clean();
    let cr0: u64;
    let cr4: u64;
    // SAFETY: valid aligned supervisor buffer; CPU extended-state support was
    // configured before loading any process. This saves but does not mutate it.
    unsafe {
        asm!("fxsave64 [{}]", in(reg) &mut state, options(nostack, preserves_flags));
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    assert_eq!(cr0 & ((1 << 2) | (1 << 3)), 0);
    assert_eq!(
        cr4 & ((1 << 9) | (1 << 10) | (1 << 18)),
        (1 << 9) | (1 << 10)
    );
    assert_eq!(
        &state.0[..5],
        &[0x7f, 0x03, 0, 0, 0],
        "kernel x87 state was poisoned"
    );
    assert_eq!(
        &state.0[24..28],
        &[0x80, 0x1f, 0, 0],
        "kernel MXCSR was poisoned"
    );
    for register in 0..8 {
        assert!(
            state.0[32 + register * 16..42 + register * 16]
                .iter()
                .all(|&byte| byte == 0),
            "kernel retained x87 register contents"
        );
    }
    assert!(
        state.0[160..416].iter().all(|&byte| byte == 0),
        "kernel retained XMM contents"
    );
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
