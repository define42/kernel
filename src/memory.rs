//! Supervisor page permissions and optional CPU access protections.
//!
//! Bootstrap's broad identity map is only temporary. Before the network or
//! userspace starts, kernel text becomes read-only executable, rodata becomes
//! read-only non-executable, and every other mapped supervisor page becomes
//! writable non-executable. User copies use supervisor physical aliases, so
//! the kernel can keep SMAP enabled without opening access to user pointers.

use core::arch::{
    asm,
    x86_64::{__cpuid, __cpuid_count},
};
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

const PAGE_SIZE: u64 = 4096;
const HUGE_SIZE: u64 = 2 * 1024 * 1024;
const IDENTITY_END: u64 = 1 << 32;
const SPLIT_TABLES: usize = 16;
const KERNEL_LIMIT: u64 = SPLIT_TABLES as u64 * HUGE_SIZE;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const HUGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const SMEP: u64 = 1 << 20;
const SMAP: u64 = 1 << 21;

#[repr(C, align(4096))]
struct Tables([[u64; 512]; SPLIT_TABLES]);

static mut KERNEL_TABLES: Tables = Tables([[0; 512]; SPLIT_TABLES]);
static INITIALIZED: AtomicBool = AtomicBool::new(false);
// RET makes an execute probe return safely if NX were accidentally disabled.
#[cfg(feature = "userspace-test")]
static mut NX_PROBE: u8 = 0xc3;

unsafe extern "C" {
    static __kernel_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __kernel_end: u8;
    static boot_stack_guard: u8;
    static mut boot_page_directory: [u64; 2048];
}

#[derive(Clone, Copy, Debug)]
pub struct Capabilities {
    pub smep: bool,
    pub smap: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Permissions {
    pub physical: u64,
    pub writable: bool,
    pub user: bool,
    pub executable: bool,
}

/// Harden the bootstrap mapping after `arch::init`, while interrupts are off.
/// No userspace pages may have been installed yet.
pub fn init() -> Capabilities {
    assert!(
        !INITIALIZED.swap(true, Ordering::Relaxed),
        "memory initialized twice"
    );
    let flags: u64;
    // SAFETY: inspecting flags does not change CPU state.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    assert_eq!(
        flags & (1 << 9),
        0,
        "page-table setup requires interrupts disabled"
    );
    assert!(
        __cpuid(0x8000_0000).eax >= 0x8000_0001 && __cpuid(0x8000_0001).edx & (1 << 20) != 0,
        "CPU must support execute-disable pages"
    );
    let kernel_end = addr_of!(__kernel_end) as u64;
    assert!(
        kernel_end <= KERNEL_LIMIT,
        "kernel exceeds split-page-table capacity"
    );
    let split_count = kernel_end.div_ceil(HUGE_SIZE) as usize;
    let capabilities = capabilities();
    let guards = guard_pages();

    // SAFETY: arch::init has already installed writable GDT/TSS/IDT tables.
    // We are the only CPU, IF is clear, and every table is in resident kernel
    // RAM. NXE must be enabled before publishing entries containing NX.
    unsafe {
        let low: u32;
        let high: u32;
        asm!("rdmsr", in("ecx") 0xc000_0080u32, out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags));
        asm!("wrmsr", in("ecx") 0xc000_0080u32, in("eax") low | (1 << 11), in("edx") high,
            options(nomem, nostack, preserves_flags));

        let tables = addr_of_mut!(KERNEL_TABLES).cast::<u64>();
        let directory = addr_of_mut!(boot_page_directory).cast::<u64>();
        for index in 0..2048 {
            let entry = read_volatile(directory.add(index));
            assert_eq!(
                entry & (PRESENT | HUGE | USER),
                PRESENT | HUGE,
                "bootstrap map was changed before memory setup"
            );
            if index < split_count {
                let table = tables.add(index * 512);
                for page in 0..512 {
                    let address = index as u64 * HUGE_SIZE + page as u64 * PAGE_SIZE;
                    write_volatile(table.add(page), leaf_entry(address, &guards));
                }
                write_volatile(directory.add(index), table as u64 | PRESENT | WRITABLE);
            } else {
                // Preserve MMIO's uncacheable PAT selection and physical base.
                write_volatile(directory.add(index), entry | NX);
            }
        }
        let cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov cr0, {}", in(reg) cr0 | (1 << 16), options(nostack, preserves_flags));
        let cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        let protections =
            if capabilities.smep { SMEP } else { 0 } | if capabilities.smap { SMAP } else { 0 };
        // Clear AC before enabling SMAP; user traps clear it on every entry too.
        asm!("pushfq", "and qword ptr [rsp], -262145", "popfq");
        asm!("mov cr4, {}", in(reg) cr4 | protections, options(nostack, preserves_flags));
        flush_tlb();
    }
    check_permissions();
    capabilities
}

pub fn capabilities() -> Capabilities {
    let features = if __cpuid(0).eax >= 7 {
        __cpuid_count(7, 0).ebx
    } else {
        0
    };
    Capabilities {
        smep: features & (1 << 7) != 0,
        smap: features & (1 << 20) != 0,
    }
}

fn guard_pages() -> [u64; 3] {
    let [trap, double_fault] = crate::arch::guard_pages();
    [addr_of!(boot_stack_guard) as u64, trap, double_fault]
}

fn leaf_entry(address: u64, guards: &[u64; 3]) -> u64 {
    if address == 0 || guards.contains(&address) {
        return 0;
    }
    if (addr_of!(__kernel_start) as u64..addr_of!(__text_end) as u64).contains(&address) {
        address | PRESENT
    } else if (addr_of!(__rodata_start) as u64..addr_of!(__rodata_end) as u64).contains(&address) {
        address | PRESENT | NX
    } else {
        address | PRESENT | WRITABLE | NX
    }
}

/// Return the effective permissions of a page in the low 4 GiB map.
/// Intermediate U/S, R/W, and NX restrictions are included.
pub fn permissions(address: u64) -> Option<Permissions> {
    if address >= IDENTITY_END {
        return None;
    }
    let root = crate::userspace::active_root();
    assert!(
        crate::userspace::expected_pdpt(root).is_some(),
        "unknown address-space root"
    );
    // SAFETY: boot/process roots and their tables remain resident. Every root
    // shares the same protected supervisor identity mappings for these tables.
    unsafe {
        let pml4 = read_volatile(root as *const u64);
        if pml4 & PRESENT == 0 {
            return None;
        }
        let pdpt = read_volatile(((pml4 & ADDRESS) as *const u64).add((address >> 30) as usize));
        if pdpt & PRESENT == 0 {
            return None;
        }
        assert_eq!(pdpt & HUGE, 0, "unexpected 1 GiB mapping");
        let pde =
            read_volatile(((pdpt & ADDRESS) as *const u64).add(((address >> 21) & 511) as usize));
        if pde & PRESENT == 0 {
            return None;
        }
        let (leaf, offset) = if pde & HUGE != 0 {
            (pde, address & (HUGE_SIZE - 1))
        } else {
            let leaf = read_volatile(
                ((pde & ADDRESS) as *const u64).add(((address >> 12) & 511) as usize),
            );
            if leaf & PRESENT == 0 {
                return None;
            }
            (leaf, address & (PAGE_SIZE - 1))
        };
        Some(Permissions {
            physical: (leaf & ADDRESS & !(if pde & HUGE != 0 { HUGE_SIZE - 1 } else { 0 }))
                + offset,
            writable: (pml4 & pdpt & pde & leaf) & WRITABLE != 0,
            user: (pml4 & pdpt & pde & leaf) & USER != 0,
            executable: (pml4 | pdpt | pde | leaf) & NX == 0,
        })
    }
}

/// Audit actual page-table leaves, kernel section permissions, and CPU controls.
/// This checks the currently active kernel or process CR3, including ownership
/// of private user pages and the driver's narrowly assigned device mappings.
pub fn check_permissions() {
    assert!(INITIALIZED.load(Ordering::Relaxed));
    let cr0: u64;
    let cr4: u64;
    let low: u32;
    // SAFETY: these instructions only inspect privileged state on the boot CPU.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("rdmsr", in("ecx") 0xc000_0080u32, out("eax") low, out("edx") _,
            options(nomem, nostack, preserves_flags));
    }
    assert_ne!(
        cr0 & (1 << 16),
        0,
        "supervisor write protection is disabled"
    );
    assert_ne!(low & (1 << 11), 0, "execute disable is disabled");
    let features = capabilities();
    assert!(!features.smep || cr4 & SMEP != 0, "SMEP is disabled");
    assert!(!features.smap || cr4 & SMAP != 0, "SMAP is disabled");
    let guards = guard_pages();
    assert!(permissions(0).is_none(), "null page is mapped");
    for address in guards {
        assert!(permissions(address).is_none(), "stack guard is mapped");
    }

    // Confirm all intermediate tables belong to this exact address space;
    // other roots cannot borrow a process's private pages or device mappings.
    let root = crate::userspace::active_root();
    let expected_pdpt = crate::userspace::expected_pdpt(root).expect("unknown address-space root");
    audit_table(root);
    audit_table(expected_pdpt);
    // SAFETY: known static root/table identities are checked before following
    // them. All referenced tables remain supervisor-only, writable, and NX.
    unsafe {
        let pml4 = root as *const u64;
        let pdpt = expected_pdpt as *const u64;
        assert_eq!(read_volatile(pml4) & ADDRESS, expected_pdpt);
        for index in 1..512 {
            assert_eq!(read_volatile(pml4.add(index)) & PRESENT, 0);
        }
        for index in 0..512 {
            let entry = read_volatile(pdpt.add(index));
            if index >= 4 {
                assert_eq!(entry & PRESENT, 0);
                continue;
            }
            assert_ne!(entry & PRESENT, 0);
            assert_eq!(entry & HUGE, 0);
            let directory = crate::userspace::expected_directory(root, index)
                .expect("unknown process page directory");
            assert_eq!(entry & ADDRESS, directory);
            audit_table(directory);
            for offset in 0..512 {
                let entry = read_volatile((directory as *const u64).add(offset));
                if entry & PRESENT == 0 {
                    continue;
                }
                let base = (index * 512 + offset) as u64 * HUGE_SIZE;
                if entry & HUGE != 0 {
                    audit_leaf(base);
                    assert_eq!(entry & ADDRESS & !(HUGE_SIZE - 1), base);
                } else {
                    audit_table(entry & ADDRESS);
                    for page in 0..512 {
                        audit_leaf(base + page * PAGE_SIZE);
                    }
                }
            }
        }
    }
    for address in
        (addr_of!(__kernel_start) as u64..addr_of!(__kernel_end) as u64).step_by(PAGE_SIZE as usize)
    {
        let expected = leaf_entry(address, &guards);
        if expected == 0 {
            assert!(permissions(address).is_none());
            continue;
        }
        let actual = permissions(address).expect("kernel page is unmapped");
        assert_eq!(actual.physical, address, "kernel identity mapping changed");
        assert!(!actual.user, "kernel page is user accessible");
        assert_eq!(
            actual.writable,
            expected & WRITABLE != 0,
            "kernel write permissions differ"
        );
        assert_eq!(
            actual.executable,
            expected & NX == 0,
            "kernel execute permissions differ"
        );
    }
}

fn audit_table(physical: u64) {
    assert!(
        physical.is_multiple_of(PAGE_SIZE)
            && physical >= addr_of!(__data_start) as u64
            && physical + PAGE_SIZE <= addr_of!(__kernel_end) as u64,
        "page table is outside writable kernel memory"
    );
    let mapping = permissions(physical).expect("page table is unmapped");
    assert!(
        mapping.physical == physical && mapping.writable && !mapping.user && !mapping.executable,
        "page table is not supervisor RW/NX identity mapped"
    );
}

fn audit_leaf(address: u64) {
    let Some(page) = permissions(address) else {
        return;
    };
    assert!(
        !(page.writable && page.executable),
        "writable executable leaf found"
    );
    if page.user {
        assert!(
            crate::userspace::allowed_user_page(
                crate::userspace::active_root(),
                address,
                page.physical,
                page.writable,
                page.executable
            ),
            "user page belongs to another process or unassigned device"
        );
    } else if page.executable {
        assert!(
            (addr_of!(__kernel_start) as u64..addr_of!(__text_end) as u64).contains(&address),
            "executable supervisor memory outside text"
        );
    }
}

/// Addresses for narrow architecture #PF probes: immutable text and NX data.
#[cfg(feature = "userspace-test")]
pub fn probe_addresses() -> (u64, u64) {
    (init as *const () as u64, addr_of_mut!(NX_PROBE) as u64)
}

unsafe fn flush_tlb() {
    let cr3: u64;
    // SAFETY: reloading the active CR3 flushes old huge-page translations.
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}
