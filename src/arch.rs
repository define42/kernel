//! Single-CPU ring-3 transitions. Userspace runs cooperatively with IF = 0.
//!
//! All descriptor tables, trap stacks, and saved kernel state remain in the
//! supervisor-only identity mapping. Only the syscall interrupt has DPL 3.

use core::arch::{asm, global_asm};
use core::mem::{offset_of, size_of};
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, Ordering};

global_asm!(include_str!("traps.S"));

const KERNEL_CODE: u16 = 0x08;
const KERNEL_DATA: u16 = 0x10;
const USER_DATA: u64 = 0x1b;
const USER_CODE: u64 = 0x23;
const TSS_SELECTOR: u16 = 0x28;
const STACK_BYTES: usize = 32 * 1024;

/// Saved general registers followed by the normalized x86-64 trap frame.
///
/// The order is shared with `traps.S`; changing it requires updating both.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Context {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub cr2: u64,
}

impl Context {
    /// Construct a process entry context. `stack` has SysV entry alignment
    /// (RSP modulo 16 = 8), and `arg` is passed in RDI to the entry function.
    pub const fn user(entry: u64, stack: u64, arg: u64) -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rbp: 0,
            rdi: arg,
            rsi: 0,
            rdx: 0,
            rcx: 0,
            rbx: 0,
            rax: 0,
            vector: 0,
            error_code: 0,
            rip: entry,
            cs: USER_CODE,
            rflags: 2,
            rsp: stack,
            ss: USER_DATA,
            cr2: 0,
        }
    }
}

const _: () = {
    assert!(size_of::<Context>() == 184);
    assert!(offset_of!(Context, rdi) == 72);
    assert!(offset_of!(Context, rax) == 112);
    assert!(offset_of!(Context, vector) == 120);
    assert!(offset_of!(Context, error_code) == 128);
    assert!(offset_of!(Context, rip) == 136);
    assert!(offset_of!(Context, cs) == 144);
    assert!(offset_of!(Context, rflags) == 152);
    assert!(offset_of!(Context, rsp) == 160);
    assert!(offset_of!(Context, ss) == 168);
    assert!(offset_of!(Context, cr2) == 176);
};

#[repr(C, packed)]
struct TaskStateSegment {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

impl TaskStateSegment {
    const EMPTY: Self = Self {
        reserved0: 0,
        rsp: [0; 3],
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        reserved3: 0,
        // A base beyond the descriptor limit denies every port to ring 3.
        iomap_base: size_of::<Self>() as u16,
    };
}

const _: () = assert!(size_of::<TaskStateSegment>() == 104);

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl Gate {
    const EMPTY: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn interrupt(handler: u64, dpl: u8, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE,
            ist,
            attributes: 0x8e | (dpl << 5),
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

#[repr(C, packed)]
struct TablePointer {
    limit: u16,
    base: u64,
}

#[repr(C, align(16))]
struct Stack([u8; STACK_BYTES]);

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut TSS: TaskStateSegment = TaskStateSegment::EMPTY;
static mut GDT: [u64; 7] = [0; 7];
static mut IDT: [Gate; 256] = [Gate::EMPTY; 256];
static mut TRAP_STACK: Stack = Stack([0; STACK_BYTES]);
static mut DOUBLE_FAULT_STACK: Stack = Stack([0; STACK_BYTES]);

unsafe extern "C" {
    fn arch_load_gdt(pointer: *const TablePointer);
    fn arch_resume(context: *mut Context);
    fn arch_int80();
    fn arch_unexpected();
    static arch_exception_vectors: [u64; 32];
}

/// Install the GDT, TSS, and IDT on the sole bootstrap CPU.
///
/// The kernel never starts other CPUs or enables external interrupts. This
/// wrapper checks the required privilege/interrupt state and rejects reuse.
/// The static tables stay resident for the remainder of the kernel lifetime.
pub fn init() {
    let flags: u64;
    let cs: u16;
    // SAFETY: reading CS and RFLAGS is valid at every privilege level.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    assert_eq!(cs & 3, 0, "architecture setup requires ring 0");
    assert_eq!(flags & (1 << 9), 0, "architecture setup requires IF = 0");
    assert!(
        !INITIALIZED.swap(true, Ordering::Relaxed),
        "GDT already installed"
    );

    // SAFETY: execution is single-CPU with interrupts disabled. These writable
    // statics have no references elsewhere and all descriptor addresses remain
    // supervisor mapped. Packed TSS fields are written without aligned refs.
    unsafe {
        let tss = addr_of_mut!(TSS);
        let trap_top = addr_of!(TRAP_STACK) as u64 + STACK_BYTES as u64;
        let double_fault_top = addr_of!(DOUBLE_FAULT_STACK) as u64 + STACK_BYTES as u64;
        addr_of_mut!((*tss).rsp).write_unaligned([trap_top, 0, 0]);
        addr_of_mut!((*tss).ist).write_unaligned([double_fault_top, 0, 0, 0, 0, 0, 0]);

        let base = tss as u64;
        let limit = (size_of::<TaskStateSegment>() - 1) as u64;
        let tss_low = (limit & 0xffff)
            | ((base & 0xffff) << 16)
            | (((base >> 16) & 0xff) << 32)
            | (0x89 << 40) // Present, DPL 0, available 64-bit TSS.
            | (((limit >> 16) & 0xf) << 48)
            | (((base >> 24) & 0xff) << 56);
        addr_of_mut!(GDT).write([
            0,
            0x00af_9a00_0000_ffff, // Ring-0 64-bit code.
            0x00cf_9200_0000_ffff, // Ring-0 writable data.
            0x00cf_f200_0000_ffff, // Ring-3 writable data.
            0x00af_fa00_0000_ffff, // Ring-3 64-bit code.
            tss_low,
            base >> 32,
        ]);
        let gdt_pointer = TablePointer {
            limit: (size_of::<[u64; 7]>() - 1) as u16,
            base: addr_of!(GDT) as u64,
        };
        arch_load_gdt(&gdt_pointer);
        asm!("ltr {0:x}", in(reg) TSS_SELECTOR, options(nostack, preserves_flags));

        let idt = addr_of_mut!(IDT).cast::<Gate>();
        for vector in 0..256 {
            idt.add(vector)
                .write(Gate::interrupt(arch_unexpected as *const () as u64, 0, 0));
        }
        let exceptions = addr_of!(arch_exception_vectors).cast::<u64>();
        for vector in 0..32 {
            idt.add(vector).write(Gate::interrupt(
                exceptions.add(vector).read(),
                0,
                u8::from(vector == 8), // Double fault uses dedicated IST1.
            ));
        }
        idt.add(0x80)
            .write(Gate::interrupt(arch_int80 as *const () as u64, 3, 0));
        let idt_pointer = TablePointer {
            limit: (size_of::<[Gate; 256]>() - 1) as u16,
            base: addr_of!(IDT) as u64,
        };
        asm!("lidt [{}]", in(reg) &idt_pointer, options(readonly, nostack, preserves_flags));
    }
}

/// Run userspace until its next INT 0x80 or exception, then update `context`.
///
/// # Safety
/// Call only on the bootstrap CPU after `init`, with external interrupts
/// disabled, and never recursively. The kernel stack, this context, GDT/TSS,
/// IDT, and trap code/stacks must remain supervisor-only and writable/executable
/// as appropriate. No FPU or SIMD state is switched (both binaries use the
/// soft-float bare-metal target). Invalid user return addresses are reported as
/// synthetic faults, since a faulting IRET itself would execute at ring 0.
pub unsafe fn resume(context: &mut Context) {
    assert!(INITIALIZED.load(Ordering::Relaxed), "GDT is not installed");
    // A user may set a noncanonical RSP before INT 0x80. The interrupt uses
    // TSS.RSP0 and succeeds, but returning that RSP with IRET would fault in
    // ring 0. Reject invalid return frames while still in the scheduler.
    if context.cs != USER_CODE || context.ss != USER_DATA || !canonical(context.rip) {
        context.vector = 13; // #GP: invalid return code/segment state.
        context.error_code = 0;
        return;
    }
    if !canonical(context.rsp) {
        context.vector = 12; // #SS: noncanonical user stack address.
        context.error_code = 0;
        return;
    }
    // Preserve arithmetic flags and DF, but do not allow a saved frame to
    // enable interrupts, I/O privilege, single stepping, or nested tasks.
    context.rflags = (context.rflags & 0x0cd5) | 2;
    // SAFETY: the caller guarantees the mapping/lifetime/CPU invariants above.
    unsafe { arch_resume(context) };
}

fn canonical(address: u64) -> bool {
    // The bootstrap explicitly disables five-level paging (CR4.LA57).
    address <= 0x0000_7fff_ffff_ffff || address >= 0xffff_8000_0000_0000
}

/// Fatal supervisor exception entry; assembly passes individual frame values
/// so Rust never creates a reference to an incomplete/packed interrupt frame.
#[unsafe(no_mangle)]
extern "C" fn arch_kernel_fault(vector: u64, error: u64, rip: u64, cr2: u64) -> ! {
    panic!("ring-0 exception: vector={vector} error={error:#x} rip={rip:#x} cr2={cr2:#x}");
}

// Kept next to the segment constants to catch accidental descriptor changes.
const _: () = assert!(KERNEL_DATA == 0x10);
