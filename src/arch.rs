//! Single-CPU ring-3 transitions with timer preemption of userspace.
//!
//! All descriptor tables, trap stacks, and saved kernel state remain in the
//! supervisor-only identity mapping. Only the syscall interrupt has DPL 3.

use core::arch::{asm, global_asm};
use core::mem::{offset_of, size_of};
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, Ordering};

global_asm!(
    include_str!("traps.S"),
    test_probes = const cfg!(feature = "userspace-test") as u8,
);

const KERNEL_CODE: u16 = 0x08;
const KERNEL_DATA: u16 = 0x10;
const USER_DATA: u64 = 0x1b;
const USER_CODE: u64 = 0x23;
const TSS_SELECTOR: u16 = 0x28;
const STACK_BYTES: usize = 32 * 1024;
const GUARD_BYTES: usize = 4096;
pub const TIMER_VECTOR: u64 = 32;
#[cfg(feature = "baremetal")]
pub const SPURIOUS_VECTOR: u8 = 255;

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
            rflags: 0x202,
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

#[repr(C, align(4096))]
struct Stack([u8; GUARD_BYTES + STACK_BYTES]);

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut TSS: TaskStateSegment = TaskStateSegment::EMPTY;
static mut GDT: [u64; 7] = [0; 7];
static mut IDT: [Gate; 256] = [Gate::EMPTY; 256];
static mut TRAP_STACK: Stack = Stack([0; GUARD_BYTES + STACK_BYTES]);
static mut DOUBLE_FAULT_STACK: Stack = Stack([0; GUARD_BYTES + STACK_BYTES]);

unsafe extern "C" {
    fn arch_load_gdt(pointer: *const TablePointer);
    fn arch_resume(context: *mut Context);
    fn arch_int80();
    fn arch_unexpected();
    #[cfg(feature = "baremetal")]
    fn arch_spurious();
    static arch_exception_vectors: [u64; 32];
    static arch_irq_vectors: [u64; 16];
    #[cfg(all(feature = "userspace-test", feature = "baremetal"))]
    fn arch_probe_spurious(context: *mut Context);
    #[cfg(feature = "userspace-test")]
    fn arch_probe_write(address: u64) -> u64;
    #[cfg(feature = "userspace-test")]
    fn arch_probe_execute(address: u64) -> u64;
}

/// Install the GDT, TSS, and IDT on the sole bootstrap CPU.
///
/// The kernel never starts other CPUs and keeps IF clear while in ring 0.
/// This wrapper checks the privilege/interrupt state and rejects reuse.
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
        let trap_top = addr_of!(TRAP_STACK) as u64 + size_of::<Stack>() as u64;
        let double_fault_top = addr_of!(DOUBLE_FAULT_STACK) as u64 + size_of::<Stack>() as u64;
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
        let irqs = addr_of!(arch_irq_vectors).cast::<u64>();
        for irq in 0..16 {
            idt.add(TIMER_VECTOR as usize + irq)
                .write(Gate::interrupt(irqs.add(irq).read(), 0, 0));
        }
        idt.add(0x80)
            .write(Gate::interrupt(arch_int80 as *const () as u64, 3, 0));
        #[cfg(feature = "baremetal")]
        idt.add(SPURIOUS_VECTOR as usize).write(Gate::interrupt(
            arch_spurious as *const () as u64,
            0,
            0,
        ));
        let idt_pointer = TablePointer {
            limit: (size_of::<[Gate; 256]>() - 1) as u16,
            base: addr_of!(IDT) as u64,
        };
        asm!("lidt [{}]", in(reg) &idt_pointer, options(readonly, nostack, preserves_flags));
    }
}

/// Run userspace until INT 0x80, the timer, or an exception, updating `context`.
///
/// # Safety
/// Call only on the bootstrap CPU after `init`, with external interrupts
/// disabled, and never recursively. The kernel stack, this context, GDT/TSS,
/// IDT, and trap code/stacks must remain supervisor-only and writable/executable
/// as appropriate. The caller restores this process's FPU/SIMD state before
/// entry and saves it before restoring the kernel state. This routine switches
/// general registers only. Invalid user return addresses are reported as
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
    // Preserve arithmetic flags and DF. Force IF on so ring 3 cannot evade
    // preemption; IOPL stays zero so POPFQ cannot clear IF and CLI faults.
    // Single stepping, AC, and nested-task state are never restored here.
    context.rflags = (context.rflags & 0x0cd5) | 0x202;
    // SAFETY: the caller guarantees the mapping/lifetime/CPU invariants above.
    unsafe { arch_resume(context) };
}

/// Test the user spurious-return path without executing a user instruction.
#[cfg(all(feature = "userspace-test", feature = "baremetal"))]
pub fn check_spurious_context() {
    let invalid_stack = 0x0000_8000_0000_0000;
    let mut context = Context::user(crate::userspace::USER_BASE, invalid_stack, 0);
    let before = crate::timer::ticks();
    // SAFETY: one CPU, IF clear, installed tables and resident kernel context.
    // The helper constructs a hardware-shaped user frame and enters the actual
    // spurious handler. It must yield before attempting IRET to this bad RSP.
    unsafe { arch_probe_spurious(&mut context) };
    assert_eq!(context.vector, TIMER_VECTOR);
    assert_eq!(context.rsp, invalid_stack);
    assert_eq!(
        crate::timer::ticks(),
        before,
        "spurious IRQ counted as timer tick"
    );
    // SAFETY: resume rejects this noncanonical stack before entering assembly.
    unsafe { resume(&mut context) };
    assert_eq!(
        context.vector, 12,
        "spurious return bypassed stack validation"
    );
}

/// Supervisor guard pages to remove from the identity mapping before entry.
pub fn guard_pages() -> [u64; 2] {
    [
        addr_of!(TRAP_STACK) as u64,
        addr_of!(DOUBLE_FAULT_STACK) as u64,
    ]
}

/// Attempt a same-value byte write and return the page-fault error code.
///
/// # Safety
/// Test-only: call on the bootstrap CPU with IF clear, outside any other probe.
/// `address` must point to a readable kernel byte. The handler accepts only a
/// page fault at the exact probe instruction and fault address; other faults
/// retain the normal fatal handling. `None` means the write was permitted.
#[cfg(feature = "userspace-test")]
pub unsafe fn probe_write(address: u64) -> Option<u64> {
    // SAFETY: the caller provides the readable address and CPU invariants.
    let error = unsafe { arch_probe_write(address) };
    (error != u64::MAX).then_some(error)
}

/// Attempt to execute a single RET byte and return the page-fault error code.
///
/// # Safety
/// The same CPU/probe rules as `probe_write` apply. The readable kernel target
/// must contain 0xc3 (RET), so the non-faulting case safely returns unchanged.
#[cfg(feature = "userspace-test")]
pub unsafe fn probe_execute(address: u64) -> Option<u64> {
    // SAFETY: the caller supplies a RET target and the CPU invariants above.
    let error = unsafe { arch_probe_execute(address) };
    (error != u64::MAX).then_some(error)
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
