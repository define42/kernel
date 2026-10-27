# x86-64 trap/context code; field offsets are checked in arch.rs.
# Context: 15 GPRs, vector, error, RIP, CS, RFLAGS, RSP, SS, CR2.
.section .text.arch,"ax",@progbits
.code64

.global arch_load_gdt
.type arch_load_gdt,@function
arch_load_gdt:
    lgdt [rdi]
    push 0x08
    lea rax, [rip + .Lnew_cs]
    push rax
    retfq
.Lnew_cs:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    ret
.size arch_load_gdt, . - arch_load_gdt

.global arch_resume
.type arch_resume,@function
arch_resume:
    # Preserve the SysV callee-saved registers and return address on the
    # caller's supervisor stack. User traps return through this exact frame.
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rip + arch_kernel_rsp], rsp
    mov [rip + arch_active_context], rdi
    mov rax, rdi

    # IRETQ always consumes this five-qword frame in 64-bit mode.
    push qword ptr [rax + 168]       # SS
    push qword ptr [rax + 160]       # RSP
    push qword ptr [rax + 152]       # RFLAGS (sanitized by Rust)
    push qword ptr [rax + 144]       # CS
    push qword ptr [rax + 136]       # RIP

    mov dx, 0x1b
    mov ds, dx
    mov es, dx
    mov r15, [rax]
    mov r14, [rax + 8]
    mov r13, [rax + 16]
    mov r12, [rax + 24]
    mov r11, [rax + 32]
    mov r10, [rax + 40]
    mov r9, [rax + 48]
    mov r8, [rax + 56]
    mov rbp, [rax + 64]
    mov rdi, [rax + 72]
    mov rsi, [rax + 80]
    mov rdx, [rax + 88]
    mov rcx, [rax + 96]
    mov rbx, [rax + 104]
    mov rax, [rax + 112]
    iretq
.size arch_resume, . - arch_resume

# Normalize hardware exceptions to [vector, error, RIP, CS, flags, RSP, SS].
# CPU-pushed error codes exist for #DF, #TS, #NP, #SS, #GP, #PF, #AC,
# #CP, #VC, and #SX. Other vectors receive a synthetic zero.
.macro EXCEPTION number, has_error=0
.type arch_exception_\number,@function
arch_exception_\number:
.if \has_error == 0
    push 0
.endif
    push \number
    jmp arch_trap_common
.size arch_exception_\number, . - arch_exception_\number
.endm

EXCEPTION 0
EXCEPTION 1
EXCEPTION 2
EXCEPTION 3
EXCEPTION 4
EXCEPTION 5
EXCEPTION 6
EXCEPTION 7
EXCEPTION 8, 1
EXCEPTION 9
EXCEPTION 10, 1
EXCEPTION 11, 1
EXCEPTION 12, 1
EXCEPTION 13, 1
EXCEPTION 14, 1
EXCEPTION 15
EXCEPTION 16
EXCEPTION 17, 1
EXCEPTION 18
EXCEPTION 19
EXCEPTION 20
EXCEPTION 21, 1
EXCEPTION 22
EXCEPTION 23
EXCEPTION 24
EXCEPTION 25
EXCEPTION 26
EXCEPTION 27
EXCEPTION 28
EXCEPTION 29, 1
EXCEPTION 30, 1
EXCEPTION 31

# Legacy PIC IRQ0..15, remapped clear of the CPU exception vectors.
EXCEPTION 32
EXCEPTION 33
EXCEPTION 34
EXCEPTION 35
EXCEPTION 36
EXCEPTION 37
EXCEPTION 38
EXCEPTION 39
EXCEPTION 40
EXCEPTION 41
EXCEPTION 42
EXCEPTION 43
EXCEPTION 44
EXCEPTION 45
EXCEPTION 46
EXCEPTION 47

.global arch_int80
.type arch_int80,@function
arch_int80:
    push 0
    push 128
    jmp arch_trap_common
.size arch_int80, . - arch_int80

.global arch_unexpected
.type arch_unexpected,@function
arch_unexpected:
    push 0
    push 255
    jmp arch_trap_common
.size arch_unexpected, . - arch_unexpected

# Local APIC spurious interrupts never set an ISR bit and need no EOI.
# Internal sentinel 256 keeps them distinct from unexpected-vector faults.
.global arch_spurious
.type arch_spurious,@function
arch_spurious:
    push 0
    push 256
    jmp arch_trap_common
.size arch_spurious, . - arch_spurious

.type arch_trap_common,@function
arch_trap_common:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    # Ring 3 can set DF. The kernel and REP MOVSQ require DF clear.
    cld
    # Ring 3 can also set AC. Clear it before entering Rust or touching
    # potentially unaligned data (independent of the current CR0.AM setting).
    pushfq
    btr qword ptr [rsp], 18
    popfq
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    mov rax, [rsp + 120]
    cmp eax, 256
    je .Lreturn_interrupt
    cmp eax, 32
    je .Ltimer_irq
    cmp eax, 33
    jb .Ldeliver_context
    cmp eax, 47
    jbe .Lother_irq

.Ldeliver_context:
    mov rax, [rsp + 144]            # Saved CS.
    and eax, 3
    cmp eax, 3
    jne .Lkernel_fault
    mov rdi, [rip + arch_active_context]
    test rdi, rdi
    jz .Lkernel_fault
    # The CPU switches to TSS.RSP0 on user entry; this whole frame is
    # supervisor memory. Copy GPRs + normalized trap frame, then save CR2.
    mov rsi, rsp
    mov ecx, 22
    rep movsq
    mov rax, cr2
    mov [rdi], rax
    mov qword ptr [rip + arch_active_context], 0
    mov rsp, [rip + arch_kernel_rsp]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.Ltimer_irq:
    # All registers are saved. The sole boot CPU publishes its supervisor
    # APIC EOI address before enabling the local timer; zero selects PIC IRQ0.
    lock inc qword ptr [rip + TIMER_TICKS]
    mov rax, [rip + TIMER_APIC_EOI]
    test rax, rax
    jz .Ltimer_pic_eoi
    mov dword ptr [rax], 0
    jmp .Ltimer_acknowledged
.Ltimer_pic_eoi:
    mov al, 0x60
    out 0x20, al
.Ltimer_acknowledged:
    test byte ptr [rsp + 144], 3
    jnz .Ldeliver_context
    # IF is normally zero in ring 0. If an IRQ nevertheless interrupted it,
    # resume that exact frame; never abandon a kernel operation mid-flight.
    jmp .Lreturn_interrupt

.Lother_irq:
    # The local APIC backend masks all other LVTs and legacy PIC inputs. If
    # a stale external vector survives, acknowledge its controller and resume.
    mov rdx, [rip + TIMER_APIC_EOI]
    test rdx, rdx
    jz .Lother_pic_irq
    mov dword ptr [rdx], 0
    jmp .Lreturn_interrupt
.Lother_pic_irq:
    # All other PIC inputs are masked. If a pending or spurious interrupt
    # survives initialization, acknowledge it correctly and resume directly.
    cmp eax, 39
    je .Lmaster_irq7
    cmp eax, 47
    je .Lslave_irq15
    cmp eax, 40
    jae .Lack_slave_irq
    and al, 7
    or al, 0x60
    out 0x20, al
    jmp .Lreturn_interrupt
.Lmaster_irq7:
    mov al, 0x0b                  # OCW3: read in-service register.
    out 0x20, al
    in al, 0x20
    test al, 0x80
    jz .Lreturn_interrupt        # Spurious IRQ7 has no ISR bit to clear.
    mov al, 0x67
    out 0x20, al
    jmp .Lreturn_interrupt
.Lslave_irq15:
    mov al, 0x0b
    out 0xa0, al
    in al, 0xa0
    test al, 0x80
    jz .Lack_cascade             # Spurious IRQ15 still needs master EOI.
    mov al, 0x67
    out 0xa0, al
    jmp .Lack_cascade
.Lack_slave_irq:
    and al, 7
    or al, 0x60
    out 0xa0, al
.Lack_cascade:
    mov al, 0x62                 # Master IRQ2 is the slave cascade.
    out 0x20, al
    jmp .Lreturn_interrupt

.Lkernel_fault:
.if {test_probes}
    # Only the explicit test probes may recover from a supervisor page fault.
    # Match both the exact expected instruction and CR2; never swallow an
    # unrelated exception or a user fault at a superficially similar address.
    cmp qword ptr [rsp + 120], 14
    jne .Lfatal_kernel_fault
    mov rax, [rip + arch_probe_rip]
    test rax, rax
    jz .Lfatal_kernel_fault
    cmp rax, [rsp + 136]
    jne .Lfatal_kernel_fault
    mov rax, cr2
    cmp rax, [rip + arch_probe_address]
    jne .Lfatal_kernel_fault
    mov rax, [rip + arch_probe_fixup]
    mov [rsp + 136], rax
    mov rax, [rsp + 128]
    mov [rsp + 112], rax         # Probe returns the page-fault error code.
    mov qword ptr [rip + arch_probe_rip], 0
    jmp .Lreturn_interrupt
.endif

.Lfatal_kernel_fault:
    mov rdi, [rsp + 120]
    mov rsi, [rsp + 128]
    mov rdx, [rsp + 136]
    mov rcx, cr2
    # Fatal handlers never return. Align even for an unusual interrupted RSP.
    and rsp, -16
    call arch_kernel_fault
    ud2

.Lreturn_interrupt:
    test byte ptr [rsp + 144], 3
    jz .Lrestore_registers
    # Even an ignored IRQ cannot IRET directly to an untrusted user RSP: it
    # might be noncanonical and fault in ring 0. Yield without a timer tick;
    # the scheduler's normal resume path validates and sanitizes the frame.
    mov qword ptr [rsp + 120], 32
    jmp .Ldeliver_context
.Lrestore_registers:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16                  # Normalized vector and error code.
    iretq
.size arch_trap_common, . - arch_trap_common

.if {test_probes}
.global arch_probe_spurious
.type arch_probe_spurious,@function
arch_probe_spurious:
    # Build an interrupted user frame without entering untrusted memory. This
    # exercises spurious-IRQ return with an adversarial, noncanonical user RSP.
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rip + arch_kernel_rsp], rsp
    mov [rip + arch_active_context], rdi
    push qword ptr [rdi + 168]
    push qword ptr [rdi + 160]
    push qword ptr [rdi + 152]
    push qword ptr [rdi + 144]
    push qword ptr [rdi + 136]
    jmp arch_spurious
.size arch_probe_spurious, . - arch_probe_spurious

.global arch_probe_write
.type arch_probe_write,@function
arch_probe_write:
    # Read before enabling fixup: callers promise a readable target. Writing
    # the same byte leaves text unchanged even if write protection is broken.
    movzx eax, byte ptr [rdi]
    mov [rip + arch_probe_address], rdi
    lea r11, [rip + .Lwrite_fault_return]
    mov [rip + arch_probe_fixup], r11
    lea r11, [rip + .Lwrite_probe_instruction]
    mov [rip + arch_probe_rip], r11
.Lwrite_probe_instruction:
    mov byte ptr [rdi], al
    mov rax, -1
.Lwrite_fault_return:
    mov qword ptr [rip + arch_probe_rip], 0
    ret
.size arch_probe_write, . - arch_probe_write

.global arch_probe_execute
.type arch_probe_execute,@function
arch_probe_execute:
    # Call a known RET byte. On an NX fault, discard this extra return address
    # in the fixup before returning to the original Rust caller.
    mov [rip + arch_probe_address], rdi
    lea r11, [rip + .Lexecute_fault_return]
    mov [rip + arch_probe_fixup], r11
    mov [rip + arch_probe_rip], rdi
    mov rax, -1
    call rdi
    mov qword ptr [rip + arch_probe_rip], 0
    ret
.Lexecute_fault_return:
    add rsp, 8
    mov qword ptr [rip + arch_probe_rip], 0
    ret
.size arch_probe_execute, . - arch_probe_execute
.endif

.section .rodata.arch,"a",@progbits
.balign 8
.global arch_exception_vectors
arch_exception_vectors:
    .quad arch_exception_0, arch_exception_1, arch_exception_2, arch_exception_3
    .quad arch_exception_4, arch_exception_5, arch_exception_6, arch_exception_7
    .quad arch_exception_8, arch_exception_9, arch_exception_10, arch_exception_11
    .quad arch_exception_12, arch_exception_13, arch_exception_14, arch_exception_15
    .quad arch_exception_16, arch_exception_17, arch_exception_18, arch_exception_19
    .quad arch_exception_20, arch_exception_21, arch_exception_22, arch_exception_23
    .quad arch_exception_24, arch_exception_25, arch_exception_26, arch_exception_27
    .quad arch_exception_28, arch_exception_29, arch_exception_30, arch_exception_31

.global arch_irq_vectors
arch_irq_vectors:
    .quad arch_exception_32, arch_exception_33, arch_exception_34, arch_exception_35
    .quad arch_exception_36, arch_exception_37, arch_exception_38, arch_exception_39
    .quad arch_exception_40, arch_exception_41, arch_exception_42, arch_exception_43
    .quad arch_exception_44, arch_exception_45, arch_exception_46, arch_exception_47

.section .bss.arch,"aw",@nobits
.balign 8
arch_active_context:
    .skip 8
arch_kernel_rsp:
    .skip 8
.if {test_probes}
arch_probe_rip:
    .skip 8
arch_probe_address:
    .skip 8
arch_probe_fixup:
    .skip 8
.endif

.section .note.GNU-stack,"",@progbits
