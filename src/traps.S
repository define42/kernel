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

.Lkernel_fault:
    mov rdi, [rsp + 120]
    mov rsi, [rsp + 128]
    mov rdx, [rsp + 136]
    mov rcx, cr2
    # Fatal handlers never return. Align even for an unusual interrupted RSP.
    and rsp, -16
    call arch_kernel_fault
    ud2
.size arch_trap_common, . - arch_trap_common

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

.section .bss.arch,"aw",@nobits
.balign 8
arch_active_context:
    .skip 8
arch_kernel_rsp:
    .skip 8

.section .note.GNU-stack,"",@progbits
