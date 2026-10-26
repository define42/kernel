# QEMU's Multiboot loader enters here in 32-bit protected mode, paging off.
# The address fields let it load our flat binary even though Rust emits ELF64.
.set MULTIBOOT_MAGIC, 0x1badb002
.set MULTIBOOT_FLAGS, (1 << 16) | 3
.set MULTIBOOT_BOOT_MAGIC, 0x2badb002

.section .multiboot,"a",@progbits
.balign 4
.global multiboot_header
multiboot_header:
    .long MULTIBOOT_MAGIC
    .long MULTIBOOT_FLAGS
    .long -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)
    .long multiboot_header
    .long __kernel_start
    .long __load_end
    .long __kernel_end
    .long _start
multiboot_header_end:

.section .text.boot,"ax",@progbits
.code32
.global _start
.type _start,@function
_start:
    cli
    cld
    cmp eax, MULTIBOOT_BOOT_MAGIC
    jne .Lbad_multiboot

    # Keep the boot arguments across BSS initialization and CPUID.
    mov ebp, eax
    mov esi, ebx

    # A Multiboot loader already zeros BSS; doing so explicitly also makes
    # the page-table and Rust static initialization requirements clear.
    # Do not use the stack until its backing storage has been cleared.
    mov edi, offset __bss_start
    mov ecx, offset __bss_end
    sub ecx, edi
    shr ecx, 2
    xor eax, eax
    rep stosd
    mov esp, offset boot_stack_top

    # Check that EFLAGS.ID is writable before executing CPUID.
    pushfd
    pop eax
    mov ecx, eax
    xor eax, 1 << 21
    push eax
    popfd
    pushfd
    pop eax
    push ecx
    popfd
    xor eax, ecx
    test eax, 1 << 21
    jz .Lno_cpuid

    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .Lno_long_mode
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .Lno_long_mode

    # PML4[0] -> PDPT[0..4] -> 2048 entries mapping the first 4 GiB.
    # All other entries and the high halves are zero from BSS clearing.
    mov eax, offset boot_pdpt
    or eax, 3
    mov dword ptr [boot_pml4], eax
    mov eax, offset boot_page_directory
    or eax, 3
    xor ecx, ecx
.Lmap_directory:
    mov dword ptr [boot_pdpt + ecx * 8], eax
    add eax, 4096
    inc ecx
    cmp ecx, 4
    jne .Lmap_directory
    xor ecx, ecx
    mov eax, 0x83                 # Present, writable, huge page.
.Lmap_page:
    cmp ecx, 512
    jne .Lmap_page_store
    # Keep RAM below 1 GiB cached. PCI and HPET MMIO above it use
    # PCD|PWT (default PAT entry 3 = uncacheable, huge-page PAT bit = 0).
    or eax, (1 << 4) | (1 << 3)
.Lmap_page_store:
    mov dword ptr [boot_page_directory + ecx * 8], eax
    add eax, 0x200000
    inc ecx
    cmp ecx, 2048
    jne .Lmap_page

    # Select four-level paging, enable PAE, and install the top-level table.
    mov eax, cr4
    and eax, ~(1 << 12)           # CR4.LA57 = 0.
    or eax, 1 << 5                # CR4.PAE = 1.
    mov cr4, eax
    mov eax, offset boot_pml4
    mov cr3, eax

    mov ecx, 0xc0000080           # IA32_EFER.
    rdmsr
    or eax, 1 << 8                # EFER.LME = 1.
    wrmsr

    lgdt [boot_gdt_pointer]
    mov eax, cr0
    or eax, 0x80000001            # CR0.PG and CR0.PE.
    mov cr0, eax

    # Far jump with a 32-bit offset loads the 64-bit code segment.
    .byte 0xea
    .long .Llong_mode
    .word 0x08

.Lbad_multiboot:
    mov al, 'M'
    jmp .Lboot_error
.Lno_cpuid:
    mov al, 'C'
    jmp .Lboot_error
.Lno_long_mode:
    mov al, 'L'
.Lboot_error:
    # Red VGA diagnostic: ERROR: M (Multiboot), C (CPUID), or L (long mode).
    mov dword ptr [0xb8000], 0x4f524f45
    mov dword ptr [0xb8004], 0x4f4f4f52
    mov dword ptr [0xb8008], 0x4f3a4f52
    mov word ptr [0xb800c], 0x4f20
    mov byte ptr [0xb800e], al
    mov byte ptr [0xb800f], 0x4f
.Lhalt32:
    hlt
    jmp .Lhalt32

.code64
.Llong_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax

    # SysV AMD64: RSP is 16-byte aligned immediately before CALL;
    # the first two integer arguments are EDI and ESI.
    lea rsp, [rip + boot_stack_top]
    mov edi, ebp
    xor ebp, ebp
    call kernel_main
.Lhalt64:
    cli
    hlt
    jmp .Lhalt64
.size _start, . - _start

.section .rodata.boot,"a",@progbits
.balign 8
boot_gdt:
    .quad 0
    .quad 0x00af9a000000ffff       # Ring 0 executable, long mode, D = 0.
    .quad 0x00cf92000000ffff       # Ring 0 writable data.
boot_gdt_end:
boot_gdt_pointer:
    .word boot_gdt_end - boot_gdt - 1
    .long boot_gdt

.section .bss.boot,"aw",@nobits
.balign 4096
boot_pml4:
    .skip 4096
boot_pdpt:
    .skip 4096
boot_page_directory:
    .skip 4096 * 4
.balign 16
boot_stack_bottom:
    .skip 262144
boot_stack_top:

.section .note.GNU-stack,"",@progbits
