OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    /* Avoid the low-memory ACPI NVS holes used by UEFI firmware. The
       complete range is still checked against the loader memory map. */
    . = 16M;
    __kernel_start = .;

    .multiboot ALIGN(4) :
    {
        KEEP(*(.multiboot))
    } :text

    .text ALIGN(16) :
    {
        KEEP(*(.text.boot))
        *(.text .text.*)
    } :text

    . = ALIGN(4096);
    __text_end = .;
    __rodata_start = .;

    .rodata ALIGN(4096) :
    {
        *(.rodata .rodata.* .srodata .srodata.*)
        . = ALIGN(4096);
    } :rodata
    __rodata_end = .;
    __data_start = .;

    .data ALIGN(4096) :
    {
        *(.data .data.* .sdata .sdata.*)
        *(.got .got.*)
        /* Guarantee a final initialized section even without Rust globals.
           Its end must equal the exact end of the objcopy flat binary. */
        BYTE(0)
        . = ALIGN(4096);
        __load_end = .;
    } :data

    .bss ALIGN(4096) (NOLOAD) :
    {
        __bss_start = .;
        *(.bss.boot)
        *(.bss .bss.* .sbss .sbss.*)
        *(COMMON)
        . = ALIGN(4096);
        __bss_end = .;
    } :data
    __kernel_end = .;

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame.* .eh_frame_hdr)
        *(.gcc_except_table .gcc_except_table.*)
        *(.comment .note .note.*)
    }

    ASSERT(SIZEOF(.multiboot) >= 32, "Missing Multiboot headers")
    ASSERT(ADDR(.multiboot) - __kernel_start + SIZEOF(.multiboot) <= 8192,
           "Multiboot header must be inside the first 8 KiB")
    ASSERT((ADDR(.multiboot) & 3) == 0, "Multiboot header must be aligned")
    ASSERT(((__bss_end - __bss_start) & 3) == 0, "BSS must contain whole dwords")
    ASSERT(__kernel_end <= 0x08000000, "Kernel exceeds the 128 MiB protected-page-table capacity")
}
