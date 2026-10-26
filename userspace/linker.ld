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
    . = 0x40000000;
    __image_start = .;
    .text ALIGN(4096) :
    {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text

    .rodata ALIGN(4096) :
    {
        *(.rodata .rodata.* .srodata .srodata.*)
    } :rodata

    .data ALIGN(4096) :
    {
        *(.data .data.* .sdata .sdata.*)
        *(.got .got.*)
        BYTE(0)
    } :data

    .bss ALIGN(4096) (NOLOAD) :
    {
        *(.bss .bss.* .sbss .sbss.*)
        *(COMMON)
        . = ALIGN(4096);
    } :data
    __image_end = .;

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame.* .eh_frame_hdr)
        *(.gcc_except_table .gcc_except_table.*)
        *(.comment .note .note.*)
    }

    ASSERT(_start == 0x40000000, "Userspace entry must be at the image base")
    ASSERT(__image_end < 0x401ef000, "Userspace image overlaps the stack guard")
}
