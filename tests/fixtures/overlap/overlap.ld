/* A deliberately broken layout: .rodata is pinned 16 bytes after .text
   starts, but .text is bigger than 16 bytes, so the two overlap. */
ENTRY(_start)
MEMORY
{
    ROM (rx) : ORIGIN = 0x1000, LENGTH = 0x100
}
SECTIONS
{
    .text 0x1000 : { *(.text*) } > ROM
    .rodata 0x1010 : { *(.rodata*) } > ROM
}
