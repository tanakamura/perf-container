ENTRY(_start)

SECTIONS
{
  . = 0x00401000;
  .text : { *(.text) }
  .data : { *(.data) }
  .bss : { *(.bss) }
  /DISCARD/ : { *(*) }
}
