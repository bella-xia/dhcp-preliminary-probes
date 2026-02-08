ENTRY(_start)

MEMORY 
{
    RAM (rwx) : ORIGIN = 0x8000, LENGTH = 128M
}

SECTIONS 
{
    . = 0x8000;

    .text : { 
        __text_start = .;
        KEEP(*(.text.boot))
        *(.text*) 
        . = ALIGN(16);
        __text_end = .;
     } > RAM

    .rodata : { 
        __rodata_start = .;
        *(.rodata*) 
        . = ALIGN(16);
        __rodata_end = .;
     } > RAM 

    .data : { 
        __data_start = .;
        *(.data*) 
        . = ALIGN(16);
        __data_end = .;
     } > RAM

    .bss : { 
        __bss_start = .;
        *(.bss*) 
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
     } > RAM
    
    . = ALIGN(16);
    . = . + 0x10000; /* 64 KB stack */
    _stack_top = .;

/DISCARD/ : {  /* ARM compiler adds exception/debug metadata that bare-meta doesn't need */
    *(.ARM.exitdx*)
    *(.ARM.attributes*)
    *(.comment)
    }
}
