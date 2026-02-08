ENTRY(_start)

MEMORY 
{
    RAM (rwx) : ORIGIN = 0x40080000, LENGTH = 8M  /* qemu does something on its own so the code is actually loaded here */
}

SECTIONS 
{
    . = 0x40080000;

    .text : { 
        __text_start = .;
        *(.text.boot)
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
}
