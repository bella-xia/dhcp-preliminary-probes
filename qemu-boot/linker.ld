ENTRY(_start)

MEMORY 
{
    RAM (rwx) : ORIGIN = 0x40080000, LENGTH = 8M  /* qemu does something on its own so the code is actually loaded here */
}

SECTIONS 
{
    . = 0x40000000;

    .text : { 
        __text_start = .;
        *(.text.boot)
        *(.text*) 
        __text_end = .;
     }
    .rodata : { 
        __rodata_start = .;
        *(.rodata*) 
        __rodata_end = .;
     } 
    .data : { 
        __data_start = .;
        *(.data*) 
        __data_end = .;
     }
    .bss : { 
        __bss_start = .;
        *(.bss*) 
        *(COMMON)
        __bss_end = .;
        }
    
    . = ALIGN(16);
    . = . + 0x10000; /* 64 KB stack */
    _stack_top = .;
}
