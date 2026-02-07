/* start.S ARM64 minimal entry */
.section ".text.boot"
.global _start
.global hang

.extern main

/* stack top: adjust in linker.ld */
_start:
    ldr x0, =_stack_top
    mov sp, x0
    
    // clear BSS if needed
    ldr x0, =__bss_start
    ldr x1, =__bss_end

clear_bss:
    cmp x0, x1
    b.ge bss_done
    str xzr, [x0], #8
    b clear_bss
 
 bss_done:
    // jump to c code or main loop
    bl main

hang:
    wfe
    b hang
