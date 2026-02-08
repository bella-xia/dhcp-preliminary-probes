/* start.S ARM32 (ARMv6) for Raspberry Pi Zero  minimal entry */
.section ".text.boot"
.global _start
.global hang

.extern main

/* stack top: adjust in linker.ld */
_start:
    ldr sp, =_stack_top
    
    // clear BSS if needed
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    mov r2, #0

clear_bss:
    cmp r0, r1
    bge bss_done
    str r2, [r0], #4 /* store 0. increment by 4 bytes (32 bit) */
    b clear_bss
 
 bss_done:
    // jump to c code or main loop
    bl main

hang:
    wfe
    b hang

