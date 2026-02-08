.globl dev_barrier
.globl kwait
.globl GET32
.globl PUT32

dev_barrier:
    b dsb

/* Data memory barrier 
UNUSED for now?
*/
dmb:
    mov r0, #0
    mcr p15, 0, r0, c7, c10, 5
    bx lr

/*
 * used to be called "drain write buffer"
 * includes all cache operations.  is a superset (>) DMB
 */
dsb:
    mcr p15, 0, r0, c7, c10, 4
    bx lr

GET32:
    ldr r0, [r0]
    bx lr

PUT32:
    str r1, [r0]
    bx lr

kwait:
    nop
    bx lr
