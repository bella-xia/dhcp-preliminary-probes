#include "gpio.h"

extern unsigned GET32(unsigned addr);
extern void PUT32(unsigned addr, unsigned v);

void rmw_peripheral(unsigned mask_base, unsigned bits, unsigned shift, unsigned reg_addr) {
    unsigned mask = mask_base << shift; 
    unsigned reg_val = GET32(reg_addr); 
    reg_val &= ~mask;
    reg_val |= (bits & mask_base) << shift;
    PUT32(reg_addr, reg_val);
}

void write_peripheral(unsigned bits, unsigned shift, unsigned reg_addr) {
    unsigned val = bits << shift;
    PUT32(reg_addr, val);
}

unsigned read_peripheral(unsigned mask_base, unsigned shift, unsigned reg_addr) {
    unsigned reg_val = GET32(reg_addr); 
    reg_val >>= shift;
    reg_val &= mask_base;
    return reg_val;
}
