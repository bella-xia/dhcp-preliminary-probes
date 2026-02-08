#ifndef MMIO_H
#define MMIO_H

void dev_barrier(void);
void kwait(void);  

void PUT32(unsigned addr, unsigned v);
unsigned GET32(unsigned addr);

#endif // mmio.h

