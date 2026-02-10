#ifndef TIMER_H
#define TIMER_H

#include <stdint.h>

// return time in usec
uint32_t timer_get_usec(void); 

void delay_us(uint32_t us);
void delay_ms(uint32_t ms);
void delay_sec(uint32_t sec);

#endif // timer.h
