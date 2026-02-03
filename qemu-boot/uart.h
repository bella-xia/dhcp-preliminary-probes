#ifndef UART_H
#define UART_H

#include <stdint.h>

#define UART0_BASE 0x09000000UL
#define UARTDR 0x000 // data register
#define UARTFR 0x018 // flag register 

void uart_init(void);
void uart_putc(char c);
void uart_puts(const char *s);
char uart_getc(void);
int uart_has_data(void);

#endif
