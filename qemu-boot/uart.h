#ifndef UART_H
#define UART_H

#include <stdint.h>

#define UART0_BASE 0x09000000UL
#define UARTDR 0x000 // data register
#define UARTFR 0x018 // flag register 

void uart_init(void);
void uart_putc(char c);
char uart_getc(void);
int uart_has_data(void);

// string i/o
void uart_puts(const char *s);

// hex i/o
void uart_put_hexbyte(uint8_t byte);
void uart_put_hex32(uint32_t val, int loose);
void uart_put_hex64(uint64_t val, int loose);

// decimal i/o
void uart_put_u32(uint32_t val);
void uart_put_u64(uint64_t val);
void uart_put_int(int val);
void uart_put_percentage(uint64_t part, uint64_t total);
#endif
