#ifndef UART_H
#define UART_H

#include <stdint.h>

void uart_init(void);
void uart_putc(char c);
char uart_getc(void);
int uart_tx_avail(void);
int uart_rx_avail(void);

// string i/o
void uart_puts(const char *s);

// hex i/o
void uart_put_hexbyte(uint8_t byte);
void uart_put_hex32(uint32_t val, int loose);

// decimal i/o
void uart_put_u32(uint32_t val);
void uart_put_int(int val);
void uart_put_percentage(uint32_t part, uint32_t total);
#endif
