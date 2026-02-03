#include "uart.h"

static inline void mmio_write(uint64_t reg, uint32_t val) {
    *(volatile uint32_t *)reg = val;
}

static inline uint32_t mmio_read(uint64_t reg) {
    return *(volatile uint32_t *)reg;
}


void uart_init(void) {
    // QEMU virt UART is always initialized
}

void uart_putc(char c) {
    // wait until TX is empty
    while (mmio_read(UART0_BASE + UARTFR) & (1 << 5));
    mmio_write(UART0_BASE + UARTDR, c);
}


void uart_puts(const char *s) {
    while (*s) {
        if (*s == '\n') 
            uart_putc('\r');
        uart_putc(*s++);
    }
}

char uart_getc(void) {
    while (mmio_read(UART0_BASE + UARTFR) & (1 << 4));
    return (char)mmio_read(UART0_BASE + UARTDR);
}

int uart_has_data(void) {
    return !(mmio_read(UART0_BASE + UARTFR) & (1 << 4));
}
