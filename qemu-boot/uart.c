#include "uart.h"


#define HEX "0123456789abcdef"
#define HEX64_BOUND 60
#define HEX32_BOUND 28


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

char uart_getc(void) {
    while (mmio_read(UART0_BASE + UARTFR) & (1 << 4));
    return (char)mmio_read(UART0_BASE + UARTDR);
}

int uart_has_data(void) {
    return !(mmio_read(UART0_BASE + UARTFR) & (1 << 4));
}

/* ==========  STRING RELATED OPERATIONS ========= */
void uart_puts(const char *s) {
    while (*s) {
        if (*s == '\n') 
            uart_putc('\r');
        uart_putc(*s++);
    }
}

/* ========== HEX RELATED OPERATIONS ========== */
void uart_put_hexbyte(uint8_t byte) {
    uart_putc(HEX[byte >> 4]);
    uart_putc(HEX[byte & 0x0F]);
}

void uart_put_hex64(uint64_t val, int loose) {
    uart_puts("0x");
    int start = 0;
    for (int i = HEX64_BOUND; i >= 0; i -= 4) {
        if (loose && !start) {
            if ((val >> i) == 0)
                continue;
            start = 1;
        }
        uart_putc(HEX[(val >> i) & 0xF]);
    }
    if (loose && !start)
        uart_putc('0');
}

void uart_put_hex32(uint32_t val, int loose) {
    uart_puts("0x");
    int start = 0;
    for (int i = HEX32_BOUND; i >= 0; i -= 4) {
        if (loose && !start) {
            if ((val >> i) == 0)
                continue;
            start = 1;
        }
        uart_putc(HEX[(val >> i) & 0xF]);
    }
    if (loose && !start)
        uart_putc('0');
}

/* ========== DECIMAL RELATED OPERATIONS ========= */
void uart_put_u64(uint64_t val) {
    char buf[20];
    unsigned i = 0;

    if (val == 0) {
        uart_putc('0');
        return;
    }

    while (val > 0) {
        buf[i++] = '0' + (val % 10);
        val  /= 10;
    }

    for (int j = i-1; j >= 0; j--) 
        uart_putc(buf[j]);
}

void uart_put_u32(uint32_t val) {
    char buf[10];
    unsigned i = 0;

    if (val == 0) {
        uart_putc('0');
        return;
    }

    while (val > 0) {
        buf[i++] = '0' + (val % 10);
        val  /= 10;
    }

    for (int j = i-1; j >= 0; j--) 
        uart_putc(buf[j]);
}

void uart_put_int(int val) {
    if (val < 0) {
        uart_putc('-');
        val = -val;
    }
    uart_put_u32((uint32_t)val);
}

void uart_put_percentage(uint64_t part, uint64_t total) {
    if (total == 0) {
        uart_puts("0%");
        return;
    }
    uint64_t percent = (part * 100) / total;
    uart_put_u64(percent);
    uart_putc('%');
}
