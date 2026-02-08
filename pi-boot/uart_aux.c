#include "uart.h"

#define HEX "0123456789abcdef"
#define HEX64_BOUND 60
#define HEX32_BOUND 28

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
    uint32_t v32;
    if (val < 0) {
        uart_putc('-');
        v32 = ~((uint32_t)val) + 1;
    } else {
        v32 = val;
    }
    uart_put_u32(v32);
}

void uart_put_percentage(uint32_t part, uint32_t total) {
    if (total == 0) {
        uart_puts("0%");
        return;
    }
    uint32_t percent = 0;
    part *= 100;
    while (part >= total) {
        part -= total;
        percent++;
    }
    uart_put_u32(percent);
    uart_putc('%');
}
