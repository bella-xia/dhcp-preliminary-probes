#ifndef GPIO_H
#define GPIO_H


enum {
    GPIO_BASE       = 0x20200000,
    gpio_fun_sel0   = GPIO_BASE,
    gpio_fun_sel1   = (GPIO_BASE + 0x04),
    gpio_set0       = (GPIO_BASE + 0x1C),
    gpio_clr0       = (GPIO_BASE + 0x28),
    gpio_lev0       = (GPIO_BASE + 0x34),

    AUX_IRQ         = 0x20215000,
    AUX_ENABLES     = 0x20215004,

    UART_BASE       = 0x20215040,
    uart_io         = UART_BASE,
    uart_ier        = (UART_BASE + 0x04),
    uart_iir        = (UART_BASE + 0x08),
    uart_lcr        = (UART_BASE + 0x0C),
    uart_mcr        = (UART_BASE + 0x10),
    uart_lsr        = (UART_BASE + 0x14),
    uart_cntl       = (UART_BASE + 0x20),
    uart_stat       = (UART_BASE + 0x24),
    uart_baud       = (UART_BASE + 0x28),
};


void rmw_peripheral(unsigned mask_base, unsigned bits, unsigned shift, unsigned reg_addr);
void write_peripheral(unsigned bits, unsigned shift, unsigned reg_addr); 
unsigned read_peripheral(unsigned mask_base, unsigned shift, unsigned reg_addr);

#endif // gpio.h
