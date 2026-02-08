#include "uart.h"
#include "gpio.h"
#include "mmio.h"

// returns:
//  - 1 if TX FIFO empty AND idle.
//  - 0 if not empty.
int uart_tx_empty(void) {
    // LSR bit 6 denotes whether the tx FIFO is empty AND idle
    dev_barrier();
    int tx_idle = read_peripheral(0b1, 6, uart_lsr);
    return tx_idle != 0;
}

// returns 1 if the hardware TX (output) FIFO has room
// for at least one byte.  returns 0 otherwise.
int uart_tx_avail(void) {
    // READ
    // bit 1 of stat register indicates whether there is space available
    dev_barrier();
    int space_avail = read_peripheral(0b1, 1, uart_stat);
    return space_avail != 0;
}

// returns:
//  - 1 if at least one byte on the hardware RX FIFO.
//  - 0 otherwise
int uart_rx_avail(void) {
    // READ
    // bit 0 of stat register indicates whether there is symbol available
    dev_barrier();
    int symbol_avail = read_peripheral(0b1, 0, uart_stat);
    return symbol_avail != 0;
}

// return only when the TX FIFO is empty AND the
// TX transmitter is idle.  
void uart_flush_tx(void) {
    while(!uart_tx_empty())
        kwait();
}

void uart_init(void) {
    // 1. set GPIO
    // set 14, 15 FUNC SELECT to ALT5
    // READ-MODIFY-WRITE
    // push two 5 (alt fun 5) starting bit 12
    dev_barrier();
    rmw_peripheral(0b111, 0b010, 12, gpio_fun_sel1);
    rmw_peripheral(0b111, 0b010, 15, gpio_fun_sel1);
    dev_barrier();

    // 2. set AUXENB
    // READ-MODIFY-WRITE
    // set bit 0 to 1 to enable Mini UART
    rmw_peripheral(0b1, 0b1, 0, AUX_ENABLES);
    dev_barrier();
     
    // 3. before doing anything, disable uart
    write_peripheral(0, 0, uart_cntl);

    // 4.1. clean transmitter and reciever FIFO??
    // WRITE 
    // set bit 1 and set 2 to 1 to clear
    // baud rate is irrelevant since we are not using DLAB
    write_peripheral(0b11, 1, uart_iir);

    // 4.2. disable interrupt by cleaning ier
    // WRITE
    write_peripheral(0, 0, uart_ier);

    // 5.1. set baud rate
    // WRITE
    // set bits 0-15 to expected baud rate
    write_peripheral(270, 0, uart_baud);

    // 5.2. set 8n1 configuration
    // WRITE
    // set bits 0 and 1 to 1
    // clear DLAB to 0
    write_peripheral(0b11, 0, uart_lcr);

    // 5.3 clear all modem signal configuration
    write_peripheral(0, 0, uart_mcr);
    
    // 6. re-enable uart tx and rx
    // WRITE
    write_peripheral(0b11, 0, uart_cntl);
    dev_barrier();
}

// disable the uart: make sure all bytes have been
// flushed 
void uart_disable(void) {
    
    uart_flush_tx();
    dev_barrier();

    unsigned mask_base = 0b1, bits = 0x0, shift = 0;
    rmw_peripheral(mask_base, bits, shift, AUX_ENABLES);
    dev_barrier();
}

// returns one byte from the RX (input) hardware
// FIFO.  if FIFO is empty, blocks until there is 
// at least one byte.
unsigned char uart_getbyte(void) {
    while (!uart_rx_avail())
        kwait();

    // uart io register
    // READ
    // bits 0-7 holds next byte of data to read/write
    dev_barrier();
    unsigned mask_base = 0xFF, shift = 0;
    unsigned b = read_peripheral(mask_base, shift, uart_io);
    return (unsigned char)b;
}

char uart_getc(void) {
    return (char) uart_getbyte();
}

// put one byte on the TX FIFO, if necessary, waits
// until the FIFO has space.
void uart_putbyte(unsigned char b) {
    while (!uart_tx_avail())
        kwait();
    
    // uart io register
    // WRITE
    // bits 0-7 holds next byte of data to read/write
    write_peripheral(b, 0, uart_io);
    dev_barrier();
}

void uart_putc(char c) {
    uart_putbyte((unsigned char)c);
}

