#include "mmio.h"
#include "uart.h"
#include "timer.h"
#include "kstring.h"
#include "handshake.h"

#define MAX_READ 15
#define RESPONSE "ACK"

static unsigned has_data_timeout(unsigned timeout) {
    unsigned start = timer_get_usec();
    while (timer_get_usec() - start < timeout) {
        if (uart_rx_avail()) return 1;
        kwait();
    }
    return 0;
}

void put_handshake(unsigned usec_timeout) {
    while (!has_data_timeout(usec_timeout))
        uart_puts("BOOT\n");
}

unsigned get_handshake(void) {
    char st[MAX_READ];
    unsigned i = 0, min_len;
    while (i < MAX_READ && uart_rx_avail())
        st[i++] = uart_getc();
    
    min_len = (i < kstrlen(RESPONSE)) ? i : kstrlen(RESPONSE); 
    return (kstrncmp(st, RESPONSE, min_len) == 0);
}
