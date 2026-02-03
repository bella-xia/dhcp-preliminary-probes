#include "uart.h"
#include "kstring.h"

#define MAX_BUF 128

void main(void) {
    uart_init();
    uart_puts("Hello, minimal bootloader!\n");
    uart_puts("Simple CLI - type 'help for commands\n");
    uart_puts("u-boot> ");
    
    char buf[MAX_BUF];
    int index = 0;

    while (1) {
        char c = uart_getc();
        uart_putc(c);

        if (c == '\r' || c == '\n') {
            uart_puts("\n");
            buf[index] = '\0';

            if (index > 0) {
                if (strncmp(buf, "help", strlen("help")) == 0) {
                    uart_puts("Available commands:\n");
                    uart_puts("  help - Show this help\n");
                    uart_puts("  echo - Echo back user input\n");
                }
                else if (strncmp(buf, "echo", strlen("echo")) == 0) {
                    uart_puts((const char *)(buf + 5));
                    uart_puts("\n");
                }
                else {
                    uart_puts("Unknown command: ");
                    uart_puts(buf);
                    uart_puts("\n");
                }
            }
            index = 0;
            uart_puts("u-boot> ");
        } else if (c == 127 || c == 8) {
            // backspace or delete
            if (index > 0)
                index--;
            uart_puts("\b \b");
        } else if (index < 127) {
            buf[index++] = c;
        }
    } 
}
