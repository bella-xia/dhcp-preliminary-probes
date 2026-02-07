#include "cli_cmds.h"
#include "uart.h"

extern void hang(void);

void cmd_help(const char *args UNUSED) {
    uart_puts("Available commands:\n");
    
    // general
    uart_puts("  help - Show this help\n");
    uart_puts("  echo <input> - Echo back <input>\n");
    uart_puts("  exit - Exit terminal\n");
    uart_puts("  clear - Clear terminal history\n");

    // memory-related 
    uart_puts("  info - Provides info on memory alignment\n");
    uart_puts("  usage - Provides snapshot on current RAM and stack usage\n");
    uart_puts("  peek <addr> - Display 32-bit word at specified <addr>\n");
    uart_puts("  hexdump <addr> <len> - Dump <len> bytes of memory starting <addr>\n");
    uart_puts("  dump32 <addr> <count> - Dump <count> 32-bit words starting <addr>\n"); 
}

void cmd_exit(const char *args UNUSED) {
    uart_puts("exiting... (still requires Ctrl-a + x to exit qemu)\n");
    hang();
}
void cmd_clear(const char *args UNUSED) {
    uart_puts("\033[2J\033[H");
}

void cmd_echo(const char *args) {
    uart_puts(args);
    uart_puts("\n");
}

void cmd_unknow(const char *args) {
    uart_puts("Unknown command: ");
    uart_puts(args);
    uart_puts("\n");
}
