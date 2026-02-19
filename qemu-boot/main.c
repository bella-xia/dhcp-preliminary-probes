#include "uart.h"
#include "kstring.h"
#include "cli_cmds.h"

#define MAX_BUF 128

extern void hang(void);

typedef void (*cmd_fn_t)(const char *args);
struct command {
    const char *name;
    cmd_fn_t fn;
    unsigned arg_offset;
};

static const struct command commands[] = {
    // general cli
    {"exit",    cmd_exit,       0},
    {"clear",   cmd_clear,      0},
    {"help",    cmd_help,       0},
    {"echo",    cmd_echo,       5},
    
    // memory-related cli
    {"info",    cmd_info,       0},
    {"usage",   cmd_usage,      0},
    {"hexdump", cmd_hexdump,    8},
    {"dump32",  cmd_dump32,     7},
    {"peek",    cmd_peek,       5},
    
    // DHCP-related cli
    {"dhcp_init",    cmd_dhcp_init,      0},
    {"dhcp_leases",  cmd_dhcp_leases,    0},
    {"dhcp_test",    cmd_dhcp_test,      0},
    

    // network-related cli
    {"virtio_init", cmd_virtio_init, 0},
    {"virtio_test", cmd_virtio_test, 0},

    // packet-parser-builder-related
    {"parser_test",  cmd_parser_test, 0}, 
};

void main(void) {
    uart_init();
    uart_puts("Hello, minimal bootloader!\n");
    uart_puts("Simple CLI - type 'help' for commands\n");
    uart_puts("u-boot> ");
    
    char buf[MAX_BUF];
    int index = 0, paired = 0;
    unsigned n_cmds = sizeof(commands) / sizeof(struct command);

    while (1) {
        char c = uart_getc();
        uart_putc(c);

        if (c == '\r' || c == '\n') {
            uart_puts("\n");
            buf[index] = '\0';
            paired = 0;

            if (index > 0) {

                for (unsigned i = 0; i < n_cmds; i++) {
                    const struct command *c = &commands[i];
                    if (kstrncmp(buf, c->name, kstrlen(c->name)) == 0) {
                        c->fn(buf + c->arg_offset);
                        paired = 1;
                        break;
                    }
                }
                if (!paired)
                    cmd_unknow(buf);
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
