#include "cli_cmds.h"
#include "uart.h"
#include "cli_utils.h"

#define TOTAL_STACK 0x10000 // 64 kb configed in linker
#define TOTAL_RAM 8 * 1024 * 1024 // total memory 8M configed in linker

#define PTR(x) ((uintptr_t)(x))
#define PRINT_HEX(x) uart_put_hex64(PTR(x), 1)

#define PRINT_BYTES(x)                      \
    do {                                    \
        PRINT_HEX(x);                       \
        uart_puts(" bytes");                \
    } while (0)

#define PRINT_PERCENT(part, total)          \
    do {                                    \
        uart_putc('(');                     \
        uart_put_percentage(part, total);   \
        uart_putc(')');                     \
    } while (0)

#define PRINT_REGION(name, start, end)      \
    do {                                    \
        uintptr_t _s = PTR(start);          \
        uintptr_t _e = PTR(end);            \
        uart_puts(" " name " : ");          \
        PRINT_HEX(_s);                      \
        uart_puts(" - ");                   \
        PRINT_HEX(_e);                      \
        uart_puts(" (");                    \
        PRINT_HEX(_e - _s);                 \
        uart_puts(" bytes)\n");             \
    } while (0)

#define PRINT_USAGE(label, used, total)     \
    do {                                    \
        uart_puts(" " label ": ");          \
        PRINT_HEX(used);                    \
        uart_puts(" bytes ");               \
        PRINT_PERCENT(used, total);         \
        uart_putc('\n');                    \
    } while (0)

static int is_printable(char c) {
    return (c >= 0x20 && c <= 0x7e);
}


void cmd_hexdump(const char *args) {
    // parse: hexdump <addr> <len>
    // skip leading spaces

    uint64_t addr = parse_hex(args);

    while (*args && *args != ' ') args++;  // get rid of first argument
    while (*args == ' ') args++; // get rid of space between arguments

    uint64_t len = parse_dec(args);

    if (len == 0 || len > 4096) {
        uart_puts("Invalid length (max 4096)\n");
        return;
    }

    uint8_t *ptr = (uint8_t *)addr;

    for (uint64_t i = 0; i < len; i += 16) {
        uart_put_hex64((uint64_t)(ptr + i), 0);
        uart_puts(": ");

        // print hex bytes
        for (int j = 0; j < 16; j++) {
            if (i + j < len) {
                uart_put_hexbyte(ptr[i+j]);
                uart_putc(' ');
            } else {
                uart_puts("   "); // end of hexdump len
            }
            // extra space in the middle
            if (j == 7) 
                uart_putc(' ');
        }

        uart_puts("| ");

        // print ASCII representation
        for (int j = 0; j < 16 && i + j < len; j++) {
            char c = ptr[i+j];
            uart_putc(is_printable(c) ? c : '.');
        }
        uart_puts("\n");
    }
}

void cmd_dump32(const char *args) {
    // parse: dump32 <addr> <len>

    uint64_t addr = parse_hex(args);

    while (*args && *args != ' ') args++;  // get rid of first argument
    while (*args == ' ') args++; // get rid of space between arguments

    uint64_t cnt = parse_dec(args);

    if (cnt == 0 || cnt > 1024) {
        uart_puts("Invalid count (max 1024)\n");
        return;
    }

    uint32_t *ptr = (uint32_t *)addr;

    for (uint64_t i = 0; i < cnt; i ++) {
        if (i % 4 == 0) {
            if (i > 0) uart_puts("\n");
            uart_put_hex64((uint64_t)&ptr[i], 0);
            uart_puts(": ");
        }
        uart_put_hex32(ptr[i], 0);
        uart_putc(' ');
    }
    uart_puts("\n");
}

void cmd_peek(const char *args) {
    // parse: peek <addr>
    uint64_t addr = parse_hex(args);

    if (addr == 0 && *args != '0') {
        uart_puts("invalid address\n");
        return;
    }

    uint32_t *ptr = (uint32_t *)addr;
    uint32_t val = *ptr;

    uart_put_hex64(addr, 0);
    uart_puts(": ");
    uart_put_hex32(val, 0);
    uart_puts("\n");
}

void cmd_info(const char *args UNUSED) {
    extern char __text_start, __text_end;
    extern char __rodata_start, __rodata_end;
    extern char __data_start, __data_end;
    extern char __bss_start, __bss_end;
    extern char _stack_top;

    uart_puts("==== Bootloader Info ====\n");

    uintptr_t _stack_bottom = (uintptr_t)&_stack_top - TOTAL_STACK;
    PRINT_REGION(".text  ",     &__text_start,      &__text_end);
    PRINT_REGION(".rodata",     &__rodata_start,    &__rodata_end);
    PRINT_REGION(".data  ",     &__data_start,      &__data_end);
    PRINT_REGION(".bss   ",     &__bss_start,       &__bss_end);
    PRINT_REGION("stack  ",     _stack_bottom,      &_stack_top); 
}

void cmd_usage(const char *args UNUSED) {
    extern char _stack_top;
    extern char __text_start, __bss_end;
    
    uintptr_t sp, st_used, st_free;
    asm volatile("mov %0, sp": "=r"(sp));
    st_used = (uintptr_t)&_stack_top - sp;
    st_free = TOTAL_STACK - st_used;

    uintptr_t static_size, reserved_ram, free_ram;
    reserved_ram = (uintptr_t) &_stack_top - (uintptr_t) &__text_start;
    free_ram = TOTAL_RAM - reserved_ram; 
    static_size = (uintptr_t) &__bss_end - (uintptr_t)&__text_start; 

    uart_puts("==== Usage Stats ====\n");

    PRINT_USAGE("stack allocated", TOTAL_STACK, TOTAL_STACK);
    PRINT_USAGE("stack used", st_used, TOTAL_STACK);
    PRINT_USAGE("stack free", st_free, TOTAL_STACK);
    uart_putc('\n');

    PRINT_USAGE("total memory size", TOTAL_RAM, TOTAL_RAM);
    PRINT_USAGE("static segment mapped", static_size, TOTAL_RAM);
    PRINT_USAGE("dynamic stack allocated", TOTAL_STACK, TOTAL_RAM);
    PRINT_USAGE("total memory reserved", reserved_ram, TOTAL_RAM);
    PRINT_USAGE("total memory free", free_ram, TOTAL_RAM);
}

