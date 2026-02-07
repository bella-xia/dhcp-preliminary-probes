#include "cli_utils.h"

static int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

uint64_t parse_hex(const char *str) {
    uint64_t res = 0;
    int digit;

    // skip "0x" prefix is any
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) 
        str += 2;
    
    while (*str) {
       digit = hex_to_int(*str); 
       if (digit < 0) break; // encouter other element, meaning the hex terminates
       res <<= 4;
       res += digit;
       str++;
    }
    return res;
}


uint64_t parse_dec(const char *str) {
    uint64_t res = 0;
    int digit;
    
    while (*str) {
       digit = *str - '0'; 
       res *= 10;
       res += digit;
       str++;
    }
    return res; 
}
