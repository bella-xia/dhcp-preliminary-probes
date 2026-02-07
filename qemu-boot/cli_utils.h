#ifndef CLI_UTILS_H
#define CLI_UTILS_H

#include <stdint.h>
#include <stddef.h>

// parse hex string to uint64_t
uint64_t parse_hex(const char *str);

// parse decimal string to uint64_t
uint64_t parse_dec(const char *str);


#endif // cli_utils.h
