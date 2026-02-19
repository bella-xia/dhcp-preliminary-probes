#ifndef CLI_CMDS_H
#define CLI_CMDS_H

#define UNUSED __attribute__((unused))
// general cmds
void cmd_exit(const char *args UNUSED);
void cmd_clear(const char *args UNUSED);
void cmd_help(const char *args UNUSED);
void cmd_echo(const char *args);
void cmd_unknow(const char *args);

// memory related
void cmd_info(const char *args UNUSED);
void cmd_usage(const char *args UNUSED);
void cmd_peek(const char *args);
void cmd_hexdump(const char *args);
void cmd_dump32(const char *args);

// DHCP-related
void cmd_dhcp_init(const char *args UNUSED);
void cmd_dhcp_leases(const char *args UNUSED);
void cmd_dhcp_test(const char *args UNUSED);

// network related
void cmd_virtio_init(const char *args UNUSED);
void cmd_virtio_test(const char *args UNUSED);

// packet parser and builder related
void cmd_parser_test(const char *args UNUSED);

// UNIMPLEMENTED
#if 0
void cmd_poke(const char *args);
void cmd_test(void); 
#endif

#endif
