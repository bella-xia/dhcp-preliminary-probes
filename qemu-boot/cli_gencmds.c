#include "cli_cmds.h"
#include "uart.h"
#include "dhcp_server.h"
#include "kstring.h"
#include <stdlib.h>
#include <string.h>

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
    
    // DHCP-related
    uart_puts("  dhcp_init - Initialize DHCP server\n");
    uart_puts("  dhcp_leases - Show active DHCP leases\n");
    uart_puts("  dhcp_test - Simulate a DHCP discovery request\n");
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

/* Global DHCP server state */
// TODO: make it not static
static dhcp_lease_t g_leases[100];  /* Static lease pool. */
static dhcp_server_t g_dhcp_server;
static uint8_t g_server_initialized = 0;

/* DHCP CLI Commands */
void cmd_dhcp_init(const char *args UNUSED) {
    uart_puts("INIT:");
    if (g_server_initialized) {
        uart_puts("DHCP server already been initialized.\n");
        return;
    }
    
    uart_puts("1");
    /* Default configuration */
    dhcp_config_t config;
    // uart_puts("2");
    // Server IP: 192.168.1.1
    config.server_ip = ip_to_uint32(192, 168, 1, 1);
    // uart_puts("3");
    // subnet mask
    config.subnet_mask = ip_to_uint32(255, 255, 255, 0);
    // uart_puts("4");
    // gateway IP: 192.168.1.1
    config.gateway_ip = ip_to_uint32(192, 168, 1, 1);
    // uart_puts("5");
    // DNS address: 8.8.8.8
    config.dns_ip = ip_to_uint32(8, 8, 8, 8);
    // uart_puts("6");
    // Pool: 192.168.1.100 - 192.168.1.200
    config.pool_start = ip_to_uint32(192, 168, 1, 100);
    // uart_puts("7");
    config.pool_end = ip_to_uint32(192, 168, 1, 200);
    // uart_puts("8");
    config.lease_time = 3600;
    // uart_puts("9");
    
    /* Set the static lease pool */
    g_dhcp_server.leases = g_leases;
    // uart_puts("A");
    
    dhcp_init_server(&g_dhcp_server, &config, 100);
    // uart_puts("B");
    g_server_initialized = 1;
    // uart_puts("C");
    // TODO: not to hard code
    uart_puts("\nDHCP server initialized\n");
    uart_puts("  Server IP: 192.168.1.1\n");
    uart_puts("  Pool: 192.168.1.100 - 192.168.1.200\n");
    uart_puts("  Lease time: 3600 seconds\n");
}

void cmd_dhcp_leases(const char *args UNUSED) {
    if (!g_server_initialized) {
        uart_puts("DHCP server not initialized\n");
        return;
    }
    
    uart_puts("Active DHCP Leases:\n");
    
    for (uint16_t i = 0; i < g_dhcp_server.lease_count; i++) {
        dhcp_lease_t *lease = &g_dhcp_server.leases[i];
        
        if (lease->in_use) {
            uint8_t a, b, c, d;
            uint32_to_ip(lease->ip_address, &a, &b, &c, &d);
            
            uart_puts("  ");
            uart_put_int(a);
            uart_puts(".");
            uart_put_int(b);
            uart_puts(".");
            uart_put_int(c);
            uart_puts(".");
            uart_put_int(d);
            uart_puts("  ");
            
            uart_put_hexbyte(lease->mac_address[0]);
            uart_putc(':');
            uart_put_hexbyte(lease->mac_address[1]);
            uart_putc(':');
            uart_put_hexbyte(lease->mac_address[2]);
            uart_putc(':');
            uart_put_hexbyte(lease->mac_address[3]);
            uart_putc(':');
            uart_put_hexbyte(lease->mac_address[4]);
            uart_putc(':');
            uart_put_hexbyte(lease->mac_address[5]);
            uart_puts("\n");
        }
    }
    
    uart_puts("Total: ");
    uart_put_int(g_dhcp_server.lease_count);
    uart_puts("/");
    uart_put_int(g_dhcp_server.max_leases);
    uart_puts("\n");
}

/* Global variable for testing */
uint16_t MAC1 = 0xAA;
uint16_t MAC2 = 0xBB;
uint16_t MAC3 = 0xCC;
uint16_t MAC4 = 0xDD;
uint16_t MAC5 = 0xEE;
uint16_t MAC6 = 0x00;

void cmd_dhcp_test(const char *args UNUSED) {
    if (!g_server_initialized) {
        uart_puts("DHCP server not initialized\n");
        return;
    }
    
    uart_puts("TEST_V2: Simulating DHCP DISCOVER + REQUEST...\n");
    
    /* Create mock DHCP messages */
    static dhcp_message_t discover;
    // uart_puts("1");
    static dhcp_message_t discover_response;
    // uart_puts("2");
    static dhcp_message_t request;
    // uart_puts("3");
    static dhcp_message_t request_response;
    // uart_puts("4");
    
    kmemset(&discover, 0, sizeof(dhcp_message_t));
    // uart_puts("5");
    kmemset(&discover_response, 0, sizeof(dhcp_message_t));
    // uart_puts("6");
    kmemset(&request, 0, sizeof(dhcp_message_t));
    // uart_puts("7");
    kmemset(&request_response, 0, sizeof(dhcp_message_t));
    // uart_puts("8");
    
    /* Set up DISCOVER message */
    discover.op = 1;                    /* BOOTREQUEST */
    // uart_puts("9");
    discover.htype = 1;                 /* Ethernet */
    // uart_puts(" 10");
    discover.hlen = 6;                  /* MAC address length */
    // uart_puts(" 11");
    discover.hops = 0;
    // uart_puts(" 12");
    discover.xid = 0x12345678;          /* Transaction ID */
    // uart_puts(" 13");
    discover.secs = 0;
    // uart_puts(" 14");
    discover.flags = 0;
    // uart_puts(" 15");
    discover.ciaddr = 0;
    // uart_puts(" 16");
    discover.yiaddr = 0;
    // uart_puts(" 17");
    discover.siaddr = 0;
    // uart_puts(" 18");
    discover.giaddr = 0;
    // uart_puts(" 19");
    
    /* Test MAC address: AA:BB:CC:DD:EE:FF */
    discover.chaddr[0] = MAC1;
    discover.chaddr[1] = MAC2;
    discover.chaddr[2] = MAC3;
    discover.chaddr[3] = MAC4;
    discover.chaddr[4] = MAC5;
    discover.chaddr[5] = MAC6;
    MAC6 += 1;
    
    discover.magic_cookie = DHCP_MAGIC_COOKIE;
    
    /* Add DISCOVER message type */
    uint8_t discover_type = DHCP_DISCOVER;
    dhcp_add_option(&discover, DHCP_OPT_MESSAGE_TYPE, 1, &discover_type);
    
    /* Process DISCOVER */
    uart_puts("  Sending DISCOVER...\n");
    dhcp_process_message(&g_dhcp_server, &discover, &discover_response);
    
    /* Extract offered IP from OFFER response (use numeric yiaddr) */
    uint32_t offered_ip = discover_response.yiaddr;

    if (offered_ip == 0) {
        uart_puts("  ERROR: No IP offered!\n");
        return;
    }
    
    uart_puts("  IP offered: ");
    uart_put_int((offered_ip >> 24) & 0xFF);
    uart_putc('.');
    uart_put_int((offered_ip >> 16) & 0xFF);
    uart_putc('.');
    uart_put_int((offered_ip >> 8) & 0xFF);
    uart_putc('.');
    uart_put_int(offered_ip & 0xFF);
    uart_puts("\n");
    
    /* Set up REQUEST message */
    request.op = 1;
    request.htype = 1;
    request.hlen = 6;
    request.hops = 0;
    request.xid = 0x12345678;
    request.secs = 1;
    request.flags = 0;
    request.ciaddr = 0;
    request.yiaddr = 0;
    request.siaddr = 0;
    request.giaddr = 0;
    
     /* Same MAC address */
     kmemcpy(request.chaddr, discover.chaddr, 6);
     request.magic_cookie = DHCP_MAGIC_COOKIE;

     /* Add REQUEST message type and requested IP option; ensure option bytes
         are in network byte order (big-endian) */
     uint8_t request_type = DHCP_REQUEST;
     dhcp_add_option(&request, DHCP_OPT_MESSAGE_TYPE, 1, &request_type);
     uint8_t requested_ip_bytes[4];
     requested_ip_bytes[0] = (offered_ip >> 24) & 0xFF;
     requested_ip_bytes[1] = (offered_ip >> 16) & 0xFF;
     requested_ip_bytes[2] = (offered_ip >> 8) & 0xFF;
     requested_ip_bytes[3] = offered_ip & 0xFF;
     dhcp_add_option(&request, DHCP_OPT_REQUESTED_IP, 4, requested_ip_bytes);
    
    /* Process REQUEST */
    uart_puts("  Sending REQUEST...\n");
    dhcp_process_message(&g_dhcp_server, &request, &request_response);
    
    uart_puts("Lease allocation complete. Active leases:\n");
    cmd_dhcp_leases("");
}

