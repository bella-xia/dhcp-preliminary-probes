#include "dhcp_server.h"
#include "cli_utils.h"

static dhcp_server_t g_dhcp_server;
static uint8_t g_server_initialized = 0;

/* Initialize DHCP server with default configuration */
int dhcp_init_cmd(int argc, char *argv[]) {
    if (g_server_initialized) {
        uart_printf("DHCP server already initialized\n");
        return 0;
    }
    
    /* Default configuration */
    dhcp_config_t config = {
        .server_ip = ip_to_uint32(192, 168, 1, 1),      /* 192.168.1.1 */
        .subnet_mask = ip_to_uint32(255, 255, 255, 0),  /* 255.255.255.0 */
        .gateway_ip = ip_to_uint32(192, 168, 1, 1),     /* 192.168.1.1 */
        .dns_ip = ip_to_uint32(8, 8, 8, 8),             /* 8.8.8.8 */
        .pool_start = ip_to_uint32(192, 168, 1, 100),   /* 192.168.1.100 */
        .pool_end = ip_to_uint32(192, 168, 1, 200),     /* 192.168.1.200 */
        .lease_time = 3600,                              /* 1 hour */
    };
    
    dhcp_init_server_table(&g_dhcp_server, &config, 100);
    g_server_initialized = 1;
    
    uart_printf("DHCP server initialized\n");
    uart_printf("  Server IP: 192.168.1.1\n");
    uart_printf("  Pool: 192.168.1.100 - 192.168.1.200\n");
    uart_printf("  Lease time: 3600 seconds\n");
    
    return 0;
}

/* Show DHCP leases */
int dhcp_leases_cmd(int argc, char *argv[]) {
    if (!g_server_initialized) {
        uart_printf("DHCP server not initialized\n");
        return -1;
    }
    
    uart_printf("Active DHCP Leases:\n");
    uart_printf("IP Address\t\tMAC Address\t\t\tXID\n");
    uart_printf("--------\t\t-----------\t\t\t---\n");
    
    for (uint16_t i = 0; i < g_dhcp_server.pool.table.lease_count; i++) {
        dhcp_lease_t *lease = &g_dhcp_server.pool.table.leases[i];
        
        if (lease->in_use) {
            uint8_t a, b, c, d;
            uint32_to_ip(lease->ip_address, &a, &b, &c, &d);
            
            uart_printf("%d.%d.%d.%d\t\t", a, b, c, d);
            uart_printf("%02x:%02x:%02x:%02x:%02x:%02x\t\t", 
                       lease->mac_address[0], lease->mac_address[1],
                       lease->mac_address[2], lease->mac_address[3],
                       lease->mac_address[4], lease->mac_address[5]);
            uart_printf("0x%x\n", lease->xid);
        }
    }
    
    uart_printf("Total leases: %d/%d\n", g_dhcp_server.pool.table.lease_count,
                                         g_dhcp_server.pool.table.max_leases);
    
    return 0;
}

/* IP address utility helper */
uint32_t ip_to_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

/* IP address parsing helper */
void uint32_to_ip(uint32_t ip, uint8_t *a, uint8_t *b, uint8_t *c, uint8_t *d) {
    *a = (ip >> 24) & 0xFF;
    *b = (ip >> 16) & 0xFF;
    *c = (ip >> 8) & 0xFF;
    *d = ip & 0xFF;
}
