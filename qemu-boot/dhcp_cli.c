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
    
    dhcp_init_server(&g_dhcp_server, &config, 100);
    g_server_initialized = 1;
    
    uart_printf("DHCP server initialized\n");
    uart_printf("  Server IP: 192.168.1.1\n");
    uart_printf("  Pool: 192.168.1.100 - 192.168.1.200\n");
    uart_printf("  Lease time: 3600 seconds\n");
    
    return 0;
}

/* Configure DHCP server parameters */
int dhcp_config_cmd(int argc, char *argv[]) {
    if (argc < 3) {
        uart_printf("Usage: dhcp_config <param> <value>\n");
        uart_printf("Parameters:\n");
        uart_printf("  server_ip <a.b.c.d>\n");
        uart_printf("  pool_start <a.b.c.d>\n");
        uart_printf("  pool_end <a.b.c.d>\n");
        uart_printf("  lease_time <seconds>\n");
        return -1;
    }
    
    char *param = argv[1];
    char *value = argv[2];
    
    if (strcmp(param, "server_ip") == 0) {
        /* Parse IP address */
        uint8_t a, b, c, d;
        if (sscanf(value, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) == 4) {
            g_dhcp_server.config.server_ip = ip_to_uint32(a, b, c, d);
            uart_printf("Server IP set to %s\n", value);
        } else {
            uart_printf("Invalid IP address format\n");
            return -1;
        }
    }
    else if (strcmp(param, "lease_time") == 0) {
        g_dhcp_server.config.lease_time = atoi(value);
        uart_printf("Lease time set to %d seconds\n", g_dhcp_server.config.lease_time);
    }
    
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
    
    for (uint16_t i = 0; i < g_dhcp_server.lease_count; i++) {
        dhcp_lease_t *lease = &g_dhcp_server.leases[i];
        
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
    
    uart_printf("Total leases: %d/%d\n", g_dhcp_server.lease_count, g_dhcp_server.max_leases);
    
    return 0;
}

/* Release a lease by MAC address */
int dhcp_release_cmd(int argc, char *argv[]) {
    if (argc < 2) {
        uart_printf("Usage: dhcp_release <mac_address> (format: xx:xx:xx:xx:xx:xx)\n");
        return -1;
    }
    
    if (!g_server_initialized) {
        uart_printf("DHCP server not initialized\n");
        return -1;
    }
    
    uint8_t mac[6];
    if (sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        uart_printf("Invalid MAC address format\n");
        return -1;
    }
    
    dhcp_lease_t *lease = dhcp_find_lease(&g_dhcp_server, mac);
    if (lease) {
        lease->in_use = 0;
        uart_printf("Lease released\n");
        return 0;
    } else {
        uart_printf("Lease not found\n");
        return -1;
    }
}

/* Show DHCP statistics */
int dhcp_stats_cmd(int argc, char *argv[]) {
    if (!g_server_initialized) {
        uart_printf("DHCP server not initialized\n");
        return -1;
    }
    
    uint32_t total_ips = g_dhcp_server.config.pool_end - g_dhcp_server.config.pool_start + 1;
    uint32_t available_ips = total_ips - g_dhcp_server.lease_count;
    
    uart_printf("DHCP Server Statistics:\n");
    uart_printf("Total IPs in pool: %d\n", total_ips);
    uart_printf("Allocated IPs: %d\n", g_dhcp_server.lease_count);
    uart_printf("Available IPs: %d\n", available_ips);
    uart_printf("Pool utilization: %d%%\n", 
               (g_dhcp_server.lease_count * 100) / total_ips);
    
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
