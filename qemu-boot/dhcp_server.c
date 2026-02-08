#include "dhcp_server.h"
#include "kstring.h"
#include <stdio.h>
#include "uart.h"
/* Helper function to convert integer to IP address bytes */
void uint32_to_ip(uint32_t ip, uint8_t *a, uint8_t *b, uint8_t *c, uint8_t *d) {
    *a = (ip >> 24) & 0xFF;
    *b = (ip >> 16) & 0xFF;
    *c = (ip >> 8) & 0xFF;
    *d = ip & 0xFF;
}

uint32_t ip_to_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

/* Initialize the DHCP server */
void dhcp_init_server(dhcp_server_t *server, dhcp_config_t *config, uint16_t max_leases) {
    // TODO: some how it doesn't work without printing the debug messages. 
    // extern void uart_puts(const char *s);
    // uart_puts("[S]");
    
    server->max_leases = max_leases;
    // uart_puts("[1]");
    server->lease_count = 0;
    // uart_puts("[2]");
    
    /* Note: leases array should be allocated by caller or use static storage */
    if (server->leases) {
        // uart_puts("[3]");
        for (uint16_t i = 0; i < max_leases; i++) {
            server->leases[i].in_use = 0;
        }
        // uart_puts("[4]");
    }
    
    // uart_puts("[5]");
    server->config.server_ip = config->server_ip;
    // uart_puts("[6]");
    server->config.subnet_mask = config->subnet_mask;
    // uart_puts("[7]");
    server->config.gateway_ip = config->gateway_ip;
    // uart_puts("[8]");
    server->config.dns_ip = config->dns_ip;
    // uart_puts("[9]");
    server->config.pool_start = config->pool_start;
    // uart_puts("[10]");
    server->config.pool_end = config->pool_end;
    // uart_puts("[11]");
    server->config.lease_time = config->lease_time;
    // uart_puts("[E]\n");
}

/* Get the DHCP message type from options */
uint8_t dhcp_get_message_type(dhcp_message_t *msg) {
    uint8_t length = 0;
    uint8_t *opt = dhcp_get_option(msg, DHCP_OPT_MESSAGE_TYPE, &length);
    
    if (opt && length >= 1) {
        return opt[0];
    }
    return 0;
}

/* Set the DHCP message type in options */
void dhcp_set_message_type(dhcp_message_t *msg, uint8_t type) {
    dhcp_add_option(msg, DHCP_OPT_MESSAGE_TYPE, 1, &type);
}

/* Find an available IP address from the pool */
uint32_t dhcp_find_available_ip(dhcp_server_t *server, uint8_t *mac_address) {
    /* Check if MAC already has a lease */
    // uart_puts("1");
    dhcp_lease_t *existing = dhcp_find_lease(server, mac_address);
    // uart_puts("2");
    if (existing) {
        return existing->ip_address;
    }
    
    // uart_puts("3");
    /* Find first available IP */
    for (uint32_t ip = server->config.pool_start; ip <= server->config.pool_end; ip++) {
    // uart_puts("4");
        uint8_t found = 0;
        for (uint16_t i = 0; i < server->lease_count; i++) {
            if (server->leases[i].in_use && server->leases[i].ip_address == ip) {
                found = 1;
                break;
            }
        }
        if (!found) {
            return ip;
        }
    }
    
    return 0; /* No available IP */
}

/* Find a lease by MAC address */
dhcp_lease_t *dhcp_find_lease(dhcp_server_t *server, uint8_t *mac_address) {
    for (uint16_t i = 0; i < server->lease_count; i++) {
        if (server->leases[i].in_use && 
            kmemcmp(server->leases[i].mac_address, mac_address, 6) == 0) {
            return &server->leases[i];
        }
    }
    return NULL;
}

/* Allocate a new lease */
dhcp_lease_t *dhcp_allocate_lease(dhcp_server_t *server, uint32_t ip, uint8_t *mac_address, uint32_t xid) {
    if (server->lease_count >= server->max_leases) {
        return NULL;
    }
    
    dhcp_lease_t *lease = &server->leases[server->lease_count];
    lease->ip_address = ip;
    kmemcpy(lease->mac_address, mac_address, 6);
    lease->lease_time = server->config.lease_time;
    lease->assigned_time = 0; /* TODO: Set to current time */
    lease->in_use = 1;
    lease->xid = xid;
    
    server->lease_count++;
    return lease;
}

/* Add an option to DHCP message */
void dhcp_add_option(dhcp_message_t *msg, uint8_t option, uint8_t length, uint8_t *data) {
    uint8_t *ptr = msg->options;

    /* If options appear uninitialized (all zero), set an explicit END marker
       so the scan below can find the end quickly and new options can be
       appended at the start of the options field. */
    if (ptr[0] == 0) {
        ptr[0] = DHCP_OPT_END;
    }

    /* Find end of options */
    while (ptr < (msg->options + 308) && *ptr != DHCP_OPT_END) {
        if (*ptr == DHCP_OPT_PAD) {
            ptr++;
            continue;
        }
        ptr += 2 + ptr[1]; /* Skip option code and length, then data */
    }

    /* Add new option if space available */
    if (ptr + 2 + length + 1 <= msg->options + 308) {
        *ptr++ = option;
        *ptr++ = length;
        if (data && length > 0) {
            kmemcpy(ptr, data, length);
        }
        ptr += length;
        if (ptr < msg->options + 308) {
            *ptr = DHCP_OPT_END;
        }
    }
}

/* Get an option from DHCP message */
uint8_t *dhcp_get_option(dhcp_message_t *msg, uint8_t option, uint8_t *length) {
    uint8_t *ptr = msg->options;
    
    while (*ptr != DHCP_OPT_END && ptr < (msg->options + 308)) {
        if (*ptr == option) {
            *length = ptr[1];
            return &ptr[2];
        }
        
        if (*ptr == DHCP_OPT_PAD) {
            ptr++;
            continue;
        }
        
        ptr += 2 + ptr[1];
    }
    
    *length = 0;
    return NULL;
}

/* Build a DHCP OFFER message */
void dhcp_build_offer(dhcp_server_t *server, dhcp_message_t *request, 
                      dhcp_message_t *offer, uint32_t offered_ip) {
    /* Initialize offer message */
    kmemset(offer, 0, sizeof(dhcp_message_t));
    
    offer->op = 2;              /* BOOTREPLY */
    offer->htype = request->htype;
    offer->hlen = request->hlen;
    offer->hops = 0;
    offer->xid = request->xid;
    offer->secs = 0;
    offer->flags = request->flags;
    offer->ciaddr = 0;
    offer->yiaddr = offered_ip;
    offer->siaddr = server->config.server_ip;
    offer->giaddr = request->giaddr;
    kmemcpy(offer->chaddr, request->chaddr, 16);
    offer->magic_cookie = DHCP_MAGIC_COOKIE;
    
    /* Add DHCP options */
    dhcp_set_message_type(offer, DHCP_OFFER);
    
    uint8_t server_id_bytes[4];
    uint32_to_ip(server->config.server_ip, &server_id_bytes[0], &server_id_bytes[1], 
                 &server_id_bytes[2], &server_id_bytes[3]);
    dhcp_add_option(offer, DHCP_OPT_SERVER_ID, 4, server_id_bytes);
    
    uint8_t subnet_bytes[4];
    uint32_to_ip(server->config.subnet_mask, &subnet_bytes[0], &subnet_bytes[1], 
                 &subnet_bytes[2], &subnet_bytes[3]);
    dhcp_add_option(offer, DHCP_OPT_SUBNET_MASK, 4, subnet_bytes);
    
    uint8_t router_bytes[4];
    uint32_to_ip(server->config.gateway_ip, &router_bytes[0], &router_bytes[1], 
                 &router_bytes[2], &router_bytes[3]);
    dhcp_add_option(offer, DHCP_OPT_ROUTER, 4, router_bytes);
    
    uint8_t dns_bytes[4];
    uint32_to_ip(server->config.dns_ip, &dns_bytes[0], &dns_bytes[1], 
                 &dns_bytes[2], &dns_bytes[3]);
    dhcp_add_option(offer, DHCP_OPT_DNS_SERVER, 4, dns_bytes);
    
    uint8_t lease_bytes[4];
    uint32_t lease_time = server->config.lease_time;
    lease_bytes[0] = (lease_time >> 24) & 0xFF;
    lease_bytes[1] = (lease_time >> 16) & 0xFF;
    lease_bytes[2] = (lease_time >> 8) & 0xFF;
    lease_bytes[3] = lease_time & 0xFF;
    dhcp_add_option(offer, DHCP_OPT_LEASE_TIME, 4, lease_bytes);
}

/* Build a DHCP ACK message */
void dhcp_build_ack(dhcp_server_t *server, dhcp_message_t *request, 
                    dhcp_message_t *ack, uint32_t assigned_ip) {
    /* Initialize ACK message (similar to OFFER) */
    kmemset(ack, 0, sizeof(dhcp_message_t));
    
    ack->op = 2;                /* BOOTREPLY */
    ack->htype = request->htype;
    ack->hlen = request->hlen;
    ack->hops = 0;
    ack->xid = request->xid;
    ack->secs = 0;
    ack->flags = request->flags;
    ack->ciaddr = request->ciaddr;
    ack->yiaddr = assigned_ip;
    ack->siaddr = server->config.server_ip;
    ack->giaddr = request->giaddr;
    kmemcpy(ack->chaddr, request->chaddr, 16);
    ack->magic_cookie = DHCP_MAGIC_COOKIE;
    
    /* Add DHCP options */
    dhcp_set_message_type(ack, DHCP_ACK);
    
    uint8_t server_id_bytes[4];
    uint32_to_ip(server->config.server_ip, &server_id_bytes[0], &server_id_bytes[1], 
                 &server_id_bytes[2], &server_id_bytes[3]);
    dhcp_add_option(ack, DHCP_OPT_SERVER_ID, 4, server_id_bytes);
    
    uint8_t subnet_bytes[4];
    uint32_to_ip(server->config.subnet_mask, &subnet_bytes[0], &subnet_bytes[1], 
                 &subnet_bytes[2], &subnet_bytes[3]);
    dhcp_add_option(ack, DHCP_OPT_SUBNET_MASK, 4, subnet_bytes);
    
    uint8_t router_bytes[4];
    uint32_to_ip(server->config.gateway_ip, &router_bytes[0], &router_bytes[1], 
                 &router_bytes[2], &router_bytes[3]);
    dhcp_add_option(ack, DHCP_OPT_ROUTER, 4, router_bytes);
    
    uint8_t dns_bytes[4];
    uint32_to_ip(server->config.dns_ip, &dns_bytes[0], &dns_bytes[1], 
                 &dns_bytes[2], &dns_bytes[3]);
    dhcp_add_option(ack, DHCP_OPT_DNS_SERVER, 4, dns_bytes);
    
    uint8_t lease_bytes[4];
    uint32_t lease_time = server->config.lease_time;
    lease_bytes[0] = (lease_time >> 24) & 0xFF;
    lease_bytes[1] = (lease_time >> 16) & 0xFF;
    lease_bytes[2] = (lease_time >> 8) & 0xFF;
    lease_bytes[3] = lease_time & 0xFF;
    dhcp_add_option(ack, DHCP_OPT_LEASE_TIME, 4, lease_bytes);
}

/* Build a DHCP NAK message */
void dhcp_build_nak(dhcp_message_t *request, dhcp_message_t *nak) {
    kmemset(nak, 0, sizeof(dhcp_message_t));
    
    nak->op = 2;                /* BOOTREPLY */
    nak->htype = request->htype;
    nak->hlen = request->hlen;
    nak->hops = 0;
    nak->xid = request->xid;
    nak->secs = 0;
    nak->flags = request->flags;
    nak->ciaddr = 0;
    nak->yiaddr = 0;
    nak->siaddr = 0;
    nak->giaddr = request->giaddr;
    kmemcpy(nak->chaddr, request->chaddr, 16);
    nak->magic_cookie = DHCP_MAGIC_COOKIE;
    
    /* Add message type option */
    uint8_t msg_type = DHCP_NAK;
    kmemset(nak->options, 0, 308);
    nak->options[0] = DHCP_OPT_MESSAGE_TYPE;
    nak->options[1] = 1;
    nak->options[2] = msg_type;
    nak->options[3] = DHCP_OPT_END;
}

/* Main DHCP message processing function */
void dhcp_process_message(dhcp_server_t *server, dhcp_message_t *request, dhcp_message_t *response) {
    // extern void uart_puts(const char *s);
    // uart_puts("Q");
    uint8_t msg_type = dhcp_get_message_type(request);
    
    // uart_puts("W");
    switch (msg_type) {
        case DHCP_DISCOVER: {
            /* Client is looking for an IP */
    // uart_puts("E");
            uint32_t offered_ip = dhcp_find_available_ip(server, request->chaddr);
    // uart_puts("R");
            if (offered_ip) {
                dhcp_build_offer(server, request, response, offered_ip);
            }
            break;
        }
        
        case DHCP_REQUEST: {
            /* Client is requesting an IP */
            uint8_t length = 0;
            uint8_t *requested_ip_opt = dhcp_get_option(request, DHCP_OPT_REQUESTED_IP, &length);
            
            if (requested_ip_opt && length == 4) {
                uint32_t requested_ip = (requested_ip_opt[0] << 24) | 
                                        (requested_ip_opt[1] << 16) |
                                        (requested_ip_opt[2] << 8) | 
                                        requested_ip_opt[3];
                
                /* Check if IP is in pool and available */
                if (requested_ip >= server->config.pool_start && 
                    requested_ip <= server->config.pool_end) {
                    
                    dhcp_lease_t *lease = dhcp_allocate_lease(server, requested_ip, 
                                                              request->chaddr, request->xid);
                    if (lease) {
                        dhcp_build_ack(server, request, response, requested_ip);
                    } else {
                        dhcp_build_nak(request, response);
                    }
                } else {
                    dhcp_build_nak(request, response);
                }
            }
            break;
        }
        
        default:
            break;
    }
}
