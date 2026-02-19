#ifndef DHCP_SERVER_H
#define DHCP_SERVER_H

#include <stdint.h>
#include <string.h>

/* DHCP Message Types */
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6

/* DHCP Option Codes */
#define DHCP_OPT_PAD                    0
#define DHCP_OPT_SUBNET_MASK            1
#define DHCP_OPT_ROUTER                 3
#define DHCP_OPT_DNS_SERVER             6
#define DHCP_OPT_HOSTNAME               12
#define DHCP_OPT_REQUESTED_IP           50
#define DHCP_OPT_LEASE_TIME             51
#define DHCP_OPT_MESSAGE_TYPE           53
#define DHCP_OPT_SERVER_ID              54
#define DHCP_OPT_PARAM_REQUEST_LIST     55
#define DHCP_OPT_MAX_MESSAGE_SIZE       57
#define DHCP_OPT_END                    255

/* DHCP Magic Cookie */
#define DHCP_MAGIC_COOKIE 0x63825363

/* UDP Port Numbers */
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

/* DHCP Message Structure */
typedef struct {
    uint8_t op;                 /* Message type: 1 = BOOTREQUEST, 2 = BOOTREPLY */
    uint8_t htype;              /* Hardware address type (1 = Ethernet) */
    uint8_t hlen;               /* Hardware address length */
    uint8_t hops;               /* Hop count */
    uint32_t xid;               /* Transaction ID */
    uint16_t secs;              /* Elapsed time in seconds */
    uint16_t flags;             /* Flags */
    uint32_t ciaddr;            /* Client IP address */
    uint32_t yiaddr;            /* Your (client) IP address */
    uint32_t siaddr;            /* Server IP address */
    uint32_t giaddr;            /* Gateway IP address */
    uint8_t chaddr[16];         /* Client hardware address */
    uint8_t sname[64];          /* Server hostname (optional) */
    uint8_t file[128];          /* Boot filename (optional) */
    uint32_t magic_cookie;      /* Magic cookie: 0x63825363 */
    uint8_t options[308];       /* Optional parameters field (variable) */
} dhcp_message_t;

/* DHCP Lease Structure */
typedef struct {
    uint32_t ip_address;        /* Leased IP address */
    uint8_t mac_address[6];     /* MAC address */
    uint32_t lease_time;        /* Lease duration in seconds */
    uint32_t assigned_time;     /* When the lease was assigned */
    uint8_t in_use;             /* Whether this lease is active */
    uint32_t xid;               /* Transaction ID for this lease */
} dhcp_lease_t;

/* DHCP Server Configuration */
typedef struct {
    uint32_t server_ip;         /* Server IP address */
    uint32_t subnet_mask;       /* Subnet mask */
    uint32_t gateway_ip;        /* Gateway/Router IP */
    uint32_t dns_ip;            /* DNS server IP */
    uint32_t pool_start;        /* First IP in pool */
    uint32_t pool_end;          /* Last IP in pool */
    uint32_t lease_time;        /* Default lease time in seconds */
} dhcp_config_t;

/* DHCP Server State */
typedef struct {
    dhcp_config_t config;
    dhcp_lease_t *leases;
    uint16_t max_leases;
    uint16_t lease_count;
} dhcp_server_t;

/* Function Declarations */
void dhcp_init_server(dhcp_server_t *server, dhcp_config_t *config, uint16_t max_leases);
void dhcp_process_message(dhcp_server_t *server, dhcp_message_t *request, dhcp_message_t *response);
uint8_t dhcp_get_message_type(dhcp_message_t *msg);
void dhcp_set_message_type(dhcp_message_t *msg, uint8_t type);
uint32_t dhcp_find_available_ip(dhcp_server_t *server, uint8_t *mac_address);
dhcp_lease_t *dhcp_find_lease(dhcp_server_t *server, uint8_t *mac_address);
dhcp_lease_t *dhcp_allocate_lease(dhcp_server_t *server, uint32_t ip, uint8_t *mac_address, uint32_t xid);
void dhcp_build_offer(dhcp_server_t *server, dhcp_message_t *request, dhcp_message_t *offer, uint32_t offered_ip);
void dhcp_build_ack(dhcp_server_t *server, dhcp_message_t *request, dhcp_message_t *ack, uint32_t assigned_ip);
void dhcp_build_nak(dhcp_message_t *request, dhcp_message_t *nak);
void dhcp_add_option(dhcp_message_t *msg, uint8_t option, uint8_t length, uint8_t *data);
uint8_t *dhcp_get_option(dhcp_message_t *msg, uint8_t option, uint8_t *length);

/* Helper functions */
uint32_t htonl(uint32_t val);
#define ntohl htonl
void uint32_to_ip(uint32_t ip, uint8_t *a, uint8_t *b, uint8_t *c, uint8_t *d);
uint32_t ip_to_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
uint32_t ip_list_to_uint32(uint8_t* ip_list);


#endif /* DHCP_SERVER_H */
