#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include "dhcp_server.h"

/* Network protocol constants */
#define ETHERTYPE_IPV4      0x0800
#define IP_PROTOCOL_UDP     17
#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

/* Ethernet header offsets */
#define ETH_DEST_MAC_OFFSET     0
#define ETH_SRC_MAC_OFFSET      6
#define ETH_ETHERTYPE_OFFSET    12
#define ETH_HEADER_LEN          14

/* IP header offsets (relative to IP header start at byte 14) */
#define IP_VERSION_IHL_OFFSET   0
#define IP_PROTOCOL_OFFSET      9

/* UDP header offsets (relative to UDP header start) */
#define UDP_SRC_PORT_OFFSET     0
#define UDP_DEST_PORT_OFFSET    2
#define UDP_HEADER_LEN          8

/* Parser result structure */
typedef struct {
    uint8_t valid;              /* 1 if valid DHCP packet, 0 otherwise */
    dhcp_message_t *dhcp_msg;    /* DHCP message* in packet */
    uint8_t src_mac[6];         /* Source MAC address for response */
    uint16_t src_port;          /* Source port for response */
} packet_parse_result_t;

packet_parse_result_t parse_dhcp_packet(uint8_t *packet, uint32_t packet_len);

#endif
