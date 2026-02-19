#ifndef PACKET_BUILDER_H
#define PACKET_BUILDER_H

#include <stdint.h>
#include "dhcp_server.h"

/**
 * Build a complete Ethernet frame containing a DHCP response
 * 
 * @param out_packet Output buffer for the complete Ethernet frame
 * @param max_len Maximum size of output buffer
 * @param dhcp_response Pointer to DHCP message to encapsulate
 * @param dst_mac Destination MAC address (6 bytes)
 * @param src_mac Source MAC address (6 bytes) - typically server's MAC
 * @param src_ip Source IP address (server IP)
 * @param dst_ip Destination IP address (typically broadcast or client IP)
 * @param src_port Source UDP port (typically 67 for DHCP server)
 * @param dst_port Destination UDP port (typically 68 for DHCP client)
 * @return Length of built packet in bytes, or 0 on error
 */
uint32_t build_dhcp_response_packet(
    uint8_t *out_packet,
    uint32_t max_len,
    dhcp_message_t *dhcp_response,
    uint8_t *dst_mac,
    uint8_t *src_mac,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port
);

/**
 * Calculate IP header checksum
 * 
 * @param ip_header Pointer to IP header (20 bytes minimum)
 * @param header_len Length of IP header in bytes
 * @return 16-bit checksum
 */
uint16_t calculate_ip_checksum(uint8_t *ip_header, uint16_t header_len);

#endif /* PACKET_BUILDER_H */
