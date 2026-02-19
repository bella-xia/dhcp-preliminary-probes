#include "packet_builder.h"
#include "packet_parser.h"
#include "kstring.h"

/* Calculate IP header checksum */
uint16_t calculate_ip_checksum(uint8_t *ip_header, uint16_t header_len) {
    uint32_t sum = 0;
    
    // Sum all 16-bit words
    for (uint16_t i = 0; i < header_len; i += 2) {
        uint16_t word = (ip_header[i] << 8) | ip_header[i + 1];
        sum += word;
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

/* Build a complete Ethernet frame containing a DHCP response */
uint32_t build_dhcp_response_packet(
    uint8_t *out_packet,
    uint32_t max_len,
    dhcp_message_t *dhcp_response,
    uint8_t *dst_mac,
    uint8_t *src_mac,
    uint32_t src_ip,    // host order
    uint32_t dst_ip,    // host order
    uint16_t src_port,  // host order
    uint16_t dst_port   // host order
) {
    // Calculate required packet size
    uint16_t dhcp_len = sizeof(dhcp_message_t);
    uint16_t udp_len = 8 + dhcp_len;
    uint16_t ip_len = 20 + udp_len;
    uint32_t total_len = 14 + ip_len;
    
    if (total_len > max_len) {
        return 0;  // Buffer too small
    }
    
    kmemset(out_packet, 0, total_len);
    
    // ========== Ethernet Header ==========
    kmemcpy(out_packet + 0, dst_mac, 6);        // Destination MAC
    kmemcpy(out_packet + 6, src_mac, 6);        // Source MAC
    out_packet[12] = 0x08;                      // EtherType = IPv4 (0x0800)
    out_packet[13] = 0x00;
    
    // ========== IP Header ==========
    uint16_t ip_offset = 14;
    
    out_packet[ip_offset + 0] = 0x45;           // Version=4, IHL=5 (20 bytes)
    out_packet[ip_offset + 1] = 0x00;           // DSCP/ECN
    out_packet[ip_offset + 2] = (ip_len >> 8) & 0xFF;   // Total length
    out_packet[ip_offset + 3] = ip_len & 0xFF;
    out_packet[ip_offset + 4] = 0x00;           // Identification
    out_packet[ip_offset + 5] = 0x00;
    out_packet[ip_offset + 6] = 0x00;           // Flags/Fragment offset
    out_packet[ip_offset + 7] = 0x00;
    out_packet[ip_offset + 8] = 64;             // TTL
    out_packet[ip_offset + 9] = 17;             // Protocol = UDP
    out_packet[ip_offset + 10] = 0x00;          // Checksum (calculate later)
    out_packet[ip_offset + 11] = 0x00;
    
    // Source IP
    out_packet[ip_offset + 12] = (src_ip >> 24) & 0xFF;
    out_packet[ip_offset + 13] = (src_ip >> 16) & 0xFF;
    out_packet[ip_offset + 14] = (src_ip >> 8) & 0xFF;
    out_packet[ip_offset + 15] = src_ip & 0xFF;
    
    // Destination IP
    out_packet[ip_offset + 16] = (dst_ip >> 24) & 0xFF;
    out_packet[ip_offset + 17] = (dst_ip >> 16) & 0xFF;
    out_packet[ip_offset + 18] = (dst_ip >> 8) & 0xFF;
    out_packet[ip_offset + 19] = dst_ip & 0xFF;
    
    // Calculate and set IP checksum
    uint16_t ip_checksum = calculate_ip_checksum(out_packet + ip_offset, 20);
    out_packet[ip_offset + 10] = (ip_checksum >> 8) & 0xFF;
    out_packet[ip_offset + 11] = ip_checksum & 0xFF;
    
    // ========== UDP Header ==========
    uint16_t udp_offset = ip_offset + 20;
    
    out_packet[udp_offset + 0] = (src_port >> 8) & 0xFF;    // Source port
    out_packet[udp_offset + 1] = src_port & 0xFF;
    out_packet[udp_offset + 2] = (dst_port >> 8) & 0xFF;    // Destination port
    out_packet[udp_offset + 3] = dst_port & 0xFF;
    out_packet[udp_offset + 4] = (udp_len >> 8) & 0xFF;     // UDP length
    out_packet[udp_offset + 5] = udp_len & 0xFF;
    out_packet[udp_offset + 6] = 0x00;                      // Checksum (optional for IPv4)
    out_packet[udp_offset + 7] = 0x00;
    
    // ========== DHCP Payload ==========
    uint16_t dhcp_offset = udp_offset + 8;
    kmemcpy(out_packet + dhcp_offset, dhcp_response, dhcp_len);
    
    return total_len;
}
