#include "packet_parser.h"
#include "kstring.h"
#include "uart.h"


packet_parse_result_t parse_dhcp_packet(uint8_t *packet, uint32_t packet_len) {
    packet_parse_result_t result;
    kmemset(&result, 0, sizeof(packet_parse_result_t));
    
    // Check minimum packet size: Ethernet(14) + IP(20) + UDP(8) = 42 bytes
    if (packet_len < 42) {
        uart_puts("[INVALID] Packet too small: ");
        uart_put_u32(packet_len);
        uart_puts(" bytes (minimum 42)\n");
        return result;
    }

    // not ipv4
    uint16_t ethertype = (packet[ETH_ETHERTYPE_OFFSET] << 8) | packet[ETH_ETHERTYPE_OFFSET + 1];
    if (ethertype != ETHERTYPE_IPV4) {
        uart_puts("[DROPPED] Ethertype not ipv4, received type: ");
        uart_put_hex32(ethertype, 0);
        uart_puts("\n");
        return result;
    }
    
    uint16_t ip_header_len = (packet[ETH_HEADER_LEN + IP_VERSION_IHL_OFFSET] & 0x0F) * 4;
    
    if (ip_header_len < 20 || ip_header_len > 60) {
        uart_puts("[INVALID] IP header length: ");
        uart_put_u32(ip_header_len);
        uart_puts(" bytes (must be 20-60)\n");
        return result;
    }

    // version number not 4
    uint8_t ip_version = (packet[ETH_HEADER_LEN + IP_VERSION_IHL_OFFSET] >> 4) & 0x0F;
    if (ip_version != 4) {
        uart_puts("[DROPPED] IP version != 4, received version: ");
        uart_put_u32(ip_version);
        uart_puts("\n");
        return result;
    }

    uint16_t ip_total_len = (packet[ETH_HEADER_LEN + 2] << 8) | packet[ETH_HEADER_LEN + 3];
    if ((uint32_t)(ETH_HEADER_LEN + ip_total_len) < (uint32_t)(14 + ip_header_len + 8 + 240)) {
        uart_puts("[DROPPED] Packet too small for DHCP, got ");
        uart_put_u32((uint32_t)(ETH_HEADER_LEN + ip_total_len));
        uart_puts(" bytes, need ");
        uart_put_u32(14 + ip_header_len + 8 + 240);
        uart_puts(" bytes\n");
        return result;
    }

    if (packet_len < (uint32_t)(ETH_HEADER_LEN + ip_total_len)) {
        uart_puts("[INVALID] Packet truncated: got ");
        uart_put_u32(packet_len);
        uart_puts(" bytes, IP header indicates minimum ");
        uart_put_u32(ETH_HEADER_LEN + ip_total_len);
        uart_puts("\n");
        return result;
    }

    // not UDP
    if (packet[ETH_HEADER_LEN + IP_PROTOCOL_OFFSET] != IP_PROTOCOL_UDP) {
        uart_puts("[DROPPED] Not UDP, got protocol ");
        uart_put_u32(packet[ETH_HEADER_LEN + IP_PROTOCOL_OFFSET]);
        uart_puts("\n");
        return result;
    }

    uint16_t udp_offset = ETH_HEADER_LEN + ip_header_len;
    // not for port 67 (DHCP server)
    uint16_t dest_port = (packet[udp_offset + UDP_DEST_PORT_OFFSET] << 8) | 
                         packet[udp_offset + UDP_DEST_PORT_OFFSET + 1];
    if (dest_port != DHCP_SERVER_PORT) {
        uart_puts("[DROPPED] Not dest port 67, got port ");
        uart_put_u32(dest_port);
        uart_puts("\n");
        return result;
    }
    
    // Validate UDP length
    uint16_t udp_len = (packet[udp_offset + 4] << 8) | packet[udp_offset + 5];
    if (udp_len != ip_total_len - ip_header_len) {
        uart_puts("[INVALID] UDP length field ");
        uart_put_u32(udp_len);
        uart_puts(" inconsistent with calculated UDP length in from IP header ");
        uart_put_u32(ip_total_len - ip_header_len);
        uart_puts("\n");
        return result;
    }
    
    uint16_t dhcp_offset = udp_offset + UDP_HEADER_LEN;
    // Validate DHCP magic cookie (0x63825363)
    uint32_t magic_cookie = (packet[dhcp_offset + 236] << 24) |
                            (packet[dhcp_offset + 237] << 16) |
                            (packet[dhcp_offset + 238] << 8) |
                            packet[dhcp_offset + 239];
    if (magic_cookie != 0x63825363) {
        uart_puts("[DROPPED] Not DHCP packet, magic cookie: 0x");
        uart_put_hex32(magic_cookie, 0);
        uart_puts(" (expected 0x63825363)\n");
        return result;
    }
    
    kmemcpy(result.src_mac, packet + ETH_SRC_MAC_OFFSET, 6);
    result.src_port = (packet[udp_offset + UDP_SRC_PORT_OFFSET] << 8) | 
                      packet[udp_offset + UDP_SRC_PORT_OFFSET + 1];
    result.dhcp_msg = (dhcp_message_t *)(packet + dhcp_offset);
    result.valid = 1;
    
    return result;
}
