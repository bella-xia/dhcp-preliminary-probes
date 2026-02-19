#include "cli_cmds.h"
#include "uart.h"
#include "dhcp_server.h"
#include "kstring.h"
#include "virtio.h"
#include "packet_parser.h"
#include "packet_builder.h"


// Local static DHCP server for testing
static dhcp_lease_t test_leases[10];
static dhcp_server_t test_server;
static uint8_t test_server_initialized = 0;

void parser_test_init_dhcp(void) {
    if (test_server_initialized) {
        uart_puts("[TEST] DHCP server already initialized\n");
        return;
    }
    
    test_server.leases = test_leases;
    
    dhcp_config_t config = {
        .server_ip = ip_to_uint32(10, 0, 2, 2),
        .subnet_mask = ip_to_uint32(255, 255, 255, 0),
        .gateway_ip = ip_to_uint32(10, 0, 2, 2),
        .dns_ip = ip_to_uint32(8, 8, 8, 8),
        .pool_start = ip_to_uint32(10, 0, 2, 100),
        .pool_end = ip_to_uint32(10, 0, 2, 255),
        .lease_time = 3600
    };
    
    dhcp_init_server(&test_server, &config, 10);
    test_server_initialized = 1;
    uart_puts("[TEST] DHCP server initialized for parser testing\n");
}


void cmd_parser_test(const char *args UNUSED) {
    uart_puts("\n");
    uart_puts("================================\n");
    uart_puts("  Parser & DHCP Loop Test\n");
    uart_puts("================================\n");
    uart_puts("\n");

    // Initialize test DHCP server
    parser_test_init_dhcp();

    // Initialize virtio
    uart_puts("[TEST] Initializing network interface (virtio)...\n");
    if (virtio_net_init() != 0) {
        uart_puts("[ERROR] virtio init failed!\n");
        return;
    }
    uart_puts("[TEST] Network interface ready\n");
    uart_puts("[TEST] Listening for DHCP packets...\n");
    uart_puts("[TEST] Press 'q' to quit\n\n");

    uint8_t rx_buf[PKT_BUF_SZ];
    uint8_t tx_buf[PKT_BUF_SZ];
    int packet_count = 0;
    int dhcp_packet_count = 0;
    
    // Server MAC address (you can customize this)
    uint8_t server_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    
    // For testing, limit to 50 packets or 5 DHCP packets
    while (1) {
        // Check for user input (non-blocking)
        if (uart_has_data()) {
            char c = uart_getc();
            if (c == 'q') {
                uart_puts("\n[TEST] User requested exit\n");
                break;
            }
        }

        int len = virtio_net_recv(rx_buf, PKT_BUF_SZ);
        
        if (len > 0) {
            packet_count++;
            uart_puts("\n[RX] Packet #");
            uart_put_int(packet_count);
            uart_puts(" received (");
            uart_put_int(len);
            uart_puts(" bytes)\n");
            
            packet_parse_result_t parse_result = parse_dhcp_packet(rx_buf, len);
            
            if (parse_result.valid) {
                dhcp_packet_count++;
                uart_puts("[DHCP] Valid DHCP packet #");
                uart_put_int(dhcp_packet_count);
                uart_puts(" detected\n");
                
                // Print source MAC
                uart_puts("[DHCP] Source MAC: ");
                uart_put_hexbyte(parse_result.src_mac[0]);
                uart_putc(':');
                uart_put_hexbyte(parse_result.src_mac[1]);
                uart_putc(':');
                uart_put_hexbyte(parse_result.src_mac[2]);
                uart_putc(':');
                uart_put_hexbyte(parse_result.src_mac[3]);
                uart_putc(':');
                uart_put_hexbyte(parse_result.src_mac[4]);
                uart_putc(':');
                uart_put_hexbyte(parse_result.src_mac[5]);
                uart_puts("\n");
                
                uart_puts("[DHCP] Source port: ");
                uart_put_int(parse_result.src_port);
                uart_puts("\n");
                
                // Get and print message type
                uint8_t msg_type = dhcp_get_message_type(parse_result.dhcp_msg);
                uart_puts("[DHCP] Message type: ");
                switch (msg_type) {
                    case DHCP_DISCOVER:
                        uart_puts("DISCOVER");
                        break;
                    case DHCP_REQUEST:
                        uart_puts("REQUEST");
                        break;
                    case DHCP_DECLINE:
                        uart_puts("DECLINE");
                        break;
                    default:
                        uart_put_int(msg_type);
                        break;
                }
                uart_puts("\n");
                
                uart_puts("[DHCP] Transaction ID: 0x");
                uart_put_hex32(parse_result.dhcp_msg->xid, 0);
                uart_puts("\n");
                
                // Process and generate response
                dhcp_message_t response;
                kmemset(&response, 0, sizeof(dhcp_message_t));
                dhcp_process_message(&test_server, parse_result.dhcp_msg, &response);
                
                // Check if a response was generated
                uint8_t response_type = dhcp_get_message_type(&response);
                if (response_type != 0) {
                    uart_puts("[DHCP] Generated response: ");
                    switch (response_type) {
                        case DHCP_OFFER:
                            uart_puts("OFFER");
                            break;
                        case DHCP_ACK:
                            uart_puts("ACK");
                            break;
                        case DHCP_NAK:
                            uart_puts("NAK");
                            break;
                        default:
                            uart_puts("other type ");
                            uart_put_int(response_type);
                            break;
                    }
                    uart_puts("\n");
                    
                    // Print offered/assigned IP
                    if (response.yiaddr != 0) {
                        uart_puts("[DHCP] Offered/Assigned IP: ");
                        uart_put_int(response.yiaddr & 0xFF);
                        uart_putc('.');
                        uart_put_int((response.yiaddr >> 8) & 0xFF);
                        uart_putc('.');
                        uart_put_int((response.yiaddr >> 16) & 0xFF);
                        uart_putc('.');
                        uart_put_int((response.yiaddr >> 24) & 0xFF);
                        uart_puts("\n");

                        uart_puts("[DHCP] response.yiaddr bytes: ");
                        uint8_t *ip = (uint8_t *)&response.yiaddr;
                        uart_put_int(ip[0]); uart_putc('.');
                        uart_put_int(ip[1]); uart_putc('.');
                        uart_put_int(ip[2]); uart_putc('.');
                        uart_put_int(ip[3]); uart_putc('\n');
                    }

                    // Print current lease count
                    uart_puts("[DHCP] Active leases: ");
                    uart_put_int(test_server.lease_count);
                    uart_putc('/');
                    uart_put_int(test_server.max_leases);
                    uart_puts("\n");
                                                            
                    // Build complete Ethernet packet with DHCP response
                    uart_puts("[TX] Building response packet...\n");
                    
                    // Server IP from test_server config
                    uint32_t server_ip = test_server.config.server_ip;

                    // Determine destination IP and MAC
                    uint32_t dest_ip;
                    uint8_t dest_mac[6];

                    if (response.flags & 0x8000) {  // Broadcast flag set
                        dest_ip = 0xFFFFFFFF;
                        // Broadcast MAC
                        kmemset(dest_mac, 0xFF, 6);
                        uart_puts("[TX] Using broadcast (flag set)\n");
                    } else if (response.yiaddr != 0) {
                        dest_ip = ntohl(response.yiaddr);
                        // Client's MAC address
                        kmemcpy(dest_mac, parse_result.src_mac, 6);
                        uart_puts("[TX] Using unicast to client MAC\n");
                    } else {
                        dest_ip = 0xFFFFFFFF;
                        // Broadcast MAC
                        kmemset(dest_mac, 0xFF, 6);
                        uart_puts("[TX] Using broadcast (fallback)\n");
                    }

                    uint32_t pkt_len = build_dhcp_response_packet(
                        tx_buf,
                        PKT_BUF_SZ,
                        &response,
                        dest_mac,           
                        server_mac,         // Source MAC (server's MAC)
                        server_ip,          
                        dest_ip,            
                        DHCP_SERVER_PORT,   
                        parse_result.src_port 
                    );
                    
                    if (pkt_len > 0) {
                        uart_puts("[TX] Packet built successfully (");
                        uart_put_int(pkt_len);
                        uart_puts(" bytes)\n");
                        
                        // Send the packet
                        if (virtio_net_send(tx_buf, pkt_len) == 0) {
                            uart_puts("[TX] Response sent successfully!\n");
                        } else {
                            uart_puts("[TX] ERROR: Failed to send response\n");
                        }
                    } else {
                        uart_puts("[TX] ERROR: Failed to build packet\n");
                    }
                    
                } else {
                    uart_puts("[DHCP] No response generated\n");
                }
                
                uart_puts("[DHCP] ---\n");
            }
        }
    }
    
    uart_puts("\n[TEST] Complete\n");
    uart_puts("[TEST] Total packets: ");
    uart_put_int(packet_count);
    uart_puts(", DHCP packets: ");
    uart_put_int(dhcp_packet_count);
    uart_puts("\n");
}
