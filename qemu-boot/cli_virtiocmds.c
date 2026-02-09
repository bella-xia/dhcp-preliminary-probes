#include "cli_cmds.h"
#include "uart.h"
#include "kstring.h"
#include "virtio.h"

static const uint8_t pkt_template[64] = {
        /* Ethernet header */
        0xff,0xff,0xff,0xff,0xff,0xff,   // dst MAC: broadcast
        0x52,0x54,0x00,0x12,0x34,0x56,   // src MAC (QEMU-style, arbitrary)
        0x08,0x00,                       // EtherType: IPv4 (0x0800)

        /* IPv4 header */
        0x45,                           // Version=4, IHL=5
        0x00,                           // DSCP/ECN
        0x00,0x32,                      // Total length = 50 bytes
        0x12,0x34,                      // Identification
        0x00,0x00,                      // Flags/Fragment
        0x40,                           // TTL = 64
        0xff,                           // Protocol = 255 (experimental)
        0x00,0x00,                      // Header checksum (optional here)
        192,168,0,2,                    // Src IP
        192,168,0,1,                    // Dst IP

        /* Payload (random, but valid) */
        0xde,0xad,0xbe,0xef,
        0xaa,0xbb,0xcc,0xdd,
        0x11,0x22,0x33,0x44,
        0x55,0x66,0x77,0x88,
    };

void cmd_virtio_init(const char *args UNUSED) {
    int ret = virtio_net_init();
    uart_puts("[virtio] init return code: ");
    uart_put_int(ret);
    uart_putc('\n');
    if (ret != 0) 
        uart_puts("[virtio] WARNING: expected return code to be 0\n");
}

void cmd_virtio_test(const char *args UNUSED) {
    uart_puts("\n");
    uart_puts("================================\n");
    uart_puts("  Testing virtio TX and RX\n");
    uart_puts("================================\n");
    uart_puts("\n");

    // Initialize
    if (virtio_net_init() != 0) {
        uart_puts("[virtio] virtio init fails!");
        return;
    }

    uart_puts("[TX] Initializing test packet...\n");

    // Test TX
    uint8_t test_pkt[64];
    kmemcpy(test_pkt, pkt_template, 64);
    uart_puts("[TX] Sending test packet...\n");

    if (virtio_net_send(test_pkt, 64) == 0 && virtio_net_send(test_pkt, 64) == 0) {
        uart_puts("[TX] 2 packets sent successfully\n");
    } else {
        uart_puts("[TX] ERROR: Send failed\n");
    }
    
    // Test RX
    uart_puts("[RX] Polling packets for 1000 times...\n");
    uint8_t rx_buf[PKT_BUF_SZ];
    int count = 0;
    
    for (int i = 0; i < 1000; i++) {  // Poll 1000 times
        int len = virtio_net_recv(rx_buf, PKT_BUF_SZ);
        if (len > 0) {
            count++;
            uart_puts("[RX] Packet received: ");
            uart_put_int(len);
            uart_puts(" bytes\n");
            
            // Show first 16 bytes
            uart_puts("     Data: ");
            for (int j = 0; j < 16 && j < len; j++) {
                uart_put_hexbyte(rx_buf[j]);
                uart_puts(" ");
            }
            uart_puts("\n");
        }
    }
    
    uart_puts("\n[DONE] Received ");
    uart_put_int(count);
    uart_puts(" packets\n");
    uart_puts("==========================================\n\n");
}
