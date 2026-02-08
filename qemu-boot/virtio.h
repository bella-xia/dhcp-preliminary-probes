// This file contains functions that get/send eth packets through virtio_mmio

#ifndef VIRTIO_H
#define VIRTIO_H

#include <stdint.h>

#define PKT_BUF_SZ 2048

// Reset RX pkt buffers
void virtio_net_clear_rx();
// Returns: 0 on success, negative on error
int virtio_net_init();

// Returns: ethernet frame length, or 0 if no packet
int virtio_net_recv(uint8_t *out_buf, uint32_t max_len);
// Returns: 0 on success, -1 on error
int virtio_net_send(const uint8_t *pkt, uint32_t len);

#endif