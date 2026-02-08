#include "virtio.h"
#include "uart.h"
#include "kstring.h"

/* ---------------- virtio-mmio regs ---------------- */
#define VIRTIO_BASE     0x0a003e00   // typical first virtio-mmio slot on -M virt

#define VIRTIO_MMIO_MAGIC_VALUE         0x000
#define VIRTIO_MMIO_VERSION             0x004
#define VIRTIO_MMIO_DEVICE_ID           0x008
#define VIRTIO_MMIO_VENDOR_ID           0x00c

#define VIRTIO_MMIO_DEVICE_FEATURES     0x010
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014
#define VIRTIO_MMIO_DRIVER_FEATURES     0x020
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024

#define VIRTIO_MMIO_QUEUE_SEL           0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX       0x034
#define VIRTIO_MMIO_QUEUE_NUM           0x038
#define VIRTIO_MMIO_QUEUE_READY         0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY        0x050

#define VIRTIO_MMIO_STATUS              0x070

#define VIRTIO_MMIO_QUEUE_DESC_LOW      0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH     0x084
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW     0x090
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH    0x094
#define VIRTIO_MMIO_QUEUE_USED_LOW      0x0a0
#define VIRTIO_MMIO_QUEUE_USED_HIGH     0x0a4

/* status bits */
#define VIRTIO_STATUS_ACKNOWLEDGE       0x01
#define VIRTIO_STATUS_DRIVER            0x02
#define VIRTIO_STATUS_DRIVER_OK         0x04
#define VIRTIO_STATUS_FEATURES_OK       0x08
#define VIRTIO_STATUS_FAILED            0x80

/* virtqueue desc flags */
#define VIRTQ_DESC_F_WRITE              2


/* ---------------- MMIO helpers ---------------- */
static inline void w32(uintptr_t a, uint32_t v){ *(volatile uint32_t*)a = v; }
static inline void w64(uintptr_t base, uint32_t lo, uint32_t hi, uint64_t v) {
    w32(base + lo, (uint32_t)v);
    w32(base + hi, (uint32_t)(v >> 32));
}
static inline uint32_t r32(uintptr_t a){ return *(volatile uint32_t*)a; }
static inline uint32_t v2p(const void *p){ return (uint32_t)(uintptr_t)p; }
static inline void dmb_ish(void){ __asm__ volatile("dmb ish" ::: "memory"); }


/* ---------------- virtqueue structs ---------------- */
// https://docs.zephyrproject.org/latest/doxygen/html/virtqueue_8h_source.html
// descriptor to a packet buffer
typedef struct {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} virtq_desc_t;

typedef struct {
    uint32_t id;
    uint32_t len;
} virtq_used_elem_t;


/* ---------------- minimal RX/TX ring memory ---------------- */
#define RX_QSZ      8   // how many packets allowed in a RX queue
#define TX_QSZ      1   // how many packets allowed in a TX queue
#define RX_QID      0
#define TX_QID      1
#define VHDR_LEN    10   // virtio-net header len

static uint8_t rx_buf[RX_QSZ][PKT_BUF_SZ];
static uint8_t tx_buf[TX_QSZ][PKT_BUF_SZ];

static virtq_desc_t rx_desc[RX_QSZ];
static struct { uint16_t flags, idx; uint16_t ring[RX_QSZ]; } rx_avail;         // virtq_avail_t
static struct { uint16_t flags, idx; virtq_used_elem_t ring[RX_QSZ]; } rx_used; // virtq_used_t

static virtq_desc_t tx_desc[TX_QSZ];
static struct { uint16_t flags, idx; uint16_t ring[TX_QSZ]; } tx_avail;         // virtq_avail_t
static struct { uint16_t flags, idx; virtq_used_elem_t ring[TX_QSZ]; } tx_used; // virtq_used_t

// last_rx_used and last_tx_used are automatically wrapped at uint16 max
static uint16_t last_rx_used = 0;
static uint16_t last_tx_used = 0;

void virtio_net_clear_rx() {
    for (int i = 0; i < RX_QSZ; i++) {
        // Set up descriptor pointing to rx_buf[i]
        rx_desc[i].addr = v2p(rx_buf[i]);
        rx_desc[i].len = PKT_BUF_SZ;
        rx_desc[i].flags = VIRTQ_DESC_F_WRITE;  // device writes to this buffer
        rx_desc[i].next = 0;
        
        // Add to available ring
        rx_avail.ring[i] = i;
    }
    
    rx_avail.idx = RX_QSZ;  // total # of avail pkt buffers
    dmb_ish();
    
    // Notify device
    w32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY, RX_QID);
}

int virtio_net_init(){
    uint32_t magic = r32(VIRTIO_BASE + VIRTIO_MMIO_MAGIC_VALUE);
    uint32_t did   = r32(VIRTIO_BASE + VIRTIO_MMIO_DEVICE_ID);
    uint32_t ver   = r32(VIRTIO_BASE + VIRTIO_MMIO_VERSION);

    if (magic != 0x74726976u) return -1; // "virt"
    if (did != 1u) return -2;            // 1 = virtio-net

    uart_puts("[virtio] Version: ");
    uart_put_int(ver);
    uart_puts("\n");

    /* reset */
    w32(VIRTIO_BASE + VIRTIO_MMIO_STATUS, 0);
    dmb_ish();

    /* ACK + DRIVER */
    w32(VIRTIO_BASE + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
    w32(VIRTIO_BASE + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    /* accept no features */
    w32(VIRTIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
    w32(VIRTIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES, 0);
    w32(VIRTIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES_SEL, 1);
    w32(VIRTIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES, 0);

    /* FEATURES_OK */
    uint32_t st = r32(VIRTIO_BASE + VIRTIO_MMIO_STATUS);
    w32(VIRTIO_BASE + VIRTIO_MMIO_STATUS, st | VIRTIO_STATUS_FEATURES_OK);

    /* verify it sticks */
    st = r32(VIRTIO_BASE + VIRTIO_MMIO_STATUS);
    if (!(st & VIRTIO_STATUS_FEATURES_OK)) {
        uart_puts("[virtio] FEATURES_OK rejected\n");
        w32(VIRTIO_BASE + VIRTIO_MMIO_STATUS, st | VIRTIO_STATUS_FAILED);
        return -3;
    }

    /* RX queue */
    w32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_SEL, RX_QID);
    if (r32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_NUM_MAX) < RX_QSZ) return -4;
    w32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_NUM, RX_QSZ);

    kmemset(rx_desc, 0, sizeof(rx_desc));
    kmemset(&rx_avail, 0, sizeof(rx_avail));
    kmemset(&rx_used, 0, sizeof(rx_used));

    w64(VIRTIO_BASE, VIRTIO_MMIO_QUEUE_DESC_LOW,  VIRTIO_MMIO_QUEUE_DESC_HIGH,  v2p(rx_desc));
    w64(VIRTIO_BASE, VIRTIO_MMIO_QUEUE_AVAIL_LOW, VIRTIO_MMIO_QUEUE_AVAIL_HIGH, v2p(&rx_avail));
    w64(VIRTIO_BASE, VIRTIO_MMIO_QUEUE_USED_LOW,  VIRTIO_MMIO_QUEUE_USED_HIGH,  v2p(&rx_used));
    w32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_READY, 1);

    /* TX queue */
    w32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_SEL, TX_QID);
    if (r32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_NUM_MAX) < TX_QSZ) return -5;
    w32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_NUM, TX_QSZ);

    kmemset(tx_desc, 0, sizeof(tx_desc));
    kmemset(&tx_avail, 0, sizeof(tx_avail));
    kmemset(&tx_used, 0, sizeof(tx_used));

    w64(VIRTIO_BASE, VIRTIO_MMIO_QUEUE_DESC_LOW,  VIRTIO_MMIO_QUEUE_DESC_HIGH,  v2p(tx_desc));
    w64(VIRTIO_BASE, VIRTIO_MMIO_QUEUE_AVAIL_LOW, VIRTIO_MMIO_QUEUE_AVAIL_HIGH, v2p(&tx_avail));
    w64(VIRTIO_BASE, VIRTIO_MMIO_QUEUE_USED_LOW,  VIRTIO_MMIO_QUEUE_USED_HIGH,  v2p(&tx_used));
    w32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_READY, 1);

    /* DRIVER_OK */
    st = r32(VIRTIO_BASE + VIRTIO_MMIO_STATUS);
    w32(VIRTIO_BASE + VIRTIO_MMIO_STATUS, st | VIRTIO_STATUS_DRIVER_OK);

    /* Reset RX buffers */
    virtio_net_clear_rx();

    /* Reset last rx/tx used */
    last_rx_used = 0;
    last_tx_used = 0;

    uart_puts("[virtio] init ok\n");
    return 0;
}


/* ---------------- RX: Receive packets ---------------- */
int virtio_net_recv(uint8_t *out_buf, uint32_t max_len) {
    dmb_ish();

    // Check if any pkt buffer is used
    if (last_rx_used == rx_used.idx) {
        return 0;   // no new pkt
    }

    // Get a used pkt buffer
    uint16_t used_idx = last_rx_used % RX_QSZ;
    virtq_used_elem_t *used_elem = &rx_used.ring[used_idx];
    
    uint32_t desc_id = used_elem->id;
    uint32_t total_len = used_elem->len;
    
    if (total_len <= VHDR_LEN) {
        last_rx_used++;
        return 0;  // invalid packet
    }
    
    // Copy packet data (peel out virtio-net header)
    uint32_t pkt_len = total_len - VHDR_LEN;
    if (pkt_len > max_len) pkt_len = max_len;
    
    kmemcpy(out_buf, rx_buf[desc_id] + VHDR_LEN, pkt_len);
    
    // Refill this descriptor
    rx_desc[desc_id].addr = v2p(rx_buf[desc_id]);
    rx_desc[desc_id].len = PKT_BUF_SZ;
    rx_desc[desc_id].flags = VIRTQ_DESC_F_WRITE;
    
    // Add back to available ring
    uint16_t avail_idx = rx_avail.idx % RX_QSZ;
    rx_avail.ring[avail_idx] = desc_id;
    dmb_ish();
    rx_avail.idx++;
    dmb_ish();
    
    // Notify device of new buffer
    w32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY, RX_QID);
    
    last_rx_used++;
    return pkt_len;
}


/* ---------------- TX: Send packets ---------------- */
int virtio_net_send(const uint8_t *pkt, uint32_t len) {
    if (len > (PKT_BUF_SZ - VHDR_LEN)) {
        return -1;  // pkt too large
    }
    
    // Wait for previous TX to complete (simple blocking approach)
    while (last_tx_used != tx_used.idx) {
        dmb_ish();
    }
    
    // Zero out virtio-net header
    kmemset(tx_buf[0], 0, VHDR_LEN);
    
    // Copy packet data after header
    kmemcpy(tx_buf[0] + VHDR_LEN, pkt, len);
    
    // Set up descriptor
    tx_desc[0].addr = v2p(tx_buf[0]);
    tx_desc[0].len = VHDR_LEN + len;
    tx_desc[0].flags = 0;  // device reads from this buffer
    tx_desc[0].next = 0;
    
    // Add to available ring
    tx_avail.ring[tx_avail.idx % TX_QSZ] = 0;
    dmb_ish();
    tx_avail.idx++;
    dmb_ish();
    
    // Notify device
    w32(VIRTIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY, TX_QID);
    
    // Wait for completion (blocking)
    while (last_tx_used == tx_used.idx) {
        dmb_ish();
    }
    
    last_tx_used++;
    return 0;
}
