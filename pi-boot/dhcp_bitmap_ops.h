#ifndef DHCP_BITMAP_OPS_H
#define DHCP_BITMAP_OPS_H

/*
 * Shared bitmap constants and bit-manipulation helpers used by 
 * all bitmap-based IP pool headers.
 */

#include <stdint.h>
#include <stdbool.h>

/*
 * Tuneable compile-time parameters
 * Override with -DDHCP_BITMAP_MAX_RANGE_SIZE=N and -DDHCP_BITMAP_MAX_RANGES=M
 */

// Maximum number of range slices per pool.
#ifndef DHCP_BITMAP_MAX_RANGES
#define DHCP_BITMAP_MAX_RANGES 2u
#endif

// Maximum IPs per range slice. 
#ifndef DHCP_BITMAP_MAX_RANGE_SIZE
#define DHCP_BITMAP_MAX_RANGE_SIZE 65536u
#endif

// 32-bit words required to hold one range's full bitmap.
#define DHCP_BITMAP_WORDS_PER_RANGE \
    ((DHCP_BITMAP_MAX_RANGE_SIZE + 31u) / 32u)

/*
 * Bitmap operations.
 * All operate on a uint32_t array where bit i represents IP slot i within a range.
 */
void dhcp_bm_udivmod(uint32_t n, uint32_t d, uint32_t *quot, uint32_t *rem);    // div+mod
void dhcp_bm_set(uint32_t *bm, uint32_t idx);           // mark slot as in-use
void dhcp_bm_clear(uint32_t *bm, uint32_t idx);         // mark slot as free
bool dhcp_bm_used(const uint32_t *bm, uint32_t idx);    // return slot status

/*
 * Monotonic offer counter: assign each DISCOVER a unique counter value.
 * This value is mapped to an IP in the pool by pool_start + (count % pool_size)
 */
typedef struct { uint64_t count; } dhcp_bm_offcnt_t;

void dhcp_bm_offcnt_init(dhcp_bm_offcnt_t *c);
uint32_t dhcp_bm_next_ip(dhcp_bm_offcnt_t *c, uint32_t pool_start, uint32_t pool_size);

#endif /* DHCP_BITMAP_OPS_H */
