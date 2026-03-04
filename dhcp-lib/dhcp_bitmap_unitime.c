#include "dhcp_bitmap_unitime.h"
#include "dhcp_compat.h"

#define POOL_SIZE (DHCP_BITMAP_MAX_RANGES * DHCP_BITMAP_RANGE_SIZE)

static uint32_t range_base(const dhcp_bmpool_uni_t *pool, uint8_t range_idx) {
    return pool->pool_start + (uint32_t)range_idx * DHCP_BITMAP_RANGE_SIZE;
}

/* First free bit in a range bitmap; returns DHCP_BITMAP_RANGE_SIZE if full. */
static uint32_t bm_find_free(const uint32_t *bm)
{
    for (uint32_t w = 0; w < DHCP_BITMAP_WORDS_PER_RANGE; ++w) {
        uint32_t free = ~bm[w];
        if (w == DHCP_BITMAP_WORDS_PER_RANGE - 1u && (DHCP_BITMAP_RANGE_SIZE & 31u))
            free &= (1u << (DHCP_BITMAP_RANGE_SIZE & 31u)) - 1u;
        if (free) {
#if defined(__GNUC__) || defined(__clang__)
            return w * 32u + (uint32_t)__builtin_ctz(free);
#else
            uint32_t n = 0, v = free;
            while ((v & 1u) == 0u) { v >>= 1; ++n; }
            return w * 32u + n;
#endif
        }
    }
    return DHCP_BITMAP_RANGE_SIZE;
}

/* Count set bits in one range bitmap. */
static uint16_t bm_popcount(const uint32_t *bm)
{
    uint16_t total = 0;
    for (uint32_t w = 0; w < DHCP_BITMAP_WORDS_PER_RANGE; ++w) {
#if defined(__GNUC__) || defined(__clang__)
        total += (uint16_t)__builtin_popcount(bm[w]);
#else
        uint32_t v = bm[w];
        while (v) { total += (uint16_t)(v & 1u); v >>= 1; }
#endif
    }
    return total;
}

static bool dhcp_bmpool_uni_ip_used(const dhcp_bmpool_uni_t *pool, uint32_t ip) {
    if (ip < pool->pool_start || ip >= pool->pool_start + POOL_SIZE) return 0u;
    uint32_t offset = ip - pool->pool_start;
    return dhcp_bm_used(&(pool->ranges[pool->cur_range]), offset % DHCP_BITMAP_RANGE_SIZE);
}

void dhcp_bmpool_uni_init(dhcp_bmpool_uni_t *pool, uint32_t pool_start, uint32_t lease_time) {
    pool->pool_start = pool_start;
    pool->lease_time = lease_time;
    pool->cur_range = 0;
    dhcp_bm_offcnt_init(&pool->counter);
    for (uint8_t i = 0; i < DHCP_BITMAP_MAX_RANGES; ++i) {
        kmemset(pool->ranges[i].ips, 0, sizeof(pool->ranges[i].ips));
        pool->ranges[i].is_free = true;
    }
}

void dhcp_bmpool_uni_recycle(dhcp_bmpool_uni_t *pool, uint32_t range_idx) {
    if (range_idx >= DHCP_BITMAP_MAX_RANGES) return;
    kmemset(pool->ranges[range_idx].ips, 0, sizeof(pool->ranges[range_idx].ips));
    pool->ranges[range_idx].is_free = true;
}

uint32_t dhcp_bmpool_uni_peek(dhcp_bmpool_uni_t *pool, uint32_t cur_time) {
    uint32_t range_start = range_base(pool, pool->cur_range);

    // Try to advance to next range if current range is full
    uint32_t last_ip = dhcp_bm_last_ip(&(pool->counter), range_start);
    if (dhcp_bm_range_full(range_start, last_ip)) {
        uint8_t next_range = (uint8_t)((pool->cur_range + 1u) % DHCP_BITMAP_MAX_RANGES);
        if (!pool->ranges[next_range].is_free && 
            pool->ranges[next_range].expire_time <= cur_time) {
            // Recycle next range
            dhcp_bmpool_uni_recycle(pool, next_range);
        }

        if (pool->ranges[next_range].is_free) {
            pool->cur_range = next_range;
            range_start = pool->cur_range;
        } else {
            // No range is available
            return 0u;
        }
    }

    // We are now on an available range
    uint32_t candidate = dhcp_bm_next_ip(&pool->counter, range_start);
    if (dhcp_bm_used(pool, candidate)) return 0u;
    
    // Set expiration time + 1-min grace period if current range is full
    if (dhcp_bm_range_full(range_start, candidate)) {
        pool->ranges[pool->cur_range].expire_time = cur_time + pool->lease_time + 60;
    }

    return candidate;
}

bool dhcp_bmpool_uni_alloc_ip(dhcp_bmpool_uni_t *pool, uint32_t ip) {
    if (ip < pool->pool_start || ip >= pool->pool_start + POOL_SIZE) return false;
    if (dhcp_bmpool_uni_ip_used(pool, ip)) return false;

    uint32_t offset = ip - pool->pool_start;
    uint8_t range_idx = (uint8_t)(offset / DHCP_BITMAP_RANGE_SIZE);
    uint32_t bit = offset % DHCP_BITMAP_RANGE_SIZE;
    dhcp_bm_set(&(pool->ranges[range_idx]), bit);
    return true;
}

void dhcp_bmpool_uni_stats(const dhcp_bmpool_uni_t *pool, int16_t *out_used, uint16_t *out_total) {
    uint32_t used = 0;
    for (uint8_t i = 0; i < DHCP_BITMAP_MAX_RANGES; ++i)
        used += bm_popcount(pool->ranges[i].ips);
    if (out_used)  *out_used  = (int16_t)used;
    if (out_total) *out_total = (uint16_t)POOL_SIZE;
}
