#include "dhcp_bitmap_unitime.h"
#include "dhcp_compat.h"

/* Scan bitmap for the first free slot in [0, size).  Returns slot index or -1. */
static int bm_find_free(const uint32_t *bm, uint32_t size)
{
    uint32_t words = (size + 31u) / 32u;
    for (uint32_t w = 0; w < words; ++w) {
        uint32_t free_bits = ~bm[w];
        if (w == words - 1u && (size & 31u))
            free_bits &= (1u << (size & 31u)) - 1u;
        if (free_bits) {
#if defined(__GNUC__) || defined(__clang__)
            return (int)(w * 32u) + __builtin_ctz(free_bits);
#else
            int n = 0; uint32_t v = free_bits;
            while ((v & 1u) == 0u) { v >>= 1; ++n; }
            return (int)(w * 32u) + n;
#endif
        }
    }
    return -1;
}

/* Open range slot i without activating it (inactive placeholder). */
static void unifrange_create_inactive(dhcp_bmpool_uni_t *pool, uint8_t i)
{
    dhcp_unifrange_t *r = &pool->ranges[i];
    r->range_start    = pool->pool_start + (uint32_t)i * pool->range_size;
    uint32_t rem      = (r->range_start <= pool->pool_end)
                        ? (pool->pool_end - r->range_start + 1u) : 0u;
    r->range_size     = (pool->range_size <= (uint16_t)rem)
                        ? pool->range_size : (uint16_t)rem;
    r->used_count     = 0;
    r->lease_duration = pool->lease_duration;
    r->filled_at      = 0;
    r->active         = 0;
    r->packed         = 0;
    kmemset(r->bitmap, 0, sizeof(r->bitmap));
}

static void unifrange_check_packed(dhcp_unifrange_t *r, uint32_t current_time)
{
    if (!r->packed && r->used_count == r->range_size) {
        r->packed    = 1;
        r->filled_at = current_time;
    }
}

void dhcp_unifpool_init(dhcp_bmpool_uni_t *pool,
                        uint32_t pool_start, uint32_t pool_end,
                        uint16_t range_size, uint32_t lease_duration)
{
    pool->pool_start     = pool_start;
    pool->pool_end       = pool_end;
    pool->range_size     = range_size;
    pool->lease_duration = lease_duration;
    pool->num_ranges     = 0;
    pool->max_ranges     = DHCP_BITMAP_MAX_RANGES;
    dhcp_bm_offcnt_init(&pool->offer_counter);

    for (uint8_t i = 0; i < DHCP_BITMAP_MAX_RANGES; ++i) {
        pool->ranges[i].active     = 0;
        pool->ranges[i].packed     = 0;
        pool->ranges[i].used_count = 0;
        kmemset(pool->ranges[i].bitmap, 0, sizeof(pool->ranges[i].bitmap));
    }
}

void dhcp_unifpool_recycle(dhcp_bmpool_uni_t *pool, uint32_t current_time)
{
    for (uint8_t i = 0; i < pool->num_ranges; ++i) {
        dhcp_unifrange_t *r = &pool->ranges[i];
        if (!r->active || !r->packed) continue;
        if ((current_time - r->filled_at) >= r->lease_duration) {
            kmemset(r->bitmap, 0, sizeof(r->bitmap));
            r->used_count = 0;
            r->active     = 0;
            r->packed     = 0;
        }
    }
}

uint32_t dhcp_unifpool_alloc(dhcp_bmpool_uni_t *pool, uint32_t current_time)
{
    dhcp_unifpool_recycle(pool, current_time);

    /* 1. Free slot in an active, non-packed range */
    for (uint8_t i = 0; i < pool->num_ranges; ++i) {
        dhcp_unifrange_t *r = &pool->ranges[i];
        if (!r->active || r->packed) continue;
        int slot = bm_find_free(r->bitmap, r->range_size);
        if (slot < 0) continue;
        dhcp_bm_set(r->bitmap, (uint16_t)slot);
        r->used_count++;
        unifrange_check_packed(r, current_time);
        return r->range_start + (uint32_t)slot;
    }

    /* 2. Reactivate the lowest-index inactive range */
    for (uint8_t i = 0; i < pool->num_ranges; ++i) {
        dhcp_unifrange_t *r = &pool->ranges[i];
        if (r->active) continue;
        r->active     = 1;
        r->packed     = 0;
        r->used_count = 1;
        kmemset(r->bitmap, 0, sizeof(r->bitmap));
        dhcp_bm_set(r->bitmap, 0);
        unifrange_check_packed(r, current_time);
        return r->range_start;
    }

    /* 3. Open a brand-new range slice */
    if (pool->num_ranges >= pool->max_ranges) return 0u;
    uint32_t new_start = pool->pool_start
                         + (uint32_t)pool->num_ranges * pool->range_size;
    if (new_start > pool->pool_end) return 0u;

    unifrange_create_inactive(pool, pool->num_ranges);
    dhcp_unifrange_t *r = &pool->ranges[pool->num_ranges];
    r->active     = 1;
    r->used_count = 1;
    dhcp_bm_set(r->bitmap, 0);
    pool->num_ranges++;
    unifrange_check_packed(r, current_time);
    return new_start;
}

uint32_t dhcp_unifpool_peek(dhcp_bmpool_uni_t *pool, uint32_t current_time)
{
    dhcp_unifpool_recycle(pool, current_time);

    for (uint8_t i = 0; i < pool->num_ranges; ++i) {
        dhcp_unifrange_t *r = &pool->ranges[i];
        if (!r->active || r->packed) continue;
        int slot = bm_find_free(r->bitmap, r->range_size);
        if (slot >= 0) return r->range_start + (uint32_t)slot;
    }

    for (uint8_t i = 0; i < pool->num_ranges; ++i) {
        if (!pool->ranges[i].active) return pool->ranges[i].range_start;
    }

    if (pool->num_ranges < pool->max_ranges) {
        uint32_t ns = pool->pool_start
                      + (uint32_t)pool->num_ranges * pool->range_size;
        if (ns <= pool->pool_end) return ns;
    }
    return 0u;
}

uint32_t dhcp_unifpool_alloc_ip(dhcp_bmpool_uni_t *pool, uint32_t ip,
                                 uint32_t current_time)
{
    if (ip < pool->pool_start || ip > pool->pool_end) return 0u;

    dhcp_unifpool_recycle(pool, current_time);

    uint32_t offset = ip - pool->pool_start;
    uint32_t _q, _r;
    dhcp_bm_udivmod(offset, pool->range_size, &_q, &_r);
    uint16_t range_idx = (uint16_t)_q;
    uint16_t bit_idx   = (uint16_t)_r;

    while (pool->num_ranges <= range_idx) {
        if (pool->num_ranges >= pool->max_ranges) return 0u;
        unifrange_create_inactive(pool, pool->num_ranges);
        if (!pool->ranges[pool->num_ranges].range_size) return 0u;
        pool->num_ranges++;
    }

    dhcp_unifrange_t *r = &pool->ranges[range_idx];
    if (!r->active) {
        r->active = 1;
        r->packed = 0;
    }
    if (r->packed) return 0u;
    if (dhcp_bm_used(r->bitmap, bit_idx)) return 0u;
    dhcp_bm_set(r->bitmap, bit_idx);
    r->used_count++;
    unifrange_check_packed(r, current_time);
    return ip;
}

uint8_t dhcp_unifpool_is_used(const dhcp_bmpool_uni_t *pool, uint32_t ip)
{
    if (ip < pool->pool_start || ip > pool->pool_end) return 0u;
    uint32_t offset = ip - pool->pool_start;
    uint32_t _q, _r;
    dhcp_bm_udivmod(offset, pool->range_size, &_q, &_r);
    uint16_t range_idx = (uint16_t)_q;
    uint16_t bit_idx   = (uint16_t)_r;
    if (range_idx >= pool->num_ranges) return 0u;
    const dhcp_unifrange_t *r = &pool->ranges[range_idx];
    if (!r->active) return 0u;
    return dhcp_bm_used(r->bitmap, bit_idx);
}

uint32_t dhcp_unifpool_lease_time(const dhcp_bmpool_uni_t *pool, uint32_t ip)
{
    if (ip < pool->pool_start || ip > pool->pool_end) return 0u;
    uint32_t offset = ip - pool->pool_start;
    uint32_t _q, _r;
    dhcp_bm_udivmod(offset, pool->range_size, &_q, &_r);
    uint16_t range_idx = (uint16_t)_q;
    uint16_t bit_idx   = (uint16_t)_r;
    if (range_idx >= pool->num_ranges) return 0u;
    const dhcp_unifrange_t *r = &pool->ranges[range_idx];
    if (!r->active) return 0u;
    if (!dhcp_bm_used(r->bitmap, bit_idx)) return 0u;
    return r->lease_duration;
}

void dhcp_unifpool_stats(const dhcp_bmpool_uni_t *pool,
                          uint16_t *out_used, uint16_t *out_total,
                          uint8_t  *out_num_active, uint8_t *out_num_packed)
{
    uint16_t used = 0, total = 0;
    uint8_t  active = 0, packed = 0;
    for (uint8_t i = 0; i < pool->num_ranges; ++i) {
        const dhcp_unifrange_t *r = &pool->ranges[i];
        if (!r->active) continue;
        used  += r->used_count;
        total += r->range_size;
        active++;
        if (r->packed) packed++;
    }
    if (out_used)       *out_used       = used;
    if (out_total)      *out_total      = total;
    if (out_num_active) *out_num_active = active;
    if (out_num_packed) *out_num_packed = packed;
}
