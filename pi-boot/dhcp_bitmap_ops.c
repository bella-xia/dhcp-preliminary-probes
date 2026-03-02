#include "dhcp_bitmap_ops.h"

void dhcp_bm_udivmod(uint32_t n, uint32_t d, uint32_t *quot, uint32_t *rem) {
    uint32_t q = 0u, r = 0u;
    for (int i = 31; i >= 0; --i) {
        r = (r << 1u) | ((n >> i) & 1u);
        if (r >= d) { r -= d; q |= (1u << i); }
    }
    *quot = q;
    *rem  = r;
}

void dhcp_bm_set(uint32_t *bm, uint32_t idx) {
    bm[idx >> 5u] |= (1u << (idx & 31u));
}

void dhcp_bm_clear(uint32_t *bm, uint32_t idx) {
    bm[idx >> 5u] &= ~(1u << (idx & 31u));
}

bool dhcp_bm_used(const uint32_t *bm, uint32_t idx) {
    return (bool)((bm[idx >> 5u] >> (idx & 31u)) & 1u);
}

void dhcp_bm_offcnt_init(dhcp_bm_offcnt_t *c) {
    c->count = 0;
}

uint32_t dhcp_bm_next_ip(dhcp_bm_offcnt_t *c, uint32_t pool_start, uint32_t pool_size) {
    uint32_t quot, rem;
    dhcp_bm_udivmod((uint32_t)c->count, pool_size, &quot, &rem);
    uint32_t ip = pool_start + rem;
    c->count++;
    return ip;
}
