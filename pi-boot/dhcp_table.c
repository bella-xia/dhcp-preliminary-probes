#include "dhcp_table.h"
#include "kstring.h"

void dhcp_tablepool_init(dhcp_tablepool_t *pool, dhcp_lease_t *leases, uint16_t max_leases) {
    pool->leases = leases;
    pool->max_leases = max_leases;
    pool->lease_count = 0;
    
    // Note: leases array should be allocated by caller or use static storage
    if (leases) {
        for (uint16_t i = 0; i < max_leases; i++)
            leases[i].in_use = 0;
    }
}

/* Find an available IP address from the pool */
uint32_t dhcp_tablepool_find_available_ip(dhcp_tablepool_t *pool,
                                          uint32_t pool_start, uint32_t pool_end,
                                          uint8_t *mac) {
    /* Check if MAC already has a lease */
    dhcp_lease_t *existing = dhcp_tablepool_find_lease(pool, mac);
    if (existing)
        return existing->ip_address;

    /* Find first available IP */
    for (uint32_t ip = pool_start; ip <= pool_end; ip++) {
        uint8_t found = 0;
        for (uint16_t i = 0; i < pool->lease_count; i++) {
            if (pool->leases[i].in_use && pool->leases[i].ip_address == ip) {
                found = 1;
                break;
            }
        }
        if (!found)
            return ip;
    }

    return 0; /* No available IP */
}

/* Find a lease by MAC address */
dhcp_lease_t *dhcp_tablepool_find_lease(dhcp_tablepool_t *pool, uint8_t *mac) {
    for (uint16_t i = 0; i < pool->lease_count; i++) {
        if (pool->leases[i].in_use && 
            kmemcmp(pool->leases[i].mac_address, mac, 6) == 0) {
            return &pool->leases[i];
        }
    }
    return NULL;
}

/* Allocate a new lease */
dhcp_lease_t *dhcp_tablepool_alloc_lease(dhcp_tablepool_t *pool,
                                         uint32_t ip, uint8_t *mac,
                                         uint32_t xid, uint32_t lease_time) {
    if (pool->lease_count >= pool->max_leases)
        return NULL;

    dhcp_lease_t *lease = &pool->leases[pool->lease_count];
    lease->ip_address = ip;
    kmemcpy(lease->mac_address, mac, 6);
    lease->lease_time = lease_time;
    lease->assigned_time = 0; /* TODO: Set to current time */
    lease->in_use = 1;
    lease->xid = xid;

    pool->lease_count++;
    return lease;
}
