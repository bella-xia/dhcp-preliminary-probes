#ifndef DHCP_TABLE_H
#define DHCP_TABLE_H

/*
 * TABLE-mode IP lease pool.
 * Tracks per-client leases in a caller-provided array, keyed by MAC address.
 */

#include <stdint.h>

/* One lease entry, mapping a client MAC to an IP address. */
typedef struct {
    uint32_t ip_address;        /* Leased IP address */
    uint8_t mac_address[6];     /* MAC address */
    uint32_t lease_time;        /* Lease duration in seconds */
    uint32_t assigned_time;     /* When the lease was assigned */
    uint8_t in_use;             /* Whether this lease is active */
    uint32_t xid;               /* Transaction ID for this lease */
} dhcp_lease_t;

/* TABLE-mode lease pool */
typedef struct {
    dhcp_lease_t *leases;
    uint16_t max_leases;
    uint16_t lease_count;
} dhcp_tablepool_t;

void dhcp_tablepool_init(dhcp_tablepool_t *pool, dhcp_lease_t *leases, uint16_t max_leases);
uint32_t dhcp_tablepool_find_available_ip(dhcp_tablepool_t *pool, uint32_t pool_start, uint32_t pool_end, uint8_t *mac);
dhcp_lease_t *dhcp_tablepool_find_lease(dhcp_tablepool_t *pool, uint8_t *mac);
dhcp_lease_t *dhcp_tablepool_alloc_lease(dhcp_tablepool_t *pool, uint32_t ip, uint8_t *mac, uint32_t xid, uint32_t lease_time);

#endif /* DHCP_TABLE_H */
