#ifndef DHCP_BITMAP_VARTIME_H
#define DHCP_BITMAP_VARTIME_H

/*
 * dhcp_bitmap_vartime.h — Bitmap IP pool with a range-level, rolling timer.
 *
 * Lease-time model
 * ────────────────
 * The pool is divided into equal-size, sequential ranges.  When the FIRST
 * IP in a range is allocated, a countdown of `lease_duration` seconds
 * begins.  When that countdown expires the ENTIRE range is recycled
 * atomically (bitmap reset).
 *
 * Because the timer is shared across the range but each client joins at a
 * different moment, the lease time ADVERTISED to each client is the
 * remaining range lifetime at the moment of allocation:
 *
 *   advertised_lease = activated_at + lease_duration − current_time
 *
 * As a result, clients that arrive later receive shorter lease times.
 * No MAC→IP mapping and no per-IP timestamp are stored.
 *
 * Range layout invariant
 * ──────────────────────
 * ranges[i].range_start == pool_start + i * range_size  (always)
 *
 * Allocation priority (minimises live ranges)
 * ───────────────────────────────────────────
 *  1. Free slot in an active, non-expired range.
 *  2. First IP of a recycled (inactive) range  — reactivated in place.
 *  3. First IP of a brand-new range slice      — range created.
 */

#include "dhcp_bitmap_ops.h"

/* ─────────────────────────────────────────────────────────────────────────
 * Data structures
 * ───────────────────────────────────────────────────────────────────────── */

/*
 * One range tracked by a bitmap.
 * The timer starts at activated_at (first allocation) and the range is
 * recycled when (current_time - activated_at) >= lease_duration.
 */
typedef struct {
    uint32_t range_start;       /* First IP of this range (host byte order) */
    uint16_t range_size;        /* Number of IPs (≤ DHCP_BITMAP_MAX_RANGE_SIZE) */
    uint16_t used_count;        /* IPs currently marked in-use */
    uint32_t lease_duration;    /* Total range lifetime in seconds */
    uint32_t activated_at;      /* Timestamp (s) when first IP was allocated */
    uint8_t  active;            /* 0 = recycled / never used,  1 = live */
    uint8_t  _pad[3];
    /* bit i set  ⟺  IP (range_start + i) is currently allocated */
    uint32_t bitmap[DHCP_BITMAP_WORDS_PER_RANGE];
} dhcp_varrange_t;

/*
 * Pool container: an ordered array of range slices tiling the address space.
 * num_ranges is a high-water mark; ranges[0..num_ranges-1] have been created
 * (some may be inactive/recycled and eligible for reactivation).
 */
typedef struct {
    uint32_t       pool_start;      /* First IP of the overall address pool */
    uint32_t       pool_end;        /* Last  IP of the pool (inclusive) */
    uint16_t       range_size;      /* IPs per range (≤ DHCP_BITMAP_MAX_RANGE_SIZE) */
    /* 2 bytes implicit padding (aligns lease_duration) */
    uint32_t       lease_duration;  /* Lifetime applied to every new range */
    dhcp_bm_offcnt_t offer_counter; /* Monotonically increasing; maps each DISCOVER to a
                                        unique IP: offered = pool_start + (counter % pool_size) */
    uint8_t        num_ranges;      /* Ranges created so far (high-water mark) */
    uint8_t        max_ranges;      /* Hard limit (≤ DHCP_BITMAP_MAX_RANGES) */
    uint8_t        _pad[2];
    dhcp_varrange_t ranges[DHCP_BITMAP_MAX_RANGES];
} dhcp_bmpool_var_t;

/* ─────────────────────────────────────────────────────────────────────────
 * Function declarations
 * ───────────────────────────────────────────────────────────────────────── */

/*
 * Initialise a vartime pool.
 *   pool_start / pool_end — inclusive address range to manage.
 *   range_size            — IPs per range slice (clamped to MAX_RANGE_SIZE).
 *   lease_duration        — total range lifetime in seconds; determines both
 *                           the recycle interval and the maximum advertised
 *                           lease time.
 */
void dhcp_varpool_init(dhcp_bmpool_var_t *pool,
                       uint32_t pool_start, uint32_t pool_end,
                       uint16_t range_size, uint32_t lease_duration);

/*
 * Recycle all ranges whose (current_time - activated_at) >= lease_duration.
 * Expired ranges have their bitmaps zeroed and active flag cleared so they
 * can be reactivated by the next allocation.
 * Must be called before every allocation attempt.
 */
void dhcp_varpool_recycle(dhcp_bmpool_var_t *pool, uint32_t current_time);

/*
 * Allocate the next available IP following the priority described above.
 * Returns the allocated IP address, or 0 if the pool is fully exhausted.
 */
uint32_t dhcp_varpool_alloc(dhcp_bmpool_var_t *pool, uint32_t current_time);

/*
 * Peek at the next available IP without committing it.
 * Used for DHCP DISCOVER handling to form an OFFER without yet allocating.
 * Returns 0 if the pool is exhausted.
 */
uint32_t dhcp_varpool_peek(dhcp_bmpool_var_t *pool, uint32_t current_time);

/*
 * Commit a specific IP address.
 * Creates or reactivates the enclosing range as needed.
 * Returns the IP on success, or 0 when:
 *   – the IP is outside the pool range, or
 *   – the bit is already set (IP already allocated), or
 *   – the pool capacity (max_ranges) is exhausted.
 */
uint32_t dhcp_varpool_alloc_ip(dhcp_bmpool_var_t *pool, uint32_t ip,
                                uint32_t current_time);

/*
 * Returns 1 if ip is currently allocated within an active range, 0 otherwise.
 */
uint8_t dhcp_varpool_is_used(const dhcp_bmpool_var_t *pool, uint32_t ip);

/*
 * Returns the remaining lease time for ip in seconds — i.e. the value that
 * should be advertised to the DHCP client at the moment of allocation.
 *
 *   remaining = activated_at + lease_duration − current_time
 *
 * Returns 0 if ip is not in an active, in-use range or if the range has
 * already expired.
 */
uint32_t dhcp_varpool_lease_remaining(const dhcp_bmpool_var_t *pool,
                                       uint32_t ip, uint32_t current_time);

/*
 * Report pool utilisation.  Any output pointer may be NULL.
 *   out_used       — IPs currently allocated across all active ranges.
 *   out_total      — capacity (IPs) across all active ranges.
 *   out_num_active — number of currently active (non-recycled) ranges.
 */
void dhcp_varpool_stats(const dhcp_bmpool_var_t *pool,
                         uint16_t *out_used, uint16_t *out_total,
                         uint8_t  *out_num_active);

#endif /* DHCP_BITMAP_VARTIME_H */
