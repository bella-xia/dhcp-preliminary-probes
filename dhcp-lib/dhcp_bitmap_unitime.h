#ifndef DHCP_BITMAP_UNITIME_H
#define DHCP_BITMAP_UNITIME_H

/*
 * dhcp_bitmap_uniftime.h — Bitmap IP pool where every lease in a range
 *                          carries the same (full) lease duration, and the
 *                          recycle timer starts only once the range is
 *                          completely packed.
 *
 * Lease-time model
 * ────────────────
 * All IPs in a range share a single `lease_duration` value.  Regardless of
 * when within the range's lifetime a client connects, the server advertises
 * the full `lease_duration` as the client's lease time.
 *
 * The range-level recycling clock begins only when the LAST slot in the
 * range is allocated (i.e. used_count == range_size, the range is "packed").
 * At that moment `filled_at` is recorded.  When
 *
 *   current_time − filled_at  >=  lease_duration
 *
 * the range is expired: the entire bitmap is reset and the range is marked
 * inactive so its IPs can be reused.
 *
 * If the range is never completely filled, it is never recycled by this
 * mechanism.  The occupied slots remain allocated until the range is
 * explicitly reset or the server is restarted.
 *
 * No MAC→IP mapping and no per-IP timestamp are stored.
 *
 * Range layout invariant
 * ──────────────────────
 * ranges[i].range_start == pool_start + i * range_size  (always)
 *
 * Allocation priority (minimises live ranges)
 * ───────────────────────────────────────────
 *  1. Free slot in an active, non-packed range.
 *  2. First IP of an expired-and-recycled (inactive) range — reactivated.
 *  3. First IP of a brand-new range slice — range created.
 */

#include "dhcp_bitmap_ops.h"

/* ─────────────────────────────────────────────────────────────────────────
 * Data structures
 * ───────────────────────────────────────────────────────────────────────── */

/*
 * One range tracked by a bitmap.
 *
 * The range transitions through these states:
 *   inactive → active (first allocation sets active=1)
 *   active   → packed (last slot taken sets packed=1 and records filled_at)
 *   packed   → inactive (recycled when current_time − filled_at ≥ lease_duration)
 */
typedef struct {
    uint32_t range_start;       /* First IP of this range (host byte order) */
    uint16_t range_size;        /* Number of IPs (≤ DHCP_BITMAP_MAX_RANGE_SIZE) */
    uint16_t used_count;        /* IPs currently marked in-use */
    uint32_t lease_duration;    /* Lease duration advertised to every client */
    uint32_t filled_at;         /* Timestamp (s) when the last slot was taken */
    uint8_t  active;            /* 0 = recycled / never used,  1 = has allocations */
    uint8_t  packed;            /* 1 = all slots are in-use; recycle timer is running */
    uint8_t  _pad[2];
    /* bit i set  ⟺  IP (range_start + i) is currently allocated */
    uint32_t bitmap[DHCP_BITMAP_WORDS_PER_RANGE];
} dhcp_unifrange_t;

/*
 * Pool container: an ordered array of range slices tiling the address space.
 * num_ranges is a high-water mark; ranges[0..num_ranges-1] have been created
 * (some may be inactive and eligible for reactivation).
 */
typedef struct {
    uint32_t        pool_start;     /* First IP of the overall address pool */
    uint32_t        pool_end;       /* Last  IP of the pool (inclusive) */
    uint16_t        range_size;     /* IPs per range (≤ DHCP_BITMAP_MAX_RANGE_SIZE) */
    /* 2 bytes implicit padding (aligns lease_duration) */
    uint32_t        lease_duration; /* Full lease duration advertised to all clients */
    dhcp_bm_offcnt_t offer_counter; /* Monotonically increasing; maps each DISCOVER to a
                                        unique IP: offered = pool_start + (counter % pool_size) */
    uint8_t         num_ranges;     /* Ranges created so far (high-water mark) */
    uint8_t         max_ranges;     /* Hard limit (≤ DHCP_BITMAP_MAX_RANGES) */
    uint8_t         _pad[2];
    dhcp_unifrange_t ranges[DHCP_BITMAP_MAX_RANGES];
} dhcp_bmpool_uni_t;

/* ─────────────────────────────────────────────────────────────────────────
 * Function declarations
 * ───────────────────────────────────────────────────────────────────────── */

/*
 * Initialise a uniftime pool.
 *   pool_start / pool_end — inclusive address range to manage.
 *   range_size            — IPs per range slice (clamped to MAX_RANGE_SIZE).
 *   lease_duration        — seconds advertised to clients and used as the
 *                           recycle period after the range becomes packed.
 */
void dhcp_unifpool_init(dhcp_bmpool_uni_t *pool,
                        uint32_t pool_start, uint32_t pool_end,
                        uint16_t range_size, uint32_t lease_duration);

/*
 * Recycle all PACKED ranges for which
 *   (current_time − filled_at) >= lease_duration.
 * Recycled ranges have their bitmaps zeroed and both active and packed flags
 * cleared, making them eligible for reactivation.
 * Must be called before every allocation attempt.
 */
void dhcp_unifpool_recycle(dhcp_bmpool_uni_t *pool, uint32_t current_time);

/*
 * Allocate the next available IP following the priority described above.
 * When a range transitions to packed as a result of this call, filled_at is
 * set to current_time and the recycle countdown begins.
 * Returns the allocated IP address, or 0 if the pool is fully exhausted.
 */
uint32_t dhcp_unifpool_alloc(dhcp_bmpool_uni_t *pool, uint32_t current_time);

/*
 * Peek at the next available IP without committing it.
 * Used for DHCP DISCOVER handling to form an OFFER without yet allocating.
 * Returns 0 if the pool is exhausted.
 */
uint32_t dhcp_unifpool_peek(dhcp_bmpool_uni_t *pool, uint32_t current_time);

/*
 * Commit a specific IP address.
 * Creates or reactivates the enclosing range as needed.
 * Sets packed + filled_at if this allocation completes the range.
 * Returns the IP on success, or 0 when:
 *   – the IP is outside the pool range, or
 *   – the bit is already set (IP already allocated), or
 *   – the pool capacity (max_ranges) is exhausted.
 */
uint32_t dhcp_unifpool_alloc_ip(dhcp_bmpool_uni_t *pool, uint32_t ip,
                                 uint32_t current_time);

/*
 * Returns 1 if ip is currently allocated within an active range, 0 otherwise.
 */
uint8_t dhcp_unifpool_is_used(const dhcp_bmpool_uni_t *pool, uint32_t ip);

/*
 * Returns the lease time that should be advertised to a client for ip.
 *
 * Because all clients in a range receive the full `lease_duration`, this
 * function always returns pool->ranges[range_idx].lease_duration when ip is
 * in an active range, regardless of when the range was activated or packed.
 *
 * Returns 0 if ip is not in an active, in-use range.
 */
uint32_t dhcp_unifpool_lease_time(const dhcp_bmpool_uni_t *pool, uint32_t ip);

/*
 * Report pool utilisation.  Any output pointer may be NULL.
 *   out_used       — IPs currently allocated across all active ranges.
 *   out_total      — capacity (IPs) across all active ranges.
 *   out_num_active — number of currently active (non-recycled) ranges.
 *   out_num_packed — number of currently packed ranges (recycle timer live).
 */
void dhcp_unifpool_stats(const dhcp_bmpool_uni_t *pool,
                          uint16_t *out_used, uint16_t *out_total,
                          uint8_t  *out_num_active, uint8_t *out_num_packed);

#endif /* DHCP_BITMAP_UNITIME_H */
