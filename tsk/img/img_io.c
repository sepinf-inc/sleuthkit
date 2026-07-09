/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file img_io.c
 * Contains the basic img reading API redirection functions.
 */

#include "tsk_img_i.h"

/* Read-ahead kill switch: TSK_IMG_READAHEAD=0 disables the sequential
 * prefetch. Checked once; the racy first initialization is benign since
 * every thread computes the same value. */
static int
img_readahead_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0) {
        const char *env = getenv("TSK_IMG_READAHEAD");
        enabled = (env == NULL || strcmp(env, "0") != 0) ? 1 : 0;
    }
    return enabled;
}

/**
 * \ingroup imglib
 * Initialize the backend lock and the per-bank cache locks of a
 * TSK_IMG_INFO. Every code path that creates a TSK_IMG_INFO (including
 * the pool wrappers) must call this instead of initializing
 * cache_lock directly.
 */
void
tsk_img_lock_init(TSK_IMG_INFO * a_img_info)
{
    int i;
    tsk_init_lock(&(a_img_info->cache_lock));
    for (i = 0; i < TSK_IMG_INFO_CACHE_BANKS; i++) {
        tsk_init_lock(&(a_img_info->cache_bank_locks[i]));
    }
}

/**
 * \ingroup imglib
 * Destroy the locks initialized by tsk_img_lock_init().
 */
void
tsk_img_lock_deinit(TSK_IMG_INFO * a_img_info)
{
    int i;
    tsk_deinit_lock(&(a_img_info->cache_lock));
    for (i = 0; i < TSK_IMG_INFO_CACHE_BANKS; i++) {
        tsk_deinit_lock(&(a_img_info->cache_bank_locks[i]));
    }
}

// This function assumes that we hold the cache_lock even though we're not modifying
// the cache.  This is because the lower-level read callbacks make the same assumption.
static ssize_t tsk_img_read_no_cache(TSK_IMG_INFO * a_img_info, TSK_OFF_T a_off,
    char *a_buf, size_t a_len)
{
    ssize_t nbytes;

    /* Some of the lower-level methods like block-sized reads.
        * So if the len is not that multiple, then make it. */
    if ((a_img_info->sector_size > 0) && (a_len % a_img_info->sector_size)) {
        char *buf2 = NULL;

        size_t len_tmp;
        len_tmp = roundup(a_len, a_img_info->sector_size);
        if ((buf2 = (char *) tsk_malloc(len_tmp)) == NULL) {
            return -1;
        }
        nbytes = a_img_info->read(a_img_info, a_off, buf2, len_tmp);
        if ((nbytes > 0) && (nbytes < (ssize_t) a_len)) {
            memcpy(a_buf, buf2, nbytes);
        }
        else {
            memcpy(a_buf, buf2, a_len);
            nbytes = (ssize_t)a_len;
        }
        free(buf2);
    }
    else {
        nbytes = a_img_info->read(a_img_info, a_off, a_buf, a_len);
    }
    return nbytes;
}

/**
 * \ingroup imglib
 * Reads data from an open disk image
 * @param a_img_info Disk image to read from
 * @param a_off Byte offset to start reading from
 * @param a_buf Buffer to read into
 * @param a_len Number of bytes to read into buffer
 * @returns -1 on error or number of bytes read
 *
 * Cache design: blocks are TSK_IMG_INFO_CACHE_LEN bytes, aligned to
 * TSK_IMG_INFO_CACHE_LEN. The image address space is divided into
 * regions of TSK_IMG_INFO_CACHE_BANK_ENTRIES consecutive blocks; each
 * region maps to one cache bank, so a block always lives in exactly one
 * bank and a lookup only scans that bank's entries under that bank's
 * lock. Backend reads are serialized by cache_lock (the image-format
 * backends keep shared state such as seek positions). Lock order is
 * strictly bank lock -> cache_lock, and no thread ever holds two bank
 * locks (the read-ahead only prefetches blocks of the same bank), so
 * the locking is deadlock-free.
 */
ssize_t
tsk_img_read(TSK_IMG_INFO * a_img_info, TSK_OFF_T a_off,
    char *a_buf, size_t a_len)
{
#define CACHE_AGE   1000
    const TSK_OFF_T region_len =
        (TSK_OFF_T) TSK_IMG_INFO_CACHE_LEN * TSK_IMG_INFO_CACHE_BANK_ENTRIES;
    ssize_t read_count = 0;
    int cache_index = 0;
    int cache_next = 0;         // index to lowest age cache (to use next)
    int bank = 0;
    int bank_first = 0;
    int bank_last = 0;          // exclusive
    int hit = 0;
    TSK_OFF_T block_off = 0;
    size_t len2 = 0;

    if (a_img_info == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("tsk_img_read: a_img_info: NULL");
        return -1;
    }

    // Do not allow a_buf to be NULL.
    if (a_buf == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("tsk_img_read: a_buf: NULL");
        return -1;
    }

    // The function cannot handle negative offsets.
    if (a_off < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("tsk_img_read: a_off: %" PRIdOFF, a_off);
        return -1;
    }

    // Protect a_off against overflowing when a_len is added since TSK_OFF_T
    // maps to an int64 we prefer it over size_t although likely checking
    // for ( a_len > SSIZE_MAX ) is better but the code does not seem to
    // use that approach.

    if (a_len > (size_t) INT64_MAX) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("tsk_img_read: a_len: %" PRIuSIZE, a_len);
        return -1;
    }

    // TODO: why not just return 0 here (and be POSIX compliant)?
    // and why not check earlier for this condition?
    if (a_off >= a_img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("tsk_img_read - %" PRIdOFF, a_off);
        return -1;
    }

    /* Requests that cross a cache-block boundary (or exceed the block
     * size) bypass the cache. cache_lock serializes the backend call
     * and protects the shared variables in the img type specific INFO
     * structs. */
    if ((size_t) (a_off % TSK_IMG_INFO_CACHE_LEN) + a_len >
        TSK_IMG_INFO_CACHE_LEN) {
        tsk_take_lock(&(a_img_info->cache_lock));
        read_count = tsk_img_read_no_cache(a_img_info, a_off, a_buf, a_len);
        tsk_release_lock(&(a_img_info->cache_lock));
        return read_count;
    }

    /* See if the requested length is going to be too long.
     * we'll use this length when checking the cache. */
    len2 = a_len;

    // Protect against INT64_MAX + INT64_MAX > value
    if (((TSK_OFF_T) len2 > a_img_info->size)
        || (a_off >= (a_img_info->size - (TSK_OFF_T)len2))) {
        len2 = (size_t) (a_img_info->size - a_off);
    }

    block_off = (a_off / TSK_IMG_INFO_CACHE_LEN) * TSK_IMG_INFO_CACHE_LEN;
    bank = (int) ((a_off / region_len) % TSK_IMG_INFO_CACHE_BANKS);
    bank_first = bank * TSK_IMG_INFO_CACHE_BANK_ENTRIES;
    bank_last = bank_first + TSK_IMG_INFO_CACHE_BANK_ENTRIES;
    cache_next = bank_first;

    tsk_take_lock(&(a_img_info->cache_bank_locks[bank]));

    // Detect sequential access pattern for read-ahead (per bank).
    // Consider sequential if the new offset equals the expected continuation
    // (previous offset + previous length) or is within 8KB of it.
    {
        TSK_OFF_T expected = a_img_info->last_read_offset[bank]
            + (TSK_OFF_T) a_img_info->last_read_len[bank];
        if ((a_off >= a_img_info->last_read_offset[bank]) &&
            ((a_off == expected) || ((a_off > expected) && (a_off < expected + 8192)))) {
            // saturate so the counter cannot overflow on very long streaks
            if (a_img_info->sequential_streak[bank] < 1000)
                a_img_info->sequential_streak[bank]++;
        } else {
            a_img_info->sequential_streak[bank] = 0;
        }
        a_img_info->last_read_offset[bank] = a_off;
    }

    // check if the block is in this bank of the cache
    for (cache_index = bank_first; cache_index < bank_last; cache_index++) {

        // Look into the in-use cache entries
        if (a_img_info->cache_len[cache_index] > 0) {

            if ((hit == 0)
                && (a_img_info->cache_off[cache_index] == block_off)
                && (a_img_info->cache_off[cache_index] +
                    (TSK_OFF_T) a_img_info->cache_len[cache_index] >=
                    a_off + (TSK_OFF_T) len2)) {

                // We found it...
                memcpy(a_buf,
                    &a_img_info->cache[cache_index][a_off - block_off],
                    len2);
                read_count = (ssize_t) len2;
                hit = 1;

                // reset its "age" since it was useful
                a_img_info->cache_age[cache_index] = CACHE_AGE;

                // we don't break out of the loop so that we update all ages
            }
            else {
                /* decrease its "age" since it was not useful.
                 * We don't let used ones go below 1 so that they are not
                 * confused with entries that have never been used. */
                a_img_info->cache_age[cache_index]--;

                // see if this is the most eligible replacement
                if ((a_img_info->cache_len[cache_next] > 0)
                    && (a_img_info->cache_age[cache_index] <
                        a_img_info->cache_age[cache_next]))
                    cache_next = cache_index;
            }
        }
        else {
            cache_next = cache_index;
        }
    }

    // if we didn't find it, then load it into the cache_next entry
    if (hit == 0) {
        size_t read_size = TSK_IMG_INFO_CACHE_LEN;

        if ((block_off + (TSK_OFF_T) read_size) > a_img_info->size) {
            read_size = (size_t) (a_img_info->size - block_off);
        }

        /* Backend reads are serialized: the image-format callbacks keep
         * shared state (seek positions, library handles) that assumes a
         * single caller at a time. Lock order: bank lock -> cache_lock. */
        tsk_take_lock(&(a_img_info->cache_lock));

        read_count = a_img_info->read(a_img_info, block_off,
            a_img_info->cache[cache_next], read_size);

        // if no error, then set the variables and copy the data
        // Although a read_count of -1 indicates an error,
        // since read_count is used in the calculation it may not be negative.
        // Also it does not make sense to copy data when the read_count is 0.
        if (read_count > 0) {

            TSK_OFF_T rel_off = 0;
            a_img_info->cache_age[cache_next] = CACHE_AGE;
            a_img_info->cache_len[cache_next] = read_count;
            a_img_info->cache_off[cache_next] = block_off;

            // Determine the offset relative to the start of the cached data.
            rel_off = a_off - block_off;

            // Make sure we were able to read sufficient data into the cache.
            if (rel_off > (TSK_OFF_T) read_count) {
                len2 = 0;
            }
            // Make sure not to copy more than is available in the cache.
            else if ((rel_off + (TSK_OFF_T) len2) > (TSK_OFF_T) read_count) {
                len2 = (size_t) (read_count - rel_off);
            }
            // Only copy data when we have something to copy.
            if (len2 > 0) {
                memcpy(a_buf, &(a_img_info->cache[cache_next][rel_off]), len2);
            }
            read_count = (ssize_t) len2;

            // Read-ahead: if sequential access pattern detected, preload the
            // next block into a low-priority slot of the SAME bank (blocks
            // of other banks are never touched, keeping the locking
            // deadlock-free). Can be disabled with TSK_IMG_READAHEAD=0.
            if (img_readahead_enabled()
                && a_img_info->sequential_streak[bank] >= 2) {
                TSK_OFF_T ra_off = block_off + TSK_IMG_INFO_CACHE_LEN;

                if ((ra_off < a_img_info->size)
                    && ((ra_off / region_len) == (block_off / region_len))) {
                    int ra_slot = -1;
                    int ra_slot_unused = 0;
                    int already_cached = 0;
                    int i;

                    // Find best slot for prefetch (prefer unused, else
                    // lowest age) and skip if the next block is already
                    // in this bank.
                    for (i = bank_first; i < bank_last; i++) {
                        if ((a_img_info->cache_len[i] > 0)
                            && (a_img_info->cache_off[i] == ra_off)) {
                            already_cached = 1;
                            break;
                        }
                        if (i == cache_next)
                            continue;
                        if (a_img_info->cache_len[i] == 0) {
                            if (!ra_slot_unused) {
                                ra_slot = i;
                                ra_slot_unused = 1;
                            }
                        }
                        else if (!ra_slot_unused
                            && (ra_slot == -1
                                || a_img_info->cache_age[i] <
                                   a_img_info->cache_age[ra_slot])) {
                            ra_slot = i;
                        }
                    }

                    if (!already_cached && ra_slot != -1) {
                        size_t ra_rdsize = TSK_IMG_INFO_CACHE_LEN;
                        ssize_t ra_count;

                        if (ra_off + (TSK_OFF_T)ra_rdsize > a_img_info->size) {
                            ra_rdsize = (size_t)(a_img_info->size - ra_off);
                        }

                        ra_count = a_img_info->read(a_img_info, ra_off,
                            a_img_info->cache[ra_slot], ra_rdsize);

                        if (ra_count > 0) {
                            a_img_info->cache_off[ra_slot] = ra_off;
                            a_img_info->cache_len[ra_slot] = ra_count;
                            // Assign lower age so it can be evicted more easily
                            a_img_info->cache_age[ra_slot] = CACHE_AGE / 4;
                        }
                    }
                }
            }
        }
        else {
            a_img_info->cache_len[cache_next] = 0;
            a_img_info->cache_age[cache_next] = 0;
            a_img_info->cache_off[cache_next] = 0;

            // Something went wrong so let's try skipping the cache
            // (cache_lock is already held, as tsk_img_read_no_cache expects)
            read_count = tsk_img_read_no_cache(a_img_info, a_off, a_buf, a_len);
        }

        tsk_release_lock(&(a_img_info->cache_lock));
    }

    a_img_info->last_read_len[bank] =
        (read_count > 0) ? (size_t) read_count : 0;

    tsk_release_lock(&(a_img_info->cache_bank_locks[bank]));
    return read_count;
}
