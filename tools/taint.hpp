#include "branch_pred.h"
#include "libdft_api.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Taint tag definition
 * Using libdft's tag_t, with structured interpretation
 *
 * Tag bits:
 * - Bits 0-3: Taint source type
 * - Bits 4-7: Taint level/confidence
 */

#define MAX_SOURCE_TYPES 16 // 4 bits
#define SOURCE_TYPE_MASK 0x0F
#define TAINT_LEVEL_SHIFT 4
#define TAINT_LEVEL_MASK 0xF0
#define MAX_REGIONS 1024 // max tracked regions
// TODO: paginate max region

// Debug print macro
#ifdef DEBUG_TAINT
#define TAINT_DEBUG(fmt, ...) printf("[DBG] " fmt "\n", ##__VA_ARGS__)
#else
#define TAINT_DEBUG(fmt, ...)                                                                      \
  do {                                                                                             \
  } while (0)
#endif

typedef enum {
  TS_NONE = 0,        // no taint
  TS_NETWORK = 1,     // data from network
  TS_FILE = 2,        // data from file
  TS_USER_INPUT = 3,  // data from user input
  TS_ENVIRONMENT = 4, // data from environment variables
  TS_IPC = 5,         // data from IPC mechanisms
  TS_HEAP = 6,        // data from heap allocations
  TS_ARGUMENT = 7,    // data from function arguments
  TS_RETURN = 8,      // data from function returns
  TS_CUSTOM1 = 9,     // custom source type 1
  TS_CUSTOM2 = 10,    // custom source type 2
  TS_CUSTOM3 = 11,    // custom source type 3
  TS_CUSTOM4 = 12,    // custom source type 4
  TS_PROPAGATED = 15  // tag used for propagated taint
} taint_source_t;

/*
 * Allocation tracking entry
 */
/*typedef struct {*/
/*  int valid;      // validity flag (1=valid, 0=invalid/free)*/
/*  uintptr_t addr; // allocation address*/
/*  size_t size;    // allocation size*/
/*} alloc_entry_t;*/

/*
 * Clear alloc
 */
/*void*/
/*alloc_clear(alloc_entry_t *alloc) {*/
/*  alloc->valid = 0;*/
/*  alloc->addr = 0;*/
/*  alloc->size = 0;*/
/*}*/

/*
 * Taint region structure
 */
typedef struct {
  tag_t tag;               // taint tag for the region
  uintptr_t start_addr;    // start address of the region
  uintptr_t end_addr;      // end address of the region (inclusive)
  int instance_id;         // e.g., file descriptor, packet number, unique ID for event
  const char *description; // optional description of the event/region
  // alloc_entry_t *alloc_info; // if allocated memory segment
} taint_region_t;

/*
 * Clear region
 */
void
region_clear(taint_region_t *region) {
  if (region) {
    region->tag = 0;
    region->start_addr = 0;
    region->end_addr = 0;
    region->instance_id = -1;
    region->description = NULL;
    // region->alloc_info = NULL;
  }
}

/*
 * Clear region
 */
void
region_set(taint_region_t *region, tag_t tag, uintptr_t start_addr, uintptr_t end_addr,
           int instance_id, const char *description) {
  if (region) {
    region->tag = tag;
    region->start_addr = start_addr;
    region->end_addr = end_addr;
    region->instance_id = instance_id;
    region->description = description;
    // region->alloc_info = NULL;
  }
}

/*
 * Helper eq operation function
 */
void
region_copy(taint_region_t *lhs, taint_region_t *rhs) {
  if (lhs && rhs && (lhs != rhs)) {
    lhs->tag = rhs->tag;
    lhs->start_addr = rhs->start_addr;
    lhs->end_addr = rhs->end_addr;
    lhs->instance_id = rhs->instance_id;
    lhs->description = rhs->description;
    // lhs->alloc_info = rhs->alloc_info;
  }
}

/*
 * Global taint tracker state
 * TODO: inteval tree for regions
 * TODO: hashmap for allocs
 */
typedef struct {
  taint_region_t regions[MAX_REGIONS];
  size_t region_count;
  size_t tainted_bytes_count;

  /*alloc_entry_t allocations[MAX_REGIONS];*/
  /*size_t alloc_count;*/
} taint_tracker_t;

/*
 * Global taint tracking state
 * TODO: maybe lose the static global state
 * and create a class-like structure
 */
static taint_tracker_t g_taint_tracker = {0};

/*
 * Clear all taint tracking state
 */
void
tf_clear_taint_tracker() {
  TAINT_DEBUG("tf_clear_taint_tracker: clearing all tracking state and taint tags");

  // clear all taint tags from tracked regions
  taint_region_t *region = nullptr;
  for (size_t i = 0; i < g_taint_tracker.region_count; i++) {
    region = &g_taint_tracker.regions[i];

    TAINT_DEBUG("tf_clear_taint_tracker: clearing taint tags for region %zu (0x%lx - 0x%lx)", i,
                region->start_addr, region->end_addr);

    // clear each byte in the region
    for (uintptr_t addr = region->start_addr; addr <= region->end_addr; addr++) {
      tagmap_clrb(addr);
    }
  }

  // clear regions
  for (size_t i = 0; i < MAX_REGIONS; i++) {
    region = &g_taint_tracker.regions[i];
    region_clear(region);
  }

  // reset region tracking metadata
  g_taint_tracker.region_count = 0;
  g_taint_tracker.tainted_bytes_count = 0;

  // clear allocs
  /*alloc_entry_t *alloc = nullptr;*/
  /*for (size_t i = 0; i < MAX_REGIONS; i++) {*/
  /*  alloc = &g_taint_tracker.allocations[i];*/
  /*  alloc_clear(alloc);*/
  /*}*/

  // reset alloc tracking counter
  /*g_taint_tracker.alloc_count = 0;*/

  printf("[TNT] Cleared all taint tracking state and taint tags\n");
}

/*
 * Make a tag from a source type and level
 */
static inline tag_t
make_tag(taint_source_t source_type, uint8_t level) {
  assert(level <= 0x0F);
  tag_t result = ((level << TAINT_LEVEL_SHIFT) | (source_type & SOURCE_TYPE_MASK));
  TAINT_DEBUG("make_tag: source=%d, level=%u, result=0x%x", (int)source_type, level, result);
  return result;
}

/*
 * Extract source type from tag
 */
static inline taint_source_t
get_tag_source(tag_t tag) {
  taint_source_t result = (taint_source_t)(tag & SOURCE_TYPE_MASK);
  TAINT_DEBUG("get_tag_source: tag=0x%x, source=%d", tag, (int)result);
  return result;
}

/*
 * Extract taint level from tag
 */
static inline uint8_t
get_tag_level(tag_t tag) {
  uint8_t result = (tag & TAINT_LEVEL_MASK) >> TAINT_LEVEL_SHIFT;
  TAINT_DEBUG("get_tag_level: tag=0x%x, level=%u", tag, result);
  return result;
}

/*
 * Return minimum of two values
 */
static inline uint8_t
min_u8(uint8_t a, uint8_t b) {
  return (a < b) ? a : b;
}

/*
 * Return maximum of two values
 */
static inline uint8_t
max_u8(uint8_t a, uint8_t b) {
  return (a > b) ? a : b;
}

/*
 * Combine two tags - take the highest confidence level and either
 * keep the original source or mark as propagated if sources differ
 */
static inline tag_t
combine_tags(tag_t t1, tag_t t2) {
  if (t1 == 0)
    return t2;
  if (t2 == 0)
    return t1;

  taint_source_t src1 = get_tag_source(t1);
  taint_source_t src2 = get_tag_source(t2);
  uint8_t lvl1 = get_tag_level(t1);
  uint8_t lvl2 = get_tag_level(t2);

  // if sources are the same, keep the source, otherwise mark as propagated
  taint_source_t result_src = (src1 == src2) ? src1 : TS_PROPAGATED;

  // take maximum level
  uint8_t result_lvl = max_u8(lvl1, lvl2);

  tag_t result = make_tag(result_src, result_lvl);

  TAINT_DEBUG("combine_tags: t1=0x%x(%d,lvl=%u), t2=0x%x(%d,lvl=%u) => result=0x%x(%d,lvl=%u)", t1,
              src1, lvl1, t2, src2, lvl2, result, result_src, result_lvl);

  return result;
}

/*
 * Simple hash function for allocation addresses
 */
static inline size_t
hash_addr(uintptr_t addr) {
  size_t result = (addr ^ (addr >> 16)) % MAX_REGIONS;
  TAINT_DEBUG("hash_addr: addr=0x%lx => hash=%zu", addr, result);
  return result;
}

/*
 * Apply taint to a memory region
 * TODO: return a taint_handle_t for easier management
 * Idea: output param, that is NULL if not needed
 */
void
tf_taint_memory(void *addr, size_t size, taint_source_t source_type, uint8_t level, int instance_id,
                const char *description) {
  // sanity check
  if (unlikely(!addr || size == 0)) {
    TAINT_DEBUG("tf_taint_memory: invalid parameters (addr=%p, size=%zu)", addr, size);
    return;
  }

  uintptr_t start_addr = (uintptr_t)addr;
  uintptr_t end_addr = start_addr + size - 1;

  TAINT_DEBUG("tf_taint_memory: tainting region 0x%lx - 0x%lx (%zu bytes) "
              "source=%d, level=%u, instance_id=%d, desc=%s",
              start_addr, end_addr, size, (int)source_type, level, source_id,
              description ? description : "NULL");

  // create tag
  tag_t tag = make_tag(source_type, level);

  // apply taint tags to memory
  // Note: using libdft api
  for (uintptr_t curr_addr = start_addr; curr_addr <= end_addr; curr_addr++) {
    tagmap_setb(curr_addr, tag);
  }

  // record the tainted region
  taint_region_t *region = nullptr;
  if (g_taint_tracker.region_count < MAX_REGIONS) {
    region = &g_taint_tracker.regions[g_taint_tracker.region_count++];
    region_set(region, tag, start_addr, end_addr, instance_id, description);

    // update statistics
    g_taint_tracker.tainted_bytes_count += size;

    TAINT_DEBUG("tf_taint_memory: added region #%zu, total tainted bytes now: %zu",
                g_taint_tracker.region_count - 1, g_taint_tracker.tainted_bytes_count);
  } else {
    TAINT_DEBUG("tf_taint_memory: WARNING - no more space for region tracking");
    // TODO: implement paging/alloc of region tracking space
  }

  // TODO: overlapping regions should be implemented
  // using a combination of taint values
  // Scenario: tainting a memory region that already
  // had been partially tainted (edge case but theorethically can happen)
}

/*
 * Clear taint from a memory region
 */
void
tf_clear_taint(void *addr, size_t size) {
  if (unlikely(!addr || size == 0)) {
    TAINT_DEBUG("tf_clear_taint: invalid parameters (addr=%p, size=%zu)", addr, size);
    return;
  }

  uintptr_t c_start = (uintptr_t)addr;
  uintptr_t c_end = c_start + size - 1;

  TAINT_DEBUG("tf_clear_taint: clearing taint from region 0x%lx - 0x%lx (%zu bytes)", c_start,
              c_end, size);

  // clear taint tags
  // Note: using libdft api
  for (uintptr_t curr_addr = c_start; curr_addr <= c_end; curr_addr++) {
    tagmap_clrb(curr_addr);
  }

  // clear regions
  size_t i = 0;
  uintptr_t r_start = (uintptr_t)nullptr;
  uintptr_t r_end = (uintptr_t)nullptr;
  taint_region_t *region = nullptr;
  while (i < g_taint_tracker.region_count) {
    region = &g_taint_tracker.regions[i];
    r_start = region->start_addr;
    r_end = region->end_addr;

    size_t original_region_length = (r_start <= r_end) ? (r_end - r_start + 1) : 0;

    // no overlap -> skip
    if (r_end < c_start || r_start > c_end) {
      i++;
      continue;
    }

    // perfect overlap
    else if (r_start >= c_start && r_end <= c_end) {

      TAINT_DEBUG("Region [0x%lx-0x%lx] fully cleared.", r_start, r_end);
      g_taint_tracker.tainted_bytes_count -= original_region_length;

      // if not last region
      if (i < g_taint_tracker.region_count - 1) {
        // swap with last
        region_copy(&g_taint_tracker.regions[i],
                    &g_taint_tracker.regions[g_taint_tracker.region_count - 1]); //< last
      }

      region_clear(&g_taint_tracker.regions[g_taint_tracker.region_count - 1]);
      g_taint_tracker.region_count--;
      // do not increment i; the swapped-in region at current 'i' needs to be processed.
      continue;
    }

    // complete containment (hole punching)
    // [r_start ... c_start ... c_end ... r_end]
    else if (r_start < c_start && r_end > c_end) {
      TAINT_DEBUG("Region [0x%lx-0x%lx] hole punched by [0x%lx-0x%lx].", r_start, r_end, c_start,
                  c_end);
      g_taint_tracker.tainted_bytes_count -= size;
      if (g_taint_tracker.region_count < MAX_REGIONS) {
        // create new region for the split region second part
        taint_region_t *new_region = &g_taint_tracker.regions[g_taint_tracker.region_count];
        region_copy(new_region, region);
        new_region->start_addr = c_end + 1;
        // new_region->end_addr remains region->end_addr

        // modify current_region to be the first part (before the hole)
        region->end_addr = c_start - 1;

        g_taint_tracker.region_count++;
        // the new_region will be processed in the next iteration if it also overlaps
      } else {
        // not enough space to split
        // TODO: this checking disappears with interval trees
        // Fallback: Truncate the original region, losing metadata for the part after the hole.
        TAINT_DEBUG(
            "MAX_REGIONS reached, cannot split. Truncating region [0x%lx-0x%lx] to end at 0x%lx.",
            r_start, r_end, clear_start_addr - 1);
        region->end_addr = c_start - 1;
        if (region->end_addr < region->start_addr) {
          // TODO
          // if it became invalid, effectively remove it
          // this edge case needs careful handling if the fallback is just truncation.
          // for simplicity now, we assume cs - 1 >= rs.
        }
      }
      i++;
      continue;
    }

    else if (r_start < c_start && r_end >= c_start) {
      TAINT_DEBUG("Region [0x%lx-0x%lx] truncated at end by [0x%lx-0x%lx]. New end: 0x%lx", r_start,
                  r_end, clear_start_addr, clear_end_addr, clear_start_addr - 1);
      g_taint_tracker.tainted_bytes_count -= (r_end - c_start + 1);
      region->end_addr = c_start - 1;
      if (region->end_addr < region->start_addr) {
        TAINT_DEBUG("Region became invalid after end truncation, should be removed.");
        // for now, we assume valid truncation, if end < start, it's effectively empty/invalid.
        // TODO: remove it here
        // fallback to simple invalidation if not removing:
        // region_clear(current_region)
      }
      i++;
      continue;
    }

    else if (r_end > c_end && r_start <= c_end) {
      TAINT_DEBUG("Region [0x%lx-0x%lx] truncated at start by [0x%lx-0x%lx]. New start: 0x%lx",
                  r_start, r_end, c_start, c_end, c_end + 1);
      g_taint_tracker.tainted_bytes_count -= (c_end - r_start + 1);
      region->start_addr = c_end + 1;
      if (region->start_addr > region->end_addr) {
        // this implies the region was fully consumed
        TAINT_DEBUG("Region became invalid after start truncation, should be removed.");
        // TODO: remove
      }
      i++;
      continue;
    }

    // logic error in the conditions or an unhandled edge case
    TAINT_DEBUG("Unhandled overlap for region [0x%lx-0x%lx] with clear range [0x%lx-0x%lx]",
                r_start, r_end, c_start, c_end);
    assert(0 && "Unhandled overlap case in tf_clear_taint!");
    i++;
  }

  TAINT_DEBUG("Finished clearing taint. Region count: %zu, Tainted bytes: %zu",
              g_taint_tracker.region_count, g_taint_tracker.tainted_bytes_count);
}

/*
 * Check if a memory region has any tainted bytes
 */
int
tf_is_memory_tainted(void *addr, size_t size) {
  if (unlikely(!addr || size == 0)) {
    TAINT_DEBUG("tf_is_memory_tainted: invalid parameters (addr=%p, size=%zu)", addr, size);
    return 0;
  }

  uintptr_t start_addr = (uintptr_t)addr;
  uintptr_t end_addr = start_addr + size - 1;

  TAINT_DEBUG("tf_is_memory_tainted: checking region 0x%lx - 0x%lx (%zu bytes)", start_addr,
              end_addr, size);

  // check each byte
  for (uintptr_t curr_addr = start_addr; curr_addr <= end_addr; curr_addr++) {
    if (tagmap_getb(curr_addr) != 0) {
      TAINT_DEBUG("tf_is_memory_tainted: found taint at address 0x%lx", curr_addr);
      return 1;
    }
  }

  TAINT_DEBUG("tf_is_memory_tainted: no taint found in region");
  return 0;
}

/*
 * Get detailed taint information for a memory address
 */
tag_t
tf_get_taint_info(void *addr, taint_source_t *source_type, uint8_t *level) {
  if (unlikely(!addr)) {
    TAINT_DEBUG("tf_get_taint_info: invalid address (NULL)");
    return 0;
  }

  uintptr_t address = (uintptr_t)addr;
  tag_t tag = tagmap_getb(address);

  taint_source_t src = get_tag_source(tag);
  uint8_t lvl = get_tag_level(tag);

  TAINT_DEBUG("tf_get_taint_info: addr=0x%lx, tag=0x%x, source=%d, level=%u", address, tag,
              (int)src, lvl);

  if (source_type != NULL) {
    *source_type = src;
  }

  if (level != NULL) {
    *level = lvl;
  }

  return tag;
}

/*
 * Propagate taint between memory regions
 * TODO: high chance this is completely incorrect
 */
void
tf_propagate_taint(void *dst, const void *src, size_t size, int preserve_dst) {
  if (unlikely(!dst || !src || size == 0)) {
    TAINT_DEBUG("tf_propagate_taint: invalid parameters (dst=%p, src=%p, size=%zu)", dst, src,
                size);
    return;
  }

  uintptr_t dst_addr = (uintptr_t)dst;
  uintptr_t src_addr = (uintptr_t)src;

  TAINT_DEBUG("tf_propagate_taint: copying taint from 0x%lx to 0x%lx (%zu bytes)%s", src_addr,
              dst_addr, size, preserve_dst ? " with preservation" : "");

  // Check if any source bytes are tainted - early return optimization
  int has_taint = 0;
  size_t check_limit =
      (size > 100) ? 100 : size; // Check first 100 bytes to see if worth continuing

  for (size_t i = 0; i < check_limit; i++) {
    if (tagmap_getb(src_addr + i) != 0) {
      has_taint = 1;
      break;
    }
  }

  if (!has_taint && !preserve_dst) {
    TAINT_DEBUG("tf_propagate_taint: early return - no taint in first %zu bytes and not preserving",
                check_limit);
    return;
  }

  // handle potential overlap (like memmove)
  if (dst_addr < src_addr + size && src_addr < dst_addr + size) {
    TAINT_DEBUG("tf_propagate_taint: handling overlapping memory regions");

#define MAX_STACK_TAGS 1024
    tag_t stack_tags[MAX_STACK_TAGS];
    tag_t *temp_tags = stack_tags;

    // for larger sizes, process in chunks to avoid dynamic allocation
    if (size <= MAX_STACK_TAGS) {
      // copy source tags to temporary buffer
      for (size_t i = 0; i < size; i++) {
        temp_tags[i] = tagmap_getb(src_addr + i);
      }

      // apply tags to destination
      for (size_t i = 0; i < size; i++) {
        tag_t src_tag = temp_tags[i];

        if (src_tag != 0) {
          if (preserve_dst) {
            tag_t dst_tag = tagmap_getb(dst_addr + i);
            tag_t combined = combine_tags(dst_tag, src_tag);
            tagmap_setb(dst_addr + i, combined);
          } else {
            tagmap_setb(dst_addr + i, src_tag);
          }
        } else if (!preserve_dst) {
          tagmap_clrb(dst_addr + i);
        }
      }
    } else {
      // for larger regions, process in chunks
      TAINT_DEBUG("tf_propagate_taint: processing large overlapping region in chunks");

      for (size_t chunk = 0; chunk < size; chunk += MAX_STACK_TAGS) {
        size_t chunk_size = (chunk + MAX_STACK_TAGS > size) ? (size - chunk) : MAX_STACK_TAGS;

        TAINT_DEBUG("tf_propagate_taint: processing chunk at offset %zu, size %zu", chunk,
                    chunk_size);

        // copy chunk of source tags
        for (size_t i = 0; i < chunk_size; i++) {
          temp_tags[i] = tagmap_getb(src_addr + chunk + i);
        }

        // apply chunk of tags
        for (size_t i = 0; i < chunk_size; i++) {
          tag_t src_tag = temp_tags[i];

          if (src_tag != 0) {
            if (preserve_dst) {
              tag_t dst_tag = tagmap_getb(dst_addr + chunk + i);
              tag_t combined = combine_tags(dst_tag, src_tag);
              tagmap_setb(dst_addr + chunk + i, combined);
            } else {
              tagmap_setb(dst_addr + chunk + i, src_tag);
            }
          } else if (!preserve_dst) {
            tagmap_clrb(dst_addr + chunk + i);
          }
        }
      }
    }
  } else {
    // non-overlapping case - process directly
    TAINT_DEBUG("tf_propagate_taint: handling non-overlapping memory regions");

    size_t tainted_count = 0;

    for (size_t i = 0; i < size; i++) {
      tag_t src_tag = tagmap_getb(src_addr + i);

      if (src_tag != 0) {
        tainted_count++;
        if (preserve_dst) {
          tag_t dst_tag = tagmap_getb(dst_addr + i);
          tag_t combined = combine_tags(dst_tag, src_tag);
          tagmap_setb(dst_addr + i, combined);
        } else {
          tagmap_setb(dst_addr + i, src_tag);
        }
      } else if (!preserve_dst) {
        tagmap_clrb(dst_addr + i);
      }
    }

    TAINT_DEBUG("tf_propagate_taint: processed %zu bytes, %zu had taint", size, tainted_count);
  }

  // Check if any taint was actually propagated
  int has_taint_after = 0;
  for (size_t i = 0; i < size && !has_taint_after; i++) {
    if (tagmap_getb(src_addr + i) != 0) {
      has_taint_after = 1;
    }
  }

  if (has_taint_after) {
    printf("[TNT] Propagated taint from 0x%lx to 0x%lx (%zu bytes)%s\n", src_addr, dst_addr, size,
           preserve_dst ? " with preservation" : "");
  }
}

/*
 * Track a memory allocation
 */
void
tf_track_allocation(void *ptr, size_t size) {
  if (ptr == NULL) {
    TAINT_DEBUG("tf_track_allocation: invalid pointer (NULL)");
    return;
  }

  uintptr_t addr = (uintptr_t)ptr;
  TAINT_DEBUG("tf_track_allocation: tracking allocation at 0x%lx, size %zu", addr, size);

  int idx = find_allocation(addr);

  if (idx >= 0) {
    // update existing entry
    TAINT_DEBUG("tf_track_allocation: updating existing entry at idx %d", idx);
    g_taint_tracker.allocations[idx].size = size;
    g_taint_tracker.allocations[idx].valid = 1;
  } else {
    // find a free slot
    idx = find_free_alloc_slot(hash_addr(addr));
    if (idx >= 0) {
      TAINT_DEBUG("tf_track_allocation: creating new entry at idx %d", idx);
      g_taint_tracker.allocations[idx].addr = addr;
      g_taint_tracker.allocations[idx].size = size;
      g_taint_tracker.allocations[idx].valid = 1;
      g_taint_tracker.alloc_count++;
      TAINT_DEBUG("tf_track_allocation: total allocations now: %zu", g_taint_tracker.alloc_count);
    } else {
      // TODO: implement reallocation
      TAINT_DEBUG("tf_track_allocation: WARNING - no free slots for tracking allocation");
    }
  }
}

/*
 * Untrack a memory allocation (e.g., when freed)
 */
void
tf_untrack_allocation(void *ptr) {
  if (ptr == NULL) {
    TAINT_DEBUG("tf_untrack_allocation: invalid pointer (NULL)");
    return;
  }

  uintptr_t addr = (uintptr_t)ptr;
  TAINT_DEBUG("tf_untrack_allocation: untracking allocation at 0x%lx", addr);

  int idx = find_allocation(addr);

  if (idx >= 0) {
    TAINT_DEBUG("tf_untrack_allocation: found allocation at idx %d, marking invalid", idx);
    alloc_clear(&g_taint_tracker.allocations[idx]);
    g_taint_tracker.alloc_count--;
    TAINT_DEBUG("tf_untrack_allocation: total allocations now: %zu", g_taint_tracker.alloc_count);
  } else {
    TAINT_DEBUG("tf_untrack_allocation: allocation not found");
  }
}

/*
 * Get allocation size for a pointer
 */
size_t
tf_get_allocation_size(void *ptr) {
  if (ptr == NULL) {
    TAINT_DEBUG("tf_get_allocation_size: invalid pointer (NULL)");
    return 0;
  }

  uintptr_t addr = (uintptr_t)ptr;
  TAINT_DEBUG("tf_get_allocation_size: looking up allocation at 0x%lx", addr);

  int idx = find_allocation(addr);

  if (idx >= 0 && g_taint_tracker.allocations[idx].valid) {
    size_t size = g_taint_tracker.allocations[idx].size;
    TAINT_DEBUG("tf_get_allocation_size: found allocation at idx %d, size %zu", idx, size);
    return size;
  }

  TAINT_DEBUG("tf_get_allocation_size: allocation not found or invalid");
  return 0;
}

/*
 * Print taint statistics
 */
/*void*/
/*tf_print_taint_stats() {*/
/*  TAINT_DEBUG("tf_print_taint_stats: generating statistics");*/
/**/
/*  printf("===== TAINT TRACKING STATISTICS =====\n");*/
/*  printf("Total tracked taint regions: %zu\n", g_taint_tracker.region_count);*/
/*  printf("Total tainted bytes: %zu\n", g_taint_tracker.tainted_bytes_count);*/
/*  printf("Active memory allocations: %zu\n", g_taint_tracker.alloc_count);*/
/**/
/*  size_t current_tainted = 0;*/
/*  size_t checked_bytes = 0;*/
/**/
/*  for (size_t i = 0; i < MAX_REGIONS; i++) {*/
/*    if (g_taint_tracker.allocations[i].valid) {*/
/*      uintptr_t addr = g_taint_tracker.allocations[i].addr;*/
/*      size_t size = g_taint_tracker.allocations[i].size;*/
/**/
/*      TAINT_DEBUG("tf_print_taint_stats: checking allocation at 0x%lx, size %zu", addr, size);*/
/**/
/*      // limit checking to avoid excessive overhead*/
/*      size_t check_size = (size < 1024) ? size : 1024;*/
/**/
/*      for (size_t j = 0; j < check_size; j++) {*/
/*        if (tagmap_getb(addr + j) != 0) {*/
/*          current_tainted++;*/
/*        }*/
/*        checked_bytes++;*/
/*      }*/
/*    }*/
/*  }*/
/**/
/*  if (checked_bytes > 0) {*/
/*    float taint_percentage = (float)current_tainted / checked_bytes * 100.0f;*/
/*    printf("Sampled tainted bytes: %zu out of %zu checked (%.2f%%)\n", current_tainted,*/
/*           checked_bytes, taint_percentage);*/
/**/
/*    TAINT_DEBUG("tf_print_taint_stats: found %zu tainted bytes (%.2f%%)", current_tainted,*/
/*                taint_percentage);*/
/*  }*/
/**/
/*  printf("===================================\n");*/
/*}*/
