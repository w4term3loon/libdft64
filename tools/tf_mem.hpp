#ifndef _TF_MEMMNG_H
#define _TF_MEMMNG_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include "pin.H"

/**
 * @brief Memory segment structure
 *
 * Represents a tracked memory region with its base address, size, and status.
 */
typedef struct {
  uintptr_t low; /**< Base address of the memory segment */
  size_t offset; /**< Size of the memory segment in bytes */
  int freed;     /**< Status: 0 = active, 1 = freed */
} mem_segment_t;

/**
 * @brief Memory manager structure
 *
 * Internal structure managing the array of memory segments.
 */
typedef struct {
  mem_segment_t *segments; /**< Dynamic array of memory segments */
  size_t size;             /**< Current capacity of segments array */
  size_t next;             /**< Index of next available slot */
} memory_manager_t;

/** @brief Initial capacity for memory segments array */
#define MEMMNG_CHUNK 32

/**
 * @brief Initialize the memory manager
 *
 * Must be called before using any other memory manager functions.
 * Allocates initial storage for tracking memory segments.
 *
 * @note Prints error message to stdout on allocation failure
 * @note Safe to call multiple times (idempotent behavior not guaranteed)
 */
void
tf_mem_init(void);

/**
 * @brief Cleanup and destroy the memory manager
 *
 * Frees all internal storage and resets the manager state.
 * After calling this function, tf_mem_init() must be called again
 * before using other functions.
 *
 * @note Safe to call even if not initialized
 */
void
tf_mem_die(void);

/**
 * @brief Register a memory region for tracking
 *
 * Adds a new memory region to the tracking system. The region is
 * marked as active (not freed) initially.
 *
 * @param address Base address of the memory region
 * @param size Size of the memory region in bytes
 *
 * @note Prints error messages to stdout on failure
 * @note Does not check for duplicate registrations
 * @note Automatically grows internal storage as needed
 */
void
tf_mem_register(void *address, size_t size);

/**
 * @brief Unregister a memory region from tracking
 *
 * Removes a memory region from tracking by marking its address as NULL.
 * The slot remains in the array but is considered invalid.
 *
 * @param address Base address of the memory region to unregister
 *
 * @note Prints error to stderr if address not found
 * @note Does not compact the array (leaves gaps)
 */
void
tf_mem_unregister(void *address);

/**
 * @brief Mark a memory region as freed
 *
 * Marks a tracked memory region as freed without removing it from
 * the tracking system. This enables use-after-free detection.
 *
 * @param address Base address of the memory region to mark as freed
 *
 * @note Silent failure if address not found or manager not initialized
 * @note Does not prevent further operations on the address
 */
void
tf_mem_free(void *address);

/**
 * @brief Check if a memory region is marked as freed
 *
 * Determines whether a tracked memory region has been marked as freed.
 *
 * @param address Base address to check
 * @return 1 if freed, 0 if active, -1 if not found or manager not initialized
 *
 * @note Returns -1 for both "not found" and "not initialized" cases
 */
int
tf_mem_is_freed(void *address);

/**
 * @brief Get the size of a tracked memory region
 *
 * Retrieves the registered size of a memory region.
 *
 * @param address Base address of the memory region
 * @return Size in bytes, or 0 if not found or manager not initialized
 *
 * @note Returns 0 for both "not found" and "not initialized" cases
 * @note Returns size even for freed regions
 */
size_t
tf_mem_get_size(void *address);

static memory_manager_t memory_manager = {0};

void
tf_mem_init(void) {
  memory_manager.next = 0;
  memory_manager.size = MEMMNG_CHUNK;
  memory_manager.segments = (mem_segment_t *)malloc(memory_manager.size * sizeof(mem_segment_t));
  if (memory_manager.segments == NULL) {
    fprintf(stderr, "memmng init fail\n");
    return;
  }
}

void
tf_mem_die(void) {
  free(memory_manager.segments);
  memory_manager.segments = NULL;
  memory_manager.size = 0;
  memory_manager.next = 0;
}

void
tf_mem_register(void *address, size_t size) {
  if (memory_manager.segments == NULL) {
    fprintf(stderr, "memmng not initialized\n");
    return;
  }
  if (memory_manager.next >= memory_manager.size) {
    size_t new_size = memory_manager.size * 2;
    mem_segment_t *new_segments =
        (mem_segment_t *)realloc(memory_manager.segments, new_size * sizeof(mem_segment_t));
    if (new_segments == NULL) {
      fprintf(stderr, "memmng realloc fail\n");
      return;
    }
    memory_manager.segments = new_segments;
    memory_manager.size = new_size;
  }
  // add new segment
  memory_manager.segments[memory_manager.next].low = (uintptr_t)address;
  memory_manager.segments[memory_manager.next].offset = size;
  memory_manager.segments[memory_manager.next].freed = 0;
  memory_manager.next += 1;
}

void
tf_mem_unregister(void *address) {
  if (memory_manager.segments == NULL) {
    return;
  }
  for (size_t i = 0; i < memory_manager.next; ++i) {
    if (memory_manager.segments[i].low == (uintptr_t)address) {
      memory_manager.segments[i].low = (uintptr_t)NULL;
      memory_manager.segments[i].offset = 0;
      memory_manager.segments[i].freed = 0;
      return;
    }
  }
  fprintf(stderr, "[MEM] Memory region %p was never allocated.\n", address);
}

size_t
tf_mem_get_size(void *address) {
  if (memory_manager.segments == NULL) {
    return 0;
  }
  for (size_t i = 0; i < memory_manager.next; ++i) {
    if (memory_manager.segments[i].low == (uintptr_t)address) {
      return memory_manager.segments[i].offset;
    }
  }
  return 0;
}

void
tf_mem_free(void *address) {
  if (memory_manager.segments == NULL) {
    return;
  }
  for (size_t i = 0; i < memory_manager.next; ++i) {
    if (memory_manager.segments[i].low == (uintptr_t)address) {
      memory_manager.segments[i].freed = 1; // mark as freed
      return;
    }
  }
  fprintf(stderr, "[MEM] Attempted to free untracked memory region %p\n", address);
}

int
tf_mem_is_freed(void *address) {
  if (memory_manager.segments == NULL) {
    return -1;
  }
  for (size_t i = 0; i < memory_manager.next; ++i) {
    if (memory_manager.segments[i].low == (uintptr_t)address) {
      return memory_manager.segments[i].freed;
    }
  }
  return -1;
}

// MAPPED MEMORY REGIONS
// TODO: organize in other file
// tf_type.hpp
typedef enum {
  UNKNOWN = 0,
  MAPPED_PTR,
  HEAP_PTR,
  STACK_PTR,
  LIB_PTR,
  SIZE_ARG,   // likely a size argument
  FD_ARG,     // likely a file descriptor
  FLAGS_ARG,  // likely flags/options
  SMALL_INT,  // small integer value
  NULL_PTR,   // NULL pointer
  INVALID_PTR // invalid pointer value
} tf_type_t;

const char *
type_to_string(tf_type_t type) {
  switch (type) {
  case UNKNOWN:
    return "UNKNOWN";
  case MAPPED_PTR:
    return "ANON";
  case HEAP_PTR:
    return "HEAP";
  case STACK_PTR:
    return "STACK";
  case LIB_PTR:
    return "LIB";
  case SIZE_ARG:
    return "SIZE_ARG";
  case FD_ARG:
    return "FD_ARG";
  case FLAGS_ARG:
    return "FLAGS_ARG";
  case SMALL_INT:
    return "SMALL_INT";
  case NULL_PTR:
    return "NULL_PTR";
  case INVALID_PTR:
    return "INVALID_PTR";
  default:
    return "INVALID";
  }
}

struct memory_region_t {
  uintptr_t start;
  uintptr_t end;
  tf_type_t type;
  std::string path;
};

// singleton global vector :)
static std::vector<memory_region_t> g_memory_map;

void
refresh_memory_map() {
  g_memory_map.clear();

  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp)
    return;

  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    uintptr_t start, end;
    char perms[5];
    char path[256] = "";

    int matched = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start, &end, perms, path);
    if (matched >= 3 && perms[0] == 'r') {
      tf_type_t type = UNKNOWN;
      if (strcmp(path, "[heap]") == 0)
        type = HEAP_PTR;
      else if (strcmp(path, "[stack]") == 0 || strstr(path, "[stack:"))
        type = STACK_PTR;
      else if (strstr(path, ".so") || strstr(path, "/lib"))
        type = LIB_PTR;
      else if (strlen(path) == 0)
        type = MAPPED_PTR;

      memory_region_t region = {start, end, type, path};
      g_memory_map.push_back(region);

      /*fprintf(stdout, "[MAP] %lx-%lx perms: %s type: %d path: %s\n",*/
      /*        start, end, perms, type, strlen(path) ? path : "[anonymous]");*/
    }
  }

  fclose(fp);
}

tf_type_t
guess_argument_type(ADDRINT value) {
  if (value == 0) {
    return NULL_PTR;
  }

  // check for small integers
  if (value <= 0xFFFF) { // 16-bit range
    if (value <= 10) {
      // very small values are often file descriptors
      return FD_ARG;
    } else if (value <= 65536) {
      // medium small values often sizes or counts
      return SIZE_ARG;
    }
    return SMALL_INT;
  }

  // check for common flag patterns
  if (value != 0 && (value & (value - 1)) == 0) {
    // power of 2, likely a flag
    return FLAGS_ARG;
  }

  // check for typical size ranges
  if (value >= 256 && value <= 0x40000000) { // .2KB to 1GB
    // could be a size argument
    return SIZE_ARG;
  }

// check if it looks like a valid pointer range but unmapped
#ifdef __x86_64__
  if (value >= 0x400000 && value < 0x800000000000ULL) {
    // typical x86_64 user space range but not mapped
    return INVALID_PTR;
  }
#else
  if (value >= 0x8000 && value < 0xC0000000) {
    // typical 32-bit user space range but not mapped
    return INVALID_PTR;
  }
#endif

  return UNKNOWN;
}

void
print_typed_value(ADDRINT ptr, tf_type_t type) {
  switch (type) {
  case NULL_PTR:
    fprintf(stdout, "[CMR] check NULL for memory type: %s\n", type_to_string(type));
    break;
  case FD_ARG:
  case SMALL_INT:
  case SIZE_ARG:
    fprintf(stdout, "[CMR] check %lu (%lx) for memory type: %s\n", ptr, ptr,
            type_to_string(type));
    break;
  case FLAGS_ARG:
    fprintf(stdout, "[CMR] check 0x%lx (flags) for memory type: %s\n", ptr,
            type_to_string(type));
    break;
  case HEAP_PTR:
  case STACK_PTR:
  case LIB_PTR:
  case MAPPED_PTR:
  case INVALID_PTR:
  default:
    fprintf(stdout, "[CMR] check %lx for memory type: %s\n", ptr, type_to_string(type));
    break;
  }
}

tf_type_t
tf_check_type(ADDRINT value) {
  tf_type_t type = UNKNOWN;

  for (const auto &region : g_memory_map) {
    if (value >= region.start && value < region.end) {
      type = region.type;
      break;
    }
  }

  if (type == UNKNOWN) {
    type = guess_argument_type(value);
  }

  print_typed_value(value, type);

  return type;
}

#endif // _TF_MEMMNG_H
