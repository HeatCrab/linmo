/* libc: memory allocation. */

#include <lib/libc.h>
#include <sys/task.h>
#include <types.h>

#include "private/error.h"
#include "private/utils.h"

/* Memory allocator using first-fit strategy with selective coalescing.
 *
 * Performance characteristics:
 * - malloc(): O(n) worst case; searches linearly from heap start; coalesces
 *             free blocks when fragmentation threshold is reached.
 * - free(): O(1) average case; marks memory areas as unused with immediate
 *           forward coalescing and optional backward coalescing.
 *
 * This implementation prioritizes fast allocation/deallocation with proper
 * fragmentation management to minimize memory waste.
 *
 * FIXME(SMP): Global heap state assumes single-core execution. For SMP, either
 * use per-CPU heaps to avoid contention, or replace CRITICAL_ENTER/LEAVE with
 * spinlocks that provide cross-CPU mutual exclusion.
 */

typedef struct __memblock {
    struct __memblock *next; /* pointer to the next block */
    size_t size;             /* block size, LSB = used flag */
} memblock_t;

static memblock_t *first_free;
static void *heap_start, *heap_end;
static uint32_t free_blocks_count; /* track fragmentation */

/* Block manipulation macros */
#define IS_USED(b) ((b)->size & 1L)
#define GET_SIZE(b) ((b)->size & ~1L)
#define MARK_USED(b) ((b)->size |= 1L)
#define MARK_FREE(b) ((b)->size &= ~1L)

/* Memory layout validation */
#define IS_VALID_BLOCK(b)                                     \
    ((void *) (b) >= heap_start && (void *) (b) < heap_end && \
     (size_t) (b) % sizeof(size_t) == 0)

/* Fragmentation threshold - coalesce when free blocks exceed this ratio */
#define COALESCE_THRESHOLD 8

/* Validate block integrity */
static inline bool validate_block(memblock_t *block)
{
    if (unlikely(!IS_VALID_BLOCK(block)))
        return false;

    size_t size = GET_SIZE(block);
    if (unlikely(!size || size > MALLOC_MAX_SIZE))
        return false;

    /* Check if block extends beyond heap */
    if (unlikely((uint8_t *) block + sizeof(memblock_t) + size >
                 (uint8_t *) heap_end))
        return false;

    if (unlikely(block->next &&
                 (uint8_t *) block + sizeof(memblock_t) + GET_SIZE(block) !=
                     (uint8_t *) block->next))
        return false;

    return true;
}

/* O(1) with immediate forward coalescing, conditional backward coalescing */
void free(void *ptr)
{
    if (!ptr)
        return;

    CRITICAL_ENTER();

    memblock_t *p = ((memblock_t *) ptr) - 1;

    /* Validate the block being freed */
    if (unlikely(!validate_block(p) || !IS_USED(p))) {
        CRITICAL_LEAVE();
        panic(ERR_HEAP_CORRUPT);
        return; /* Invalid or double-free */
    }

    MARK_FREE(p);
    free_blocks_count++;

    /* Forward merge if the next block is free and physically adjacent */
    if (p->next && !IS_USED(p->next)) {
        p->size = GET_SIZE(p) + sizeof(memblock_t) + GET_SIZE(p->next);
        p->next = p->next->next;
        free_blocks_count--;
    }

    /* Backward merge: optimized single-pass search with early termination */
    memblock_t *prev = NULL;
    memblock_t *current = first_free;
    while (current && current != p) {
        prev = current;
        current = current->next;
    }

    if (prev && !IS_USED(prev)) {
        if (unlikely(!validate_block(prev))) {
            CRITICAL_LEAVE();
            panic(ERR_HEAP_CORRUPT);
            return;
        }
        prev->size = GET_SIZE(prev) + sizeof(memblock_t) + GET_SIZE(p);
        prev->next = p->next;
        free_blocks_count--;
    }

    CRITICAL_LEAVE();
}

/* Selective coalescing: only when fragmentation becomes significant */
static void selective_coalesce(void)
{
    memblock_t *p = first_free;

    while (p && p->next) {
        /* Merge only when blocks are FREE *and* adjacent in memory */
        if (unlikely(!validate_block(p))) {
            panic(ERR_HEAP_CORRUPT);
            return;
        }
        if (!IS_USED(p) && !IS_USED(p->next)) {
            p->size = GET_SIZE(p) + sizeof(memblock_t) + GET_SIZE(p->next);
            p->next = p->next->next;
            free_blocks_count--;
        } else {
            p = p->next;
        }
    }
}

static inline void split_block(memblock_t *block, size_t size)
{
    size_t remaining;
    memblock_t *new_block;

    if (unlikely(size > GET_SIZE(block))) {
        panic(ERR_HEAP_CORRUPT);
        return;
    }
    remaining = GET_SIZE(block) - size;
    /* Split only when remaining memory is large enough */
    if (remaining < sizeof(memblock_t) + MALLOC_MIN_SIZE)
        return;
    new_block = (memblock_t *) ((size_t) block + sizeof(memblock_t) + size);
    new_block->next = block->next;
    new_block->size = remaining - sizeof(memblock_t);
    MARK_FREE(new_block);
    block->next = new_block;
    block->size = size | IS_USED(block);
    free_blocks_count++; /* New free block created */
}

/* O(n) first-fit allocation with selective coalescing */
void *malloc(uint32_t size)
{
    /* Input validation */
    if (unlikely(!size || size > MALLOC_MAX_SIZE))
        return NULL;

    size = ALIGN4(size);

    /* Ensure minimum allocation size */
    if (size < MALLOC_MIN_SIZE)
        size = MALLOC_MIN_SIZE;

    CRITICAL_ENTER();

    /* Trigger coalescing only when fragmentation is high */
    if (free_blocks_count > COALESCE_THRESHOLD)
        selective_coalesce();

    memblock_t *p = first_free;
    while (p) {
        if (unlikely(!validate_block(p))) {
            CRITICAL_LEAVE();
            panic(ERR_HEAP_CORRUPT);
            return NULL; /* Heap corruption detected */
        }

        if (!IS_USED(p) && GET_SIZE(p) >= size) {
            /* Split block only if remainder is large enough to be useful */
            split_block(p, size);

            MARK_USED(p);
            if (unlikely(free_blocks_count <= 0)) {
                CRITICAL_LEAVE();
                panic(ERR_HEAP_CORRUPT);
                return NULL;
            }
            free_blocks_count--;

            CRITICAL_LEAVE();
            return (void *) (p + 1);
        }
        p = p->next;
    }

    CRITICAL_LEAVE();
    return NULL; /* allocation failed */
}

/* Initializes memory allocator with enhanced validation */
void mo_heap_init(size_t *zone, uint32_t len)
{
    memblock_t *start, *end;

    if (unlikely(!zone || len < 2 * sizeof(memblock_t) + MALLOC_MIN_SIZE))
        return; /* Invalid parameters */

    len = ALIGN4(len);
    start = (memblock_t *) zone;
    end = (memblock_t *) ((size_t) zone + len - sizeof(memblock_t));

    start->next = end;
    start->size = len - 2 * sizeof(memblock_t);
    MARK_FREE(start);

    end->next = NULL;
    end->size = 0;
    MARK_USED(end); /* end block marks heap boundary */

    first_free = start;
    heap_start = (void *) zone;
    heap_end = (void *) ((size_t) end + sizeof(memblock_t));
    free_blocks_count = 1;
}

/* Allocates zero-initialized memory with overflow protection */
void *calloc(uint32_t nmemb, uint32_t size)
{
    /* Check for multiplication overflow */
    if (unlikely(nmemb && size > MALLOC_MAX_SIZE / nmemb))
        return NULL;

    uint32_t total_size = ALIGN4(nmemb * size);
    void *buf = malloc(total_size);

    if (buf)
        memset(buf, 0, total_size);

    return buf;
}

/* Reallocates memory with improved efficiency */
void *realloc(void *ptr, uint32_t size)
{
    if (unlikely(size > MALLOC_MAX_SIZE))
        return NULL;

    if (!ptr)
        return malloc(size);

    if (!size) {
        free(ptr);
        return NULL;
    }

    size = ALIGN4(size);

    memblock_t *old_block = ((memblock_t *) ptr) - 1;

    /* Validate the existing block */
    if (unlikely(!validate_block(old_block) || !IS_USED(old_block))) {
        panic(ERR_HEAP_CORRUPT);
        return NULL;
    }

    size_t old_size = GET_SIZE(old_block);

    /* If shrinking or size is close, reuse existing block */
    if (size <= old_size &&
        old_size - size < sizeof(memblock_t) + MALLOC_MIN_SIZE)
        return ptr;

    CRITICAL_ENTER();

    /* fast path for shrinking */
    if (size <= old_size) {
        split_block(old_block, size);
        /* Trigger coalescing only when fragmentation is high */
        if (free_blocks_count > COALESCE_THRESHOLD)
            selective_coalesce();
        CRITICAL_LEAVE();
        return (void *) (old_block + 1);
    }

    /* fast path for growing */
    if (old_block->next && !IS_USED(old_block->next) &&
        GET_SIZE(old_block) + sizeof(memblock_t) + GET_SIZE(old_block->next) >=
            size) {
        old_block->size = GET_SIZE(old_block) + sizeof(memblock_t) +
                          GET_SIZE(old_block->next);
        old_block->next = old_block->next->next;
        free_blocks_count--;
        split_block(old_block, size);
        /* Trigger coalescing only when fragmentation is high */
        if (free_blocks_count > COALESCE_THRESHOLD)
            selective_coalesce();
        CRITICAL_LEAVE();
        return (void *) (old_block + 1);
    }

    /* Allocate new buffer while still holding critical section.
     * This prevents race where another task/ISR frees ptr before we copy.
     * malloc/free use nested CRITICAL_ENTER internally - safe due to nesting.
     */
    void *new_buf = malloc(size);
    if (new_buf) {
        memcpy(new_buf, ptr, min(old_size, size));
        free(ptr);
    }

    CRITICAL_LEAVE();

    return new_buf;
}
