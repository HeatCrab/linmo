/* Memory Protection Abstractions
 *
 * Software abstractions for managing memory protection at different
 * granularities. These structures build upon hardware protection
 * mechanisms (such as RISC-V PMP) to provide flexible, architecture-
 * independent memory isolation.
 */

#pragma once

#include <types.h>

/* Forward declarations */
struct fpage;
struct as;

/* Flex Page
 *
 * Contiguous physical memory region with hardware-enforced protection.
 * Supports arbitrary base addresses and sizes without alignment constraints.
 */
typedef struct fpage {
    struct fpage *as_next;  /* Next in address space list */
    struct fpage *map_next; /* Next in mapping chain */
    struct fpage *pmp_next; /* Next in PMP queue */
    uint32_t base;          /* Physical base address */
    uint32_t size;          /* Region size */
    uint32_t rwx;           /* R/W/X permission bits */
    uint32_t pmp_id;        /* PMP region index */
    uint32_t flags;         /* Status flags */
    uint32_t priority;      /* Eviction priority */
    int used;               /* Usage counter */
} fpage_t;

/* Memory Space
 *
 * Collection of flexpages forming a task's memory view. Can be shared
 * across multiple tasks.
 */
typedef struct memspace {
    uint32_t as_id;          /* Address space identifier */
    struct fpage *first;     /* Head of flex page list */
    struct fpage *pmp_first; /* Head of PMP-loaded list */
    struct fpage *pmp_stack; /* Stack regions */
    uint32_t shared;         /* Shared flag */
} memspace_t;

/* Memory Pool
 *
 * Static memory region descriptor for boot-time PMP initialization.
 */
typedef struct {
    const char *name; /* Pool name */
    uintptr_t start;  /* Start address */
    uintptr_t end;    /* End address */
    uint32_t flags;   /* Access permissions */
    uint32_t tag;     /* Pool type/priority */
} mempool_t;

/* Memory Pool Declaration Helpers
 *
 * Simplifies memory pool initialization with designated initializers.
 * DECLARE_MEMPOOL_FROM_SYMBOLS uses token concatenation to construct
 * linker symbol names automatically.
 */
#define DECLARE_MEMPOOL(name_, start_, end_, flags_, tag_) \
    { \
        .name = (name_), \
        .start = (uintptr_t)(start_), \
        .end = (uintptr_t)(end_), \
        .flags = (flags_), \
        .tag = (tag_), \
    }

#define DECLARE_MEMPOOL_FROM_SYMBOLS(name_, sym_base_, flags_, tag_) \
    DECLARE_MEMPOOL((name_), &(sym_base_##_start), &(sym_base_##_end), (flags_), (tag_))
