/* RISC-V Physical Memory Protection (PMP) Implementation
 *
 * Provides hardware-enforced memory isolation using PMP in TOR mode.
 */

#include <hal.h>
#include <lib/libc.h>
#include <sys/task.h>

#include "csr.h"
#include "pmp.h"
#include "private/error.h"

/* PMP CSR Access Helpers
 *
 * RISC-V CSR instructions require compile-time constant addresses encoded in
 * the instruction itself. These helpers use switch-case dispatch to provide
 * runtime indexed access to PMP configuration and address registers.
 *
 * - pmpcfg0-3: Four 32-bit configuration registers (16 regions, 8 bits each)
 * - pmpaddr0-15: Sixteen address registers for TOR (Top-of-Range) mode
 */

/* Read PMP configuration register by index (0-3) */
static uint32_t read_pmpcfg(uint8_t idx)
{
    switch (idx) {
    case 0:
        return read_csr_num(CSR_PMPCFG0);
    case 1:
        return read_csr_num(CSR_PMPCFG1);
    case 2:
        return read_csr_num(CSR_PMPCFG2);
    case 3:
        return read_csr_num(CSR_PMPCFG3);
    default:
        return 0;
    }
}

/* Write PMP configuration register by index (0-3) */
static void write_pmpcfg(uint8_t idx, uint32_t val)
{
    switch (idx) {
    case 0:
        write_csr_num(CSR_PMPCFG0, val);
        break;
    case 1:
        write_csr_num(CSR_PMPCFG1, val);
        break;
    case 2:
        write_csr_num(CSR_PMPCFG2, val);
        break;
    case 3:
        write_csr_num(CSR_PMPCFG3, val);
        break;
    }
}

/* Read PMP address register by index (0-15) */
static uint32_t __attribute__((unused)) read_pmpaddr(uint8_t idx)
{
    switch (idx) {
    case 0:
        return read_csr_num(CSR_PMPADDR0);
    case 1:
        return read_csr_num(CSR_PMPADDR1);
    case 2:
        return read_csr_num(CSR_PMPADDR2);
    case 3:
        return read_csr_num(CSR_PMPADDR3);
    case 4:
        return read_csr_num(CSR_PMPADDR4);
    case 5:
        return read_csr_num(CSR_PMPADDR5);
    case 6:
        return read_csr_num(CSR_PMPADDR6);
    case 7:
        return read_csr_num(CSR_PMPADDR7);
    case 8:
        return read_csr_num(CSR_PMPADDR8);
    case 9:
        return read_csr_num(CSR_PMPADDR9);
    case 10:
        return read_csr_num(CSR_PMPADDR10);
    case 11:
        return read_csr_num(CSR_PMPADDR11);
    case 12:
        return read_csr_num(CSR_PMPADDR12);
    case 13:
        return read_csr_num(CSR_PMPADDR13);
    case 14:
        return read_csr_num(CSR_PMPADDR14);
    case 15:
        return read_csr_num(CSR_PMPADDR15);
    default:
        return 0;
    }
}

/* Write PMP address register by index (0-15) */
static void write_pmpaddr(uint8_t idx, uint32_t val)
{
    switch (idx) {
    case 0:
        write_csr_num(CSR_PMPADDR0, val);
        break;
    case 1:
        write_csr_num(CSR_PMPADDR1, val);
        break;
    case 2:
        write_csr_num(CSR_PMPADDR2, val);
        break;
    case 3:
        write_csr_num(CSR_PMPADDR3, val);
        break;
    case 4:
        write_csr_num(CSR_PMPADDR4, val);
        break;
    case 5:
        write_csr_num(CSR_PMPADDR5, val);
        break;
    case 6:
        write_csr_num(CSR_PMPADDR6, val);
        break;
    case 7:
        write_csr_num(CSR_PMPADDR7, val);
        break;
    case 8:
        write_csr_num(CSR_PMPADDR8, val);
        break;
    case 9:
        write_csr_num(CSR_PMPADDR9, val);
        break;
    case 10:
        write_csr_num(CSR_PMPADDR10, val);
        break;
    case 11:
        write_csr_num(CSR_PMPADDR11, val);
        break;
    case 12:
        write_csr_num(CSR_PMPADDR12, val);
        break;
    case 13:
        write_csr_num(CSR_PMPADDR13, val);
        break;
    case 14:
        write_csr_num(CSR_PMPADDR14, val);
        break;
    case 15:
        write_csr_num(CSR_PMPADDR15, val);
        break;
    }
}

/* Static Memory Pools for Boot-time PMP Initialization
 *
 * Defines kernel memory regions protected at boot. Each pool specifies
 * a memory range and access permissions.
 */
static const mempool_t kernel_mempools[] = {
    DECLARE_MEMPOOL("kernel_text",
                    &_stext,
                    &_etext,
                    PMPCFG_PERM_RX,
                    PMP_PRIORITY_KERNEL),
    DECLARE_MEMPOOL("kernel_data",
                    &_sdata,
                    &_edata,
                    PMPCFG_PERM_RW,
                    PMP_PRIORITY_KERNEL),
    DECLARE_MEMPOOL("kernel_bss",
                    &_sbss,
                    &_ebss,
                    PMPCFG_PERM_RW,
                    PMP_PRIORITY_KERNEL),
};

#define KERNEL_MEMPOOL_COUNT \
    (sizeof(kernel_mempools) / sizeof(kernel_mempools[0]))

/* Global PMP configuration (shadow of hardware state) */
static pmp_config_t pmp_global_config;

/* Helper to compute pmpcfg register index and bit offset for a given region */
static inline void pmp_get_cfg_indices(uint8_t region_idx,
                                       uint8_t *cfg_idx,
                                       uint8_t *cfg_offset)
{
    *cfg_idx = region_idx / 4;
    *cfg_offset = (region_idx % 4) * 8;
}

pmp_config_t *pmp_get_config(void)
{
    return &pmp_global_config;
}

int32_t pmp_init(pmp_config_t *config)
{
    if (!config)
        return ERR_PMP_INVALID_REGION;

    /* Clear all PMP regions in hardware and shadow configuration */
    for (uint8_t i = 0; i < PMP_MAX_REGIONS; i++) {
        write_pmpaddr(i, 0);
        if (i % 4 == 0)
            write_pmpcfg(i / 4, 0);

        config->regions[i].addr_start = 0;
        config->regions[i].addr_end = 0;
        config->regions[i].permissions = 0;
        config->regions[i].priority = PMP_PRIORITY_TEMPORARY;
        config->regions[i].region_id = i;
        config->regions[i].locked = 0;
    }

    config->region_count = 0;
    config->next_region_idx = 0;
    config->initialized = 1;

    return ERR_OK;
}
int32_t pmp_init_pools(pmp_config_t *config,
                       const mempool_t *pools,
                       size_t count)
{
    if (!config || !pools || count == 0)
        return ERR_PMP_INVALID_REGION;

    /* Initialize PMP hardware and state */
    int32_t ret = pmp_init(config);
    if (ret < 0)
        return ret;

    /* Configure each memory pool as a PMP region */
    for (size_t i = 0; i < count; i++) {
        const mempool_t *pool = &pools[i];

        /* Validate pool boundaries */
        if (pool->start >= pool->end)
            return ERR_PMP_ADDR_RANGE;

        /* Prepare PMP region configuration */
        pmp_region_t region = {
            .addr_start = pool->start,
            .addr_end = pool->end,
            .permissions = pool->flags & (PMPCFG_R | PMPCFG_W | PMPCFG_X),
            .priority = pool->tag,
            .region_id = i,
            .locked = (pool->tag == PMP_PRIORITY_KERNEL),
        };

        /* Configure the PMP region */
        ret = pmp_set_region(config, &region);
        if (ret < 0)
            return ret;
    }

    return ERR_OK;
}

int32_t pmp_init_kernel(pmp_config_t *config)
{
    return pmp_init_pools(config, kernel_mempools, KERNEL_MEMPOOL_COUNT);
}

int32_t pmp_set_region(pmp_config_t *config, const pmp_region_t *region)
{
    if (!config || !region)
        return ERR_PMP_INVALID_REGION;

    /* Validate region index is within bounds */
    if (region->region_id >= PMP_MAX_REGIONS)
        return ERR_PMP_INVALID_REGION;

    /* Validate address range */
    if (region->addr_start >= region->addr_end)
        return ERR_PMP_ADDR_RANGE;

    /* Check if region is already locked */
    if (config->regions[region->region_id].locked)
        return ERR_PMP_LOCKED;

    uint8_t region_idx = region->region_id;
    uint8_t pmpcfg_idx, pmpcfg_offset;
    pmp_get_cfg_indices(region_idx, &pmpcfg_idx, &pmpcfg_offset);

    /* Build configuration byte with TOR mode and permissions */
    uint8_t pmpcfg_perm =
        region->permissions & (PMPCFG_R | PMPCFG_W | PMPCFG_X);
    uint8_t pmpcfg_byte = PMPCFG_A_TOR | pmpcfg_perm;

    /* Read current pmpcfg register to preserve other regions */
    uint32_t pmpcfg_val = read_pmpcfg(pmpcfg_idx);

    /* Clear the configuration byte for this region */
    pmpcfg_val &= ~(0xFFU << pmpcfg_offset);

    /* Write new configuration byte */
    pmpcfg_val |= (pmpcfg_byte << pmpcfg_offset);

    /* Write pmpaddr register with the upper boundary */
    write_pmpaddr(region_idx, region->addr_end >> 2);

    /* Write pmpcfg register with updated configuration */
    write_pmpcfg(pmpcfg_idx, pmpcfg_val);

    /* Update shadow configuration */
    config->regions[region_idx].addr_start = region->addr_start;
    config->regions[region_idx].addr_end = region->addr_end;
    config->regions[region_idx].permissions = region->permissions;
    config->regions[region_idx].priority = region->priority;
    config->regions[region_idx].region_id = region_idx;
    config->regions[region_idx].locked = region->locked;

    /* Update region count if this is a newly used region */
    if (region_idx >= config->region_count)
        config->region_count = region_idx + 1;

    return ERR_OK;
}

int32_t pmp_disable_region(pmp_config_t *config, uint8_t region_idx)
{
    if (!config)
        return ERR_PMP_INVALID_REGION;

    /* Validate region index is within bounds */
    if (region_idx >= PMP_MAX_REGIONS)
        return ERR_PMP_INVALID_REGION;

    /* Check if region is already locked */
    if (config->regions[region_idx].locked)
        return ERR_PMP_LOCKED;

    uint8_t pmpcfg_idx, pmpcfg_offset;
    pmp_get_cfg_indices(region_idx, &pmpcfg_idx, &pmpcfg_offset);

    /* Read current pmpcfg register to preserve other regions */
    uint32_t pmpcfg_val = read_pmpcfg(pmpcfg_idx);

    /* Clear the configuration byte for this region (disables it) */
    pmpcfg_val &= ~(0xFFU << pmpcfg_offset);

    /* Write pmpcfg register with updated configuration */
    write_pmpcfg(pmpcfg_idx, pmpcfg_val);

    /* Update shadow configuration */
    config->regions[region_idx].addr_start = 0;
    config->regions[region_idx].addr_end = 0;
    config->regions[region_idx].permissions = 0;

    return ERR_OK;
}

int32_t pmp_lock_region(pmp_config_t *config, uint8_t region_idx)
{
    if (!config)
        return ERR_PMP_INVALID_REGION;

    /* Validate region index is within bounds */
    if (region_idx >= PMP_MAX_REGIONS)
        return ERR_PMP_INVALID_REGION;

    uint8_t pmpcfg_idx, pmpcfg_offset;
    pmp_get_cfg_indices(region_idx, &pmpcfg_idx, &pmpcfg_offset);

    /* Read current pmpcfg register to preserve other regions */
    uint32_t pmpcfg_val = read_pmpcfg(pmpcfg_idx);

    /* Get current configuration byte for this region */
    uint8_t pmpcfg_byte = (pmpcfg_val >> pmpcfg_offset) & 0xFFU;

    /* Set lock bit */
    pmpcfg_byte |= PMPCFG_L;

    /* Clear the configuration byte for this region */
    pmpcfg_val &= ~(0xFFU << pmpcfg_offset);

    /* Write new configuration byte with lock bit set */
    pmpcfg_val |= (pmpcfg_byte << pmpcfg_offset);

    /* Write pmpcfg register with updated configuration */
    write_pmpcfg(pmpcfg_idx, pmpcfg_val);

    /* Update shadow configuration */
    config->regions[region_idx].locked = 1;

    return ERR_OK;
}

int32_t pmp_get_region(const pmp_config_t *config,
                       uint8_t region_idx,
                       pmp_region_t *region)
{
    if (!config || !region)
        return ERR_PMP_INVALID_REGION;

    /* Validate region index is within bounds */
    if (region_idx >= PMP_MAX_REGIONS)
        return ERR_PMP_INVALID_REGION;

    uint8_t pmpcfg_idx, pmpcfg_offset;
    pmp_get_cfg_indices(region_idx, &pmpcfg_idx, &pmpcfg_offset);

    /* Read the address and configuration from shadow configuration */
    region->addr_start = config->regions[region_idx].addr_start;
    region->addr_end = config->regions[region_idx].addr_end;
    region->permissions = config->regions[region_idx].permissions;
    region->priority = config->regions[region_idx].priority;
    region->region_id = region_idx;
    region->locked = config->regions[region_idx].locked;

    return ERR_OK;
}

int32_t pmp_check_access(const pmp_config_t *config,
                         uint32_t addr,
                         uint32_t size,
                         uint8_t is_write,
                         uint8_t is_execute)
{
    if (!config)
        return ERR_PMP_INVALID_REGION;

    /* Reject overflow to prevent security bypass */
    if (addr > UINT32_MAX - size)
        return 0;

    uint32_t access_end = addr + size;

    /* In TOR mode, check all regions in priority order */
    for (uint8_t i = 0; i < config->region_count; i++) {
        const pmp_region_t *region = &config->regions[i];

        /* Skip disabled regions */
        if (region->addr_start == 0 && region->addr_end == 0)
            continue;

        /* Check if access falls within this region */
        if (addr >= region->addr_start && access_end <= region->addr_end) {
            /* Verify permissions match access type */
            uint8_t required_perm = 0;
            if (is_write)
                required_perm |= PMPCFG_W;
            if (is_execute)
                required_perm |= PMPCFG_X;
            if (!is_write && !is_execute)
                required_perm = PMPCFG_R;

            if ((region->permissions & required_perm) == required_perm)
                return 1; /* Access allowed */
            else
                return 0; /* Access denied */
        }
    }

    /* Access not covered by any region */
    return 0;
}

/* Selects victim flexpage for eviction using priority-based algorithm.
 *
 * @mspace : Pointer to memory space
 * Returns pointer to victim flexpage, or NULL if no evictable page found.
 */
static fpage_t *select_victim_fpage(memspace_t *mspace)
{
    if (!mspace)
        return NULL;

    fpage_t *victim = NULL;
    uint32_t lowest_prio = 0;

    /* Select page with highest priority value (lowest priority).
     * Kernel regions (priority 0) are never selected. */
    for (fpage_t *fp = mspace->pmp_first; fp; fp = fp->pmp_next) {
        if (fp->priority > lowest_prio) {
            victim = fp;
            lowest_prio = fp->priority;
        }
    }

    return victim;
}

/* Sets base address for a TOR paired region entry */
static void pmp_set_base_entry(uint8_t entry_idx, uint32_t base_addr)
{
    if (entry_idx >= PMP_MAX_REGIONS)
        return;

    write_pmpaddr(entry_idx, base_addr >> 2);
}

/* Loads a flexpage into a PMP hardware region */
int32_t pmp_load_fpage(fpage_t *fpage, uint8_t region_idx)
{
    if (!fpage || region_idx >= PMP_MAX_REGIONS)
        return -1;

    pmp_config_t *config = pmp_get_config();
    if (!config)
        return -1;

    uint32_t base = fpage->base;
    uint32_t size = fpage->size;
    uint32_t end = base + size;

    /* User regions use paired entries (base + top), kernel regions use single
     * entry */
    if (PMP_IS_USER_REGION(region_idx)) {
        uint8_t base_entry = PMP_USER_BASE_ENTRY(region_idx);
        uint8_t top_entry = PMP_USER_TOP_ENTRY(region_idx);

        if (top_entry >= PMP_MAX_REGIONS) {
            return -1;
        }

        /* Set base entry (address-only, pmpcfg=0) */
        pmp_set_base_entry(base_entry, base);
        config->regions[base_entry].addr_start = base;
        config->regions[base_entry].addr_end = base;
        config->regions[base_entry].permissions = 0;
        config->regions[base_entry].locked = 0;

        /* Set top entry (TOR mode with permissions) */
        pmp_region_t top_region = {
            .addr_start = base,
            .addr_end = end,
            .permissions = fpage->rwx,
            .priority = fpage->priority,
            .region_id = top_entry,
            .locked = 0,
        };

        int32_t ret = pmp_set_region(config, &top_region);
        if (ret < 0)
            return ret;

        fpage->pmp_id = base_entry;

    } else {
        /* Kernel region: single entry TOR mode */
        pmp_region_t region = {
            .addr_start = base,
            .addr_end = end,
            .permissions = fpage->rwx,
            .priority = fpage->priority,
            .region_id = region_idx,
            .locked = 0,
        };

        int32_t ret = pmp_set_region(config, &region);
        if (ret < 0)
            return ret;

        fpage->pmp_id = region_idx;
    }

    return 0;
}

/* Evicts a flexpage from its PMP hardware region */
int32_t pmp_evict_fpage(fpage_t *fpage)
{
    if (!fpage)
        return -1;

    /* Only evict if actually loaded into PMP */
    if (fpage->pmp_id == PMP_INVALID_REGION)
        return 0;

    pmp_config_t *config = pmp_get_config();
    if (!config)
        return -1;

    uint8_t region_idx = fpage->pmp_id;

    /* User regions need to clear both base and top entries */
    if (PMP_IS_USER_REGION(region_idx)) {
        uint8_t base_entry = PMP_USER_BASE_ENTRY(region_idx);
        uint8_t top_entry = PMP_USER_TOP_ENTRY(region_idx);

        /* Clear base entry (address and shadow config) */
        pmp_set_base_entry(base_entry, 0);
        config->regions[base_entry].addr_start = 0;
        config->regions[base_entry].addr_end = 0;
        config->regions[base_entry].permissions = 0;

        /* Clear top entry using existing pmp_disable_region() */
        int32_t ret = pmp_disable_region(config, top_entry);
        if (ret < 0)
            return ret;

    } else {
        /* Kernel region uses simple single-entry eviction */
        int32_t ret = pmp_disable_region(config, region_idx);
        if (ret < 0)
            return ret;
    }

    fpage->pmp_id = PMP_INVALID_REGION;
    return 0;
}

/* Atomically replaces a victim flexpage with a target flexpage in hardware.
 *
 * Captures victim's PMP ID before eviction to avoid use-after-invalidation.
 *
 * @victim : Flexpage to evict (must be currently loaded)
 * @target : Flexpage to load (must not be currently loaded)
 * Returns 0 on success, negative error code on failure.
 */
static int32_t replace_fpage(fpage_t *victim, fpage_t *target)
{
    if (!victim || !target)
        return -1;

    /* Capture region ID before eviction invalidates it */
    uint8_t region_idx = victim->pmp_id;

    /* Evict victim from hardware */
    int32_t ret = pmp_evict_fpage(victim);
    if (ret != 0)
        return ret;

    /* Load target into the freed slot */
    return pmp_load_fpage(target, region_idx);
}

/* Handles PMP access faults by loading the required flexpage into hardware. */
int32_t pmp_handle_access_fault(uint32_t fault_addr, uint8_t is_write)
{
    if (!kcb || !kcb->task_current || !kcb->task_current->data)
        return PMP_FAULT_UNHANDLED;

    tcb_t *current = (tcb_t *) kcb->task_current->data;
    memspace_t *mspace = current->mspace;
    if (!mspace)
        return PMP_FAULT_UNHANDLED;

    /* Find flexpage containing faulting address */
    fpage_t *target_fpage = NULL;
    for (fpage_t *fp = mspace->first; fp; fp = fp->as_next) {
        if (fault_addr >= fp->base && fault_addr < (fp->base + fp->size)) {
            target_fpage = fp;
            break;
        }
    }

    /* Cannot recover: address not in task's memory space or already loaded */
    if (!target_fpage || target_fpage->pmp_id != PMP_INVALID_REGION) {
        /* Mark task as zombie for deferred cleanup */
        current->state = TASK_ZOMBIE;
        return PMP_FAULT_TERMINATE;
    }

    pmp_config_t *config = pmp_get_config();
    if (!config)
        return PMP_FAULT_UNHANDLED;

    /* Load into available region or evict victim */
    if (config->next_region_idx < PMP_MAX_REGIONS)
        return pmp_load_fpage(target_fpage, config->next_region_idx);

    fpage_t *victim = select_victim_fpage(mspace);
    if (!victim)
        return PMP_FAULT_UNHANDLED;

    /* Use helper to safely replace victim with target */
    return replace_fpage(victim, target_fpage);
}
/* Finds next available PMP region slot
 *
 * User regions require two consecutive free entries.
 * Kernel regions require single entry.
 *
 * Returns region index on success, -1 if none available.
 */
static int8_t find_free_region_slot(const pmp_config_t *config)
{
    if (!config)
        return -1;

    for (uint8_t i = 0; i < PMP_MAX_REGIONS; i++) {
        /* Skip locked regions */
        if (config->regions[i].locked)
            continue;

        bool is_free = (config->regions[i].addr_start == 0 &&
                        config->regions[i].addr_end == 0);

        if (!is_free)
            continue;

        /* Kernel regions use single entry */
        if (i < PMP_USER_REGION_START)
            return i;

        /* User regions need two consecutive slots */
        if (i + 1 < PMP_MAX_REGIONS) {
            bool next_is_free = (config->regions[i + 1].addr_start == 0 &&
                                 config->regions[i + 1].addr_end == 0);
            bool next_not_locked = !config->regions[i + 1].locked;

            if (next_is_free && next_not_locked)
                return i;
        }
    }

    return -1;
}

int32_t pmp_switch_context(memspace_t *old_mspace, memspace_t *new_mspace)
{
    if (old_mspace == new_mspace) {
        return 0;
    }

    pmp_config_t *config = pmp_get_config();
    if (!config) {
        return -1;
    }

    /* Evict old task's dynamic regions */
    if (old_mspace) {
        for (fpage_t *fp = old_mspace->pmp_first; fp; fp = fp->pmp_next) {
            /* pmp_evict_fpage correctly handles paired entries */
            if (fp->pmp_id != PMP_INVALID_REGION) {
                pmp_evict_fpage(fp);
            }
        }
    }

    /* Load new task's regions and rebuild tracking list */
    if (new_mspace) {
        new_mspace->pmp_first = NULL;

        for (fpage_t *fp = new_mspace->first; fp; fp = fp->as_next) {
            /* Shared regions may already be loaded */
            if (fp->pmp_id != PMP_INVALID_REGION) {
                fp->pmp_next = new_mspace->pmp_first;
                new_mspace->pmp_first = fp;
                continue;
            }

            int32_t region_idx = find_free_region_slot(config);
            if (region_idx < 0)
                break;

            if (pmp_load_fpage(fp, (uint8_t) region_idx) != 0)
                break;

            fp->pmp_next = new_mspace->pmp_first;
            new_mspace->pmp_first = fp;
        }
    }

    return 0;
}
