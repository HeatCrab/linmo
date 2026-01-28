/* Deferred logging: async I/O pattern for thread-safe printf.
 *
 * Design rationale:
 * - Ring buffer + mutex
 * - Logger task at IDLE priority: drains queue without blocking tasks
 * - UART output outside lock: other tasks enqueue while we output
 * - Graceful degradation: fallback to direct output on queue full
 */

#include <lib/libc.h>
#include <sys/logger.h>
#include <sys/mutex.h>
#include <sys/task.h>

#include "private/error.h"
#include "private/task.h"

/* Ring buffer entry: fixed-size for O(1) enqueue/dequeue */
typedef struct {
    uint16_t length;
    char data[LOG_ENTRY_SZ];
} log_entry_t;

/* Logger state: single global instance, no dynamic allocation */
typedef struct {
    log_entry_t queue[LOG_QSIZE];
    uint32_t head, tail, count;
    uint32_t dropped; /* Diagnostic: tracks queue overflow events */
    mutex_t lock;     /* Protects queue manipulation, not UART output */
    int32_t task_id;
    bool initialized;

    /* When true, printf bypasses queue.
     * volatile: prevent compiler caching for lock-free read. Written under
     * mutex, read without - safe on single-core.
     */
    volatile bool direct_mode;
} logger_state_t;

static logger_state_t logger;

/* Logger task: IDLE priority ensures application tasks run first */
static void logger_task(void)
{
    log_entry_t entry;

    while (1) {
        bool have_message = false;

        /* Critical section: only queue manipulation, not UART I/O */
        mo_mutex_lock(&logger.lock);
        if (logger.count > 0) {
            memcpy(&entry, &logger.queue[logger.tail], sizeof(log_entry_t));
            logger.tail = (logger.tail + 1) % LOG_QSIZE;
            logger.count--;
            have_message = true;
        }
        mo_mutex_unlock(&logger.lock);

        if (have_message) {
            /* Key design: UART output outside lock prevents blocking enqueuers.
             * shorter UART write does not hold mutex - other tasks enqueue in
             * parallel.
             */
            for (uint16_t i = 0; i < entry.length; i++)
                _putchar(entry.data[i]);
        } else {
            /* Block when idle: sleep 1 tick, scheduler wakes us next period */
            mo_task_delay(1);
        }
    }
}

/* Call after heap + task system init, before enabling preemption */
int32_t mo_logger_init(void)
{
    if (logger.initialized)
        return ERR_OK;

    memset(&logger, 0, sizeof(logger_state_t));

    if (mo_mutex_init(&logger.lock) != ERR_OK)
        return ERR_FAIL;

    /* 1024B stack: space for log_entry_t (130B) + ISR frame (128B) + calls */
    /* Kernel internal: always use direct API for kernel-mode task */
    logger.task_id = mo_task_spawn_kernel(logger_task, 1024);
    if (logger.task_id < 0) {
        mo_mutex_destroy(&logger.lock);
        return ERR_FAIL;
    }

    /* IDLE priority: runs only when no application tasks are ready */
    mo_task_priority(logger.task_id, TASK_PRIO_IDLE);

    logger.initialized = true;
    return ERR_OK;
}

/* Non-blocking enqueue: returns ERR_TASK_BUSY on overflow, never waits */
int32_t mo_logger_enqueue(const char *msg, uint16_t length)
{
    if (!logger.initialized || !msg || length == 0)
        return ERR_FAIL;

    /* Defensive check: stdio.c pre-filters, but validate anyway */
    if (length > LOG_ENTRY_SZ - 1)
        length = LOG_ENTRY_SZ - 1;

    mo_mutex_lock(&logger.lock);

    /* Drop message on full queue: non-blocking design, caller falls back to
     * direct I/O
     */
    if (logger.count >= LOG_QSIZE) {
        logger.dropped++;
        mo_mutex_unlock(&logger.lock);
        return ERR_TASK_BUSY;
    }

    log_entry_t *entry = &logger.queue[logger.head];
    entry->length = length;
    memcpy(entry->data, msg, length);
    /* Safety: enables direct string ops on data[] */
    entry->data[length] = '\0';

    logger.head = (logger.head + 1) % LOG_QSIZE;
    logger.count++;

    mo_mutex_unlock(&logger.lock);

    return ERR_OK;
}

/* Diagnostic: monitor queue depth to detect sustained overflow conditions */
uint32_t mo_logger_queue_depth(void)
{
    if (!logger.initialized)
        return 0;

    mo_mutex_lock(&logger.lock);
    uint32_t depth = logger.count;
    mo_mutex_unlock(&logger.lock);

    return depth;
}

/* Diagnostic: total messages lost since init (non-resettable counter) */
uint32_t mo_logger_dropped_count(void)
{
    if (!logger.initialized)
        return 0;

    mo_mutex_lock(&logger.lock);
    uint32_t dropped = logger.dropped;
    mo_mutex_unlock(&logger.lock);

    return dropped;
}

/* Check if logger is in direct output mode.
 * Lock-free read: safe because direct_mode is only set atomically by flush
 * and cleared by async_resume, both under mutex protection. Reading a stale
 * value is benign (worst case: one extra direct output or one queued message).
 */
bool mo_logger_direct_mode(void)
{
    return logger.initialized && logger.direct_mode;
}

/* Flush all pending messages and enter direct output mode.
 * Drains the queue directly from caller's context, bypassing logger task.
 * After flush, printf/puts bypass the queue for ordered output.
 * Call mo_logger_async_resume() to re-enable async logging.
 */
void mo_logger_flush(void)
{
    if (!logger.initialized)
        return;

    log_entry_t entry;

    while (1) {
        bool have_message = false;

        mo_mutex_lock(&logger.lock);
        if (logger.count > 0) {
            memcpy(&entry, &logger.queue[logger.tail], sizeof(log_entry_t));
            logger.tail = (logger.tail + 1) % LOG_QSIZE;
            logger.count--;
            have_message = true;
        } else {
            /* Queue drained: enter direct mode while still holding lock */
            logger.direct_mode = true;
        }
        mo_mutex_unlock(&logger.lock);

        if (!have_message)
            break;

        /* Output outside lock */
        for (uint16_t i = 0; i < entry.length; i++)
            _putchar(entry.data[i]);
    }
}

/* Re-enable async logging after a flush.
 * Call this after completing ordered output that required direct mode.
 */
void mo_logger_async_resume(void)
{
    if (!logger.initialized)
        return;

    mo_mutex_lock(&logger.lock);
    logger.direct_mode = false;
    mo_mutex_unlock(&logger.lock);
}
