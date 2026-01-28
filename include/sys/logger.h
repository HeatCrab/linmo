#pragma once

/* Deferred logging system for thread-safe printf in preemptive mode.
 *
 * Architecture:
 * - printf/puts format into a buffer and enqueue the complete message
 * - Logger task dequeues messages and outputs to UART
 * - Minimal critical sections (only during enqueue/dequeue operations)
 * - No long interrupt disable periods during UART output
 *
 * Benefits:
 * - Low interrupt latency
 * - ISRs remain responsive during logging
 * - No nested critical section issues
 * - Proper separation between formatting and output
 */

#include <types.h>

/* Logger Configuration - Optimized for memory efficiency
 * These values balance memory usage with logging capacity:
 * - 8 entries handles typical burst logging scenarios
 * - 128 bytes accommodates most debug messages
 * Total buffer overhead: 8 × 128 = 1KB (down from 4KB)
 */
#define LOG_QSIZE 8      /* Number of log entries in ring buffer */
#define LOG_ENTRY_SZ 128 /* Maximum length of single log message */

/* Logger Control */

/* Initialize the logger subsystem.
 * Creates the log queue and spawns the logger task.
 * Must be called during kernel initialization, after heap and task system init.
 *
 * Returns ERR_OK on success, ERR_FAIL on failure
 */
int32_t mo_logger_init(void);

/* Enqueue a log message for deferred output.
 * [ISR-SAFE] Protected by CRITICAL_ENTER - safe to call from ISR context
 *
 * Non-blocking: if queue is full, message is dropped.
 * Thread-safe: protected by short critical section.
 *
 * This is the RECOMMENDED way to log from timer callbacks and ISRs.
 * The message is queued and output later by the logger task, avoiding
 * the risk of deadlock from direct UART output in ISR context.
 *
 * @msg    : Null-terminated message string
 * @length : Length of message (excluding null terminator)
 *
 * Returns ERR_OK if enqueued, ERR_BUSY if queue full
 */
int32_t mo_logger_enqueue(const char *msg, uint16_t length);

/* Get the number of messages currently in the queue.
 * Useful for monitoring queue depth and detecting overruns.
 *
 * Returns number of queued messages
 */
uint32_t mo_logger_queue_depth(void);

/* Get the total number of dropped messages due to queue overflow.
 *
 * Returns total dropped message count since logger init
 */
uint32_t mo_logger_dropped_count(void);

/* Check if logger is in direct output mode.
 * Lock-free read for performance - safe to call frequently.
 * Returns true if printf/puts should bypass the queue.
 */
bool mo_logger_direct_mode(void);

/* Flush all pending messages and enter direct output mode.
 * Drains the queue directly from caller's context.
 * After flush, printf/puts bypass the queue for ordered output.
 * Call mo_logger_async_resume() to re-enable async logging.
 */
void mo_logger_flush(void);

/* Re-enable async logging after a flush.
 * Call this after completing ordered output that required direct mode.
 */
void mo_logger_async_resume(void);
