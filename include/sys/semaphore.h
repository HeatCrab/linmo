#pragma once

/* Counting Semaphores for Task Synchronization
 *
 * Provides counting semaphores with FIFO queuing for blocked tasks.
 * Supports both binary semaphores (initial_count = 1) and general
 * counting semaphores for resource management.
 */

#include <lib/queue.h>

/* Forward declaration of the opaque semaphore type */
typedef struct sem_t sem_t;

/* Maximum semaphore count to prevent overflow issues */
#define SEM_MAX_COUNT (INT32_MAX - 1)

/* Semaphore Management Functions */

/* Creates and initializes a counting semaphore.
 * @max_waiters   : The maximum number of tasks that can be blocked on the
 *                  semaphore at one time. This determines the size of the
 *                  internal wait queue. Must be > 0.
 * @initial_count : The initial number of available resources (tokens).
 *                  Must be >= 0 and <= SEM_MAX_COUNT.
 *                  For a binary semaphore, this should be 1.
 *
 * Returns pointer to the newly created semaphore on success, or NULL on
 *         failure (e.g., invalid arguments, memory allocation failure).
 */
sem_t *mo_sem_create(uint16_t max_waiters, int32_t initial_count);

/* Destroys a semaphore.
 *
 * This operation will fail if any tasks are currently blocked waiting for the
 * semaphore, as destroying it would leave them in a permanent blocked state.
 * @s : A pointer to the semaphore to destroy. Can be NULL (no-op).
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int32_t mo_sem_destroy(sem_t *s);

/* Semaphore Wait Operations */

/* Acquires the semaphore (a "P" or "pend" operation), blocking if necessary.
 * [TASK-ONLY] May block caller - NOT safe from ISR context
 *
 * If the semaphore's count is > 0, it is decremented and the function returns
 * immediately. If the count is 0, the calling task is placed in the semaphore's
 * wait queue and blocked until another task signals the semaphore.
 * @s : A pointer to the semaphore. Must not be NULL.
 *
 * Note: This function may not return if the task is cancelled while waiting.
 */
void mo_sem_wait(sem_t *s);

/* Attempts to acquire the semaphore without blocking.
 * [ISR-SAFE] Non-blocking, returns immediately with success/failure
 *
 * @s : A pointer to the semaphore. Must not be NULL.
 *
 * Returns 0 if the semaphore was acquired successfully, or ERR_FAIL if it could
 *         not be acquired without blocking.
 */
int32_t mo_sem_trywait(sem_t *s);

/* Semaphore Signal Operations */

/* Releases the semaphore (a "V" or "post" operation), potentially unblocking
 * a waiter.
 * [ISR-SAFE] Protected by NOSCHED_ENTER - safe for ISR-to-task signaling
 *
 * If there are tasks blocked in the wait queue, the oldest waiting task is
 * unblocked (FIFO order). If the wait queue is empty, the semaphore's
 * resource count is incremented up to SEM_MAX_COUNT.
 * @s : A pointer to the semaphore. Must not be NULL.
 *
 * Common ISR pattern: Timer callback signals semaphore to wake waiting task.
 */
void mo_sem_signal(sem_t *s);

/* Semaphore Query Functions */

/* Gets the current count of available resources.
 * @s : A pointer to the semaphore. Must not be NULL.
 *
 * Returns the current semaphore count, or -1 if s is NULL.
 *
 * Note: This value may change immediately after the function returns
 *       due to concurrent operations by other tasks.
 */
int32_t mo_sem_getvalue(sem_t *s);

/* Gets the number of tasks currently waiting on the semaphore.
 * @s : A pointer to the semaphore. Must not be NULL.
 *
 * Returns the number of waiting tasks, or -1 if s is NULL.
 */
int32_t mo_sem_waiting_count(sem_t *s);
