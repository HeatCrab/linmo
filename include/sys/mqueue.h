#pragma once

#include <lib/queue.h>

/* Message Queue
 *
 * Provides FIFO message passing between tasks with type-safe message
 * containers. Messages consist of a user-allocated payload, a type
 * discriminator, and size information.
 *
 * ISR-SAFETY WARNING:
 * [TASK-ONLY] All message queue operations are task-context only.
 * Message queue operations use underlying queue functions that may perform
 * memory allocation. These operations are NOT protected by CRITICAL_ENTER
 * and are NOT safe to call from ISR context.
 *
 * For ISR-to-task communication, use:
 * - mo_pipe_nbwrite() for simple byte streams
 * - mo_sem_signal() to wake a task
 * - mo_logger_enqueue() for logging
 */

/* Message container structure */
typedef struct {
    void *payload; /* Pointer to user-allocated buffer */
    uint16_t type; /* User-defined discriminator for message type */
    uint16_t size; /* Payload size in bytes */
} message_t;

/* Message queue descriptor structure */
typedef struct {
    queue_t *q; /* FIFO queue of (message_t *) pointers */
} mq_t;

/* Message Queue Management */

/* Creates a new message queue with specified capacity.
 * @size : Maximum number of messages the queue can hold
 *
 * Returns pointer to new message queue on success, NULL on failure
 */
mq_t *mo_mq_create(uint16_t size);

/* Destroys a message queue and frees its resources.
 * Note: Does not free individual message payloads - caller responsibility
 * @mq : Pointer to message queue (NULL is safe no-op)
 *
 * Returns ERR_OK on success, ERR_FAIL on failure
 */
int32_t mo_mq_destroy(mq_t *mq);

/* Message Queue Operations */

/* Enqueues a message to the tail of the queue.
 * @mq : Pointer to message queue (must be valid)
 * @m  : Pointer to message to enqueue (must be valid)
 *
 * Returns ERR_OK on success, ERR_FAIL if queue is full or invalid
 */
int32_t mo_mq_enqueue(mq_t *mq, message_t *m);

/* Dequeues a message from the head of the queue.
 * @mq : Pointer to message queue (must be valid)
 *
 * Returns pointer to dequeued message on success, NULL if empty or invalid
 */
message_t *mo_mq_dequeue(mq_t *mq);

/* Peeks at the next message without removing it from the queue.
 * @mq : Pointer to message queue (must be valid)
 *
 * Returns pointer to next message on success, NULL if empty or invalid
 */
message_t *mo_mq_peek(mq_t *mq);

/* Gets the current number of messages in the queue.
 * @mq : Pointer to message queue
 *
 * Returns number of queued messages, or 0 if queue is invalid/empty
 */
static inline int32_t mo_mq_items(mq_t *mq)
{
    /* Add NULL safety to prevent crashes */
    if (unlikely(!mq || !mq->q))
        return 0;
    return queue_count(mq->q);
}
