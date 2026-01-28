#pragma once

/* Inter-task Communication Pipes
 *
 * Pipes provide a unidirectional FIFO communication channel between tasks.
 * They support both blocking and non-blocking I/O operations with automatic
 * buffer management using power-of-2 sizing for efficient masking operations.
 */

#include <types.h>

/* Magic number for pipe validation and corruption detection */
#define PIPE_MAGIC 0x50495045 /* "PIPE" */

/* Pipe descriptor structure
 *
 * The circular buffer uses head/tail indices with power-of-2 masking
 * for efficient wraparound. The 'used' counter provides O(1) empty/full
 * detection and accurate size reporting without head/tail comparison issues.
 */
typedef struct {
    char *buf;              /* Data buffer (power-of-2 size) */
    uint16_t mask;          /* Capacity - 1 (for efficient modulo) */
    volatile uint16_t head; /* Read index (consumer position) */
    volatile uint16_t tail; /* Write index (producer position) */
    volatile uint16_t used; /* Bytes currently stored (0 to capacity) */
    uint32_t magic;         /* Magic number for validation */
} pipe_t;

/* Pipe Management Functions */

/* Create a new pipe with specified buffer size.
 * @size : Desired buffer size (will be rounded up to next power-of-2)
 *
 * Returns pointer to new pipe on success, NULL on failure
 * Note: Minimum size is 2 bytes, maximum is 32768 bytes
 */
pipe_t *mo_pipe_create(uint16_t size);

/* Destroy a pipe and free its resources.
 * @pipe : Pointer to pipe structure (NULL is safe no-op)
 *
 * Returns ERR_OK on success, ERR_FAIL if pipe is invalid
 */
int32_t mo_pipe_destroy(pipe_t *pipe);

/* Pipe Status and Control Operations */

/* Flush all data from the pipe (reset to empty state).
 * @pipe : Pointer to pipe structure (must be valid)
 */
void mo_pipe_flush(pipe_t *pipe);

/* Get the number of bytes currently stored in the pipe.
 * @pipe : Pointer to pipe structure
 *
 * Returns number of bytes available for reading, or -1 if pipe is invalid
 */
int32_t mo_pipe_size(pipe_t *pipe);

/* Get the total capacity of the pipe.
 * @pipe : Pointer to pipe structure
 *
 * Returns total buffer size in bytes, or -1 if pipe is invalid
 */
int32_t mo_pipe_capacity(pipe_t *pipe);

/* Get the number of free bytes in the pipe.
 * @pipe : Pointer to pipe structure
 *
 * Returns number of bytes available for writing, or -1 if pipe is invalid
 */
int32_t mo_pipe_free_space(pipe_t *pipe);

/* Blocking I/O Operations
 * [TASK-ONLY] These functions block the caller and invoke the scheduler.
 * They must NOT be called from ISR context (including timer callbacks).
 */

/* Read data from pipe, blocking until all requested bytes are available.
 * [TASK-ONLY] Blocks caller - NOT safe from ISR context
 *
 * @pipe : Pointer to pipe structure (must be valid)
 * @data : Buffer to store read data (must be non-NULL)
 * @size : Number of bytes to read (must be > 0)
 *
 * Returns number of bytes read (equals size on success), negative on error
 * Note: This function will block until all requested data is available
 */
int32_t mo_pipe_read(pipe_t *pipe, char *data, uint16_t size);

/* Write data to pipe, blocking until all data is written.
 * [TASK-ONLY] Blocks caller - NOT safe from ISR context
 *
 * @pipe : Pointer to pipe structure (must be valid)
 * @data : Data to write (must be non-NULL)
 * @size : Number of bytes to write (must be > 0)
 *
 * Returns number of bytes written (equals size on success), negative on error
 * Note: This function will block until all data can be written
 */
int32_t mo_pipe_write(pipe_t *pipe, const char *data, uint16_t size);

/* Non-blocking I/O Operations
 * [ISR-SAFE] These functions return immediately without blocking or invoking
 * the scheduler. Safe to call from ISR context, including timer callbacks.
 * Ideal for ISR-to-task communication patterns.
 */

/* Read available data from pipe without blocking.
 * [ISR-SAFE] Non-blocking, returns immediately
 *
 * @pipe : Pointer to pipe structure (must be valid)
 * @data : Buffer to store read data (must be non-NULL)
 * @size : Maximum number of bytes to read
 *
 * Returns number of bytes actually read (0 to size), negative on error
 * Note: Returns immediately even if no data is available
 */
int32_t mo_pipe_nbread(pipe_t *pipe, char *data, uint16_t size);

/* Write data to pipe without blocking.
 * [ISR-SAFE] Non-blocking, returns immediately
 *
 * @pipe : Pointer to pipe structure (must be valid)
 * @data : Data to write (must be non-NULL)
 * @size : Number of bytes to write
 *
 * Returns number of bytes actually written (0 to size), negative on error
 * Note: Returns immediately even if no space is available
 */
int32_t mo_pipe_nbwrite(pipe_t *pipe, const char *data, uint16_t size);
