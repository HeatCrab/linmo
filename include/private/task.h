#pragma once

/* Kernel-internal task management APIs.
 *
 * These functions are for kernel use only (logger, main, syscall handlers).
 * Applications should use the mo_task_spawn() macro from <sys/task.h>.
 *
 * Note: This header must be included after <sys/task.h> or other headers
 * that define int32_t and uint16_t (project uses arch-specific types).
 */

/* Include error.h to get __LINMO_KERNEL marker for compile-time guard */
#include "private/error.h"

/* Compile-time guard: reject non-kernel builds */
#ifndef __LINMO_KERNEL
#error \
    "private/task.h is for kernel use only. Applications must use mo_task_spawn() from <sys/task.h>"
#endif

/* Creates and starts a new task in kernel (machine) mode.
 * @task_entry : Pointer to the task's entry function (void func(void))
 * @stack_size : The desired stack size in bytes (minimum is enforced)
 *
 * Returns the new task's ID on success, -1 on privilege violation,
 * or panics on memory allocation failure.
 *
 * Security: Protected by defense-in-depth:
 * - Runtime check rejects calls from syscall context (returns -1)
 * - Hardware protection: read_csr(mstatus) traps immediately if called
 *   from U-mode (illegal instruction exception)
 */
int32_t mo_task_spawn_kernel(void *task_entry, uint16_t stack_size);

/* Creates and starts a new task in user mode.
 * @task_entry : Pointer to the task's entry function (void func(void))
 * @stack_size : The desired stack size in bytes (minimum is enforced)
 *
 * Returns the new task's ID on success. Panics on memory allocation failure.
 *
 * Used by kernel bootstrap (main.c) and syscall handlers.
 * U-mode tasks run with restricted privileges and must use syscalls.
 */
int32_t mo_task_spawn_user(void *task_entry, uint16_t stack_size);
