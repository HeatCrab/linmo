#pragma once

/* Linmo Operating System - Main API Header
 *
 * This header includes all kernel APIs for task management, synchronization,
 * IPC, and system services.
 *
 * Interrupt Service Routines (ISRs), including timer callbacks, execute in
 * interrupt context with special restrictions. Violating these restrictions
 * causes heap corruption, deadlocks, or undefined behavior.
 *
 * [ISR-SAFE] Functions (callable from interrupt context):
 * -------------------------------------------------------
 * System Info:     mo_task_id(), mo_task_count(), mo_ticks(), mo_uptime()
 * Timer API:       mo_timer_create/destroy/start/cancel() [NOSCHED protected]
 * Semaphore:       mo_sem_trywait(), mo_sem_signal() [non-blocking]
 * Mutex:           mo_mutex_trylock(), mo_mutex_unlock() [non-blocking]
 * Condition Var:   mo_cond_signal(), mo_cond_broadcast() [non-blocking]
 * Pipe I/O:        mo_pipe_nbread(), mo_pipe_nbwrite() [non-blocking]
 * Logging:         mo_logger_enqueue() [CRITICAL protected]
 * Direct I/O:      _putchar() for emergency/debug output
 *
 * [TASK-ONLY] Functions (must NOT call from ISR context):
 * -------------------------------------------------------
 * Memory:          mo_task_spawn(), mo_task_cancel() - use malloc/free
 * Blocking:        mo_task_delay(), mo_task_yield(), mo_task_suspend()
 * Blocking Sync:   mo_sem_wait(), mo_mutex_lock(), mo_cond_wait()
 * Blocking I/O:    mo_pipe_read(), mo_pipe_write()
 * Message Queue:   mo_mq_enqueue(), mo_mq_dequeue() - unprotected malloc
 * Stdio:           printf(), puts() - may deadlock in preemptive mode
 *
 * Timer Callback Rules:
 * ---------------------
 * Timer callbacks execute in ISR context. Example safe callback:
 *
 *   void *my_callback(void *arg) {
 *       mo_logger_enqueue("Timer fired\n", 12);  // Safe: ISR-protected
 *       mo_sem_signal(signal_sem);               // Safe: non-blocking
 *       // UNSAFE: mo_task_spawn(...);           // Uses malloc
 *       // UNSAFE: printf(...);                  // May deadlock
 *       return NULL;
 *   }
 *
 * For emergency debug output in ISR, use the ISR-safe I/O functions:
 *   isr_puts("message");     // Direct UART string output
 *   isr_putx(0xDEADBEEF);    // Direct UART hex output
 * These are defined in lib/libc.h and available via linmo.h.
 */

#include <types.h>

#include <lib/libc.h>
#include <lib/malloc.h>

#include <sys/errno.h>
#include <sys/logger.h>
#include <sys/memprot.h>
#include <sys/mqueue.h>
#include <sys/mutex.h>
#include <sys/pipe.h>
#include <sys/semaphore.h>
#include <sys/syscall.h>
#include <sys/task.h>
#include <sys/timer.h>
