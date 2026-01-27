/* Condition-variable / mutex self-test
 * - One producer and one consumer share an integer "buffer".
 * - A third task exercises mo_mutex_trylock() and mo_mutex_timedlock().
 * - All public APIs of mutexes and condition variables are touched.
 *
 * NOTE: The mutex_tester is carefully written to acquire and then immediately
 * release the mutex, preventing it from causing a deadlock with the
 * producer/consumer logic.
 */

#include <linmo.h>

/* FIXME: expose error code to public APIs */
#include "private/error.h"

/* shared state */
static mutex_t m;          /* protects shared data */
static cond_t cv;          /* producer/consumer rendez-vous */
static int data_ready = 0; /* 0 = empty, 1 = full */
static int data_value = 0;

/* producer */
static void producer(void)
{
    int i = 0;

    for (;;) {
        mo_mutex_lock(&m);
        while (data_ready)
            mo_cond_wait(&cv, &m);

        data_value = i++;
        data_ready = 1;
        printf("produced %d\n", data_value);

        mo_cond_signal(&cv);
        mo_mutex_unlock(&m);
        mo_task_yield();
    }
}

/* consumer */
static void consumer(void)
{
    for (;;) {
        mo_mutex_lock(&m);
        while (!data_ready)
            mo_cond_wait(&cv, &m);

        printf("consumed %d\n", data_value);
        data_ready = 0;

        mo_cond_signal(&cv);
        mo_mutex_unlock(&m);
        mo_task_yield();
    }
}

/* task that demonstrates try-lock and timed-lock
 * This task is written to correctly handle all return paths to avoid
 * deadlocking the system.
 */
static void mutex_tester(void)
{
    /* Let the other tasks run a few cycles first. */
    mo_task_delay(10);

    /* Test Try-Lock */
    printf("Mutex Tester: trying trylock...\n");
    if (mo_mutex_trylock(&m) == ERR_TASK_BUSY) {
        printf("trylock busy – OK\n");
    } else {
        /* This case is possible if we run when the mutex happens to be free */
        printf("trylock acquired – OK\n");
        mo_mutex_unlock(&m);
    }

    /* Test Timed-Lock */
    printf("Mutex Tester: trying timedlock...\n");
    int32_t lock_result = mo_mutex_timedlock(&m, 5);
    if (lock_result == ERR_TIMEOUT) {
        printf("timedlock timeout – OK\n");
    } else if (lock_result == ERR_OK) {
        printf("timedlock acquired – OK\n");
        mo_mutex_unlock(&m);
    } else {
        /* This case should not happen */
        printf("timedlock returned an unexpected error: %d\n",
               (int) lock_result);
    }

    printf("Mutex Tester: finished.\n");
    mo_task_cancel(mo_task_id());

    /* This part of the function should not be reached */
    for (;;)
        mo_task_wfi();
}

/* idle task keeps at least one READY task in the system */
static void idle_task(void)
{
    for (;;)
        mo_task_wfi();
}

/* application entry */
int32_t app_main(void)
{
    mo_mutex_init(&m);
    mo_cond_init(&cv);

    mo_task_spawn(producer, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(consumer, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(mutex_tester, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(idle_task, DEFAULT_STACK_SIZE, TASK_MODE_M);

    /* preemptive mode */
    return 1;
}
