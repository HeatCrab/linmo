/* Software Timer Subsystem Self-Test
 *
 * It creates several timers with different periods and modes to verify
 * their correct operation.
 *
 * Note: Timer callbacks execute in ISR context. This test uses printf()
 * which may fall back to blocking direct output when the queue is full
 * or the message exceeds LOG_ENTRY_SZ. For production ISR callbacks,
 * prefer mo_logger_enqueue() or isr_puts() which are always ISR-safe.
 */
#include <linmo.h>

/* Helper function to print the current system uptime.
 * Called from timer callback (ISR context) - uses ISR-safe logging.
 */
static void print_time(void)
{
    /* mo_uptime() returns a 64-bit value to prevent rollover. */
    uint64_t time_ms = mo_uptime();
    uint32_t secs = time_ms / 1000;
    uint32_t msecs = time_ms % 1000;

    printf("%lu.%03lu", (unsigned long) secs, (unsigned long) msecs);
}

/* Generic timer callback.
 * Executes in ISR context - only ISR-safe functions are permitted here.
 * This example uses printf() for convenience in a test app; it may block
 * on direct output fallback. For guaranteed ISR-safe logging, use
 * mo_logger_enqueue(), isr_puts(), or isr_putx().
 */
void *timer_callback(void *arg)
{
    /* The argument is the timer number, cast from a void pointer. */
    int timer_num = (int) (size_t) arg;

    printf("TIMER %d (", timer_num);
    print_time();
    printf(")\n");

    return NULL;
}

/* An idle task is necessary to ensure there is always at least one task in the
 * TASK_READY state, preventing the scheduler from halting.
 * It yields the CPU in a power-efficient manner.
 */
void idle_task(void)
{
    while (1)
        mo_task_wfi();
}

/* Application entry point */
int32_t app_main(void)
{
    printf("Initializing software timer test...\n");

    /* Create three timers with different periods.
     * The second argument to mo_timer_create is the period in milliseconds.
     * The third argument is passed directly to the callback.
     */
    mo_timer_create(timer_callback, 1000, (void *) 1);
    mo_timer_create(timer_callback, 3000, (void *) 2);
    mo_timer_create(timer_callback, 500, (void *) 3);

    /* Start all created timers in auto-reload mode.
     * Note: In this simple case, the IDs will be 0x6000, 0x6001, and 0x6002.
     */
    mo_timer_start(0x6000, TIMER_AUTORELOAD);
    mo_timer_start(0x6001, TIMER_AUTORELOAD);
    mo_timer_start(0x6002, TIMER_AUTORELOAD);

    /* Spawn a single idle task to keep the kernel running. */
    mo_task_spawn(idle_task, DEFAULT_STACK_SIZE);

    /* preemptive mode */
    return 1;
}
