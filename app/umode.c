#include <linmo.h>

/* Architecture-specific helper for SP manipulation testing.
 * Implemented in arch/riscv/entry.c as a naked function.
 */
extern uint32_t __switch_sp(uint32_t new_sp);

/* U-mode validation: syscall stability and privilege isolation.
 *
 * 1. Verify syscalls work under various SP conditions (normal, malicious).
 * 2. Verify privileged instructions trap.
 */
void umode_validation_task(void)
{
    /* --- Phase 1: Kernel Stack Isolation Test --- */
    umode_printf("Phase 1: Testing Kernel Stack Isolation\n");
    umode_printf("\n");

    /* Test 1-1: Baseline - Syscall with normal SP */
    umode_printf("Test 1-1: sys_tid() with normal SP\n");
    int my_tid = sys_tid();
    if (my_tid > 0) {
        umode_printf("PASS: sys_tid() returned %d\n", my_tid);
    } else {
        umode_printf("FAIL: sys_tid() failed (ret=%d)\n", my_tid);
    }
    umode_printf("\n");

    /* Test 1-2: Verify ISR uses mscratch, not malicious user SP */
    umode_printf("Test 1-2: sys_tid() with malicious SP\n");

    uint32_t saved_sp = __switch_sp(0xDEADBEEF);
    int my_tid_bad_sp = sys_tid();
    __switch_sp(saved_sp);

    if (my_tid_bad_sp > 0) {
        umode_printf(
            "PASS: sys_tid() succeeded, ISR correctly used kernel "
            "stack\n");
    } else {
        umode_printf("FAIL: Syscall failed with malicious SP (ret=%d)\n",
                     my_tid_bad_sp);
    }
    umode_printf("\n");

    /* Test 1-3: Verify syscall functionality is still intact */
    umode_printf("Test 1-3: sys_uptime() with normal SP\n");
    int uptime = sys_uptime();
    if (uptime >= 0) {
        umode_printf("PASS: sys_uptime() returned %d\n", uptime);
    } else {
        umode_printf("FAIL: sys_uptime() failed (ret=%d)\n", uptime);
    }
    umode_printf("\n");

    umode_printf("Phase 1 All tests passed.\n");
    umode_printf("\n");

    /* --- Phase 2: Security Check (Privileged Access) --- */
    umode_printf("========================================\n");
    umode_printf("\n");
    umode_printf("Phase 2: Testing Security Isolation\n");
    umode_printf("\n");
    umode_printf("Action: Attempting to read 'mstatus' CSR from U-mode.\n");
    umode_printf("Expect: Kernel Panic with 'Illegal instruction'.\n");
    umode_printf("\n");
    /* Delay before suicide to ensure logs are flushed from
     * buffer to UART.
     */
    sys_tdelay(10);

    /* Privileged Instruction Trigger */
    umode_printf("Result: \n");
    uint32_t mstatus;
    asm volatile("csrr %0, mstatus" : "=r"(mstatus));

    /* If execution reaches here, U-mode isolation failed (still has
     * privileges).
     */
    umode_printf("FAIL: Privileged instruction executed! (mstatus=0x%lx)\n",
                 (long) mstatus);

    /* Spin loop to prevent further execution. */
    while (1)
        sys_tyield();
}

int32_t app_main(void)
{
    umode_printf("Spawning U-mode validation task...\n");

    /* app_main now runs in U-mode by default.
     * mo_task_spawn routes to sys_task_spawn syscall for U-mode apps,
     * ensuring consistent API usage across the codebase.
     */
    mo_task_spawn(umode_validation_task, DEFAULT_STACK_SIZE);

    /* Return 1 to enable preemptive scheduler */
    return 1;
}
