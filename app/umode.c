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
    /* Test 1: Basic syscall */
    umode_printf("Test 1: Basic syscall\n");
    umode_printf("Calling sys_tid()...\n");
    int my_tid = sys_tid();
    if (my_tid > 0) {
        umode_printf("[PASS] returned tid=%d\n", my_tid);
    } else {
        umode_printf("[FAIL] returned tid=%d\n", my_tid);
    }
    umode_printf("\n");

    /* Test 2: Syscall with corrupted SP */
    umode_printf("Test 2: Syscall with corrupted SP\n");
    umode_printf("Setting SP to 0xDEADBEEF...\n");

    uint32_t saved_sp = __switch_sp(0xDEADBEEF);
    int my_tid_bad_sp = sys_tid();
    __switch_sp(saved_sp);

    if (my_tid_bad_sp > 0) {
        umode_printf("[PASS] kernel stack isolation working\n");
    } else {
        umode_printf("[FAIL] syscall failed (ret=%d)\n", my_tid_bad_sp);
    }
    umode_printf("\n");

    /* Test 3: Syscall after recovery */
    umode_printf("Test 3: Syscall after recovery\n");
    umode_printf("Calling sys_uptime()...\n");
    int uptime = sys_uptime();
    if (uptime >= 0) {
        umode_printf("[PASS] returned uptime=%d\n", uptime);
    } else {
        umode_printf("[FAIL] returned uptime=%d\n", uptime);
    }
    umode_printf("\n");

    /* Test 4: Privileged CSR access
     * Delay before triggering exception to ensure logs are flushed.
     */
    umode_printf("Test 4: Privileged CSR access\n");
    sys_tdelay(10);

    umode_printf("Reading mstatus from U-mode...\n");
    umode_printf("Result: \n");
    uint32_t mstatus;
    asm volatile("csrr %0, mstatus" : "=r"(mstatus));

    /* If execution reaches here, U-mode isolation failed */
    umode_printf("[FAIL] privileged instruction executed (mstatus=0x%lx)\n",
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
