/* PMP Memory Isolation Test
 *
 * Validates PMP-based memory protection implementation.
 *
 * Test Suite:
 *   Test 1: Context Switch & Stack Integrity
 *           - Validates PMP correctly isolates task stacks during context
 * switches
 *           - Runs to completion, reports PASS/FAIL
 *
 *   Test 2: Kernel Protection (Destructive)
 *           - Validates U-mode cannot write to kernel memory
 *           - Triggers PMP fault and task termination
 *
 *   Test 3: Inter-Task Isolation (Destructive)
 *           - Validates U-mode cannot access another task's stack
 *           - Triggers PMP fault and task termination
 */

#include <linmo.h>

/* Test configuration */
#define MAX_ITERATIONS 10
#define STACK_MAGIC_A 0xAAAAAAAA
#define STACK_MAGIC_B 0xBBBBBBBB
#define STACK_MAGIC_C 0xCCCCCCCC

/* Test state tracking */
static volatile int tests_passed = 0;
static volatile int tests_failed = 0;
static volatile int tasks_completed = 0;

/* Cross-task attack: Task B exports its stack address for attacker task */
static volatile uint32_t *task_b_stack_addr = NULL;

/* External kernel symbols */
extern uint32_t _stext, _etext;
extern uint32_t _sdata, _edata;

/* ========================================================================
 * Test 1: Context Switch & Stack Integrity Check
 * ======================================================================== */

/* Task A: Stack integrity validation with magic value 0xAAAAAAAA */
void task_a_integrity(void)
{
    /* Allocate critical data on stack */
    volatile uint32_t stack_guard = STACK_MAGIC_A;
    volatile uint32_t iteration_count = 0;

    for (int i = 0; i < MAX_ITERATIONS; i++) {
        iteration_count = i + 1;

        sys_tyield();

        /* Verify stack integrity */
        if (stack_guard != STACK_MAGIC_A) {
            umode_printf(
                "[Task A] FAIL: Stack corrupted! "
                "Expected 0x%08x, got 0x%08x at iteration %d\n",
                (unsigned int) STACK_MAGIC_A, (unsigned int) stack_guard,
                (int) iteration_count);
            tests_failed++;
            tasks_completed++;
            while (1)
                sys_tyield();
        }

        /* Verify iteration counter */
        if (iteration_count != (uint32_t) (i + 1)) {
            umode_printf("[Task A] FAIL: Iteration counter corrupted!\n");
            tests_failed++;
            tasks_completed++;
            while (1)
                sys_tyield();
        }
    }

    umode_printf("[Task A] PASS: Stack integrity verified across %d switches\n",
                 MAX_ITERATIONS);
    tests_passed++;
    tasks_completed++;

    /* Keep task alive */
    while (1) {
        for (int i = 0; i < 20; i++)
            sys_tyield();
    }
}

/* Task B: Stack integrity validation with magic value 0xBBBBBBBB */
void task_b_integrity(void)
{
    volatile uint32_t stack_guard = STACK_MAGIC_B;
    volatile uint32_t checksum = 0;

    /* Export stack address for cross-task attack test */
    task_b_stack_addr = &stack_guard;

    for (int i = 0; i < MAX_ITERATIONS; i++) {
        checksum += (i + 1);

        sys_tyield();

        if (stack_guard != STACK_MAGIC_B) {
            umode_printf(
                "[Task B] FAIL: Stack guard corrupted! "
                "Expected 0x%08x, got 0x%08x\n",
                (unsigned int) STACK_MAGIC_B, (unsigned int) stack_guard);
            tests_failed++;
            tasks_completed++;
            while (1)
                sys_tyield();
        }

        uint32_t expected_checksum = ((i + 1) * (i + 2)) / 2;
        if (checksum != expected_checksum) {
            umode_printf(
                "[Task B] FAIL: Checksum mismatch! "
                "Expected %u, got %u\n",
                (unsigned int) expected_checksum, (unsigned int) checksum);
            tests_failed++;
            tasks_completed++;
            while (1)
                sys_tyield();
        }
    }

    umode_printf("[Task B] PASS: Stack integrity and checksum verified\n");
    tests_passed++;
    tasks_completed++;

    while (1) {
        for (int i = 0; i < 20; i++)
            sys_tyield();
    }
}

/* Task C: Stack integrity with array operations */
void task_c_integrity(void)
{
    volatile uint32_t stack_array[4] = {STACK_MAGIC_C, STACK_MAGIC_C + 1,
                                        STACK_MAGIC_C + 2, STACK_MAGIC_C + 3};

    for (int i = 0; i < MAX_ITERATIONS; i++) {
        sys_tyield();

        for (int j = 0; j < 4; j++) {
            uint32_t expected = STACK_MAGIC_C + j;
            if (stack_array[j] != expected) {
                umode_printf(
                    "[Task C] FAIL: Array[%d] corrupted! "
                    "Expected 0x%08x, got 0x%08x\n",
                    j, (unsigned int) expected, (unsigned int) stack_array[j]);
                tests_failed++;
                tasks_completed++;
                while (1)
                    sys_tyield();
            }
        }
    }

    umode_printf("[Task C] PASS: Stack array integrity verified\n");
    tests_passed++;
    tasks_completed++;

    while (1) {
        for (int i = 0; i < 20; i++)
            sys_tyield();
    }
}

/* ========================================================================
 * Test 2: Kernel Protection (Destructive - Triggers Fault)
 * ======================================================================== */

/* U-mode write to kernel memory (triggers PMP fault) */
void task_kernel_attack(void)
{
    sys_tdelay(50); /* Wait for Test 1 to complete */

    umode_printf("\n=== Test 2: Kernel Protection ===\n");
    umode_printf("Attempting to write to kernel .text at %p\n",
                 (void *) &_stext);
    umode_printf("Expected: [PMP] Task terminated\n");
    umode_printf("\nResult:\n");

    sys_tdelay(10);

    volatile uint32_t *kernel_addr = (volatile uint32_t *) &_stext;
    *kernel_addr = 0xDEADBEEF;

    /* Should not reach here - PMP should terminate this task */
    umode_printf("FAIL: Successfully wrote to kernel memory!\n");
    tests_failed++;

    while (1)
        sys_tyield();
}

/* ========================================================================
 * Test 3: Inter-Task Isolation (Destructive - Triggers Fault)
 * ======================================================================== */

/* U-mode task attempts to read another task's stack (triggers PMP fault) */
void task_cross_attack(void)
{
    /* Wait for Task B to export its stack address */
    while (!task_b_stack_addr)
        sys_tyield();

    sys_tdelay(70); /* Wait for Test 2 to complete */

    umode_printf("\n=== Test 3: Inter-Task Isolation ===\n");
    umode_printf("Attempting to read Task B's stack at %p\n",
                 (void *) task_b_stack_addr);
    umode_printf("Expected: [PMP] Task terminated\n");
    umode_printf("\nResult:\n");

    sys_tdelay(10);

    /* Attempt to read Task B's stack - should trigger PMP fault */
    volatile uint32_t stolen_value = *task_b_stack_addr;

    /* Should not reach here - PMP should terminate this task */
    umode_printf("FAIL: Successfully read Task B's stack! Value: 0x%08x\n",
                 (unsigned int) stolen_value);
    tests_failed++;

    while (1)
        sys_tyield();
}



/* ========================================================================
 * Monitor Task
 * ======================================================================== */

void monitor_task(void)
{
    umode_printf("\n");
    umode_printf("=================================================\n");
    umode_printf("  PMP Memory Isolation Test Suite\n");
    umode_printf("=================================================\n");
    umode_printf("Tests:\n");
    umode_printf("  [Test 1] Context Switch & Stack Integrity\n");
    umode_printf("  [Test 2] Kernel Protection\n");
    umode_printf("  [Test 3] Inter-Task Isolation\n");
    umode_printf("=================================================\n\n");

    /* Wait for Test 1 tasks to complete */
    int cycles = 0;
    while (tasks_completed < 3 && cycles < 200) {
        cycles++;
        for (int i = 0; i < 10; i++)
            sys_tyield();
    }

    /* Report Test 1 results */
    umode_printf("\n=== Test 1: Context Switch & Stack Integrity ===\n");
    umode_printf("Tasks: %d/3, Passed: %d, Failed: %d\n", tasks_completed,
                 tests_passed, tests_failed);

    if (tasks_completed == 3 && tests_passed == 3 && tests_failed == 0) {
        umode_printf("Status: PASS\n\n");
    } else {
        umode_printf("Status: FAIL\n\n");
    }

    /* Wait for Test 2 and 3 to complete */
    int failed_before = tests_failed;
    sys_tdelay(150);

    /* Verify Test 2/3 results - if tests_failed didn't increase, PMP worked */
    if (tests_failed == failed_before) {
        umode_printf("\nStatus: PASS\n");
    } else {
        umode_printf("\nStatus: FAIL\n");
    }

    /* Final summary */
    umode_printf("\n=================================================\n");
    if (tests_failed == 0 && tests_passed >= 3) {
        umode_printf("ALL PMP TESTS PASSED\n");
    } else {
        umode_printf("PMP TESTS FAILED: %d test(s) failed\n", tests_failed);
    }
    umode_printf("=================================================\n");

    while (1) {
        for (int i = 0; i < 50; i++)
            sys_tyield();
    }
}

/* ========================================================================
 * Application Entry Point
 * ======================================================================== */

int32_t app_main(void)
{
    /* Create Test 1 tasks - Context Switch & Stack Integrity */
    int32_t task_a = mo_task_spawn(task_a_integrity, 1024);
    int32_t task_b = mo_task_spawn(task_b_integrity, 1024);
    int32_t task_c = mo_task_spawn(task_c_integrity, 1024);
    int32_t monitor = mo_task_spawn(monitor_task, 1024);

    /* Test 2: Kernel Protection */
    int32_t kernel_test = mo_task_spawn(task_kernel_attack, 1024);

    /* Test 3: Inter-Task Isolation */
    int32_t cross_test = mo_task_spawn(task_cross_attack, 1024);

    if (task_a < 0 || task_b < 0 || task_c < 0 || monitor < 0 ||
        kernel_test < 0 || cross_test < 0) {
        printf("ERROR: Failed to create test tasks\n");
        return false;
    }

    return true; /* Enable preemptive scheduling */
}
