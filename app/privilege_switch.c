#include <linmo.h>

/* M-mode task: Continuously delays to test M-mode ecall context switch */
void mmode_task(void)
{
    int iteration = 0;
    while (1) {
        CRITICAL_ENTER();
        printf("[M-mode] iteration %d\n", iteration++);
        CRITICAL_LEAVE();
        mo_task_delay(2);
    }
}

/* U-mode task: Continuously delays to test U-mode syscall and kernel stack */
void umode_task(void)
{
    int iteration = 0;
    while (1) {
        umode_printf("[U-mode] iteration %d\n", iteration++);
        sys_tdelay(2);
    }
}

int32_t app_main(void)
{
    printf("[Kernel] Privilege Mode Switching Test: M-mode <-> U-mode\n");

    mo_task_spawn(mmode_task, DEFAULT_STACK_SIZE);
    mo_task_spawn_user(umode_task, DEFAULT_STACK_SIZE);

    return 1;
}
