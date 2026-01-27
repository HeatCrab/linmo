#include <linmo.h>

void timer1(void)
{
    while (1) {
        printf("T%d, TIMER 1\n", mo_task_id());
        mo_task_delay(100);
    }
}

void timer2(void)
{
    int i = 0;

    while (1) {
        printf("T%d, TIMER 2\n", mo_task_id());
        mo_task_delay(300);
        if (++i == 10) {
            printf("killing task 3...\n");
            mo_task_cancel(2);
        }
    }
}

void timer3(void)
{
    while (1) {
        printf("T%d, TIMER 3\n", mo_task_id());
        mo_task_delay(50);
    }
}

void idle(void)
{
    while (1) {
    }
}

int32_t app_main(void)
{
    mo_task_spawn(timer1, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(timer2, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(timer3, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(idle, DEFAULT_STACK_SIZE, TASK_MODE_M);

    /* preemptive mode */
    return 1;
}
