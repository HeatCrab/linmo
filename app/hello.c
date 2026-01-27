#include <linmo.h>

void task2(void)
{
    int32_t cnt = 300000;
    uint32_t secs, msecs, time;

    while (1) {
        time = mo_uptime();
        secs = time / 1000;
        msecs = time - secs * 1000;
        printf("[task %d %ld - sys uptime: %ld.%03lds]\n", mo_task_id(), cnt++,
               secs, msecs);
        mo_task_wfi();
    }
}

void task1(void)
{
    int32_t cnt = 200000;

    while (1) {
        printf("[task %d %ld]\n", mo_task_id(), cnt++);
        mo_task_wfi();
    }
}

void task0(void)
{
    int32_t cnt = 100000;

    while (1) {
        printf("[task %d %ld]\n", mo_task_id(), cnt++);
        mo_task_wfi();
    }
}

int32_t app_main(void)
{
    mo_task_spawn(task0, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task1, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task2, DEFAULT_STACK_SIZE, TASK_MODE_M);

    mo_task_priority(2, TASK_PRIO_LOW);

    printf("task0 has id %d\n", mo_task_idref(task0));
    printf("task1 has id %d\n", mo_task_idref(task1));
    printf("task2 has id %d\n", mo_task_idref(task2));

    /* preemptive mode */
    return 1;
}
