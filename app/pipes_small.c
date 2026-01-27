#include <linmo.h>

pipe_t *pipe1, *pipe2;

void task2(void)
{
    char data2[64];

    while (1) {
        snprintf(data2, sizeof(data2), "Hello from task 2!");
        /* write pipe - write size must be less than buffer size */
        mo_pipe_write(pipe2, data2, strlen((char *) data2));
    }
}

void task1(void)
{
    char data1[64];

    while (1) {
        snprintf(data1, sizeof(data1), "Hello from task 1!");
        /* write pipe - write size must be less than buffer size */
        mo_pipe_write(pipe1, data1, strlen((char *) data1));
    }
}

void task0(void)
{
    char data[64];
    uint16_t s;

    while (1) {
        /* read pipe - read size must be less than buffer size */
        memset(data, 0, sizeof(data));
        s = mo_pipe_read(pipe1, data, 63);
        printf("pipe (%d): %s\n", s, data);
        memset(data, 0, sizeof(data));
        s = mo_pipe_read(pipe2, data, 50);
        printf("pipe (%d): %s\n", s, data);
    }
}

int32_t app_main(void)
{
    mo_task_spawn(task0, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task1, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task2, DEFAULT_STACK_SIZE, TASK_MODE_M);

    pipe1 = mo_pipe_create(
        64); /* pipe buffer, 64 bytes (allocated from the heap) */
    pipe2 = mo_pipe_create(
        32); /* pipe buffer, 32 bytes (allocated from the heap) */

    /* preemptive mode */
    return 1;
}
