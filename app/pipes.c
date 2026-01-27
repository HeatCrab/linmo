#include <linmo.h>

pipe_t *pipe1, *pipe2, *pipe3;

char data1[128] = "hello from task 1!";
char data2[128] = "heya from task 2!";
char hello[64] = "hi!";

void task3(void)
{
    char data[128];
    uint16_t s;

    while (1) {
        memset(data, 0, sizeof(data));
        printf("Waiting data from task0... ");
        /* read pipe - read size must be less than buffer size */
        s = mo_pipe_read(pipe3, data, 127);
        printf("pipe 3 (%d): %s\n", s, data);
    }
}

void task2(void)
{
    while (1) {
        /* write pipe - write size must be less than buffer size */
        mo_pipe_write(pipe2, data2, strlen(data2));
    }
}

void task1(void)
{
    while (1) {
        /* write pipe - write size must be less than buffer size */
        mo_pipe_write(pipe1, data1, strlen(data1));
    }
}

void task0(void)
{
    char dat1[128]; /* data buffer 1 */
    char dat2[50];  /* data buffer 2 */
    uint16_t s;

    while (1) {
        /* read pipe - read size must be less than buffer size */
        memset(dat1, 0, sizeof(dat1));
        s = mo_pipe_read(pipe1, dat1, 127);
        printf("pipe 1 (%d): %s\n", s, dat1);
        memset(dat2, 0, sizeof(dat2));
        s = mo_pipe_read(pipe2, dat2, 10);
        printf("pipe 2 (%d): %s\n", s, dat2);

        mo_pipe_write(pipe3, hello, strlen(hello));
    }
}

int32_t app_main(void)
{
    mo_task_spawn(task0, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task1, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task2, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task3, DEFAULT_STACK_SIZE, TASK_MODE_M);

    pipe1 = mo_pipe_create(
        128); /* pipe buffer, 128 bytes (allocated on the heap) */
    pipe2 = mo_pipe_create(64); /* pipe buffer, 64 bytes */
    pipe3 = mo_pipe_create(64); /* pipe buffer, 64 bytes */

    /* preemptive mode */
    return 1;
}
