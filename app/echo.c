#include <linmo.h>

#define PIPE_CAP 32 /* bytes */
#define READ_BUF_SIZE PIPE_CAP

static pipe_t *pipe;

void task1(void)
{
    char buf[READ_BUF_SIZE];

    while (1) {
        memset(buf, 0, sizeof(buf));
        printf("[task B] Waiting for message...\n");

        /* Waits for at least one byte, but yields to avoid hogging the CPU. */
        while (mo_pipe_size(pipe) == 0)
            mo_task_yield();

        /* Read only what fits in the stack buffer. */
        size_t n = mo_pipe_size(pipe);
        if (n > READ_BUF_SIZE - 1)
            n = READ_BUF_SIZE - 1;

        memset(buf, 0, sizeof(buf));
        mo_pipe_read(pipe, buf, n);
        printf("[task B] Message: %s\n", buf);
    }
}

void task0(void)
{
    char buf[READ_BUF_SIZE];

    while (1) {
        printf("[task A] Type a message: \n");

        /* Safe line-read: stop at newline or when the buffer is full. */
        size_t i = 0;
        int ch;
        while (i < sizeof(buf) - 1 && (ch = getchar()) != '\n' && ch != '\r')
            buf[i++] = (char) ch;
        buf[i] = '\0';

        /* Clamp to pipe capacity. */
        if (i > PIPE_CAP - 1)
            i = PIPE_CAP - 1;

        /* Write at most PIPE_CAP-1 bytes to avoid overflow in the pipe. */
        mo_pipe_write(pipe, buf, i);
    }
}

int32_t app_main(void)
{
    pipe = mo_pipe_create(PIPE_CAP);

    mo_task_spawn(task0, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task1, DEFAULT_STACK_SIZE, TASK_MODE_M);

    /* preemptive mode */
    return 1;
}
