#include <linmo.h>

#define N 10

static sem_t *empty, *full, *mutex;
static int32_t in = 0, out = 0, buffer[N];

static void producer(void)
{
    int32_t item;

    for (;;) {
        item = random();
        mo_sem_wait(empty);
        mo_sem_wait(mutex);
        buffer[in] = item;
        printf("\nproducer %d putting at %ld (%ld)", mo_task_id(), in, item);
        in = (in + 1) % N;
        mo_sem_signal(mutex);
        mo_sem_signal(full);
    }
}

static void consumer(void)
{
    int32_t item;

    for (;;) {
        mo_sem_wait(full);
        mo_sem_wait(mutex);
        item = buffer[out];
        printf("\nconsumer %d getting from %ld (%ld)", mo_task_id(), out, item);
        out = (out + 1) % N;
        mo_sem_signal(mutex);
        mo_sem_signal(empty);
    }
}

int32_t app_main(void)
{
    mo_task_spawn(producer, DEFAULT_STACK_SIZE);
    mo_task_spawn(consumer, DEFAULT_STACK_SIZE);
    mo_task_spawn(consumer, DEFAULT_STACK_SIZE);

    empty = mo_sem_create(3, N);
    full = mo_sem_create(3, 0);
    mutex = mo_sem_create(3, 1);

    return 1;
}
