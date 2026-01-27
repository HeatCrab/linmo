#include <linmo.h>

static mq_t *mq1, *mq2, *mq3, *mq4;

/* Task 1: Sends messages to task 2 and task 3.
 * It waits for a signal from mq1 before starting its processing loop.
 */
void task1(void)
{
    int val = 0;          /* Counter for messages sent. */
    message_t msg1, msg2; /* Reusable message buffers for enqueuing. */
    char str[50];         /* Buffer for string messages. */
    message_t *pmsg;      /* Pointer to the message being processed. */

    while (1) {
        /* Wait for a signal from mq1. This ensures task1 starts processing
         * only after the system has initialized and provided the initial
         * signal. Task 4 is responsible for re-enqueuing into mq1 to keep the
         * cycle going.
         */
        while (mo_mq_items(mq1) == 0)
            mo_task_yield(); /* Yield the CPU to allow other tasks to run. */

        printf("task 1 enters...\n");

        /* Dequeue the signal from mq1. We don't need the content, just the
         * event. */
        if (mo_mq_items(mq1))
            mo_mq_dequeue(mq1); /* Consume the signal message. */

        /* Prepare and enqueue first message (integer payload) for task 2. */
        pmsg = &msg1;
        pmsg->payload = (void *) (size_t) val; /* Store the integer value. */
        mo_mq_enqueue(mq2, pmsg);

        /* Prepare and enqueue second message (string payload) for task 3. */
        pmsg = &msg2;

        snprintf(str, sizeof(str), "hello %d from t1...", val++);
        /* Enqueue the string. The payload points to the local 'str' buffer. */
        pmsg->payload = str;          /* Point payload to the string buffer. */
        pmsg->size = strlen(str) + 1; /* Store string size. */
        pmsg->type = 0;               /* Default message type. */
        mo_mq_enqueue(mq3, pmsg);

        mo_task_yield(); /* Yield after sending messages. */
    }
}

/* Task 2: Receives integer messages from task 1 via mq2 and sends them to task
 * 4 via mq4.
 */
void task2(void)
{
    message_t msg1; /* Reusable message buffer for enqueuing to mq4. */
    int val = 200;  /* Counter for messages sent. */
    message_t *msg; /* Pointer to the message being processed. */

    while (1) {
        /* Check if there are messages in mq2. */
        if (mo_mq_items(mq2) > 0) {
            printf("task 2 enters...\n");

            /* Dequeue the integer message from mq2. */
            msg = mo_mq_dequeue(mq2);
            /* Print the received integer payload. */
            printf("message %d\n", (int) (size_t) msg->payload);

            /* Prepare a new message for task 4. */
            msg = &msg1;
            msg->payload =
                (void *) (size_t) val++; /* Store the integer value. */
            mo_mq_enqueue(mq4, msg);     /* Enqueue the message for task 4. */
        }

        mo_task_yield(); /* Yield the CPU. */
    }
}

/* Task 3: Receives string messages from task 1 via mq3 and sends them to task 4
 * via mq4.
 */
void task3(void)
{
    message_t msg1; /* Reusable message buffer for enqueuing to mq4. */
    int val = 300;  /* Counter for messages sent. */
    message_t *msg; /* Pointer to the message being processed. */

    while (1) {
        /* Check if there are messages in mq3. */
        if (mo_mq_items(mq3) > 0) {
            printf("task 3 enters...\n");

            /* Dequeue the string message from mq3. */
            msg = mo_mq_dequeue(mq3);
            /* Print the received string payload. */
            printf("message: %s\n", (char *) msg->payload);

            /* Prepare a new message for task 4. */
            msg = &msg1;
            msg->payload = (void *) (size_t) val++;
            mo_mq_enqueue(mq4, msg); /* Enqueue the message for task 4. */
        }

        mo_task_yield(); /* Yield the CPU. */
    }
}

/* Task 4: Receives integer messages from task 2 and task 3 via mq4.
 * It processes two messages at a time and then sends a signal back to task 1
 * via mq1.
 */
void task4(void)
{
    message_t *msg1, *msg2;      /* Pointers to messages dequeued from mq4. */
    message_t dummy_msg_for_mq1; /* A dummy message to signal task1 via mq1. */

    while (1) {
        /* Check if there are at least two messages in mq4.
         * This ensures we have received messages from both task 2 and task 3.
         */
        if (mo_mq_items(mq4) >= 2) {
            printf("task 4 enters...\n");

            /* Dequeue the two messages from mq4. */
            msg1 = mo_mq_dequeue(mq4);
            msg2 = mo_mq_dequeue(mq4);

            /* Print the payloads of the received messages. */
            printf("messages: %d %d\n", (int) (size_t) msg1->payload,
                   (int) (size_t) msg2->payload);

            /* Simulate some work or delay. */
            delay_ms(100);

            /* Enqueue a dummy message into mq1 to signal task1 to proceed.
             * This is a crucial synchronization step to keep the cycle running.
             */
            mo_mq_enqueue(mq1, &dummy_msg_for_mq1);
        }

        mo_task_yield(); /* Yield the CPU. */
    }
}

/* Idle Task: Runs when no other task is ready to execute.
 * It simply waits for interrupts to conserve power and allow the scheduler
 * to switch tasks when events occur.
 */
static void idle(void)
{
    while (1)
        mo_task_wfi();
}

/* Application main entry point.
 * Sets up tasks and message queues for the message queue demonstration.
 * Returns 1 to indicate preemptive scheduling mode.
 */
int32_t app_main(void)
{
    /* Spawn all the tasks. The idle task (task 0) is typically spawned first
     * to ensure it's available when other tasks yield or block.
     */
    mo_task_spawn(idle, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task1, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task2, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task3, DEFAULT_STACK_SIZE, TASK_MODE_M);
    mo_task_spawn(task4, DEFAULT_STACK_SIZE, TASK_MODE_M);

    /* Create the message queues with a capacity of 8 items each. */
    mq1 = mo_mq_create(8); /* Queue for signaling task1. */
    mq2 = mo_mq_create(8); /* Queue for task1 -> task2. */
    mq3 = mo_mq_create(8); /* Queue for task1 -> task3. */
    mq4 = mo_mq_create(8); /* Queue for task2/task3 -> task4. */

    /* Provide the initial signal to mq1 to start task1's main loop. */
    message_t initial_signal;
    mo_mq_enqueue(mq1, &initial_signal);

    /* enable preemptive scheduling mode. */
    return 1;
}
