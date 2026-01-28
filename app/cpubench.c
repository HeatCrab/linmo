/* CPU Integer Benchmark.
 *
 * Purpose:
 * - Evaluate integer ALU throughput and pipeline utilization.
 * - Generate realistic memory access patterns to stress D-cache.
 * - Provide a microbenchmark suitable for runtime calibration or profiling.
 */

#include <linmo.h>

#define LOOPS 500000
#define OPS_PER_LOOP 500

static int32_t memory_block[256];

static inline int32_t compute(int32_t x, int32_t y)
{
    x = (x << 3) - (y >> 1);
    y = (y ^ x) + (x >> 2);
    return (x ^ y) + (x * 3 - y);
}

void idle(void)
{
    while (1)
        mo_task_wfi();
}

int32_t app_main(void)
{
    printf("CPU integer benchmark\n");
    printf("loops=%d, ops/loop=%d\n", LOOPS, OPS_PER_LOOP);

    for (int i = 0; i < 256; ++i)
        memory_block[i] = (i * 19) ^ 0x5a5a5a5a;

    volatile int32_t a = 1, b = 7, c = 0;

    uint32_t start = mo_uptime();

    for (int32_t i = 0; i < LOOPS; ++i) {
        int32_t idx = (a ^ b ^ c ^ i) & 0xff;
        int32_t val = memory_block[idx];

        if ((val ^ i) & 8)
            a += compute(val, i);
        else
            a -= compute(i, val);

        if (a & 0x10)
            b ^= val + i;
        else
            b += a ^ (val >> 3);

        c += compute(a, b);
        memory_block[(idx + 1) & 0xff] = a ^ b ^ c;
    }

    uint32_t end = mo_uptime();
    uint32_t elapsed = end - start;

    printf("Result: a=%d, b=%d, c=%d\n", a, b, c);
    printf("Elapsed time: %lu.%03lus\n", elapsed / 1000, elapsed % 1000);

    mo_task_spawn(idle, DEFAULT_STACK_SIZE);
    return 1;
}
