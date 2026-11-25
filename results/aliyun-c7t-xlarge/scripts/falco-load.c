#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static uint64_t nanos(clockid_t clock_id) {
    struct timespec t;
    clock_gettime(clock_id, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static unsigned number(const char *arg) {
    char *end;
    errno = 0;
    unsigned long value = strtoul(arg, &end, 10);
    if (*arg < '0' || *arg > '9' || *end || errno || value > UINT_MAX) {
        fprintf(stderr, "invalid numeric argument: %s\n", arg);
        exit(2);
    }
    return (unsigned)value;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    unsigned rate = number(argv[1]);
    unsigned seconds = number(argv[2]);
    uint64_t start = nanos(CLOCK_MONOTONIC);
    uint64_t begin_cpu = nanos(CLOCK_PROCESS_CPUTIME_ID);
    uint64_t until = start + (uint64_t)seconds * 1000000000;
    unsigned long long pairs = 0;
    while (nanos(CLOCK_MONOTONIC) < until) {
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0 || close(fd)) return 1;
        ++pairs;
        if (rate) {
            uint64_t due = start + pairs/ rate * 1000000000 + pairs % rate * 1000000000 / rate;
            while (nanos(CLOCK_MONOTONIC) < due) __asm__ __volatile__("pause");
        }
    }
    uint64_t end = nanos(CLOCK_MONOTONIC), end_cpu = nanos(CLOCK_PROCESS_CPUTIME_ID);
    FILE *out = fopen(argv[3], "w");
    if (!out) return 1;
    fprintf(out,"{\"pairs\":%llu,\"start_ns\":%llu,\"wall_ns\":%llu,\"cpu_ns\":%llu,\"target_pairs_s\":%u}\n",
            pairs,(unsigned long long)start,(unsigned long long)(end-start),(unsigned long long)(end_cpu-begin_cpu),rate);
    return fclose(out) != 0;
}
