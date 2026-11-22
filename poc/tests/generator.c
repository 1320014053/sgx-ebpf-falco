#define _GNU_SOURCE
#include "event.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static poc_u64 now_ns(clockid_t clock)
{
    struct timespec ts;
    clock_gettime(clock, &ts);
    return (poc_u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: generator COUNT INTERVAL_US START_FD REPORT_FD SECONDS\n");
        return 2;
    }
    poc_u64 count = strtoull(argv[1], NULL, 10);
    poc_u64 interval = strtoull(argv[2], NULL, 10);
    int start_fd = atoi(argv[3]), report_fd = atoi(argv[4]);
    poc_u64 duration = strtoull(argv[5], NULL, 10) * 1000000000ULL;
    prctl(PR_SET_NAME, "poc-generator", 0, 0, 0);
    char start;
    if (read(start_fd, &start, 1) != 1)
        return 2;
    close(start_fd);
    struct poc_generator_report report = {0};
    poc_u64 start_wall = now_ns(CLOCK_MONOTONIC);
    poc_u64 start_cpu = now_ns(CLOCK_PROCESS_CPUTIME_ID);
    struct timespec delay = {(time_t)(interval / 1000000), (long)(interval % 1000000) * 1000};
    while (duration ? now_ns(CLOCK_MONOTONIC) - start_wall < duration : report.calls < count) {
        syscall(SYS_getpid);
        ++report.calls;
        if (interval) {
            struct timespec remaining = delay;
            while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
        }
    }
    report.wall_ns = now_ns(CLOCK_MONOTONIC) - start_wall;
    report.cpu_ns = now_ns(CLOCK_PROCESS_CPUTIME_ID) - start_cpu;
    return write(report_fd, &report, sizeof(report)) == sizeof(report) ? 0 : 2;
}
