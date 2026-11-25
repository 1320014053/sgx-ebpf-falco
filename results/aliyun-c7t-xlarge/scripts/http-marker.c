#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) exit(1);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

/* Run as nobody, with basename httpd (the parent matched by the official rule). */
int main(int argc, char **argv) {
    if (argc != 4 && !(argc == 5 && !strcmp(argv[4], "--gate"))) {
        fprintf(stderr, "usage: httpd LABEL_PREFIX INTERVAL_SECONDS DURATION_SECONDS [--gate]\n");
        return 2;
    }
    int64_t interval = (int64_t)(strtod(argv[2], NULL) * 1e9);
    int64_t duration = (int64_t)(strtod(argv[3], NULL) * 1e9);
    if (interval <= 0 || duration <= 0) return 2;
    /* The harness releases the marker and the workload together. */
    if (argc == 5 && getchar() == EOF) return 1;
    int64_t start = now_ns(), end = start + duration;
    for (int64_t i = 0; start + i * interval < end; ++i) {
        int64_t due = start + i * interval;
        struct timespec ts = {due / 1000000000, due % 1000000000};
        int rc;
        do rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL); while (rc == EINTR);
        if (rc) return 1;
        if (now_ns() >= end) break;
        char label[128];
        int len = snprintf(label, sizeof(label), "%s_%lld", argv[1], (long long)i);
        if (len < 0 || (size_t)len >= sizeof(label)) return 2;
        pid_t child = fork();
        if (child < 0) return 1;
        if (!child) {
            int64_t trigger = now_ns();
            if (trigger >= end) _exit(0);
            if (dprintf(STDOUT_FILENO, "%s\t%lld\n", label, (long long)trigger) < 0) _exit(1);
            execl("/bin/bash", "bash", "-c", ":", label, (char *)NULL);
            _exit(127);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
        /* Missed slots stay empty instead of producing a catch-up burst. */
        int64_t elapsed_slots = (now_ns() - start) / interval;
        if (elapsed_slots > i) i = elapsed_slots;
    }
    return 0;
}
