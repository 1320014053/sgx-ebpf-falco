#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    pid_t child = fork();
    if (child == 0) {
        struct timespec start;
        clock_gettime(CLOCK_MONOTONIC, &start);
        dprintf(STDOUT_FILENO, "%s %lld\n", argv[1], (long long)start.tv_sec * 1000000000 + start.tv_nsec);
        execl("/bin/bash", "bash", "-c", ":", argv[1], (char *)NULL);
        _exit(127);
    }
    int status;
    return child < 0 || waitpid(child,&status,0) != child || !WIFEXITED(status) || WEXITSTATUS(status);
}
