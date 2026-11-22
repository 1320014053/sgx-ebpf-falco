#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Keep the real producer close to the measured consumer. Each progress sample is 10,000 events. */
static int wait_for_progress(FILE *log, unsigned expected) {
    char line[8192];
    struct timespec delay = {0, 100000000};
    for (unsigned i = 0; i < 6000; ++i) {
        while (fgets(line, sizeof(line), log)) {
            if (strncmp(line, "RZRET ", 6)) continue;
            char *seen = strstr(line, "\"seen\":");
            if (seen && strtoul(seen + 7, NULL, 10) >= expected) return 0;
        }
        clearerr(log);
        nanosleep(&delay, NULL);
    }
    return 1;
}

static int access_file(const char *path) {
    int fd = open(path, O_RDONLY);
    return fd < 0 || close(fd) != 0;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    char dir[] = "/root/rz-retention-XXXXXX", path[160];
    if (!mkdtemp(dir)) return 1;
    FILE *log = fopen(argv[3], "r");
    if (!log) return 1;
    unsigned events = (unsigned)strtoul(argv[2], NULL, 10);
    if (!strcmp(argv[1], "repeat")) {
        snprintf(path, sizeof(path), "%s/repeat", dir);
        int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0) return 1;
        for (unsigned i = 1; i <= events; ++i) {
            if (pwrite(fd, "x", 1, 0) != 1) return 1;
            if (i % 10000 == 0 && (access_file(path) || wait_for_progress(log, i))) return 1;
        }
        if (close(fd) || unlink(path)) return 1;
    } else if (!strcmp(argv[1], "churn")) {
        for (unsigned i = 1; i <= events/4; ++i) {
            snprintf(path, sizeof(path), "%s/file-%u", dir, i);
            pid_t child = fork();
            if (child < 0) return 1;
            if (!child) {
                int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
                if (fd < 0 || write(fd, "x", 1) != 1 || close(fd)) _exit(1);
                if (i % 2500 == 0 && access_file(path)) _exit(1);
                _exit(unlink(path) != 0);
            }
            int status = 0;
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
            if (i % 2500 == 0 && wait_for_progress(log, i*4)) return 1;
        }
    } else return 2;
    fclose(log);
    return rmdir(dir) != 0;
}
