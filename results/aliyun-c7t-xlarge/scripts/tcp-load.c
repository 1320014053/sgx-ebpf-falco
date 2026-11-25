#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t nanos(clockid_t clock_id) {
    struct timespec t;
    clock_gettime(clock_id, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static unsigned number(const char *arg, unsigned min, unsigned max) {
    char *end;
    errno = 0;
    unsigned long value = strtoul(arg, &end, 10);
    if (*arg < '0' || *arg > '9' || *end || errno || value < min || value > max) {
        fprintf(stderr, "invalid numeric argument: %s\n", arg);
        exit(2);
    }
    return (unsigned)value;
}

static int transfer(int fd, char data[64], int sending) {
    size_t pos = 0;
    while (pos < 64) {
        ssize_t n = sending ? send(fd, data + pos, 64 - pos, MSG_NOSIGNAL) :
                              recv(fd, data + pos, 64 - pos, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        pos += (size_t)n;
    }
    return 0;
}

// Only one client exchange is outstanding. A blocking accept loop avoids a
// worker handoff or epoll registration for each short connection.
static void *serve(void *arg) {
    int listener = *(int *)arg;
    for (;;) {
        int fd = accept(listener, NULL, NULL);
        if (fd < 0) {
            if (errno == EINVAL) break; // Linux shutdown on the listening socket.
            if (errno == EINTR || errno == ECONNABORTED) continue;
            perror("accept");
            shutdown(listener, SHUT_RDWR);
            break;
        }
        char data[64];
        if (!transfer(fd, data, 0)) transfer(fd, data, 1);
        close(fd);
    }
    return NULL;
}

// Typically about 10 packets: three for the handshake, two data segments,
// ACKs and the FIN exchange. Piggybacked ACKs/FINs can change the tap count.
static int exchange(const struct sockaddr_in *dest, unsigned index) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in source = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(0x7f010000u + index)};
    char data[64] = "falco-loopback";
    char echo[64];
    int failed = bind(fd, (const struct sockaddr *)&source, sizeof(source)) ||
                 connect(fd, (const struct sockaddr *)dest, sizeof(*dest)) ||
                 transfer(fd, data, 1) || transfer(fd, echo, 0) ||
                 memcmp(data, echo, sizeof(data));
    return close(fd) || failed;
}

int main(int argc, char **argv) {
    if (argc < 4 || (argc - 4) % 2) {
        fprintf(stderr, "usage: tcp-load RATE SECONDS OUT.json [--port P] [--sources N]\n");
        return 2;
    }
    unsigned rate = number(argv[1], 0, UINT_MAX);
    unsigned seconds = number(argv[2], 1, UINT_MAX);
    unsigned port = 18080, sources = 256;
    for (int i = 4; i < argc; i += 2) {
        if (!strcmp(argv[i], "--port")) port = number(argv[i + 1], 1, 65535);
        else if (!strcmp(argv[i], "--sources")) sources = number(argv[i + 1], 1, 65536);
        else return 2;
    }

    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(port),
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int listener = socket(AF_INET, SOCK_STREAM, 0), reuse = 1;
    if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
        bind(listener, (struct sockaddr *)&dest, sizeof(dest)) || listen(listener, SOMAXCONN)) {
        perror("echo listener");
        return 1;
    }
    pthread_t server;
    int err = pthread_create(&server, NULL, serve, &listener);
    if (err) {
        fprintf(stderr, "pthread_create: %s\n", strerror(err));
        return 1;
    }
    uint64_t start = nanos(CLOCK_MONOTONIC), cpu = nanos(CLOCK_PROCESS_CPUTIME_ID);
    uint64_t until = start + (uint64_t)seconds * 1000000000;
    unsigned long long attempts = 0, failed = 0;
    while (nanos(CLOCK_MONOTONIC) < until) {
        if (exchange(&dest, attempts % sources)) ++failed;
        ++attempts;
        if (rate) {
            uint64_t due = start + attempts / rate * 1000000000 + attempts % rate * 1000000000 / rate;
            while (nanos(CLOCK_MONOTONIC) < due) __asm__ __volatile__("pause");
        }
    }
    uint64_t end = nanos(CLOCK_MONOTONIC), end_cpu = nanos(CLOCK_PROCESS_CPUTIME_ID);
    shutdown(listener, SHUT_RDWR);
    pthread_join(server, NULL);
    close(listener);
    FILE *out = fopen(argv[3], "w");
    if (!out) { perror(argv[3]); return 1; }
    fprintf(out, "{\"connections\":%llu,\"failed\":%llu,\"start_ns\":%llu,\"wall_ns\":%llu,\"cpu_ns\":%llu,"
                 "\"target_conn_s\":%u,\"sources\":%u,\"port\":%u}\n",
            attempts - failed, failed, (unsigned long long)start, (unsigned long long)(end - start),
            (unsigned long long)(end_cpu - cpu), rate, sources, port);
    return fclose(out) != 0 || attempts == failed;
}
