#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int check_connections(const char* port) {
    const unsigned targets[] = {2, 2, 3, 4};
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
        struct sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_port = htons(atoi(port)),
            .sin_addr.s_addr = htonl(0x7f000000U | targets[i]),
        };
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            return 1;
        }
        int result = connect(fd, (struct sockaddr*)&address, sizeof(address));
        int refused = result == -1 && errno == ECONNREFUSED;
        close(fd);
        if (!refused) {
            return 1;
        }
    }
    return 0;
}

static int waited(pid_t child) {
    int status;
    return child > 0 && waitpid(child, &status, 0) == child &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(int argc, char** argv) {
    if (argc == 3 && strcmp(argv[1], "--connect") == 0) {
        return check_connections(argv[2]);
    }
    if (argc == 2 && strcmp(argv[1], "--flood") == 0) {
        for (int i = 0; i < 200000; ++i) {
            int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (fd < 0 || close(fd) != 0) {
                return 1;
            }
        }
        return 0;
    }
    if (argc != 2) {
        return 2;
    }

    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    socklen_t size = sizeof(local);
    int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0 || bind(server, (struct sockaddr*)&local, size) != 0 ||
        listen(server, 1) != 0 || getsockname(server, (struct sockaddr*)&local, &size) != 0) {
        perror("loopback listener");
        return 1;
    }
    char port[6];
    snprintf(port, sizeof(port), "%u", (unsigned)ntohs(local.sin_port));

    pid_t child = fork();
    if (child == 0) {
        execl("/bin/bash", "bash", "-c", ": </dev/tcp/127.0.0.1/$1", "bash", port, NULL);
        _exit(1);
    }
    if (!waited(child)) {
        return 1;
    }
    child = fork();
    if (child == 0) {
        execl(argv[1], argv[1], "--connect", port, NULL);
        _exit(1);
    }
    int success = waited(child);
    close(server);
    return success ? 0 : 1;
}
