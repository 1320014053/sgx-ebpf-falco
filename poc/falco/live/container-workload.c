#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int redirect_loopback(void) {
    const int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    const int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    socklen_t size = sizeof(address);
    if (server < 0 || client < 0 ||
        bind(server, (struct sockaddr*)&address, size) != 0 ||
        listen(server, 1) != 0 ||
        getsockname(server, (struct sockaddr*)&address, &size) != 0 ||
        connect(client, (struct sockaddr*)&address, size) != 0 ||
        dup2(client, STDIN_FILENO) < 0) {
        return 1;
    }
    close(client);
    close(server);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 2 && strcmp(argv[1], "privileged") == 0) {
        // Exercise the syscall rule with an invalid descriptor and no module bytes.
        if (syscall(SYS_finit_module, -1, "", 0) != -1 ||
            (errno != EBADF && errno != EPERM)) {
            return 1;
        }
        const int fixture = open("/tmp/release_agent", O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fixture < 0 || close(fixture) != 0) {
            return 1;
        }
        execl("/bin/debugfs", "debugfs", "-V", NULL);
    } else {
        const int packet = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (packet < 0 || close(packet) != 0 || redirect_loopback() != 0) {
            return 1;
        }
        // /bin/nc is a no-op fixture that exercises the rule's process and argument fields.
        execl("/bin/nc", "nc", "-e", "fixture-only", NULL);
    }
    perror("container workload");
    return 1;
}
