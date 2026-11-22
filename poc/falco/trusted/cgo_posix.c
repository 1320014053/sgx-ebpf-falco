#include <limits.h>
#include <openenclave/bits/fs.h>
#include <openenclave/enclave.h>
#include <openenclave/ert_args.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/select.h>

int __vasprintf_chk(char **out, int flag, const char *format, va_list args);
int _strerror_r(int error, char *buffer, size_t size);

int __xpg_strerror_r(int error, char *buffer, size_t size) {
    return _strerror_r(error, buffer, size);
}

int __asprintf_chk(char **out, int flag, const char *format, ...) {
    va_list args;
    va_start(args, format);
    const int result = __vasprintf_chk(out, flag, format, args);
    va_end(args);
    return result;
}

long __fdelt_chk(long fd) {
    if (fd < 0 || fd >= FD_SETSIZE) {
        abort();
    }
    return fd / (sizeof(long) * CHAR_BIT);
}

ert_args_t ert_get_args(void) {
    static const char *const argv[] = {"falco-sgx"};
    return (ert_args_t){.argc = 1, .argv = argv};
}

// The linked Go runtime and Podman constructor initialize before the first ECALL.
__attribute__((constructor(101))) static void initialize_container_posix(void) {
    if (oe_load_module_host_epoll() != OE_OK || oe_load_module_host_file_system() != OE_OK ||
        mount("/proc/self", "/proc/self", OE_HOST_FILE_SYSTEM, MS_RDONLY, NULL) != 0) {
        abort();
    }
}
