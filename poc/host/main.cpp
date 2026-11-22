#include "event_logic.h"
#include "Enclave_u.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sgx_urts.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <cstdio>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>

static uint64_t now_ns(clockid_t clock = CLOCK_MONOTONIC)
{
    timespec ts;
    clock_gettime(clock, &ts);
    return uint64_t(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}

static void require(bool ok, const char *message)
{
    if (!ok)
        throw std::runtime_error(message);
}

static void sgx_ok(sgx_status_t status)
{
    if (status != SGX_SUCCESS) {
        char message[80];
        snprintf(message, sizeof(message), "SGX SDK error: 0x%08x", status);
        throw std::runtime_error(message);
    }
}

struct Resources {
    bpf_object *object = nullptr;
    bpf_link *link = nullptr;
    ring_buffer *reader = nullptr;
    sgx_enclave_id_t enclave = 0;
    void *consumer = MAP_FAILED;
    void *producer = MAP_FAILED;
    poc_control *control = nullptr;
    size_t page = 4096;
    ~Resources()
    {
        if (link) bpf_link__destroy(link);
        ring_buffer__free(reader);
        if (enclave) sgx_destroy_enclave(enclave);
        if (consumer != MAP_FAILED) munmap(consumer, page);
        if (producer != MAP_FAILED) munmap(producer, page + 2 * POC_RING_BYTES);
        if (control) munmap(control, page);
        bpf_object__close(object);
    }
};

struct Callback {
    std::string mode;
    uint32_t target;
    sgx_enclave_id_t enclave;
    poc_stats stats = {};
    poc_batch batch = {};
    uint64_t data_ecalls = 0;
    uint64_t sdk_input_bytes = 0;
    uint64_t host_pack_bytes = 0;
    uint64_t first_batch_ns = 0;
    uint64_t batch_events = 0;
    uint64_t batches = 0;
};

static int flush_batch(Callback *context)
{
    if (!context->batch.count)
        return 0;
    int result = 0;
    sgx_status_t status = ecall_batch(context->enclave, &result, &context->batch);
    ++context->data_ecalls;
    context->sdk_input_bytes += sizeof(poc_batch);
    context->batch_events += context->batch.count;
    ++context->batches;
    context->batch.count = 0;
    return status == SGX_SUCCESS && result == 0 ? 0 : -EIO;
}

static int on_event(void *opaque, void *data, size_t bytes)
{
    Callback *context = static_cast<Callback *>(opaque);
    if (bytes != sizeof(poc_event)) {
        ++context->stats.format_rejected;
        return -EINVAL;
    }
    if (context->mode == "host") {
        poc_process_event(static_cast<const poc_event *>(data), context->target, &context->stats);
        return 0;
    }
    if (context->mode == "ecall") {
        ++context->data_ecalls;
        context->sdk_input_bytes += sizeof(poc_event);
        return ecall_event(context->enclave, static_cast<const poc_event *>(data)) == SGX_SUCCESS ? 0 : -EIO;
    }
    if (!context->batch.count)
        context->first_batch_ns = now_ns();
    memcpy(&context->batch.events[context->batch.count++], data, bytes);
    context->host_pack_bytes += bytes;
    return context->batch.count == POC_BATCH_MAX ? flush_batch(context) : 0;
}

static uint64_t number(const char *value)
{
    char *end;
    errno = 0;
    unsigned long long result = strtoull(value, &end, 10);
    require(*value && *value != '-' && !*end && !errno, "invalid numeric argument");
    return result;
}

static int run(int argc, char **argv)
{
    std::string mode = "direct";
    uint64_t count = 10000, interval = 1000, seconds = 0, pause_ms = 0;
    bool allow_drops = false;
    const option options[] = {
        {"mode", required_argument, nullptr, 'm'},
        {"count", required_argument, nullptr, 'n'},
        {"interval-us", required_argument, nullptr, 'i'},
        {"seconds", required_argument, nullptr, 's'},
        {"pause-ms", required_argument, nullptr, 'p'},
        {"allow-drops", no_argument, nullptr, 'd'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };
    for (int opt; (opt = getopt_long(argc, argv, "", options, nullptr)) != -1;) {
        switch (opt) {
        case 'm': mode = optarg; break;
        case 'n': count = number(optarg); break;
        case 'i': interval = number(optarg); break;
        case 's': seconds = number(optarg); break;
        case 'p': pause_ms = number(optarg); break;
        case 'd': allow_drops = true; break;
        case 'h':
            puts("poc --mode baseline|host|ecall|batch|step|direct [--count 10000] [--interval-us 1000] [--seconds 60] [--pause-ms 200] [--allow-drops]");
            return 0;
        default: return 2;
        }
    }
    require(optind == argc, "unexpected positional argument");
    require(mode == "baseline" || mode == "host" || mode == "ecall" || mode == "batch" || mode == "step" || mode == "direct", "unknown mode");
    require((count || seconds) && seconds <= 86400 && interval <= 10000000 && pause_ms <= 60000, "arguments exceed experiment limits");
    require(mode == "baseline" || geteuid() == 0, "run as root to load and attach eBPF");
    char executable[4096];
    ssize_t path_bytes = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    require(path_bytes > 0, "cannot find executable path");
    executable[path_bytes] = 0;
    std::string directory(executable);
    directory.resize(directory.find_last_of('/'));

    int start_pipe[2], report_pipe[2];
    require(pipe(start_pipe) == 0 && pipe(report_pipe) == 0, "pipe failed");
    std::string count_arg = std::to_string(count), interval_arg = std::to_string(interval);
    std::string ready_arg = std::to_string(start_pipe[0]), report_arg = std::to_string(report_pipe[1]);
    std::string seconds_arg = std::to_string(seconds), generator = directory + "/generator";
    pid_t child = fork();
    require(child >= 0, "fork failed");
    if (!child) {
        close(start_pipe[1]);
        close(report_pipe[0]);
        execl(generator.c_str(), generator.c_str(), count_arg.c_str(), interval_arg.c_str(), ready_arg.c_str(), report_arg.c_str(), seconds_arg.c_str(), nullptr);
        _exit(127);
    }
    close(start_pipe[0]);
    close(report_pipe[1]);
    Resources resources;
    resources.page = sysconf(_SC_PAGESIZE);
    require(resources.page == 4096, "this x86-64 POC expects 4 KiB system pages");
    resources.control = static_cast<poc_control *>(mmap(nullptr, resources.page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    require(resources.control != MAP_FAILED, "control mmap failed");
    Callback context;
    context.mode = mode;
    context.target = child;
    int counters_fd = -1;
    uint64_t setup_ecalls = 0, final_ecalls = 0;
    bool direct = mode == "direct" || mode == "step";
    bool enclave_mode = direct || mode == "ecall" || mode == "batch";
    if (mode != "baseline") {
        rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
        setrlimit(RLIMIT_MEMLOCK, &limit);
        resources.object = bpf_object__open_file((directory + "/probe.bpf.o").c_str(), nullptr);
        long error = libbpf_get_error(resources.object);
        if (error) resources.object = nullptr;
        require(resources.object, "opening BPF object failed");
        require(bpf_object__load(resources.object) == 0, "loading BPF probe failed");
        int config_fd = bpf_object__find_map_fd_by_name(resources.object, "config");
        counters_fd = bpf_object__find_map_fd_by_name(resources.object, "counters");
        int ring_fd = bpf_object__find_map_fd_by_name(resources.object, "events");
        uint32_t key = 0;
        poc_probe_config config = {static_cast<uint32_t>(child)};
        require(config_fd >= 0 && counters_fd >= 0 && ring_fd >= 0, "missing BPF map");
        require(bpf_map_update_elem(config_fd, &key, &config, BPF_ANY) == 0, "setting target TGID failed");
        bpf_program *program = bpf_object__find_program_by_name(resources.object, "on_getpid");
        require(program, "missing BPF program");
        resources.link = bpf_program__attach_tracepoint(program, "syscalls", "sys_enter_getpid");
        error = libbpf_get_error(resources.link);
        if (error) resources.link = nullptr;
        require(resources.link, "attaching sys_enter_getpid failed");
        if (enclave_mode) {
            sgx_ok(sgx_create_enclave((directory + "/enclave.signed.so").c_str(), SGX_DEBUG_FLAG, nullptr, nullptr, &resources.enclave, nullptr));
            context.enclave = resources.enclave;
            sgx_ok(ecall_config(resources.enclave, child));
            ++setup_ecalls;
        }
        if (direct) {
            resources.consumer = mmap(nullptr, resources.page, PROT_READ | PROT_WRITE, MAP_SHARED, ring_fd, 0);
            require(resources.consumer != MAP_FAILED, "consumer mmap failed");
            resources.producer = mmap(nullptr, resources.page + 2 * POC_RING_BYTES, PROT_READ, MAP_SHARED, ring_fd, resources.page);
            require(resources.producer != MAP_FAILED, "producer mmap failed");
            poc_ring_desc desc = {
                reinterpret_cast<uint64_t>(resources.consumer), reinterpret_cast<uint64_t>(resources.producer),
                reinterpret_cast<uint64_t>(resources.control), resources.page,
                resources.page + 2 * POC_RING_BYTES, resources.page, resources.page, POC_RING_BYTES
            };
            int result;
            sgx_ok(ecall_register(resources.enclave, &result, &desc));
            ++setup_ecalls;
            require(result == 0, "enclave rejected ring descriptor");
        } else {
            resources.reader = ring_buffer__new(ring_fd, on_event, &context, nullptr);
            require(resources.reader, "libbpf ring reader failed");
        }
    }
    int worker_result = 0;
    uint64_t worker_cpu_ns = 0, worker_end_ns = 0;
    uint64_t start_cpu = now_ns(CLOCK_PROCESS_CPUTIME_ID);
    uint64_t start_wall = now_ns();
    std::thread worker;
    if (mode != "baseline") {
        worker = std::thread([&]() {
            uint64_t cpu_start = now_ns(CLOCK_THREAD_CPUTIME_ID);
            try {
                if (pause_ms)
                    std::this_thread::sleep_for(std::chrono::milliseconds(pause_ms));
                if (mode == "direct") {
                    ++context.data_ecalls;
                    sgx_ok(ecall_run(resources.enclave, &worker_result, &context.stats));
                } else if (mode == "step") {
                    for (;;) {
                        bool stopping = __atomic_load_n(&resources.control->stop, __ATOMIC_ACQUIRE);
                        int result;
                        ++context.data_ecalls;
                        sgx_ok(ecall_step(resources.enclave, &result, &context.stats));
                        if (result < 0) { worker_result = result; break; }
                        if (stopping && result == 0)
                            break;
                        if (result == 0) __asm__ __volatile__("pause");
                    }
                } else {
                    for (;;) {
                        bool stopping = __atomic_load_n(&resources.control->stop, __ATOMIC_ACQUIRE);
                        int consumed = ring_buffer__consume(resources.reader);
                        if (consumed < 0) { worker_result = consumed; break; }
                        if (mode == "batch" && context.batch.count &&
                            (stopping || now_ns() - context.first_batch_ns >= 100000)) {
                            worker_result = flush_batch(&context);
                            if (worker_result) break;
                        }
                        if (stopping && consumed == 0) break;
                        if (consumed == 0)
                            std::this_thread::sleep_for(std::chrono::microseconds(50));
                    }
                    if (mode == "ecall" || mode == "batch") {
                        sgx_ok(ecall_stats(resources.enclave, &context.stats));
                        ++final_ecalls;
                    }
                }
            } catch (const std::exception &error) {
                fprintf(stderr, "consumer: %s\n", error.what());
                worker_result = -EIO;
            }
            worker_cpu_ns = now_ns(CLOCK_THREAD_CPUTIME_ID) - cpu_start;
            worker_end_ns = now_ns();
        });
    }
    signal(SIGPIPE, SIG_IGN);
    bool released = write(start_pipe[1], "G", 1) == 1;
    close(start_pipe[1]);
    int child_status = 0;
    pid_t waited;
    do { waited = waitpid(child, &child_status, 0); } while (waited < 0 && errno == EINTR);
    uint64_t generation_end = now_ns();
    // Detach before requesting drain, retaining the map and all mappings until join.
    if (resources.link) {
        bpf_link__destroy(resources.link);
        resources.link = nullptr;
    }
    uint64_t stop_ns = now_ns();
    __atomic_store_n(&resources.control->stop, 1, __ATOMIC_RELEASE);
    if (worker.joinable()) worker.join();
    uint64_t end_wall = now_ns();
    uint64_t host_cpu_ns = now_ns(CLOCK_PROCESS_CPUTIME_ID) - start_cpu;
    poc_generator_report report = {};
    ssize_t report_bytes = read(report_pipe[0], &report, sizeof(report));
    close(report_pipe[0]);
    require(released && waited == child && WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0 && report_bytes == sizeof(report), "generator failed");
    poc_bpf_stats bpf_stats = {};
    if (counters_fd >= 0) {
        uint32_t key = 0;
        require(bpf_map_lookup_elem(counters_fd, &key, &bpf_stats) == 0, "reading BPF counters failed");
    }
    bool ok = worker_result == 0;
    if (mode != "baseline")
        ok = ok && bpf_stats.attempted == report.calls &&
             bpf_stats.attempted == bpf_stats.submitted + bpf_stats.reserve_failed &&
             bpf_stats.submitted == context.stats.processed + context.stats.format_rejected &&
             !context.stats.format_rejected && context.stats.matched == context.stats.processed &&
             (allow_drops || bpf_stats.reserve_failed == 0);
    if (direct)
        ok = ok && context.stats.consumer_pos == context.stats.producer_pos &&
             context.stats.payload_copy_bytes == context.stats.processed * POC_EVENT_BYTES;
    printf("{\"environment\":\"QEMU TCG + SGX SIM\",\"mode\":\"%s\",\"ok\":%s,"
           "\"generator_calls\":%llu,\"attempted\":%llu,\"submitted\":%llu,\"reserve_failed\":%llu,"
           "\"processed\":%llu,\"matched\":%llu,\"format_rejected\":%llu,\"last_seq\":%llu,"
           "\"data_ecalls\":%llu,\"total_ecalls\":%llu,\"ocalls\":0,"
           "\"payload_copy_bytes\":%llu,\"sdk_input_bytes\":%llu,\"host_pack_bytes\":%llu,"
           "\"header_read_bytes\":%llu,\"index_read_bytes\":%llu,\"consumer_pos\":%llu,\"producer_pos\":%llu,"
           "\"batch_events\":%llu,\"batches\":%llu,\"worker_result\":%d,"
           "\"wall_ns\":%llu,\"generation_wall_ns\":%llu,\"generator_wall_ns\":%llu,\"drain_ns\":%llu,"
           "\"host_cpu_ns\":%llu,\"consumer_cpu_ns\":%llu,\"generator_cpu_ns\":%llu}\n",
           mode.c_str(), ok ? "true" : "false",
           (unsigned long long)report.calls, (unsigned long long)bpf_stats.attempted,
           (unsigned long long)bpf_stats.submitted, (unsigned long long)bpf_stats.reserve_failed,
           (unsigned long long)context.stats.processed, (unsigned long long)context.stats.matched,
           (unsigned long long)context.stats.format_rejected, (unsigned long long)context.stats.last_seq,
           (unsigned long long)context.data_ecalls, (unsigned long long)(setup_ecalls + context.data_ecalls + final_ecalls),
           (unsigned long long)context.stats.payload_copy_bytes, (unsigned long long)context.sdk_input_bytes,
           (unsigned long long)context.host_pack_bytes, (unsigned long long)context.stats.header_read_bytes,
           (unsigned long long)context.stats.index_read_bytes, (unsigned long long)context.stats.consumer_pos,
           (unsigned long long)context.stats.producer_pos, (unsigned long long)context.batch_events,
           (unsigned long long)context.batches, worker_result, (unsigned long long)(end_wall - start_wall),
           (unsigned long long)(generation_end - start_wall), (unsigned long long)report.wall_ns,
           (unsigned long long)(worker_end_ns > stop_ns ? worker_end_ns - stop_ns : 0),
           (unsigned long long)host_cpu_ns, (unsigned long long)worker_cpu_ns, (unsigned long long)report.cpu_ns);
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    try { return run(argc, argv); }
    catch (const std::exception &error) {
        fprintf(stderr, "poc: %s\n", error.what());
        return 1;
    }
}
