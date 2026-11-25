#include "host.hpp"
#include "ring.hpp"
#include "packet_record.h"
#include "packet_tap.skel.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <driver/ppm_ringbuffer.h>
#include <future>
#include <iostream>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <libscap/scap.h>
#include <libscap/linux/scap_linux_platform.h>
#include <libscap/scap-int.h>
#include <libscap/scap_engines.h>
#include <libscap/scap_platform.h>
#include <libscap/scap_savefile_api.h>
#include <spawn.h>
#include <signal.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern "C" int falco_open_ring_map();
extern char** environ;

namespace {

std::atomic<bool> stop_requested{false};
static_assert(std::atomic<bool>::is_always_lock_free);

void request_stop(int) { stop_requested.store(true, std::memory_order_relaxed); }

struct Mapping {
    const size_t bytes;
    void* const addr;

    Mapping(size_t bytes, int prot, int flags, int fd, off_t offset)
        : bytes(bytes), addr(mmap(nullptr, bytes, prot, flags, fd, offset)) {
        if (addr == MAP_FAILED) {
            throw std::runtime_error(std::string("mmap: ") + std::strerror(errno));
        }
    }
    ~Mapping() { munmap(addr, bytes); }
};

void log_driver(const char* component, const char* message, falcosecurity_log_severity severity) {
    if (severity <= FALCOSECURITY_LOG_SEV_INFO) {
        std::fprintf(stderr, "%s: %s\n", component, message);
    }
}

uint64_t clock_ns(clockid_t which) {
    timespec value{};
    if (clock_gettime(which, &value) != 0) throw std::runtime_error("could not read capture clock");
    return uint64_t(value.tv_sec) * 1000000000 + value.tv_nsec;
}

class PacketTap {
    std::unique_ptr<packet_tap_bpf, decltype(&packet_tap_bpf__destroy)> program{nullptr, packet_tap_bpf__destroy};
    int socket_fd = -1;
public:
    void start(int ring_fd, uint32_t capacity) {
        program.reset(packet_tap_bpf__open());
        if (!program) throw std::runtime_error("open packet tap");
        program->rodata->boot_epoch_ns = clock_ns(CLOCK_REALTIME) - clock_ns(CLOCK_BOOTTIME);
        program->rodata->loopback_index = if_nametoindex("lo");
        auto* map = program->maps.events;
        if (bpf_map__set_max_entries(map, capacity) || bpf_map__reuse_fd(map, ring_fd) ||
            packet_tap_bpf__load(program.get()))
            throw std::runtime_error("load packet tap on the Falco ring");
        socket_fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        const int filter = bpf_program__fd(program->progs.capture_ip);
        sockaddr_ll address{};
        address.sll_family = AF_PACKET;
        address.sll_protocol = htons(ETH_P_ALL);
        if (socket_fd < 0 || setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_BPF, &filter, sizeof(filter)) ||
            bind(socket_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)))
            throw std::runtime_error(std::string("attach packet tap: ") + std::strerror(errno));
    }
    void stop() {
        if (socket_fd >= 0) {
            close(socket_fd);
            socket_fd = -1;
        }
    }
    ~PacketTap() { stop(); }
    uint64_t submitted() const { return program ? program->bss->submitted : 0; }
    uint64_t dropped() const { return program ? program->bss->dropped : 0; }
};

int run(int argc, char** argv) {
    int command = 5;
    while (command < argc && std::strcmp(argv[command], "--") != 0) {
        ++command;
    }
    const bool with_workload = command < argc;
    if (argc < 6 || command == 5 || (with_workload && command == argc - 1)) {
        std::cerr << "usage: falco-live ENCLAVE CONFIG RING_KIB TRACE_OR_- "
                     "[--record-inputs EVENTS.jsonl PACKETS.pcap] RULES... [-- WORKLOAD [ARGS...]]\n";
        return 2;
    }
    if (!with_workload) {
        struct sigaction action{};
        action.sa_handler = request_stop;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr))
            throw std::runtime_error("could not install capture stop handlers");
    }
    char* end = nullptr;
    const auto kib = std::strtoul(argv[3], &end, 10);
    if (*end || kib > max_ring_bytes / 1024 || sysconf(_SC_PAGESIZE) != ring_page_bytes ||
        !validate_buffer_bytes_dim(kib * 1024, ring_page_bytes)) {
        throw std::runtime_error("expected power-of-two RING_KIB (16 through 65536) and 4 KiB pages");
    }
    const auto capacity = kib * 1024;
    int first_rule = 5;
    uint8_t record_inputs = 0;
    if (std::strcmp(argv[first_rule], "--record-inputs") == 0) {
        first_rule += 3;
        if (first_rule >= command) throw std::runtime_error("--record-inputs needs two output paths and rules");
        if (std::strcmp(argv[6], "-")) record_inputs |= record_host_events;
        if (std::strcmp(argv[7], "-")) record_inputs |= record_ip_packets;
    }
    std::unique_ptr<std::FILE, decltype(&std::fclose)> events(nullptr, std::fclose), packets(nullptr, std::fclose);
    auto enclave = load_enclave(argv[1], argv[2], argv + first_rule, command - first_rule, true);

    scap_modern_bpf_engine_params params{};
    params.cpus_for_each_buffer = 0;
    params.buffer_bytes_dim = capacity;
    params.disable_iterators = true;
    scap_open_args args{};
    args.engine_params = &params;
    args.import_users = true;
    args.proc_scan_timeout_ms = SCAP_PROC_SCAN_TIMEOUT_NONE;
    args.log_fn = log_driver;
    uint8_t selected[PPM_SC_MAX]{};
    int result = -1;
    auto status = falco_live_select(enclave.get(), &result, selected, sizeof(selected));
    check(status, result, "select live syscalls");
    std::copy_n(selected, PPM_SC_MAX, args.ppm_sc_of_interest.ppm_sc);
    char error[SCAP_LASTERR_SIZE]{};
    int32_t rc = 0;
    std::unique_ptr<scap_t, decltype(&scap_close)> driver(
        scap_open(&args, &scap_modern_bpf_engine, error, &rc), scap_close);
    if (!driver) {
        throw std::runtime_error("open Modern eBPF (rc=" + std::to_string(rc) + "): " + error);
    }
    auto check_driver = [&](int status, const char* action) {
        if (status != SCAP_SUCCESS) {
            throw std::runtime_error(std::string(action) + " (rc=" + std::to_string(status) +
                                     "): " + scap_getlasterr(driver.get()));
        }
    };
    check_driver(scap_set_dropfailed(driver.get(), false), "keep failed syscall exits");

    auto close_platform = [](scap_platform* platform) {
        scap_platform_close(platform);
        scap_platform_free(platform);
    };
    scap_proc_callbacks callbacks{};
    callbacks.m_refresh_start_cb = [](void*) {};
    callbacks.m_refresh_end_cb = callbacks.m_refresh_start_cb;
    std::unique_ptr<scap_platform, decltype(close_platform)> platform(
        scap_linux_alloc_platform(callbacks), close_platform);
    if (!platform) {
        throw std::runtime_error("allocate the procfs snapshot platform");
    }
    reinterpret_cast<scap_linux_platform*>(platform.get())->m_linux_vtable = &scap_modern_bpf_linux_vtable;
    if (scap_platform_init(platform.get(), error, driver->m_engine, &args) != SCAP_SUCCESS) {
        throw std::runtime_error(std::string("initialize procfs snapshot: ") + error);
    }
    std::vector<uint8_t> snapshot(8 * 1024 * 1024);
    std::unique_ptr<scap_dumper_t, decltype(&scap_dump_close)> dump(
        scap_memory_dump_open(platform.get(), snapshot.data(), snapshot.size(), error), scap_dump_close);
    if (!dump) {
        throw std::runtime_error(std::string("serialize procfs snapshot: ") + error);
    }
    snapshot.resize(scap_get_memorydumper_curpos(dump.get()) - snapshot.data());
    dump.reset();

    int map_fd = falco_open_ring_map();
    if (map_fd < 0) {
        throw std::runtime_error(std::string("open Modern eBPF ring map: ") + std::strerror(errno));
    }
    auto close_fd = [](int* fd) { close(*fd); };
    const std::unique_ptr<int, decltype(close_fd)> ring_fd(&map_fd, close_fd);
    bpf_map_info map{};
    uint32_t map_info_size = sizeof(map);
    if (bpf_obj_get_info_by_fd(map_fd, &map, &map_info_size) != 0 ||
        map.type != BPF_MAP_TYPE_RINGBUF || map.max_entries != capacity || scap_get_ndevs(driver.get()) != 1) {
        throw std::runtime_error("expected one shared Modern eBPF ring buffer of the configured size");
    }
    Mapping consumer(ring_page_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
    Mapping producer(ring_page_bytes + 2 * capacity, PROT_READ, MAP_SHARED, map_fd, ring_page_bytes);
    Mapping control(ring_page_bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    auto* control_page = static_cast<RingControl*>(control.addr);
    control_page->collector_pid = getpid();
    auto* flags = &control_page->flags;
    auto* consumed = static_cast<uint64_t*>(consumer.addr);
    auto* published = static_cast<const uint64_t*>(producer.addr);
    auto position = __atomic_load_n(consumed, __ATOMIC_ACQUIRE);
    if (position != __atomic_load_n(published, __ATOMIC_ACQUIRE)) {
        throw std::runtime_error("driver calibration left records in the queue");
    }

    const bool record = std::strcmp(argv[4], "-") != 0;
    std::unique_ptr<std::FILE, decltype(&std::fclose)> trace(nullptr, std::fclose);
    scap_stats before{}, after{};
    check_driver(scap_get_stats(driver.get(), &before), "read baseline driver counters");
    const auto schema = scap_get_driver_schema_version(driver.get());
    const auto api = scap_get_driver_api_version(driver.get());
    PacketTap tap;
    std::future<unsigned> worker;
    int exit_status = 0;
    uint64_t progress = 0;
    bool capturing = false, capture_started = false;
    std::chrono::steady_clock::time_point started, stopped;
    try {
        if (record) {
            trace.reset(std::fopen(argv[4], "wbex"));
            if (!trace || std::fwrite(snapshot.data(), 1, snapshot.size(), trace.get()) != snapshot.size()) {
                throw std::runtime_error(std::string("write trace snapshot: ") + std::strerror(errno));
            }
            falco_trace_file = trace.get();
        }
        if (record_inputs & record_host_events) {
            events.reset(std::fopen(argv[6], "wbex"));
            if (!events) throw std::runtime_error("could not create the detector test JSONL");
            falco_events_file = events.get();
        }
        if (record_inputs & record_ip_packets) {
            packets.reset(std::fopen(argv[7], "wbex"));
            const uint32_t pcap_header[]{0xa1b23c4d, 0x00040002, 0, 0, RZ_SNAPLEN, 101};
            if (!packets || std::fwrite(pcap_header, sizeof(pcap_header), 1, packets.get()) != 1)
                throw std::runtime_error("could not create the detector test PCAP");
            falco_packets_file = packets.get();
        }
        __atomic_store_n(&control_page->realtime_ns, clock_ns(CLOCK_REALTIME), __ATOMIC_RELEASE);
        worker = std::async(std::launch::async, [&]() {
            return run_live(enclave.get(), snapshot.data(), snapshot.size(), reinterpret_cast<uint64_t>(consumer.addr),
                     reinterpret_cast<uint64_t>(producer.addr), reinterpret_cast<uint64_t>(control.addr),
                     ring_page_bytes, capacity, record, record_inputs);
        });
        while (!(__atomic_load_n(flags, __ATOMIC_ACQUIRE) & ring_ready)) {
            if (worker.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready) {
                worker.get();
                throw std::runtime_error("Falco consumer exited during startup");
            }
        }
        if (__atomic_load_n(flags, __ATOMIC_ACQUIRE) & ring_packets) tap.start(map_fd, capacity);
        capturing = true;
        check_driver(scap_start_capture(driver.get()), "attach Modern eBPF capture programs");
        capture_started = true;
        started = std::chrono::steady_clock::now();

        pid_t child = -1;
        if (with_workload) {
            const int spawn = posix_spawnp(&child, argv[command + 1], nullptr, nullptr, argv + command + 1, environ);
            if (spawn != 0) throw std::runtime_error(std::string("start workload: ") + std::strerror(spawn));
        } else {
            std::cerr << "{\"mode\":\"capture_ready\",\"pid\":" << getpid() << ",\"map_id\":" << map.id << "}\n";
        }
        while (!stop_requested.load(std::memory_order_relaxed)) {
            __atomic_store_n(&control_page->realtime_ns, clock_ns(CLOCK_REALTIME), __ATOMIC_RELEASE);
            if (with_workload) {
                const auto waited = waitpid(child, &exit_status, WNOHANG);
                if (waited == child) break;
                if (waited < 0 && errno != EINTR)
                    throw std::runtime_error(std::string("wait for workload: ") + std::strerror(errno));
            }
            if (worker.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                worker.get();
                throw std::runtime_error("ring consumer exited before capture stopped");
            }
            const auto next = __atomic_load_n(consumed, __ATOMIC_ACQUIRE);
            if (next > position) {
                ++progress;
                position = next;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        tap.stop();
        check_driver(scap_stop_capture(driver.get()), "stop Modern eBPF capture");
        stopped = std::chrono::steady_clock::now();
        capturing = false;
    } catch (...) {
        tap.stop();
        if (capturing && scap_stop_capture(driver.get()) != SCAP_SUCCESS) {
            driver.reset();
        }
        __atomic_fetch_or(flags, ring_stop, __ATOMIC_RELEASE);
        if (worker.valid()) {
            worker.wait();
        }
        if (!capture_started) {
            // Setup rejected the run before capture, so a corrected rerun can reuse these new paths.
            for (const char* path : {trace ? argv[4] : nullptr, events ? argv[6] : nullptr, packets ? argv[7] : nullptr})
                if (path) unlink(path);
        }
        throw;
    }
    __atomic_fetch_or(flags, ring_stop, __ATOMIC_RELEASE);
    const auto data_ecalls = worker.get();
    const auto drained = std::chrono::steady_clock::now();
    check_driver(scap_get_stats(driver.get(), &after), "read final driver counters");
    if (trace && std::fflush(trace.get()) != 0) {
        throw std::runtime_error(std::string("flush trace: ") + std::strerror(errno));
    }
    falco_trace_file = nullptr;
    if ((events && std::fflush(events.get())) || (packets && std::fflush(packets.get())))
        throw std::runtime_error("could not flush detector test captures");

    const auto tail = __atomic_load_n(published, __ATOMIC_ACQUIRE);
    const auto head = __atomic_load_n(consumed, __ATOMIC_ACQUIRE);
    const auto millis = [](auto interval) { return std::chrono::duration_cast<std::chrono::milliseconds>(interval).count(); };
    std::cerr << "{\"mode\":\"modern_ebpf\",\"map_id\":" << map.id << ",\"ring_bytes\":" << capacity
              << ",\"packet_submitted\":" << tap.submitted() << ",\"packet_drops\":" << tap.dropped()
              << ",\"driver_api\":" << api << ",\"driver_schema\":" << schema
              << ",\"driver_events\":" << after.n_evts - before.n_evts
              << ",\"driver_drops\":" << after.n_drops - before.n_drops
              << ",\"driver_buffer_drops\":" << after.n_drops_buffer - before.n_drops_buffer
              << ",\"driver_size_drops\":" << after.n_drops_scratch_map - before.n_drops_scratch_map
              << ",\"driver_preemptions\":" << after.n_preemptions - before.n_preemptions
              << ",\"consumer\":" << head << ",\"producer\":" << tail
              << ",\"capture_ms\":" << millis(stopped - started) << ",\"drain_ms\":" << millis(drained - stopped)
              << ",\"progress_samples\":" << progress << ",\"data_ecalls\":" << data_ecalls << ",\"output_ocalls\":" << falco_output_ocalls
              << ",\"sleep_ocalls\":" << falco_sleep_ocalls << ",\"sleep_ns\":" << falco_sleep_ns
              << ",\"consumer_cpu_ns\":" << falco_consumer_cpu_ns
              << ",\"output_queue_peak\":" << falco_output_queue_peak
              << ",\"output_queue_peak_bytes\":" << falco_output_queue_peak_bytes
              << ",\"trace_ocalls\":" << falco_trace_ocalls << "}\n";
    if (head != tail || !WIFEXITED(exit_status) || WEXITSTATUS(exit_status) != 0) {
        throw std::runtime_error("the queue did not drain or the workload failed");
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
