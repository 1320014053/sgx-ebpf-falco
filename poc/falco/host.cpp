#include "host.hpp"
#include "capture.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iterator>
#include <mutex>
#include <signal.h>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <unistd.h>

std::FILE* falco_trace_file = nullptr;
std::FILE* falco_events_file = nullptr;
std::FILE* falco_packets_file = nullptr;
std::atomic<uint64_t> falco_output_ocalls{0}, falco_trace_ocalls{0};
uint64_t falco_sleep_ocalls = 0;
uint64_t falco_sleep_ns = 0;
uint64_t falco_consumer_cpu_ns = 0;
size_t falco_output_queue_peak = 0;
size_t falco_output_queue_peak_bytes = 0;

namespace {
struct OutputQueue {
    std::deque<std::string> chunks;
    std::mutex mutex;
    std::condition_variable changed;
    bool done = false, failed = false;
    size_t queued_bytes = 0;

    void write(RingControl* control) {
        sigset_t blocked;
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &blocked, nullptr);
        std::unique_lock<std::mutex> lock(mutex);
        for (;;) {
            changed.wait(lock, [&] { return done || !chunks.empty(); });
            if (chunks.empty()) return;
            auto chunk = std::move(chunks.front());
            chunks.pop_front();
            queued_bytes -= chunk.size();
            lock.unlock();
            const bool ok = std::fwrite(chunk.data(), 1, chunk.size(), stdout) == chunk.size() &&
                            std::fflush(stdout) == 0;
            lock.lock();
            if (!ok) {
                failed = true;
                __atomic_fetch_or(&control->flags, ring_abort, __ATOMIC_RELEASE);
                return;
            }
        }
    }
};
OutputQueue* active_output;
}

unsigned run_live(oe_enclave_t* enclave, uint8_t* snapshot, size_t bytes, uint64_t consumer, uint64_t producer,
              uint64_t control, size_t page, size_t capacity, bool record, uint8_t inputs) {
    auto* ctl = reinterpret_cast<RingControl*>(control);
    int result = -1;
    auto status = falco_live_setup(enclave, &result, snapshot, bytes, consumer, producer, control, page,
                                   capacity, record, inputs);
    check(status, result, "set up live capture");
    OutputQueue output;
    const unsigned peers = (__atomic_load_n(&ctl->flags, __ATOMIC_ACQUIRE) & ring_detectors) ? 2 : 1;
    std::thread writer;
    std::array<std::thread, 2> workers;
    std::exception_ptr error;
    std::array<oe_result_t, 2> statuses{OE_FAILURE, OE_FAILURE};
    std::array<int, 2> results{-1, -1};
    bool entered_ingest = false;
    active_output = &output;
    try {
        writer = std::thread([&] { output.write(ctl); });
        for (unsigned i = 0; i < peers; ++i) {
            workers[i] = std::thread([&, i] {
                const auto role = i == 0 ? analysis_role : detection_role;
                statuses[i] = falco_live_run(enclave, &results[i], role);
                if (statuses[i] != OE_OK || results[i]) __atomic_fetch_or(&ctl->flags, ring_abort, __ATOMIC_RELEASE);
                // A role whose ECALL failed never ran, so it cannot wake its peers itself.
                if (statuses[i] != OE_OK) falco_live_cancel(enclave);
            });
        }
        entered_ingest = true;
        timespec begin{}, end{};
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &begin);
        status = falco_live_run(enclave, &result, ingest_role);
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
        falco_consumer_cpu_ns = (end.tv_sec - begin.tv_sec) * 1000000000LL + end.tv_nsec - begin.tv_nsec;
        check(status, result, "run live ingest");
    } catch (...) {
        error = std::current_exception();
        __atomic_fetch_or(&ctl->flags, ring_abort, __ATOMIC_RELEASE);
        // A failed transport may never have entered the ingest role to wake its peers.
        if (!entered_ingest || status != OE_OK) falco_live_cancel(enclave);
    }
    for (auto& worker : workers) if (worker.joinable()) worker.join();
    {
        std::lock_guard<std::mutex> lock(output.mutex);
        output.done = true;
        output.changed.notify_one();
    }
    if (writer.joinable()) writer.join();
    active_output = nullptr;
    status = falco_live_finish(enclave, &result);
    if (error) std::rethrow_exception(error);
    for (unsigned i = 0; i < peers; ++i) {
        check(statuses[i], results[i], i == 0 ? "run live analysis" : "run live detection");
    }
    check(status, result, "finish live capture");
    if (output.failed) throw std::runtime_error("failed to write live alerts");
    return 3 + peers; // Setup, ingest, peer roles, finish.
}

void falco_sleep(uint32_t us) {
    const auto start = std::chrono::steady_clock::now();
    usleep(us);
    ++falco_sleep_ocalls;
    falco_sleep_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - start).count();
}

std::string read(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error(std::string("cannot open ") + path);
    }
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

PluginInputs PluginInputs::parse(int argc, char** argv, int& index) {
    if (index >= argc) {
        return {};
    }
    const std::string_view option(argv[index]);
    if (option == "--plugin-stream") {
        if (argc-index < 3) throw std::runtime_error("expected RAVEN JSONL and rules");
        PluginInputs stream;
        stream.events=argv[index+1]; stream.stream=true; index+=2;
        return stream;
    }
    if (option != "--plugin" && option != "--plugin-tetragon" && option != "--plugin-host") {
        return {};
    }
    if (argc - index < 4) {
        throw std::runtime_error("expected RAVEN JSONL, Zeek PCAP, and at least one Falco rule file");
    }
    PluginInputs inputs{argv[index + 1], argv[index + 2], option == "--plugin-tetragon", option == "--plugin-host"};
    index += 3;
    return inputs;
}

void PluginInputs::replay(oe_enclave_t* enclave) const {
    if (!events) {
        return;
    }
    constexpr size_t limit = 64 * 1024 * 1024;
    if (stream) {
        std::ifstream input(events);
        if (!input) throw std::runtime_error("cannot open RAVEN stream");
        std::string batch, line;
        auto send = [&](bool finish) {
            int result = -1;
            auto status = falco_plugin_stream(enclave,&result,reinterpret_cast<uint8_t*>(batch.data()),batch.size(),finish);
            check(status,result,"RAVEN stream"); batch.clear();
        };
        while (std::getline(input,line)) {
            if (line.size() >= limit) throw std::runtime_error("RAVEN stream record exceeds 64 MiB");
            if (!batch.empty() && batch.size()+line.size()+1 > 256*1024) send(false);
            batch += line; batch += '\n';
        }
        if (!input.eof()) throw std::runtime_error("error reading RAVEN stream");
        send(true);
        return;
    }
    std::string read_errors;
    auto capture = [&](const char* source, const char* path, std::string& bytes) {
        try {
            bytes = rz::read_capture(path);
            return true;
        } catch (const std::exception& error) {
            if (!read_errors.empty()) read_errors += '\n';
            read_errors += std::string(source) + " input: " + error.what();
            return false;
        }
    };
    std::string jsonl, pcap;
    capture("RAVEN", events, jsonl);
    bool have_pcap = capture("Zeek", packets, pcap);
    int result = -1;
    auto status = falco_plugin_replay(enclave, &result, reinterpret_cast<uint8_t*>(jsonl.data()), jsonl.size(),
                                      reinterpret_cast<uint8_t*>(pcap.data()), pcap.size(), have_pcap, tetragon, host_capture);
    check(status, result, read_errors.empty() ? "RAVEN and Zeek replay in Falco enclave" : read_errors.c_str());
    if (!read_errors.empty()) throw std::runtime_error(read_errors);
}

int falco_emit(const char* data, size_t bytes, int diagnostics) {
    ++falco_output_ocalls;
    if (!diagnostics && active_output) {
        auto& output = *active_output;
        std::lock_guard<std::mutex> lock(output.mutex);
        if (output.failed) return 1;
        try {
            output.chunks.emplace_back(data, bytes);
        } catch (const std::bad_alloc&) { return 1; }
        falco_output_queue_peak = std::max(falco_output_queue_peak, output.chunks.size());
        output.queued_bytes += bytes;
        falco_output_queue_peak_bytes = std::max(falco_output_queue_peak_bytes, output.queued_bytes);
        output.changed.notify_one();
        return 0;
    }
    auto* stream = diagnostics ? stderr : stdout;
    return std::fwrite(data, 1, bytes, stream) == bytes && std::fflush(stream) == 0 ? 0 : 1;
}

int falco_trace_append(const uint8_t* data, size_t bytes) {
    ++falco_trace_ocalls;
    return falco_trace_file && std::fwrite(data, 1, bytes, falco_trace_file) == bytes ? 0 : 1;
}

int falco_record_input(const uint8_t* data, size_t bytes, uint64_t ns, uint32_t wire_bytes) {
    if (!wire_bytes) {
        return falco_events_file && std::fwrite(data, 1, bytes, falco_events_file) == bytes &&
               std::fputc('\n', falco_events_file) != EOF ? 0 : 1;
    }
    const uint32_t header[]{uint32_t(ns / 1000000000), uint32_t(ns % 1000000000), uint32_t(bytes), wire_bytes};
    return falco_packets_file && std::fwrite(header, sizeof(header), 1, falco_packets_file) == 1 &&
           std::fwrite(data, 1, bytes, falco_packets_file) == bytes ? 0 : 1;
}

void check(oe_result_t status, int result, const char* action) {
    if (status != OE_OK || result != 0) {
        throw std::runtime_error(std::string(action) + ": " + oe_result_str(status) +
                                 ", enclave return " + std::to_string(result));
    }
}

Enclave load_enclave(const char* image, const char* config_path, char* const* rules, size_t rule_count, bool live) {
    const auto config = read(config_path);
    char hostname[256]{};
    if (gethostname(hostname, sizeof(hostname) - 1) != 0) {
        throw std::runtime_error("gethostname failed");
    }
    const char* host = std::getenv("FALCO_HOSTNAME");
    oe_enclave_t* handle = nullptr;
    const uint32_t flags = FALCO_SGX_HARDWARE ? 0 : OE_ENCLAVE_FLAG_SIMULATE | OE_ENCLAVE_FLAG_DEBUG;
    check(oe_create_Falco_enclave(image, OE_ENCLAVE_TYPE_SGX, flags, nullptr, 0, &handle), 0, "create Falco enclave");
    Enclave enclave(handle, oe_terminate_enclave);
#if FALCO_SGX_HARDWARE
    if (std::getenv("FALCO_SGX_REPORT")) {
        uint8_t* report = nullptr;
        size_t length = 0;
        check(oe_get_report(handle, 0, nullptr, 0, &report, &length), 0, "get Falco local REPORT");
        oe_report_t parsed{};
        const auto status = oe_parse_report(report, length, &parsed);
        oe_free_report(report);
        check(status, 0, "parse Falco local REPORT");
        const bool debug = (parsed.identity.attributes & OE_REPORT_ATTRIBUTES_DEBUG) != 0;
        std::fprintf(stderr, "REPORT DEBUG=%d MRENCLAVE=", debug);
        for (auto byte : parsed.identity.unique_id) std::fprintf(stderr, "%02x", byte);
        std::fprintf(stderr, " MRSIGNER=");
        for (auto byte : parsed.identity.signer_id) std::fprintf(stderr, "%02x", byte);
        std::fputc('\n', stderr);
        if (debug) throw std::runtime_error("Falco enclave DEBUG bit set");
    }
#endif
    int result = -1;
    auto status = falco_config(handle, &result, config.c_str(), host ? host : hostname, live);
    check(status, result, "load configuration");
    for (size_t i = 0; i < rule_count; ++i) {
        const auto yaml = read(rules[i]);
        status = falco_rules(handle, &result, rules[i], yaml.c_str());
        check(status, result, rules[i]);
    }
    return enclave;
}
