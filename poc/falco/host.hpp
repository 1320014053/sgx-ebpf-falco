#pragma once

#include "Falco_u.h"
#include "live/ring.hpp"
#include <atomic>
#include <cstdio>
#include <memory>
#include <string>

using Enclave = std::unique_ptr<oe_enclave_t, decltype(&oe_terminate_enclave)>;

std::string read(const char* path);
void check(oe_result_t status, int result, const char* action);
Enclave load_enclave(const char* image, const char* config, char* const* rules, size_t rule_count, bool live = false);

struct PluginInputs {
    const char* events = nullptr;
    const char* packets = nullptr;
    bool tetragon = false;
    bool host_capture = false;
    bool stream = false;

    static PluginInputs parse(int argc, char** argv, int& index);
    void replay(oe_enclave_t* enclave) const;
};

extern std::FILE* falco_trace_file;
extern std::FILE* falco_events_file;
extern std::FILE* falco_packets_file;
extern std::atomic<uint64_t> falco_output_ocalls;
extern std::atomic<uint64_t> falco_trace_ocalls;
extern uint64_t falco_sleep_ocalls;
extern uint64_t falco_sleep_ns;
extern uint64_t falco_consumer_cpu_ns;
extern size_t falco_output_queue_peak;
extern size_t falco_output_queue_peak_bytes;
unsigned run_live(oe_enclave_t* enclave, uint8_t* snapshot, size_t bytes, uint64_t consumer, uint64_t producer,
              uint64_t control, size_t page, size_t capacity, bool record, uint8_t inputs);
