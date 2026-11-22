#include "host.hpp"
#include "capture.hpp"
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string_view>
#include <unistd.h>

std::FILE* falco_trace_file = nullptr;
std::FILE* falco_events_file = nullptr;
std::FILE* falco_packets_file = nullptr;
uint64_t falco_output_ocalls = 0;
uint64_t falco_trace_ocalls = 0;

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
    check(oe_create_Falco_enclave(image, OE_ENCLAVE_TYPE_SGX,
                                OE_ENCLAVE_FLAG_SIMULATE | OE_ENCLAVE_FLAG_DEBUG,
                                nullptr, 0, &handle), 0, "create Falco SIM enclave");
    Enclave enclave(handle, oe_terminate_enclave);
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
