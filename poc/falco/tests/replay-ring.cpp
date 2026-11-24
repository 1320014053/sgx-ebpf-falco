#include "host.hpp"
#include "live/ring.hpp"
#include <cstring>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) try {
    if (argc != 6) return 2;
    auto snapshot = read("snapshot.scap");
    const auto records = read("ring.bin");
    constexpr size_t capacity = 64 * 1024;
    alignas(ring_page_bytes) static uint64_t consumer[ring_page_bytes / sizeof(uint64_t)]{};
    alignas(ring_page_bytes) static struct {
        uint64_t position;
        uint8_t padding[ring_page_bytes - sizeof(uint64_t)];
        uint8_t data[2 * capacity];
    } producer{};
    alignas(ring_page_bytes) static struct {
        RingControl values;
        uint8_t padding[ring_page_bytes - sizeof(RingControl)];
    } control{};
    if (records.size() > capacity) throw std::runtime_error("fixture exceeds test ring capacity");
    std::memcpy(producer.data, records.data(), records.size());
    producer.position = records.size();
    control.values.collector_pid = std::stoul(argv[2]);
    control.values.realtime_ns = std::stoull(argv[3]);
    control.values.flags = ring_stop;

    auto enclave = load_enclave(argv[1], "live.yaml", argv + 4, 2, true);
    falco_events_file = std::fopen("events.jsonl", "wb");
    if (!falco_events_file) throw std::runtime_error("cannot open translated event log");
    run_live(enclave.get(), reinterpret_cast<uint8_t*>(snapshot.data()), snapshot.size(),
             reinterpret_cast<uintptr_t>(consumer), reinterpret_cast<uintptr_t>(&producer),
             reinterpret_cast<uintptr_t>(&control), ring_page_bytes, capacity, false, record_host_events);
    std::fclose(falco_events_file);
    falco_events_file = nullptr;
    return consumer[0] == records.size() ? 0 : 1;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
