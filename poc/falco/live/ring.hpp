#pragma once

#include <cstddef>
#include <cstdint>

constexpr uint32_t ring_ready = 1;
constexpr uint32_t ring_stop = 2;
constexpr uint32_t ring_detectors = 4;
constexpr uint8_t record_host_events = 1;
constexpr uint8_t record_ip_packets = 2;
struct RingControl {
    uint32_t flags;
    uint32_t collector_pid;
    alignas(8) uint64_t realtime_ns;
};
constexpr size_t ring_page_bytes = 4096;
constexpr size_t max_ring_bytes = 64 * 1024 * 1024;
constexpr size_t max_event_bytes = 64 * 1024;
