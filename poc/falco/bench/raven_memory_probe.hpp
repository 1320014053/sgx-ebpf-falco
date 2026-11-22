#pragma once

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#ifdef RZ_ENCLAVE
#include <openenclave/advanced/mallinfo.h>
extern "C" oe_result_t falco_emit(int*, const char*, size_t, int);
#endif

namespace rz_bench {
#ifndef RZ_ENCLAVE
inline void write_process_sample(const char* text, size_t length) {
    FILE* rollup = std::fopen("/proc/self/smaps_rollup", "r");
    if (!rollup) throw std::runtime_error("cannot read smaps_rollup");
    size_t rss = 0, anonymous = 0;
    char line[256];
    while (std::fgets(line, sizeof(line), rollup)) {
        if (!std::strncmp(line, "Rss:", 4)) std::sscanf(line + 4, "%zu", &rss);
        if (!std::strncmp(line, "Anonymous:", 10)) std::sscanf(line + 10, "%zu", &anonymous);
    }
    std::fclose(rollup);
    if (!rss) throw std::runtime_error("missing Rss in smaps_rollup");
    std::fwrite(text, 1, length, stderr);
    std::fprintf(stderr, " %zu %zu\n", rss * 1024, anonymous * 1024);
    std::fflush(stderr);
}
#endif

inline void sample(const char* phase, size_t events = 0, size_t nodes = 0, size_t edges = 0,
                   size_t edge_ids = 0, size_t tree = 0, size_t ledger = 0, size_t detections = 0) {
    size_t used = 0, peak = 0, capacity = 0;
#ifdef RZ_ENCLAVE
    oe_mallinfo_t info{};
    if (oe_allocator_mallinfo(&info) != OE_OK) throw std::runtime_error("enclave allocator statistics unavailable");
    used = info.current_allocated_heap_size;
    peak = info.peak_allocated_heap_size;
    capacity = info.max_total_heap_size;
#endif
    char line[256];
    int length = std::snprintf(line, sizeof(line), "RZMEM %s %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu",
                               phase, events, nodes, edges, edge_ids, tree, ledger, detections, used, peak, capacity);
    if (length < 0 || size_t(length) >= sizeof(line)) throw std::runtime_error("invalid memory sample");
#ifdef RZ_ENCLAVE
    int written = -1;
    if (falco_emit(&written, line, length, 1) != OE_OK || written) throw std::runtime_error("cannot emit memory sample");
#else
    write_process_sample(line, static_cast<size_t>(length));
#endif
}
}
