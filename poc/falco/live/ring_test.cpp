#include "host.hpp"
#include "ring.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <driver/ppm_events_public.h>
#include <fstream>
#include <future>
#include <iostream>
#include <libscap/scap_savefile.h>
#include <stdexcept>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

namespace {

constexpr size_t capacity = 128 * 1024;
constexpr uint64_t initial_position = capacity - 16;
constexpr uint32_t busy = 1U << 31;
constexpr uint32_t discard = 1U << 30;
constexpr int expected_alerts = 220;

uint64_t* head;
uint8_t* source;
size_t source_size;
size_t alerts_before_mutation;

uint8_t* map(size_t size, int protection, int flags, int fd, off_t offset, void* address = nullptr) {
    auto* result = mmap(address, size, protection, flags, fd, offset);
    if (result == MAP_FAILED) {
        throw std::runtime_error("could not map the test ring");
    }
    return static_cast<uint8_t*>(result);
}

void run(char** args) {
    auto fixture = read(args[3]);
    size_t snapshot_size = 0;
    block_header block{};
    for (;;) {
        if (fixture.size() - snapshot_size < sizeof(block)) {
            throw std::runtime_error("test fixture has no event block");
        }
        std::memcpy(&block, fixture.data() + snapshot_size, sizeof(block));
        if (block.block_total_length < sizeof(block) ||
            block.block_total_length > fixture.size() - snapshot_size) {
            throw std::runtime_error("invalid fixture block length");
        }
        if (block.block_type == EV_BLOCK_TYPE_V2) {
            break;
        }
        snapshot_size += block.block_total_length;
    }
    auto frame = fixture.substr(snapshot_size, block.block_total_length);
    constexpr size_t frame_header = sizeof(block) + sizeof(uint16_t);
    ppm_evt_hdr event{};
    if (frame.size() < frame_header + sizeof(event) + sizeof(uint16_t) + sizeof(uint32_t)) {
        throw std::runtime_error("invalid fixture event length");
    }
    auto* payload = frame.data() + frame_header;
    std::memcpy(&event, payload, sizeof(event));
    if (event.type != PPME_SYSCALL_EXECVE_19_X || event.len > frame.size() - frame_header - sizeof(uint32_t)) {
        throw std::runtime_error("expected the shell execution from fixture.py");
    }

    int fd = memfd_create("falco-ring-test", MFD_CLOEXEC);
    if (fd < 0 || ftruncate(fd, ring_page_bytes + capacity) != 0) {
        throw std::runtime_error("could not allocate test ring");
    }
    auto producer_view = [&](int protection) {
        auto* base = map(ring_page_bytes + 2 * capacity, protection, MAP_SHARED, fd, 0);
        map(capacity, protection, MAP_SHARED | MAP_FIXED, fd, ring_page_bytes, base + ring_page_bytes + capacity);
        return base;
    };
    auto* writer = producer_view(PROT_READ | PROT_WRITE);
    auto* producer = producer_view(PROT_READ);
    close(fd);
    constexpr int anonymous = MAP_SHARED | MAP_ANONYMOUS;
    constexpr int rw = PROT_READ | PROT_WRITE;
    head = reinterpret_cast<uint64_t*>(map(ring_page_bytes, rw, anonymous, -1, 0));
    auto* flags = reinterpret_cast<uint32_t*>(map(ring_page_bytes, rw, anonymous, -1, 0));
    *head = initial_position;

    uint64_t position = initial_position;
    auto append = [&](const void* data, uint32_t size, uint32_t flags) {
        auto* slot = writer + ring_page_bytes + (position & (capacity - 1));
        auto len = size | flags;
        std::memcpy(slot, &len, sizeof(len));
        if (data) {
            std::memcpy(slot + 8, data, size);
        }
        position += (size + 15) & ~uint32_t(7);
        return slot + 8;
    };
    auto* first = append(payload, event.len, busy);
    append(nullptr, 16, discard);
    append(nullptr, 12, 0);
    auto malformed = frame;
    const uint16_t invalid_length = UINT16_MAX;
    std::memcpy(malformed.data() + frame_header + sizeof(event), &invalid_length, sizeof(invalid_length));
    append(malformed.data() + frame_header, event.len, 0);

    std::ofstream reference(args[5], std::ios::binary | std::ios::trunc);
    reference.write(fixture.data(), snapshot_size);
    reference.write(frame.data(), frame.size());
    for (int i = 1; i < expected_alerts; ++i) {
        event.ts += 1000000;
        std::memcpy(payload, &event, sizeof(event));
        source = append(payload, event.len, 0);
        reference.write(frame.data(), frame.size());
    }
    reference.close();
    if (!reference || position - initial_position >= capacity) {
        throw std::runtime_error("could not construct the test capture");
    }
    source_size = event.len;
    *reinterpret_cast<uint64_t*>(writer) = position;

    auto enclave = load_enclave(args[1], args[2], args + 4, 1, true);
    auto worker = std::async(std::launch::async, [&] {
        int result = -1;
        const auto status = falco_live(enclave.get(), &result, reinterpret_cast<uint8_t*>(fixture.data()), snapshot_size,
                                       reinterpret_cast<uint64_t>(head), reinterpret_cast<uint64_t>(producer),
                                       reinterpret_cast<uint64_t>(flags), ring_page_bytes, capacity, false, false);
        check(status, result, "Falco ring test");
    });
    while (!(__atomic_load_n(flags, __ATOMIC_ACQUIRE) & ring_ready)) {
        if (worker.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready) {
            worker.get();
            throw std::runtime_error("test consumer exited before it was ready");
        }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    const bool waited = __atomic_load_n(head, __ATOMIC_ACQUIRE) == initial_position;
    __atomic_store_n(reinterpret_cast<uint32_t*>(first - 8), event.len, __ATOMIC_RELEASE);
    __atomic_fetch_or(flags, ring_stop, __ATOMIC_RELEASE);
    worker.get();
    if (!waited || *head != position || source) {
        throw std::runtime_error("BUSY, drain or private copy assertion failed");
    }
    std::cerr << "{\"busy_waited\":true,\"source_mutated_before_batch_finished\":true,"
              << "\"alerts_formatted_before_mutation\":" << alerts_before_mutation << "}\n";
}

} // namespace

extern "C" size_t __real_fwrite(const void*, size_t, size_t, std::FILE*);

extern "C" size_t __wrap_fwrite(const void* data, size_t size, size_t count, std::FILE* stream) {
    // The first alert batch arrives after the whole ring batch was copied, while matching is still in progress.
    if (stream == stdout && source && __atomic_load_n(head, __ATOMIC_ACQUIRE) == initial_position) {
        const auto* begin = static_cast<const char*>(data);
        alerts_before_mutation = std::count(begin, begin + size * count, '\n');
        if (alerts_before_mutation < expected_alerts) {
            std::memset(source, 0, source_size);
            source = nullptr;
        }
    }
    return __real_fwrite(data, size, count, stream);
}

int main(int argc, char** argv) {
    if (argc != 6) {
        std::cerr << "usage: falco-ring-test ENCLAVE CONFIG FIXTURE RULES EXPECTED_SCAP\n";
        return 2;
    }
    try {
        run(argv);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
