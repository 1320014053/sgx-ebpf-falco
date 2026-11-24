#include "../trusted/bpf_ring.hpp"
#include <array>
#include <sys/mman.h>
#include <unistd.h>

static void require(bool ok) {
    if (!ok) throw std::runtime_error("BPF ring assertion failed");
}

template<class F>
void expect_error(F operation) {
    try { operation(); } catch (const std::runtime_error&) { return; }
    throw std::runtime_error("expected a corrupt ring");
}

int main() {
    constexpr auto page = ring_page_bytes;
    int fd = memfd_create("falco-ring", MFD_CLOEXEC);
    require(fd >= 0 && ftruncate(fd, 2 * page) == 0);
    auto* mapping = static_cast<uint8_t*>(mmap(nullptr, 3 * page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
    require(mapping != MAP_FAILED);
    require(mmap(mapping + 2 * page, page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, page) == mapping + 2 * page);
    close(fd);
    alignas(page) uint64_t consumer[page / 8]{}, control[page / 8]{};
    const auto head = reinterpret_cast<uint64_t>(consumer), base = reinterpret_cast<uint64_t>(mapping);
    const auto flags = reinterpret_cast<uint64_t>(control);
    auto outside = [](const void*, size_t) { return true; };
    expect_error([&] { BpfRing bad(head, base, head, page, page, outside); });
    expect_error([&] { BpfRing bad(head, UINT64_MAX - page + 1, flags, page, page, outside); });
    expect_error([&] { BpfRing bad(head, base + 1, flags, page, page, outside); });
    expect_error([&] { BpfRing bad(head, base, flags, page, page, [](const void*,size_t){ return false; }); });
    BpfRing ring(head, base, flags, page, page, outside);
    auto& producer = *reinterpret_cast<uint64_t*>(mapping);
    consumer[0] = page - 16;
    auto cursor = ring.consumer_position();
    producer = cursor + 32;
    const auto tail = ring.producer_position(cursor);
    auto* data = mapping + page;
    auto& word = *reinterpret_cast<uint32_t*>(data + cursor);
    word = 1U << 31;
    require(ring.next(cursor, tail).kind == BpfRing::Kind::busy);
    word = 1U << 30;
    require(ring.next(cursor, tail).kind == BpfRing::Kind::discard);
    word = 32;
    require(ring.next(cursor, tail).kind == BpfRing::Kind::corrupt);
    word = 16;
    std::memset(data + cursor + 8, 7, 8);
    std::memset(data, 9, 8);
    auto slot = ring.next(cursor, tail);
    std::array<uint8_t, 16> copy{};
    require(!ring.copy(slot, copy.data(), 17, 32) && !ring.copy(slot, copy.data(), 0, 15));
    require(ring.copy(slot, copy.data(), 16, copy.size()));
    for (size_t i = 0; i < copy.size(); ++i) require(copy[i] == (i < 8 ? 7 : 9));
    cursor += slot.span;
    *reinterpret_cast<uint32_t*>(data + 8) = 1U << 30;
    slot = ring.next(cursor, tail);
    require(slot.kind == BpfRing::Kind::discard);
    ring.release(cursor + slot.span);
    require(consumer[0] == producer && ring.next(consumer[0], tail).kind == BpfRing::Kind::empty);
    expect_error([&] { ring.producer_position(consumer[0] + 8); });
    expect_error([&] { ring.producer_position(consumer[0] - 1); });
    producer += page + 8;
    expect_error([&] { ring.producer_position(consumer[0]); });
    producer = 8;
    expect_error([&] { ring.producer_position(UINT64_MAX - 7); });
    require(munmap(mapping, page * 3) == 0);
}
