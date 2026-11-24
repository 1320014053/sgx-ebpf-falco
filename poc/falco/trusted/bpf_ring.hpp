#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

constexpr size_t ring_page_bytes = 4096;
constexpr size_t max_ring_bytes = 64 * 1024 * 1024;

class BpfRing {
public:
    enum class Kind { empty, busy, discard, record, corrupt };
    struct Slot {
        Kind kind;
        size_t offset = 0, size = 0, span = 0;
    };

    template<class Outside>
    BpfRing(uint64_t consumer, uint64_t producer, uint64_t control, size_t page, size_t capacity,
            Outside outside) : consumer_(reinterpret_cast<uint64_t*>(consumer)),
                               producer_(reinterpret_cast<const uint64_t*>(producer)), capacity_(capacity) {
        if (page != ring_page_bytes || capacity < page || capacity > max_ring_bytes ||
            (capacity & (capacity - 1))) throw std::runtime_error("invalid ring size");
        auto valid = [&](uint64_t address, size_t size) {
            return address && address % page == 0 && address <= UINT64_MAX - size &&
                   outside(reinterpret_cast<const void*>(address), size);
        };
        auto overlaps = [](uint64_t a, size_t as, uint64_t b, size_t bs) {
            return a < b + bs && b < a + as;
        };
        const auto mapping = page + 2 * capacity;
        if (!valid(consumer, page) || !valid(producer, mapping) || !valid(control, page) ||
            overlaps(consumer, page, producer, mapping) || overlaps(consumer, page, control, page) ||
            overlaps(producer, mapping, control, page)) throw std::runtime_error("invalid external ring mappings");
        asm volatile("lfence" ::: "memory");
        data_ = reinterpret_cast<const uint8_t*>(producer + page);
    }

    uint64_t consumer_position() const { return __atomic_load_n(consumer_, __ATOMIC_ACQUIRE); }

    uint64_t producer_position(uint64_t cursor) const {
        const auto tail = __atomic_load_n(producer_, __ATOMIC_ACQUIRE);
        if ((cursor & 7) || (tail & 7) || tail < cursor || tail - cursor > capacity_)
            throw std::runtime_error("invalid BPF ring positions");
        return tail;
    }

    // tail is a validated producer snapshot. An unpublished span has no safe next position.
    Slot next(uint64_t cursor, uint64_t tail) const {
        if (cursor == tail) return {Kind::empty};
        const size_t offset = cursor & (capacity_ - 1);
        auto* header = reinterpret_cast<const uint32_t*>(data_ + offset);
        const auto word = __atomic_load_n(header, __ATOMIC_ACQUIRE);
        constexpr uint32_t busy = 1U << 31, discard = 1U << 30;
        if (word & busy) return {Kind::busy};
        const size_t size = word & ~(busy | discard);
        const size_t span = (size + 15) & ~size_t(7);
        if (span > tail - cursor) return {Kind::corrupt};
        return {word & discard ? Kind::discard : Kind::record, offset, size, span};
    }

    // A published slot with an invalid payload length can be skipped by its verified span.
    bool copy(const Slot& slot, uint8_t* out, size_t minimum, size_t limit) const {
        if (slot.kind != Kind::record || slot.size < minimum || slot.size > limit) return false;
        std::memcpy(out, data_ + slot.offset + 8, slot.size);
        return true;
    }

    void release(uint64_t cursor) { __atomic_store_n(consumer_, cursor, __ATOMIC_RELEASE); }

private:
    uint64_t* consumer_;
    const uint64_t* producer_;
    const size_t capacity_;
    const uint8_t* data_;
};
