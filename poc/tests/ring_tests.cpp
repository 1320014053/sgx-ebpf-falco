#include "Enclave_u.h"
#include "event_logic.h"
#include <sgx_urts.h>
#include <sys/mman.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void check(bool ok, const char *message)
{
    if (!ok) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}

struct Fixture {
    static const size_t page = 4096, capacity = 4096;
    unsigned char *consumer;
    unsigned char *producer;
    poc_control *control;
    poc_ring_desc desc;
    sgx_enclave_id_t enclave;
    Fixture(sgx_enclave_id_t id) : enclave(id)
    {
        consumer = static_cast<unsigned char *>(mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        producer = static_cast<unsigned char *>(mmap(nullptr, page + 2 * capacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        control = static_cast<poc_control *>(mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        check(consumer != MAP_FAILED && producer != MAP_FAILED && control != MAP_FAILED, "mock mmap");
        desc = {reinterpret_cast<uint64_t>(consumer), reinterpret_cast<uint64_t>(producer),
                reinterpret_cast<uint64_t>(control), page, page + 2 * capacity, page, page, capacity};
        reset();
    }
    ~Fixture()
    {
        munmap(consumer, page);
        munmap(producer, page + 2 * capacity);
        munmap(control, page);
    }
    void reset(uint64_t position = 0)
    {
        memset(consumer, 0, page);
        memset(producer, 0, page + 2 * capacity);
        memset(control, 0, page);
        *reinterpret_cast<uint64_t *>(consumer) = position;
        *reinterpret_cast<uint64_t *>(producer) = position;
        check(ecall_config(enclave, 123) == SGX_SUCCESS, "configure");
        int result;
        check(ecall_register(enclave, &result, &desc) == SGX_SUCCESS && result == 0, "register mock ring");
    }
    uint64_t append(const void *payload, uint32_t bytes, uint32_t flags = 0)
    {
        uint64_t position = *reinterpret_cast<uint64_t *>(producer);
        uint64_t offset = position & (capacity - 1);
        uint32_t header[2] = {bytes | flags, 0};
        unsigned char record[512] = {};
        memcpy(record, header, 8);
        if (payload) memcpy(record + 8, payload, bytes);
        size_t span = (bytes + 15) & ~7U;
        check(span <= sizeof(record), "test record size");
        for (size_t i = 0; i < span; ++i) {
            size_t slot = (offset + i) & (capacity - 1);
            producer[page + slot] = record[i];
            producer[page + capacity + slot] = record[i];
        }
        *reinterpret_cast<uint64_t *>(producer) = position + span;
        return offset;
    }
    int step(poc_stats *stats)
    {
        int result;
        check(ecall_step(enclave, &result, stats) == SGX_SUCCESS, "step SDK status");
        return result;
    }
};

static poc_event event(uint64_t seq)
{
    poc_event value = {};
    value.version = POC_EVENT_VERSION;
    value.type = POC_EVENT_GETPID;
    value.event_bytes = sizeof(value);
    value.timestamp_ns = 1;
    value.seq = seq;
    value.pid = value.tgid = 123;
    memcpy(value.comm, "poc-generator", 14);
    return value;
}

int main(int argc, char **argv)
{
    check(argc == 2, "provide signed enclave path");
    sgx_enclave_id_t enclave;
    sgx_status_t status = sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, nullptr, nullptr, &enclave, nullptr);
    if (status != SGX_SUCCESS) fprintf(stderr, "create enclave: 0x%08x\n", status);
    check(status == SGX_SUCCESS, "create SIM enclave");
    {
        Fixture ring(enclave);
        poc_stats stats = {};
        check(ring.step(&stats) == 0 && !stats.processed, "empty ring");
        ring.reset(Fixture::capacity - 16);
        for (unsigned i = 1; i <= 9; ++i) {
            poc_event value = event(i);
            ring.append(&value, sizeof(value));
        }
        check(ring.step(&stats) == 0 && stats.processed == 9 && stats.matched == 9, "double mapping wrap");
        check(stats.consumer_pos == stats.producer_pos && stats.payload_copy_bytes == 9 * 256, "consumer release and one payload copy");
        ring.reset();
        poc_event value = event(1);
        uint64_t slot = ring.append(&value, sizeof(value), POC_RING_BUSY);
        check(ring.step(&stats) == 0 && !stats.processed && !stats.consumer_pos, "BUSY does not advance");
        __atomic_store_n(reinterpret_cast<uint32_t *>(ring.producer + Fixture::page + slot), sizeof(value), __ATOMIC_RELEASE);
        check(ring.step(&stats) == 0 && stats.processed == 1, "BUSY commit resumes");
        ring.reset();
        ring.append(nullptr, 16, POC_RING_DISCARD);
        ring.append(&value, sizeof(value));
        check(ring.step(&stats) == 0 && stats.discarded == 1 && stats.processed == 1, "DISCARD skip");
        ring.reset();
        ring.append(nullptr, 16);
        check(ring.step(&stats) == -3 && !stats.processed && !stats.consumer_pos, "wrong record length bounded rejection");
        ring.reset();
        *reinterpret_cast<uint32_t *>(ring.producer + Fixture::page) = 0x3fffffff;
        *reinterpret_cast<uint64_t *>(ring.producer) = 264;
        check(ring.step(&stats) == -3 && !stats.consumer_pos, "oversized header bounded rejection");
        ring.reset();
        *reinterpret_cast<uint64_t *>(ring.producer) = Fixture::capacity + 8;
        check(ring.step(&stats) == -2, "producer beyond ring capacity");
        ring.reset(264);
        *reinterpret_cast<uint64_t *>(ring.producer) = 0;
        check(ring.step(&stats) == -2, "producer behind private consumer");
        ring.reset();
        *reinterpret_cast<uint64_t *>(ring.producer) = 9;
        check(ring.step(&stats) == -2, "unaligned producer");
        ring.reset();
        value.version = 2;
        ring.append(&value, sizeof(value));
        check(ring.step(&stats) == 0 && !stats.processed && stats.format_rejected == 1, "wrong version rejected after copy");
        ring.reset();
        value = event(1);
        ring.append(&value, sizeof(value));
        ring.append(&value, sizeof(value));
        check(ring.step(&stats) == 0 && stats.processed == 1 && stats.format_rejected == 1, "duplicate sequence rejected");
        ring.reset();
        poc_ring_desc bad = ring.desc;
        bad.producer = UINT64_MAX - 4095;
        int result;
        check(ecall_register(enclave, &result, &bad) == SGX_SUCCESS && result == -1, "descriptor overflow");
        bad = ring.desc;
        bad.control = bad.consumer;
        check(ecall_register(enclave, &result, &bad) == SGX_SUCCESS && result == -1, "overlapping control rejected");
        ring.reset();
        poc_batch batch = {};
        batch.count = 3;
        poc_stats ordinary = {};
        for (unsigned i = 0; i < batch.count; ++i) {
            batch.events[i] = event(i + 1);
            poc_process_event(&batch.events[i], 123, &ordinary);
            check(ecall_event(enclave, &batch.events[i]) == SGX_SUCCESS, "event ECALL");
        }
        check(ecall_stats(enclave, &stats) == SGX_SUCCESS && stats.matched == ordinary.matched, "ordinary and event replay agree");
        check(ecall_config(enclave, 123) == SGX_SUCCESS, "reset batch stats");
        check(ecall_batch(enclave, &result, &batch) == SGX_SUCCESS && result == 0, "partial batch accepted");
        check(ecall_stats(enclave, &stats) == SGX_SUCCESS && stats.processed == ordinary.processed && stats.matched == ordinary.matched, "batch replay agrees and tail preserved");
        batch.count = POC_BATCH_MAX + 1;
        check(ecall_batch(enclave, &result, &batch) == SGX_SUCCESS && result == -1, "batch count bound");
        ring.reset();
        value = event(1);
        ring.append(&value, sizeof(value));
        __atomic_store_n(&ring.control->stop, 1, __ATOMIC_RELEASE);
        check(ecall_run(enclave, &result, &stats) == SGX_SUCCESS && result == 0 && stats.processed == 1, "stop drains and returns");
        puts("PASS: SIM parser, wrap, BUSY, DISCARD, malformed input, descriptor bounds, replay, tail batch, stop/drain");
        puts("AUTHENTICATION GAP: a well-formed event in anonymous memory was accepted; no kernel-origin authentication is claimed.");
    }
    sgx_destroy_enclave(enclave);
    return 0;
}
