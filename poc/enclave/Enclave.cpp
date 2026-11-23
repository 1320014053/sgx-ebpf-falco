#include "Enclave_t.h"
#include "event_logic.h"
#include <sgx_trts.h>
#include <sgx_utils.h>
#include <string.h>
#include <stdint.h>

static poc_u32 target;
static poc_stats totals;
static poc_ring_desc ring;
static bool registered;
static poc_event work[POC_BATCH_MAX];
static poc_u64 consumer;

static bool external_range(poc_u64 address, poc_u64 bytes)
{
    return address && bytes && address <= UINT64_MAX - bytes &&
           sgx_is_outside_enclave(reinterpret_cast<const void *>(address), bytes);
}

static bool overlap(poc_u64 a, poc_u64 an, poc_u64 b, poc_u64 bn)
{
    return a < b + bn && b < a + an;
}

void ecall_identity(uint64_t *flags, uint8_t *measurement, uint8_t *signer)
{
    const sgx_report_body_t &body = sgx_self_report()->body;
    *flags = body.attributes.flags;
    memcpy(measurement, body.mr_enclave.m, sizeof(body.mr_enclave.m));
    memcpy(signer, body.mr_signer.m, sizeof(body.mr_signer.m));
}

void ecall_config(uint32_t target_tgid)
{
    target = target_tgid;
    memset(&totals, 0, sizeof(totals));
    memset(&ring, 0, sizeof(ring));
    registered = false;
    consumer = 0;
}

int ecall_register(const poc_ring_desc *desc)
{
    if (!desc)
        return -1;
    registered = false;
    const poc_u64 p = desc->page_bytes;
    const poc_u64 c = desc->capacity;
    if (p != 4096 || c < p || c > POC_RING_BYTES || (c & (c - 1)) ||
        desc->consumer_bytes != p || desc->producer_bytes != p + 2 * c ||
        desc->control_bytes != p || (desc->consumer % p) ||
        (desc->producer % p) || (desc->control % p) ||
        !external_range(desc->consumer, p) ||
        !external_range(desc->producer, p + 2 * c) ||
        !external_range(desc->control, p))
        return -1;
    if (overlap(desc->consumer, p, desc->producer, p + 2 * c) ||
        overlap(desc->consumer, p, desc->control, p) ||
        overlap(desc->producer, p + 2 * c, desc->control, p))
        return -1;
    ring = *desc;
    consumer = __atomic_load_n(reinterpret_cast<const poc_u64 *>(ring.consumer), __ATOMIC_ACQUIRE);
    poc_u64 producer = __atomic_load_n(reinterpret_cast<const poc_u64 *>(ring.producer), __ATOMIC_ACQUIRE);
    totals.index_read_bytes += 16;
    if ((consumer & 7) || (producer & 7) || producer < consumer || producer - consumer > c)
        return -2;
    registered = true;
    return 0;
}

void ecall_event(const poc_event *event)
{
    if (!event) {
        ++totals.format_rejected;
        return;
    }
    totals.payload_copy_bytes += sizeof(*event);
    poc_process_event(event, target, &totals);
}

int ecall_batch(const poc_batch *batch)
{
    if (!batch || batch->count > POC_BATCH_MAX || batch->reserved)
        return -1;
    totals.payload_copy_bytes += batch->count * sizeof(poc_event);
    for (poc_u32 i = 0; i < batch->count; ++i)
        poc_process_event(&batch->events[i], target, &totals);
    return 0;
}

static int consume_step()
{
    if (!registered)
        return -1;
    for (unsigned int i = 0; i < POC_BATCH_MAX; ++i) {
        poc_u64 producer = __atomic_load_n(reinterpret_cast<const poc_u64 *>(ring.producer), __ATOMIC_ACQUIRE);
        totals.index_read_bytes += 8;
        totals.producer_pos = producer;
        totals.consumer_pos = consumer;
        if ((producer & 7) || producer < consumer || producer - consumer > ring.capacity)
            return -2;
        if (producer == consumer)
            return 0;
        if (producer - consumer < POC_RING_HEADER_BYTES)
            return -2;
        const poc_u64 offset = consumer & (ring.capacity - 1);
        const unsigned char *header = reinterpret_cast<const unsigned char *>(ring.producer + ring.page_bytes + offset);
        poc_u32 length_flags = __atomic_load_n(reinterpret_cast<const poc_u32 *>(header), __ATOMIC_ACQUIRE);
        totals.header_read_bytes += 4;
        if (length_flags & POC_RING_BUSY)
            return 0;
        poc_u32 page_offset = __atomic_load_n(reinterpret_cast<const poc_u32 *>(header + 4), __ATOMIC_RELAXED);
        (void)page_offset;
        totals.header_read_bytes += 4;
        poc_u64 length = length_flags & ~(POC_RING_BUSY | POC_RING_DISCARD);
        poc_u64 span = (length + POC_RING_HEADER_BYTES + 7) & ~7ULL;
        if (span > ring.capacity || span > producer - consumer ||
            offset + span > 2 * ring.capacity || consumer > UINT64_MAX - span)
            return -3;
        if (length_flags & POC_RING_DISCARD) {
            ++totals.discarded;
        } else {
            if (length != sizeof(poc_event))
                return -3;
            // Only the private copy is examined after this boundary copy.
            memcpy(&work[i], header + POC_RING_HEADER_BYTES, sizeof(poc_event));
            totals.payload_copy_bytes += sizeof(poc_event);
            poc_process_event(&work[i], target, &totals);
        }
        consumer += span;
        totals.consumer_pos = consumer;
        __atomic_store_n(reinterpret_cast<poc_u64 *>(ring.consumer), consumer, __ATOMIC_RELEASE);
    }
    return 1;
}

int ecall_step(poc_stats *stats)
{
    int result = consume_step();
    *stats = totals;
    return result;
}

int ecall_run(poc_stats *stats)
{
    if (!registered)
        return -1;
    const poc_control *control = reinterpret_cast<const poc_control *>(ring.control);
    for (;;) {
        int result = consume_step();
        if (result < 0) {
            *stats = totals;
            return result;
        }
        if (result > 0)
            continue;
        if (__atomic_load_n(&control->stop, __ATOMIC_ACQUIRE)) {
            // Reload after the stop acquire: the producer was detached before stop.
            result = consume_step();
            if (result < 0 || totals.consumer_pos == totals.producer_pos) {
                *stats = totals;
                return result < 0 ? result : 0;
            }
            // After detaching the single synchronous probe, BUSY cannot persist.
            if (result == 0) {
                *stats = totals;
                return -4;
            }
        }
        ++totals.idle_spins;
        __asm__ __volatile__("pause" ::: "memory");
    }
}

void ecall_stats(poc_stats *stats)
{
    *stats = totals;
}
