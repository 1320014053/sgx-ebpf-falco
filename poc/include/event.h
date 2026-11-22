#ifndef POC_EVENT_H
#define POC_EVENT_H

#ifdef __BPF__
#include <linux/types.h>
typedef __u16 poc_u16;
typedef __u32 poc_u32;
typedef __u64 poc_u64;
#else
#include <stdint.h>
typedef uint16_t poc_u16;
typedef uint32_t poc_u32;
typedef uint64_t poc_u64;
#endif

#define POC_EVENT_VERSION 1
#define POC_EVENT_GETPID 1
#define POC_EVENT_BYTES 256
#define POC_RING_BYTES (1024 * 1024)
#define POC_BATCH_MAX 64
#define POC_RING_BUSY (1U << 31)
#define POC_RING_DISCARD (1U << 30)
#define POC_RING_HEADER_BYTES 8

struct poc_event {
    poc_u16 version;
    poc_u16 type;
    poc_u32 event_bytes;
    poc_u64 timestamp_ns;
    poc_u64 seq;
    poc_u32 pid;
    poc_u32 tgid;
    poc_u32 cpu_id;
    poc_u32 flags;
    char comm[16];
    unsigned char reserved[200];
};

struct poc_probe_config {
    poc_u32 target_tgid;
};

struct poc_bpf_stats {
    poc_u64 attempted;
    poc_u64 submitted;
    poc_u64 reserve_failed;
};

struct poc_batch {
    poc_u32 count;
    poc_u32 reserved;
    struct poc_event events[POC_BATCH_MAX];
};

struct poc_ring_desc {
    poc_u64 consumer;
    poc_u64 producer;
    poc_u64 control;
    poc_u64 consumer_bytes;
    poc_u64 producer_bytes;
    poc_u64 control_bytes;
    poc_u64 page_bytes;
    poc_u64 capacity;
};

struct poc_control {
    poc_u32 stop;
    poc_u32 reserved;
};

struct poc_stats {
    poc_u64 processed;
    poc_u64 matched;
    poc_u64 format_rejected;
    poc_u64 last_seq;
    poc_u64 payload_copy_bytes;
    poc_u64 header_read_bytes;
    poc_u64 index_read_bytes;
    poc_u64 discarded;
    poc_u64 idle_spins;
    poc_u64 consumer_pos;
    poc_u64 producer_pos;
};

struct poc_generator_report {
    poc_u64 calls;
    poc_u64 cpu_ns;
    poc_u64 wall_ns;
};

#if defined(__cplusplus)
static_assert(sizeof(poc_event) == POC_EVENT_BYTES, "event layout");
static_assert(sizeof(poc_batch) == 8 + POC_BATCH_MAX * POC_EVENT_BYTES, "batch layout");
#else
_Static_assert(sizeof(struct poc_event) == POC_EVENT_BYTES, "event layout");
#endif
#endif
