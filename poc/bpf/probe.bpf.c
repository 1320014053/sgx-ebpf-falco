#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "event.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, POC_RING_BYTES);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct poc_probe_config);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct poc_bpf_stats);
} counters SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_getpid")
int on_getpid(void *ctx)
{
    (void)ctx;
    __u32 key = 0;
    struct poc_probe_config *cfg = bpf_map_lookup_elem(&config, &key);
    __u64 ids = bpf_get_current_pid_tgid();
    if (!cfg || (__u32)(ids >> 32) != cfg->target_tgid)
        return 0;
    struct poc_bpf_stats *stats = bpf_map_lookup_elem(&counters, &key);
    if (!stats)
        return 0;
    __u64 seq = __sync_fetch_and_add(&stats->attempted, 1) + 1;
    struct poc_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        __sync_fetch_and_add(&stats->reserve_failed, 1);
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->version = POC_EVENT_VERSION;
    event->type = POC_EVENT_GETPID;
    event->event_bytes = sizeof(*event);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->seq = seq;
    event->pid = (__u32)ids;
    event->tgid = ids >> 32;
    event->cpu_id = bpf_get_smp_processor_id();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    __sync_fetch_and_add(&stats->submitted, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
