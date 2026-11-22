#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "packet_record.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct sample {
    struct rz_packet_header header;
    __u8 ip[RZ_SNAPLEN];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sample);
} scratch SEC(".maps");

const volatile __u64 boot_epoch_ns;
const volatile __u32 loopback_index;
__u64 submitted, dropped;

SEC("socket")
int capture_ip(struct __sk_buff *skb) {
    if (skb->protocol != bpf_htons(ETH_P_IP) && skb->protocol != bpf_htons(ETH_P_IPV6))
        return 0;
    if (skb->ifindex == loopback_index && skb->pkt_type == PACKET_OUTGOING)
        return 0;
    __u32 zero = 0;
    __u64 wire = skb->len;
    if (wire < 20)
        return 0;
    __u64 length = wire < RZ_SNAPLEN ? wire : RZ_SNAPLEN;
    struct sample *data = bpf_map_lookup_elem(&scratch, &zero);
    if (!data)
        return 0;
    data->header.tag = RZ_PACKET_TAG;
    data->header.timestamp_ns = boot_epoch_ns + bpf_ktime_get_boot_ns();
    data->header.wire_bytes = wire;
    data->header.captured_bytes = length;
    if (bpf_skb_load_bytes(skb, 0, data->ip, length) ||
        bpf_ringbuf_output(&events, data, sizeof(data->header) + length, 0))
        __sync_fetch_and_add(&dropped, 1);
    else
        __sync_fetch_and_add(&submitted, 1);
    return 0; /* The Falco ring is the only delivery path. */
}

char LICENSE[] SEC("license") = "GPL";
