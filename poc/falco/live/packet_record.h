#pragma once

#include <linux/types.h>

/* Falco records start with a Unix timestamp in nanoseconds. */
#define RZ_PACKET_TAG (~(__u64)0)
#define RZ_SNAPLEN 16384

struct rz_packet_header {
    __u64 tag;
    __u64 timestamp_ns;
    __u32 wire_bytes;
    __u32 captured_bytes;
};
