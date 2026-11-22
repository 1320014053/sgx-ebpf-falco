#include <state.h>

int falco_open_ring_map(void) {
    if (g_state.n_required_buffers != 1 || g_state.allocate_online_only) {
        errno = EINVAL;
        return -1;
    }
    const int array_fd = bpf_map__fd(g_state.skel->maps.ringbuf_maps);
    uint32_t cpu = 0;
    uint32_t map_id;
    if (bpf_map_lookup_elem(array_fd, &cpu, &map_id) != 0) {
        return -1;
    }
    for (cpu = 1; cpu < (uint32_t)g_state.n_possible_cpus; ++cpu) {
        uint32_t other;
        if (bpf_map_lookup_elem(array_fd, &cpu, &other) != 0) {
            return -1;
        }
        if (other != map_id) {
            errno = EINVAL;
            return -1;
        }
    }
    return bpf_map_get_fd_by_id(map_id);
}
