#pragma once

#include "../plugin/detectors.hpp"
#include <libsinsp/events/sinsp_events_set.h>
#include <libsinsp/sinsp.h>
#include <unordered_map>

class RavenSyscalls {
    std::unordered_map<int64_t, uint32_t> effective_uids;
public:
    static libsinsp::events::set<ppm_sc_code> sc_set();
    void seed_from_snapshot(const sinsp& inspector);
    rz::Json translate(sinsp_evt& evt, uint32_t collector_pid);
};
