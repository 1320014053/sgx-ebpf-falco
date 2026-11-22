#pragma once

#include <nlohmann/json.hpp>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>

namespace rz {
using Json = nlohmann::json;
using Publish = std::function<void(const Json&)>;

struct RavenOptions {
    size_t high = 128ULL * 1024 * 1024;
    bool metrics = false;
    static RavenOptions parse(const Json& config);
};

void retention_report(const Json& sample);

struct Inputs {
    std::string_view events;
    std::optional<std::string_view> packets;
    bool tetragon;
    bool host_capture = false;
    std::deque<Json>* pending = nullptr;
    RavenOptions retention;
};

Json raven(std::string_view events, bool tetragon, RavenOptions options = {});
void zeek(std::string_view packets, bool host_capture, Publish publish);
Json zeek(std::string_view packets, bool host_capture = false);

class RavenStream {
    struct State;
    std::unique_ptr<State> state;
public:
    explicit RavenStream(Publish publish, RavenOptions options = {});
    ~RavenStream();
    void event(const Json& row);
    void line(std::string_view line);
    void advance(double ts, bool finish = false);
};

class ZeekStream {
    struct State;
    std::unique_ptr<State> state;
public:
    explicit ZeekStream(Publish publish);
    ~ZeekStream();
    void packet(uint64_t ns, std::string_view ip);
    void advance(uint64_t ns, bool finish = false);
};

#ifdef RZ_ENCLAVE
extern thread_local const Inputs* trusted_inputs;
#endif
}
