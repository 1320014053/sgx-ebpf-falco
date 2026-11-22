#include "detectors.hpp"
#include <falcosecurity/sdk.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#ifndef RZ_ENCLAVE
#include "../capture.hpp"
#endif

#ifdef RZ_ENCLAVE
namespace rz {
thread_local const Inputs* trusted_inputs = nullptr;
}
#endif

namespace {
using namespace falcosecurity;
using rz::Json;

class Replay {
    Json detections, notices;
    size_t index = 0;
    events::pluginevent_e_encoder encoder;
    std::string& last_error;
    std::string replay_error;
    bool loaded = false;
#ifdef RZ_ENCLAVE
    rz::Inputs inputs;
#else
    std::string params;
    struct StreamInput {
        std::ifstream source;
        std::deque<Json> pending;
        std::unique_ptr<rz::RavenStream> detector;
        bool finished = false;
    };
    std::shared_ptr<StreamInput> stream;
#endif

    void load() {
#ifndef RZ_ENCLAVE
        auto cfg = Json::parse(params);
        if (cfg.contains("format") && cfg.at("format") == "stream") {
            stream = std::make_shared<StreamInput>();
            stream->source.open(cfg.at("events").get<std::string>());
            if (!stream->source) throw std::runtime_error("cannot open RAVEN stream");
            stream->detector = std::make_unique<rz::RavenStream>([p=stream.get()](const auto& row){ p->pending.push_back(row); },rz::RavenOptions::parse(cfg));
            loaded = true;
            return;
        }
#endif
        try {
#ifdef RZ_ENCLAVE
            detections = rz::raven(inputs.events, inputs.tetragon, inputs.retention);
#else
            auto format = cfg.value("format", "replay");
            if (format != "replay" && format != "tetragon") throw std::runtime_error("invalid RAVEN format");
            detections = rz::raven(rz::read_capture(cfg.at("events")), format == "tetragon", rz::RavenOptions::parse(cfg));
#endif
        } catch (const std::exception& error) {
            replay_error = std::string("RAVEN input: ") + error.what();
        }
        try {
            auto publish = [this](const Json& notice) { notices.push_back(notice); };
#ifdef RZ_ENCLAVE
            if (inputs.packets) rz::zeek(*inputs.packets, inputs.host_capture, publish);
#else
            rz::zeek(rz::read_capture(cfg.at("pcap")), cfg.value("host_capture", false), publish);
#endif
        } catch (const std::exception& error) {
            if (!replay_error.empty()) {
                // libscap's 256-byte error buffer must fit diagnostics from both sources.
                if (replay_error.size() > 128) {
                    replay_error.erase(replay_error.rfind(' ', 124));
                    replay_error += "...";
                }
                replay_error += '\n';
            }
            replay_error += std::string("Zeek input: ") + error.what();
        }
        loaded = true;
    }

public:
    virtual ~Replay() = default;
#ifdef RZ_ENCLAVE
    Replay(std::string& error, rz::Inputs data) : last_error(error), inputs(data) {}
#else
    Replay(std::string& error, std::string data) : last_error(error), params(std::move(data)) {}
#endif

    result_code next_event(event_writer& event) try {
        Json row;
#ifdef RZ_ENCLAVE
        if (inputs.pending) {
            if (inputs.pending->empty()) return result_code::SS_PLUGIN_TIMEOUT;
            row = std::move(inputs.pending->front());
            inputs.pending->pop_front();
        } else
#endif
        {
            if (!loaded) load();
#ifndef RZ_ENCLAVE
            if (stream) {
                std::string line;
                while (stream->pending.empty() && !stream->finished) {
                    if (std::getline(stream->source,line)) stream->detector->line(line);
                    else {
                        if (!stream->source.eof()) throw std::runtime_error("error reading RAVEN stream");
                        stream->detector->advance(0,true);
                        stream->finished = true;
                    }
                }
                if (stream->pending.empty()) return result_code::SS_PLUGIN_EOF;
                row = std::move(stream->pending.front()); stream->pending.pop_front();
            } else
#endif
            {
                if (index == detections.size() + notices.size()) {
                    if (replay_error.empty()) return result_code::SS_PLUGIN_EOF;
                    last_error = replay_error;
                    return result_code::SS_PLUGIN_FAILURE;
                }
                row = std::move(index < detections.size() ? detections[index] : notices[index - detections.size()]);
                ++index;
            }
        }
        double ts = row.at("ts");
        if (!std::isfinite(ts)) throw std::runtime_error("non-finite event timestamp");
        auto ns = static_cast<long double>(ts) * 1000000000.0L;
        encoder.set_ts(static_cast<uint64_t>(std::clamp(ns, 0.0L, static_cast<long double>(UINT64_MAX-1))));
        auto text = row.dump(-1, ' ', false, Json::error_handler_t::replace);
        encoder.set_data(text.data(), text.size());
        encoder.encode(event);
        return result_code::SS_PLUGIN_SUCCESS;
    } catch (const std::exception& error) {
        last_error = error.what();
        return result_code::SS_PLUGIN_FAILURE;
    }
};

class Plugin {
    std::string last_error;
public:
    virtual ~Plugin() = default;
    std::string get_name() { return "raven_zeek"; }
    std::string get_version() { return "1.0.0"; }
    std::string get_description() { return "RAVEN full correlation and Zeek TCP scan detection"; }
    std::string get_contact() { return "SGX Falco POC"; }
    uint32_t get_id() { return 999; } // Falco's reserved development ID.
    std::string get_event_source() { return "raven_zeek"; }
    std::vector<std::string> get_extract_event_sources() { return {"raven_zeek"}; }
    bool init(init_input&) { return true; }
    std::string get_last_error() { return last_error; }

    std::unique_ptr<Replay> open(const std::string& params) {
#ifdef RZ_ENCLAVE
        if (!params.empty() || !rz::trusted_inputs) throw std::runtime_error("missing enclave capture");
        return std::make_unique<Replay>(last_error, *rz::trusted_inputs);
#else
        return std::make_unique<Replay>(last_error, params);
#endif
    }

    std::vector<field_info> get_fields() {
        using type = field_value_type;
        return {{type::FTYPE_STRING, "rz.rule", "Detection rule", "RAVEN rule or Zeek Notice type"},
                {type::FTYPE_STRING, "rz.state", "Disposition", "active, context_filtered, or notice"},
                {type::FTYPE_STRING, "rz.result", "Detection JSON", "Complete detection record"}};
    }

    bool extract(const extract_fields_input& input) {
        auto& request = input.get_extract_request();
        const auto& reader = input.get_event_reader();
        const auto* header = static_cast<const _internal::ss_plugin_event*>(reader.get_buf());
        constexpr size_t prefix = sizeof(*header) + 3*sizeof(uint32_t);
        if (header->nparams != 2 || header->len < prefix) throw std::runtime_error("invalid plugin event header");
        uint32_t lengths[2];
        std::memcpy(lengths, header + 1, sizeof(lengths));
        if (lengths[0] != sizeof(uint32_t) || lengths[1] != header->len-prefix) {
            throw std::runtime_error("invalid plugin event parameters");
        }
        events::pluginevent_e_decoder decoded(reader);
        uint32_t size;
        auto* bytes = static_cast<const char*>(decoded.get_data(size));
        std::string text(bytes, size);
        if (request.get_field_id() == 2) {
            request.set_value(text);
        } else {
            auto row = Json::parse(text);
            if (request.get_field_id() == 0) request.set_value(row.at(row.contains("note") ? "note" : "rule").get<std::string>());
            else request.set_value(row.value("state", "notice"));
        }
        return true;
    }
};
}

#ifdef RZ_ENCLAVE
#undef FALCOSECURITY_EXPORT
#define FALCOSECURITY_EXPORT static
#endif
FALCOSECURITY_PLUGIN(Plugin)
FALCOSECURITY_PLUGIN_EVENT_SOURCING(Plugin, Replay)
FALCOSECURITY_PLUGIN_FIELD_EXTRACTION(Plugin)

#ifdef RZ_ENCLAVE
extern "C" const void* raven_zeek_api() {
    using namespace falcosecurity::_internal;
    static const plugin_api api = [] {
        plugin_api out{};
#define ENTRY(name) out.name = plugin_##name
        ENTRY(get_required_api_version); ENTRY(get_version); ENTRY(get_name); ENTRY(get_description);
        ENTRY(get_contact); ENTRY(get_last_error); ENTRY(init); ENTRY(destroy); ENTRY(get_id);
        ENTRY(get_init_schema); ENTRY(set_config); ENTRY(get_metrics); ENTRY(get_required_event_schema_version);
        ENTRY(get_event_source); ENTRY(open); ENTRY(close); ENTRY(next_batch);
        ENTRY(get_progress); ENTRY(list_open_params); ENTRY(event_to_string);
        ENTRY(get_fields); ENTRY(get_extract_event_sources); ENTRY(get_extract_event_types); ENTRY(extract_fields);
#undef ENTRY
        return out;
    }();
    return &api;
}
#endif
