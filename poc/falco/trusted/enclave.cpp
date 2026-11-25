#include "Falco_t.h"
#include "../live/ring.hpp"
#include "live_errors.hpp"
#include "../live/packet_record.h"
#include "../plugin/detectors.hpp"
#include "raven_syscalls.hpp"
#include <array>
#include <atomic>
#include <cmath>
#include <condition_variable>
#include <mutex>
#include <cstring>
#include <falco_engine.h>
#include <falco_engine_version.h>
#include <formats.h>
#include <functional>
#include <libscap/scap_savefile.h>
#include <libscap/ringbuffer/devset.h>
#include <libsinsp/dns_manager.h>
#include <libsinsp/events/sinsp_events.h>
#include <libsinsp/filter_check_list.h>
#include <libsinsp/plugin_manager.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_config.h>
#include <nlohmann/json.hpp>
#include <openenclave/bits/fs.h>
#include <openenclave/enclave.h>
#include <set>
#include <sstream>
#include <sys/mount.h>
#include <variant>
#include <yaml_helper.h>

const plugin_api* container_api();
extern "C" const void* raven_zeek_api();

namespace {

void emit(const std::string& data, bool diagnostics) {
    int written = -1;
    if (falco_emit(&written, data.data(), data.size(), diagnostics) != OE_OK || written != 0) {
        throw std::runtime_error("failed to deliver Falco output");
    }
}

struct AlertBuffer {
    std::string alerts;
    uint64_t alert_count = 0;
    uint64_t alert_flushes = 0, alert_flush_bytes = 0;
    uint64_t event_count = 0;

    void flush() {
        if (!alerts.empty()) {
            emit(alerts, false);
            ++alert_flushes;
            alert_flush_bytes += alerts.size();
            alerts.clear();
        }
    }
};

struct Detector {
    sinsp inspector;
    sinsp_filter_check_list checks;
    std::unique_ptr<sinsp> plugin_inspector;
    filter_check_list plugin_checks;
    std::shared_ptr<falco_engine> engine = std::make_shared<falco_engine>();
    std::unique_ptr<falco_formats> formats;
    falco_common::rule_matching matching;
    falco::load_result::rules_contents_t rule_contents;
    std::vector<std::string> yaml_files;
    std::vector<std::string> paths;
    std::string hostname;
    AlertBuffer output, plugin_output;
    size_t source, plugin_source = 0;
    bool container_runtime = false;
    bool raven_enabled = false, zeek_enabled = false;
    bool buffered_outputs = true;
    bool spin = false;
    size_t block_count = 32, block_bytes = 256 * 1024;
    bool live_mode = false;
    bool live_select_allowed;
    bool base_syscalls_all = false;
    bool rules_ready = false;
    size_t loaded_rules = 0;
    std::string rules_summary;
    std::mutex format_mutex;
    LiveErrors errors;
    rz::RavenOptions retention;
    std::deque<rz::Json> stream_pending;
    std::unique_ptr<rz::RavenStream> stream;

    void configure_live_detectors(const YAML::Node& init) {
        auto options = rz::Json::object();
        if (init && init.IsMap()) {
            for (const auto& entry : init) {
                const auto key = entry.first.as<std::string>();
                const auto& value = entry.second;
                bool enabled;
                // Check the tag because yaml-cpp also decodes quoted strings as bool.
                if ((value.Tag() != "?" && value.Tag() != "tag:yaml.org,2002:bool") ||
                    !YAML::convert<bool>::decode(value, enabled))
                    throw std::runtime_error("raven_zeek init_config requires a boolean for " + key);
                options[key] = enabled;
            }
        } else if (init && !init.IsNull()) {
            if (!init.IsScalar()) throw std::runtime_error("raven_zeek init_config must be an object");
            options = rz::Json::parse(init.Scalar(), nullptr, false);
        }
        if (!options.is_object()) throw std::runtime_error("raven_zeek init_config must be an object");
        for (const auto& [key, value] : options.items()) {
            if (key != "raven" && key != "zeek") throw std::runtime_error("unknown raven_zeek init_config key: " + key);
            if (!value.is_boolean()) throw std::runtime_error("raven_zeek init_config requires a boolean for " + key);
        }
        raven_enabled = options.value("raven", true);
        zeek_enabled = options.value("zeek", true);
        if (!raven_enabled && !zeek_enabled)
            throw std::runtime_error("both detectors are disabled: remove raven_zeek from load_plugins");
    }

    Detector(const char* yaml, const char* host, bool live) : hostname(host), live_select_allowed(live) {
        const auto config = YAML::Load(yaml);
        paths = config["rules_files"].as<std::vector<std::string>>();
        if (paths.empty() || !config["json_output"].as<bool>(false) ||
            !falco_common::parse_rule_matching(config["rule_matching"].as<std::string>("first"), matching)) {
            throw std::runtime_error("expected rules_files, JSON output, and first/all rule matching");
        }
        yaml_files.reserve(paths.size());
        const auto plugins = config["plugins"];
        const auto names = config["load_plugins"].as<std::vector<std::string>>();
        YAML::Node plugin_settings;
        bool with_detectors = false;
        std::set<std::string> loaded;
        for (const auto& name : names) {
            auto entry = std::find_if(plugins.begin(), plugins.end(), [&](const auto& item) {
                return item["name"].template as<std::string>() == name;
            });
            if (entry == plugins.end() || !loaded.insert(name).second) throw std::runtime_error("invalid plugin: " + name);
            if (name == "container") plugin_settings.reset(*entry);
            else if (name == "raven_zeek") {
                with_detectors = true;
                if (live) configure_live_detectors((*entry)["init_config"]);
                auto params = (*entry)["open_params"];
                if (params && !params.IsNull()) retention = rz::RavenOptions::parse(rz::Json::parse(params.as<std::string>()));
            }
            else throw std::runtime_error("unknown compiled plugin: " + name);
        }
        if (!loaded.count("container")) throw std::runtime_error("expected the container plugin");
        const auto init = plugin_settings["init_config"];
        const auto settings = !init || init.IsNull() ? nlohmann::json::object()
                                : init.IsMap() ? init.as<nlohmann::json>()
                                               : nlohmann::json::parse(init.as<std::string>());
        if (live) {
            const auto base = config["base_syscalls"];
            if (base && !base.IsNull()) {
                const char* message = "falco-live implements only base_syscalls.all";
                if (!base.IsMap()) throw std::runtime_error(message);
                for (const auto& entry : base) {
                    if (!entry.first.IsScalar()) throw std::runtime_error(message);
                    const auto key = entry.first.Scalar();
                    const auto& value = entry.second;
                    if (key == "custom_set" && value.IsSequence() && value.size() == 0) continue;
                    if (key != "all" && key != "repair") throw std::runtime_error(message);
                    bool enabled;
                    if ((value.Tag() != "?" && value.Tag() != "tag:yaml.org,2002:bool") ||
                        !YAML::convert<bool>::decode(value, enabled) || (key == "repair" && enabled))
                        throw std::runtime_error(message);
                    if (key == "all") base_syscalls_all = enabled;
                }
            }
            buffered_outputs = config["buffered_outputs"].as<bool>(false);
            const auto idle = config["idle"].as<std::string>("sleep");
            if (idle != "sleep" && idle != "spin") throw std::runtime_error("idle must be sleep or spin");
            spin = idle == "spin";
            block_count = config["live_block_count"].as<size_t>(block_count);
            block_bytes = config["live_block_bytes"].as<size_t>(block_bytes);
            if (!block_count || block_bytes < max_event_bytes + sizeof(block_header) + 9 ||
                block_bytes > max_ring_bytes || block_count > SIZE_MAX / block_bytes)
                throw std::runtime_error("invalid live block pool size");
#ifdef FALCO_SGX_FAULT_INJECTION
            if (const auto fault = config["fault_injection"]) {
                errors.stage = fault["stage"].as<std::string>();
                errors.first = fault["first"].as<uint64_t>(1);
                errors.repeat = fault["repeat"].as<uint64_t>(1);
            }
#endif
            const auto engines = settings.value("engines", nlohmann::json::object());
            for (const auto* runtime : {"docker", "podman", "containerd", "cri", "lxc", "libvirt_lxc", "bpm"}) {
                container_runtime |= engines.value(runtime, nlohmann::json::object()).value("enabled", true);
            }
            if (container_runtime &&
                (oe_load_module_host_socket_interface() != OE_OK ||
                 mount("/", "/", OE_HOST_FILE_SYSTEM, MS_RDONLY, nullptr) != 0)) {
                throw std::runtime_error("failed to initialize container worker POSIX modules");
            }
        }
        auto plugin = inspector.register_plugin(container_api());
        std::string error;
        if (!plugin->init(settings.dump(), error)) {
            throw std::runtime_error(error);
        }
        checks.add_filter_check(sinsp_plugin::new_filtercheck(plugin));
        engine->set_min_priority(falco_common::parse_priority(config["priority"].as<std::string>("debug")));
        auto filter = std::make_shared<sinsp_filter_factory>(&inspector, checks);
        auto formatter = std::make_shared<sinsp_evt_formatter_factory>(&inspector, checks);
        formatter->set_output_format(sinsp_evt_formatter::OF_JSON);
        source = engine->add_source(falco_common::syscall_source, filter, formatter);
        if (with_detectors) {
            plugin_inspector = std::make_unique<sinsp>();
            auto rz_plugin = plugin_inspector->register_plugin(static_cast<const plugin_api*>(raven_zeek_api()));
            if (!rz_plugin->init("", error)) throw std::runtime_error(error);
            plugin_checks.add_filter_check(plugin_inspector->new_generic_filtercheck());
            plugin_checks.add_filter_check(sinsp_plugin::new_filtercheck(rz_plugin));
            auto rz_filter = std::make_shared<sinsp_filter_factory>(plugin_inspector.get(), plugin_checks);
            auto rz_format = std::make_shared<sinsp_evt_formatter_factory>(plugin_inspector.get(), plugin_checks);
            rz_format->set_output_format(sinsp_evt_formatter::OF_JSON);
            plugin_source = engine->add_source("raven_zeek", rz_filter, rz_format);
        }
        for (const auto& output : config["append_output"]) {
            for (const auto& field : output["extra_fields"]) {
                auto match = output["match"];
                engine->add_extra_output_raw_field(field.as<std::string>(), match && match["source"]
                    ? match["source"].as<std::string>() : "", {}, "");
            }
        }
        formats = std::make_unique<falco_formats>(
            engine, config["json_include_output_property"].as<bool>(true),
            config["json_include_tags_property"].as<bool>(true),
            config["json_include_message_property"].as<bool>(false),
            config["json_include_output_fields_property"].as<bool>(true),
            config["time_format_iso_8601"].as<bool>(false));
    }

    void load(const std::string& path, const char* yaml) {
        if (loaded_rules != yaml_files.size() || loaded_rules >= paths.size() || path != paths[loaded_rules]) {
            throw std::runtime_error("rule file is out of order or absent from rules_files: " + path);
        }
        yaml_files.emplace_back(yaml);
        rule_contents.emplace(path, std::cref(yaml_files.back()));
        auto result = engine->load_rules(rule_contents.at(path), path);
        emit(path + " | schema validation: " + result->schema_validation() + "\n", true);
        if (!result->successful()) {
            throw std::runtime_error(result->as_string(true, rule_contents));
        }
        if (result->has_warnings()) {
            emit(result->as_string(true, rule_contents) + "\n", true);
        }
        ++loaded_rules;
    }

    const std::string& ready() {
        if (rules_ready) return rules_summary;
        if (loaded_rules != paths.size() || rule_contents.size() != paths.size()) {
            throw std::runtime_error("not all configured rules were loaded");
        }
        std::string error;
        auto plugins = inspector.get_plugin_manager()->plugins();
        if (plugin_inspector) {
            const auto& extra = plugin_inspector->get_plugin_manager()->plugins();
            plugins.insert(plugins.end(), extra.begin(), extra.end());
        }
        std::vector<falco_engine::plugin_version_requirement> versions;
        for (const auto& plugin : plugins) {
            versions.push_back({plugin->name(), plugin->plugin_version().as_string()});
        }
        if (!engine->check_plugin_requirements(versions, error)) {
            throw std::runtime_error(error);
        }
        const auto desc = engine->describe_rule(nullptr, plugins);
        nlohmann::json enabled = nlohmann::json::array();
        for (const auto& rule : desc.at("rules")) {
            const auto& info = rule.at("info");
            if (info.at("enabled") == true) {
                enabled.push_back(info.at("name"));
            }
        }
        rules_summary = nlohmann::json{{"engine", FALCO_ENGINE_VERSION}, {"libs", SINSP_VERSION_STRING},
                                       {"required_engine_version", desc.at("required_engine_version")},
                                       {"loaded_rules", desc.at("rules").size()}, {"enabled", enabled}}.dump() + "\n";
        engine->complete_rule_loading();
        rules_ready = true;
        return rules_summary;
    }

    void select_live_syscalls(uint8_t* ppm_sc) {
        namespace events = libsinsp::events;
        ready();
        const auto rules_sc = engine->sc_codes_for_ruleset(falco_common::syscall_source);
        events::set<ppm_event_code> plugin_events;
        for (const auto& plugin : inspector.get_plugin_manager()->plugins()) {
            if (plugin->caps() & CAP_PARSING) plugin_events = plugin_events.merge(plugin->parse_event_codes());
        }
        const auto state_sc = events::sinsp_state_sc_set();
        auto selected = rules_sc.merge(events::event_set_to_sc_set(plugin_events)).merge(state_sc);
        if (!base_syscalls_all) selected = selected.diff(events::io_sc_set().diff(state_sc));
        selected.insert(PPM_SC_SCHED_PROCESS_EXIT);

        events::set<ppm_sc_code> raven_added;
        if (plugin_inspector && raven_enabled) {
            raven_added = RavenSyscalls::sc_set().diff(selected);
            selected = selected.merge(raven_added);
        }
        for (const auto code : selected) ppm_sc[code] = 1;

        const auto names = [](const events::set<ppm_sc_code>& codes) {
            const auto unordered = events::sc_set_to_event_names(codes);
            return std::set<std::string>(unordered.begin(), unordered.end());
        };
        emit(nlohmann::ordered_json{{"mode", "event_selection"}, {"base_syscalls_all", base_syscalls_all},
                                    {"selected", names(selected)}, {"raven_added", names(raven_added)},
                                    {"rules_not_activated", names(rules_sc.diff(selected))}}.dump() + "\n", true);
    }

    template<class Operation>
    bool attempt(Stage stage, Operation operation) {
        if (live_mode) return errors.run(stage, operation, [](const auto& msg) { emit(msg, true); });
        operation();
        return true;
    }

    bool process(sinsp_evt* evt, size_t expected_source) {
        const bool plugin = plugin_inspector && expected_source == plugin_source;
        auto& out = live_mode && plugin ? plugin_output : output;
        ++out.event_count;
        if (evt->get_source_idx() != expected_source) throw std::runtime_error("unexpected Falco event source");
        decltype(engine->process_event(expected_source, evt, matching)) matches;
        if (!attempt(plugin ? Stage::plugin_match : Stage::match,
                     [&] { matches = engine->process_event(expected_source, evt, matching); }))
            return false;
        if (!matches) return true;
        auto start = out.alerts.size();
        if (!attempt(plugin ? Stage::plugin_format : Stage::format, [&] {
            for (const auto& match : *matches) {
                std::string text;
                {
                    // Analysis and detection format alerts concurrently. Pinned libsinsp calls
                    // non-reentrant gmtime() in both gmt2local() and its ISO 8601 formatter.
                    std::lock_guard<std::mutex> lock(format_mutex);
                    text = formats->format_event(evt, match.rule, match.source,
                                                 falco_common::format_priority(match.priority_num),
                                                 match.format, match.tags, hostname, match.extra_output_fields);
                }
                out.alerts += text;
                out.alerts += '\n';
            }
        })) {
            out.alerts.resize(start);
            return false;
        }
        out.alert_count += matches->size();
        if ((live_mode && !buffered_outputs) || out.alerts.size() >= 64 * 1024) {
            out.flush();
        }
        return true;
    }

    void open_plugin(rz::Inputs& inputs) {
        rz::trusted_inputs = &inputs;
        try {
            plugin_inspector->open_plugin("raven_zeek", "", sinsp_plugin_platform::SINSP_PLATFORM_GENERIC);
        } catch (...) {
            rz::trusted_inputs = nullptr;
            throw;
        }
        rz::trusted_inputs = nullptr;
        plugin_inspector->start_capture();
    }

    void inspect_plugin(bool live) {
        sinsp_evt* evt = nullptr;
        for (;;) {
            auto status = plugin_inspector->next(&evt);
            if (status == SCAP_EOF || (live && status == SCAP_TIMEOUT)) break;
            if (status == SCAP_TIMEOUT || status == SCAP_FILTERED_EVENT) continue;
            if (status != SCAP_SUCCESS) {
                (live_mode ? plugin_output : output).flush();
                throw std::runtime_error(plugin_inspector->getlasterr());
            }
            process(evt, plugin_source);
        }
    }

    void inspect_blocks(const std::function<void(sinsp_evt&)>& record = {},
                        const std::function<void(sinsp_evt&)>& on_syscall = {}) {
        sinsp_evt* evt = nullptr;
        for (;;) {
            const auto result = inspector.next(&evt);
            if (!attempt(Stage::batch, [&] {
                if (result != SCAP_SUCCESS && result != SCAP_EOF && result != SCAP_FILTERED_EVENT &&
                    result != SCAP_TIMEOUT) throw std::runtime_error(inspector.getlasterr());
            })) return;
            if (result == SCAP_EOF) {
                break;
            }
            if (record && evt && (result == SCAP_SUCCESS || result == SCAP_FILTERED_EVENT)) {
                record(*evt);
            }
            if (result == SCAP_FILTERED_EVENT || result == SCAP_TIMEOUT) {
                continue;
            }
            if (process(evt, source) && on_syscall) on_syscall(*evt);
        }
    }
};

std::unique_ptr<Detector> detector;

int fail(const std::exception& error) {
    const std::string message = std::string(error.what()) + '\n';
    int ignored;
    falco_emit(&ignored, message.data(), message.size(), true);
    return 1;
}

constexpr size_t block_prefix = sizeof(block_header) + sizeof(uint16_t);
constexpr size_t block_overhead = block_prefix + sizeof(uint32_t) + 3;

uint32_t frame_event(uint8_t* block, const scap_evt& event, uint16_t cpu = 0) {
    const uint32_t kind = (scap_event_getinfo(&event)->flags & EF_LARGE_PAYLOAD)
                              ? EV_BLOCK_TYPE_V2_LARGE : EV_BLOCK_TYPE_V2;
    const uint32_t total = (event.len + block_overhead) & ~size_t(3);
    const block_header framing{kind, total};
    std::memcpy(block, &framing, sizeof(framing));
    std::memcpy(block + sizeof(framing), &cpu, sizeof(cpu));
    std::memset(block + block_prefix + event.len, 0, total - block_prefix - event.len - sizeof(total));
    std::memcpy(block + total - sizeof(total), &total, sizeof(total));
    return total;
}

bool valid_event(const scap_evt& event, const uint8_t* data, size_t bytes) {
    if (event.type >= PPM_EVENT_MAX) return false;
    const auto* info = scap_event_getinfo(&event);
    if (!info || info->category == EC_UNKNOWN || (info->flags & EF_UNUSED) ||
        event.len != bytes || event.nparams != info->nparams) {
        return false;
    }
    const size_t width = (info->flags & EF_LARGE_PAYLOAD) ? sizeof(uint32_t) : sizeof(uint16_t);
    const auto header = sizeof(event) + width * event.nparams;
    if (header > bytes) {
        return false;
    }
    auto remaining = bytes - header;
    for (size_t i = 0; i < event.nparams; ++i) {
        uint32_t size = 0;
        std::memcpy(&size, data + sizeof(event) + width * i, width);
        if (size > remaining) {
            return false;
        }
        remaining -= size;
    }
    return remaining == 0;
}

} // namespace

int falco_config(const char* yaml, const char* hostname, uint8_t live) {
    try {
        if (umount("/proc/self") != 0) {
            throw std::runtime_error("failed to unmount the container worker's startup procfs");
        }
        if (live) {
            if (oe_load_module_host_resolver() != OE_OK) {
                throw std::runtime_error("failed to initialize the live DNS resolver");
            }
            sinsp_dns_manager::get().use_live_resolver();
        }
        detector = std::make_unique<Detector>(yaml, hostname, live != 0);
        return 0;
    } catch (const std::exception& error) {
        return fail(error);
    }
}

int falco_rules(const char* path, const char* yaml) {
    try {
        detector->load(path, yaml);
        return 0;
    } catch (const std::exception& error) {
        return fail(error);
    }
}

int falco_plugin_replay(uint8_t* events, size_t event_size, uint8_t* packets, size_t packet_size,
                        uint8_t have_pcap, uint8_t tetragon, uint8_t host_capture) {
    try {
        if (!detector->plugin_inspector) throw std::runtime_error("enable raven_zeek in load_plugins");
        if (event_size > 64 * 1024 * 1024 || packet_size > 64 * 1024 * 1024) throw std::runtime_error("capture too large");
        rz::Inputs inputs{{event_size ? reinterpret_cast<char*>(events) : "", event_size}, {}, tetragon != 0, host_capture != 0};
        if (have_pcap) inputs.packets = std::string_view(packet_size ? reinterpret_cast<char*>(packets) : "", packet_size);
        inputs.retention = detector->retention;
        detector->open_plugin(inputs);
        detector->inspect_plugin(false);
        detector->plugin_inspector->close();
        detector->output.flush();
        return 0;
    } catch (const std::exception& error) {
        rz::trusted_inputs = nullptr;
        if (detector->plugin_inspector) detector->plugin_inspector->close();
        return fail(error);
    }
}

int falco_plugin_stream(uint8_t* lines, size_t bytes, uint8_t finish) {
    try {
        if (!detector->plugin_inspector || bytes > 64*1024*1024) throw std::runtime_error("invalid RAVEN stream batch");
        if (!detector->stream) {
            rz::Inputs input{{},{},false,false,&detector->stream_pending};
            detector->open_plugin(input);
            detector->stream = std::make_unique<rz::RavenStream>([](const auto& row) {
                detector->stream_pending.push_back(row);
            },detector->retention);
        }
        auto drain = [] {
            if (!detector->stream_pending.empty()) detector->inspect_plugin(true);
            detector->output.flush();
        };
        std::string_view text(bytes ? reinterpret_cast<char*>(lines) : "",bytes);
        while (!text.empty()) {
            auto end = text.find('\n');
            if (end == text.npos) throw std::runtime_error("stream batch ends inside an event");
            detector->stream->line(text.substr(0,end));
            text.remove_prefix(end+1);
            if (!detector->stream_pending.empty()) drain();
        }
        if (finish) {
            detector->stream->advance(0,true); drain();
            detector->plugin_inspector->close();
            if (detector->retention.metrics) rz::retention_report({{"phase","flushed"}});
            detector->stream.reset();
        }
        return 0;
    } catch (const std::exception& e) {
        if (detector->plugin_inspector) detector->plugin_inspector->close();
        detector->stream.reset(); detector->stream_pending.clear();
        return fail(e);
    }
}

int falco_replay(uint8_t* bytes, size_t size, const char* dns_hosts) {
    uint64_t length = size;
    try {
        std::istringstream entries(dns_hosts);
        std::string line;
        while (std::getline(entries, line)) {
            line.resize(std::min(line.size(), line.find('#')));
            char* next = nullptr;
            const auto* address = strtok_r(line.data(), " \t\r", &next);
            if (!address) {
                continue;
            }
            const auto* name = strtok_r(nullptr, " \t\r", &next);
            if (!name) {
                throw std::runtime_error(std::string("DNS hosts entry has no hostname: ") + address);
            }
            do {
                if (!sinsp_dns_manager::get().add_replay_address(name, address)) {
                    throw std::runtime_error(std::string("invalid address in DNS hosts file: ") + address);
                }
            } while ((name = strtok_r(nullptr, " \t\r", &next)));
        }
        emit(detector->ready(), true);
        auto& inspector = detector->inspector;
        inspector.open_raw_block(&bytes, &length);
        inspector.start_capture();
        detector->inspect_blocks();
        inspector.close();
        detector->output.flush();
        emit(nlohmann::json{{"events", detector->output.event_count}, {"alerts", detector->output.alert_count},
                            {"scap_bytes", size}}.dump() + "\n", true);
        return 0;
    } catch (const std::exception& error) {
        detector->inspector.close();
        return fail(error);
    }
}

namespace {

struct PacketOffset { size_t offset; };
struct DetectorTick { uint64_t ns; bool finish; };
using DetectorInput = std::variant<rz::Json, PacketOffset, DetectorTick>;

struct Batch {
    explicit Batch(size_t size) : bytes(size) {}
    std::vector<uint8_t> bytes;
    std::vector<size_t> packets;
    std::vector<DetectorInput> detection;
    size_t used = 0;
    uint64_t tick = 0;
    bool idle = false, finish = false;
};

struct LiveCapture {
    BpfRing ring;
    RingControl* control;
    const size_t capacity;
    const bool record;
    const uint8_t record_inputs;
    std::vector<uint8_t> snapshot;
    uint8_t* input;
    uint64_t input_bytes;
    const uint32_t collector_pid;
    const uint64_t initial_consumer;
    uint64_t cursor, tail;
    std::array<uint64_t, PPM_EVENT_MAX> types{};
    uint64_t records = 0, accepted = 0, discarded = 0, rejected = 0, wrapped = 0;
    uint64_t copied = 0, scans = 0, headers = 0, writes = 0, busy = 0, idle_polls = 0;
    uint64_t packet_records = 0, raven_events = 0, trace_bytes = 0;
    size_t min_event = max_event_bytes, max_event = 0;
    std::deque<rz::Json> pending;
    RavenSyscalls syscalls;
    std::unique_ptr<rz::RavenStream> raven;
    std::unique_ptr<rz::ZeekStream> zeek;

    std::vector<Batch> pool;
    std::mutex mutex;
    std::condition_variable changed;
    uint64_t submitted = 0, analyzed = 0, released = 0, stalls = 0, peak_blocks = 0;
    bool drained = false;
    std::atomic<bool> failed{false};
    std::atomic<unsigned> roles{0}, completed{0};

    LiveCapture(uint8_t* data, size_t bytes, uint64_t consumer, uint64_t producer, uint64_t ctl,
                size_t page, size_t cap, bool save, uint8_t inputs)
        : ring(consumer, producer, ctl, page, cap, oe_is_outside_enclave),
          control(reinterpret_cast<RingControl*>(ctl)), capacity(cap), record(save), record_inputs(inputs),
          snapshot(data, data + bytes), input(snapshot.data()), input_bytes(bytes),
          collector_pid(__atomic_load_n(&control->collector_pid, __ATOMIC_ACQUIRE)),
          initial_consumer(ring.consumer_position()), cursor(initial_consumer), tail(ring.producer_position(cursor)) {
        if (inputs && !detector->plugin_inspector)
            throw std::runtime_error("recording detector inputs requires raven_zeek in load_plugins");
        if ((inputs & record_host_events) && !detector->raven_enabled)
            throw std::runtime_error("--record-inputs EVENTS requires the RAVEN detector");
        if ((inputs & record_ip_packets) && !detector->zeek_enabled)
            throw std::runtime_error("--record-inputs PACKETS requires the Zeek detector");
        pool.reserve(detector->block_count);
        for (size_t i = 0; i < detector->block_count; ++i) pool.emplace_back(detector->block_bytes);
        emit(detector->ready(), true);
        auto& inspector = detector->inspector;
        inspector.open_raw_block(&input, &input_bytes, detector->container_runtime);
        inspector.start_capture();
        if (inspector.get_bytes_read() != bytes)
            throw std::runtime_error("live input must begin with a metadata-only .scap snapshot");
        if (detector->plugin_inspector) {
            if (detector->raven_enabled) syscalls.seed_from_snapshot(inspector);
            rz::Inputs plugin_inputs{{},{},false,true,&pending};
            detector->open_plugin(plugin_inputs);
            auto publish = [this](const rz::Json& row) {
                if (!std::isfinite(row.at("ts").get<double>())) throw std::runtime_error("invalid plugin timestamp");
                pending.push_back(row);
            };
            if (detector->raven_enabled) raven = std::make_unique<rz::RavenStream>(publish, detector->retention);
            if (detector->zeek_enabled) zeek = std::make_unique<rz::ZeekStream>(publish);
        }
    }

    bool has_detectors() const { return raven || zeek; }

    void cancel() {
        std::lock_guard<std::mutex> lock(mutex);
        failed = true;
        changed.notify_all();
    }

    void ingest() {
        uint32_t retry_us = BUFFER_EMPTY_WAIT_TIME_US_START;
        uint64_t stopped_busy = 0, last_tick = 0;
        while (!failed) {
            auto flags = __atomic_load_n(&control->flags, __ATOMIC_ACQUIRE);
            if (flags & ring_abort) throw std::runtime_error("host aborted live capture");
            const bool stopping = flags & ring_stop;
            tail = ring.producer_position(cursor);
            ++scans;
            const bool empty = cursor == tail;
            const auto tick = empty ? __atomic_load_n(&control->realtime_ns, __ATOMIC_ACQUIRE) : 0;
            const bool finish = empty && stopping;
            const bool poll = empty && (finish || detector->container_runtime || (has_detectors() && tick > last_tick));
            const auto before = cursor;
            if (!empty || poll) {
                {
                    std::unique_lock<std::mutex> lock(mutex);
                    if (submitted - released == pool.size()) {
                        ++stalls;
                        changed.wait(lock, [&] { return failed || submitted - released < pool.size(); });
                    }
                    if (failed) return;
                    peak_blocks = std::max(peak_blocks, submitted - released + 1);
                }
                auto& batch = pool[submitted % pool.size()];
                batch.used = 0;
                batch.packets.clear();
                batch.idle = empty;
                batch.finish = finish;
                batch.tick = tick;
                auto& used = batch.used;
                for (size_t i = 0; i < 256 && cursor < tail &&
                     batch.bytes.size() - used >= max_event_bytes + block_overhead; ++i) {
                    const auto slot = ring.next(cursor, tail);
                    ++headers;
                    if (slot.kind == BpfRing::Kind::busy) {
                        ++busy;
                        if (stopping && ++stopped_busy == 1000000) {
                            throw std::runtime_error("BPF ring record stayed busy after capture stopped");
                        }
                        break;
                    }

                    if (slot.kind == BpfRing::Kind::corrupt) {
                        throw std::runtime_error("BPF record extends beyond the published ring position");
                    }
                    cursor += slot.span;
                    ++records;
                    wrapped += slot.offset + slot.span > capacity;
                    stopped_busy = 0;
                    if (slot.kind == BpfRing::Kind::discard) {
                        ++discarded;
                        continue;
                    }
                    auto* block = batch.bytes.data() + used;
                    auto* payload = block + block_prefix;
                    if (!ring.copy(slot, payload, sizeof(scap_evt), max_event_bytes)) {
                        ++rejected;
                        continue;
                    }

                    const auto size = slot.size;
                    copied += size;
                    rz_packet_header packet;
                    static_assert(sizeof(packet) <= sizeof(scap_evt));
                    std::memcpy(&packet, payload, sizeof(packet));
                    if (packet.tag == RZ_PACKET_TAG) {
                        if (!zeek || packet.captured_bytes != size - sizeof(packet) ||
                            !packet.captured_bytes || packet.captured_bytes > RZ_SNAPLEN ||
                            packet.captured_bytes > packet.wire_bytes) {
                            ++rejected;
                            continue;
                        }
                        batch.packets.push_back(used);
                        used += (block_prefix + size + 3) & ~size_t(3);
                        ++accepted;
                        min_event = std::min(min_event, size);
                        max_event = std::max(max_event, size);
                        continue;
                    }
                    scap_evt event;
                    std::memcpy(&event, payload, sizeof(event));
                    if (!valid_event(event, payload, size)) {
                        ++rejected;
                        continue;
                    }

                    used += frame_event(block, event);
                    ++accepted;
                    ++types[event.type];
                    min_event = std::min(min_event, size);
                    max_event = std::max(max_event, size);
                }

                if (cursor != before) {
                    ring.release(cursor);
                    ++writes;
                }
                if (used || poll || (cursor != before && detector->container_runtime)) {
                    std::lock_guard<std::mutex> lock(mutex);
                    ++submitted;
                    drained = finish;
                    changed.notify_all();
                    if (finish) return;
                }
                if (poll) last_tick = std::max(last_tick, tick);
            }
            if (cursor != before) {
                retry_us = BUFFER_EMPTY_WAIT_TIME_US_START;
            } else {
                ++idle_polls;
                if (detector->spin || stopping) __builtin_ia32_pause();
                else {
                    if (falco_sleep(retry_us) != OE_OK) throw std::runtime_error("ring sleep OCALL failed");
                    retry_us = std::min<uint32_t>(retry_us * 2, BUFFER_EMPTY_WAIT_TIME_US_MAX);
                }
            }
        }
    }

    void analyze() {
        auto& inspector = detector->inspector;
        std::vector<uint8_t> trace;
        uint64_t last_tick = 0;
        auto flush_trace = [&]() {
            if (!trace.empty()) {
                int written = -1;
                if (falco_trace_append(&written, trace.data(), trace.size()) != OE_OK || written != 0) {
                    throw std::runtime_error("failed to save event blocks from the enclave");
                }
                trace_bytes += trace.size();
                trace.clear();
            }
        };
        std::function<void(sinsp_evt&)> record_merged;
        if (record && detector->container_runtime) {
            record_merged = [&](sinsp_evt& evt) {
                const auto* event = evt.get_scap_evt();
                const auto offset = trace.size();
                const auto size = (event->len + block_overhead) & ~size_t(3);
                trace.resize(offset + size);
                auto* block = trace.data() + offset;
                std::memcpy(block + block_prefix, event, event->len);
                frame_event(block, *event, evt.get_cpuid());
                if (trace.size() >= 128 * 1024) {
                    flush_trace();
                }
            };
        }

        std::function<void(sinsp_evt&)> on_syscall;
        std::vector<DetectorInput>* ordered = nullptr;
        auto queue_tick = [&](uint64_t ns, bool finish) {
            last_tick = std::max(last_tick, ns);
            ordered->emplace_back(DetectorTick{last_tick, finish});
        };
        auto archive = [&](const void* data, size_t size, uint64_t ns, uint32_t wire) {
            int result = -1;
            if (falco_record_input(&result, static_cast<const uint8_t*>(data), size, ns, wire) != OE_OK || result)
                throw std::runtime_error("could not save detector test input");
        };
        if (has_detectors()) {
            on_syscall = [&](sinsp_evt& evt) {
                // A busy syscall ring may have no idle poll between TCP timeouts.
                auto ns = evt.get_ts();
                if (ns > last_tick && ns - last_tick >= 100000000) queue_tick(ns, false);
                if (!raven) return;
                rz::Json row;
                if (!detector->attempt(Stage::translate, [&] { row = syscalls.translate(evt, collector_pid); })) return;
                if (row.is_null()) return;
                ++raven_events;
                if (record_inputs & record_host_events) {
                    auto line = row.dump(-1, ' ', false, rz::Json::error_handler_t::replace);
                    archive(line.data(), line.size(), evt.get_ts(), 0);
                }
                ordered->emplace_back(std::move(row));
            };
        }
#ifdef FALCO_SGX_FAULT_INJECTION
        uint64_t batch_number = 0;
#endif
        auto consume = [&](uint8_t* data, size_t size) {
            input = data;
            input_bytes = size;
#ifdef FALCO_SGX_FAULT_INJECTION
            if (size && ++batch_number == detector->errors.first && detector->errors.stage == "raw_block")
                input_bytes = 1;
#endif
            inspector.fseek(0);
            detector->inspect_blocks(record_merged, on_syscall);
            if (size && record && !detector->container_runtime) {
                trace.insert(trace.end(), data, data + size);
                if (trace.size() >= 128 * 1024) flush_trace();
            }
            // libsinsp retains both pointers. Idle polls must never revisit a released block.
            input = snapshot.data();
            input_bytes = 0;
            inspector.fseek(0);
        };
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(mutex);
                changed.wait(lock, [&] { return failed || analyzed != submitted || drained; });
                if (failed) return;
                if (analyzed == submitted) break;
            }
            auto& batch = pool[analyzed % pool.size()];
            ordered = &batch.detection;
            auto* data = batch.bytes.data();
            if (has_detectors() && batch.idle && !batch.finish && batch.tick > last_tick) queue_tick(batch.tick, false);
            size_t begin = 0;
            for (auto offset : batch.packets) {
                if (offset > begin) consume(data + begin, offset - begin);
                rz_packet_header packet;
                std::memcpy(&packet, data + offset + block_prefix, sizeof(packet));
                auto* ip = data + offset + block_prefix + sizeof(packet);
                ordered->emplace_back(PacketOffset{offset});
                if (record_inputs & record_ip_packets) archive(ip, packet.captured_bytes, packet.timestamp_ns, packet.wire_bytes);
                begin = offset + ((block_prefix + sizeof(packet) + packet.captured_bytes + 3) & ~size_t(3));
            }
            if (batch.used > begin) consume(data + begin, batch.used - begin);
            else if (detector->container_runtime) consume(snapshot.data(), 0);
            if (has_detectors() && batch.finish) queue_tick(batch.tick, true);
            {
                std::lock_guard<std::mutex> lock(mutex);
                ++analyzed;
                if (!has_detectors()) released = analyzed;
                changed.notify_all();
            }
        }
        detector->output.flush();
        flush_trace();
    }

    void detect() {
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(mutex);
                changed.wait(lock, [&] { return failed || released != analyzed; });
                if (failed) return;
            }
            auto& batch = pool[released % pool.size()];
            for (const auto& work : batch.detection) {
                if (auto* row = std::get_if<rz::Json>(&work)) {
                    const auto before = pending.size();
                    const auto sequence = raven->seen() + 1;
                    if (!detector->attempt(Stage::raven, [&] { raven->event(*row); })) {
                        const auto discarded = pending.size() - before;
                        pending.resize(before);
                        raven->error_gap(sequence, discarded);
                    }
                } else if (auto* packet = std::get_if<PacketOffset>(&work)) {
                    auto* payload = batch.bytes.data() + packet->offset + block_prefix;
                    rz_packet_header header;
                    std::memcpy(&header, payload, sizeof(header));
                    auto* ip = reinterpret_cast<const char*>(payload + sizeof(header));
                    const auto before = pending.size();
                    if (!detector->attempt(Stage::zeek, [&] {
                        zeek->packet(header.timestamp_ns, {ip, header.captured_bytes});
                    })) pending.resize(before);
                    ++packet_records;
                } else {
                    const auto& tick = std::get<DetectorTick>(work);
                    auto before = pending.size();
                    if (raven && !detector->attempt(Stage::raven_advance, [&] {
                        raven->advance(double(tick.ns) / 1e9, tick.finish);
                    })) {
                        // A tick consumes no event, so the gap ends at the last event already fed.
                        const auto discarded = pending.size() - before;
                        pending.resize(before);
                        raven->error_gap(raven->seen(), discarded);
                    }
                    before = pending.size();
                    if (packet_records && !detector->attempt(Stage::zeek_advance, [&] {
                        zeek->advance(tick.ns, tick.finish);
                    })) pending.resize(before);
                }
            }
            if (!pending.empty()) detector->inspect_plugin(true);
            const bool finish = batch.finish;
            batch.detection.clear();
            {
                std::lock_guard<std::mutex> lock(mutex);
                ++released;
                changed.notify_all();
            }
            if (finish) break;
        }
        detector->plugin_output.flush();
        if (raven && detector->retention.metrics) rz::retention_report({{"phase","flushed"}});
    }

    unsigned role_mask() const { return has_detectors() ? 7u : 3u; }

    void report() {
        nlohmann::json event_types = nlohmann::json::object();
        for (size_t i = 0; i < types.size(); ++i) {
            if (types[i]) {
                auto& count = event_types[scap_get_event_info_table()[i].name];
                count = (count.is_null() ? 0 : count.get<uint64_t>()) + types[i];
            }
        }
        nlohmann::json errors = nlohmann::json::object();
        for (size_t i = 0; i < stage_names.size(); ++i) errors[stage_names[i]] = detector->errors.counts[i].failures;
        emit(nlohmann::json{{"mode", "live"}, {"errors", errors}, {"records", records}, {"accepted", accepted},
                            {"detectors", {{"raven", bool(raven)}, {"zeek", bool(zeek)}}},
                            {"packet_records", packet_records}, {"raven_events", raven_events},
                            {"discarded", discarded}, {"format_rejected", rejected}, {"wrapped", wrapped},
                            {"busy_observations", busy}, {"payload_copy_bytes", copied},
                            {"index_read_bytes", 8 * (scans + 2)}, {"control_read_bytes", 4 * scans},
                            {"header_read_bytes", 4 * headers}, {"consumer_write_bytes", 8 * writes},
                            {"initial_consumer", initial_consumer}, {"consumer", cursor}, {"producer", tail},
                            {"events", detector->output.event_count + detector->plugin_output.event_count},
                            {"alerts", detector->output.alert_count + detector->plugin_output.alert_count},
                            {"alert_flushes", detector->output.alert_flushes + detector->plugin_output.alert_flushes},
                            {"alert_flush_bytes", detector->output.alert_flush_bytes + detector->plugin_output.alert_flush_bytes},
                            {"idle_polls", idle_polls}, {"ingest_stalls", stalls},
                            {"block_count", pool.size()}, {"block_bytes", detector->block_bytes},
                            {"peak_blocks", peak_blocks},
                            {"event_types", event_types}, {"min_event_bytes", accepted ? min_event : 0},
                            {"max_event_bytes", max_event}, {"snapshot_bytes", snapshot.size()},
                            {"trace_bytes", trace_bytes}}.dump() + "\n", true);
    }
};

std::mutex live_mutex;
std::shared_ptr<LiveCapture> live;

} // namespace

int falco_live_select(uint8_t* ppm_sc, size_t bytes) {
    std::lock_guard<std::mutex> lock(live_mutex);
    try {
        if (!ppm_sc || bytes != PPM_SC_MAX) throw std::runtime_error("invalid live syscall table");
        std::memset(ppm_sc, 0, bytes);
        if (!detector || !detector->live_select_allowed)
            throw std::runtime_error("select live syscalls after live configuration and before capture setup");
        detector->select_live_syscalls(ppm_sc);
        return 0;
    } catch (const std::exception& error) {
        return fail(error);
    }
}

int falco_live_setup(uint8_t* snapshot, size_t bytes, uint64_t consumer, uint64_t producer,
                     uint64_t control, size_t page, size_t capacity, uint8_t record, uint8_t inputs) {
    std::lock_guard<std::mutex> lock(live_mutex);
    try {
        if (live) throw std::runtime_error("live capture already configured");
        if (!bytes || bytes > max_ring_bytes) throw std::runtime_error("invalid snapshot size");
        live = std::make_shared<LiveCapture>(snapshot, bytes, consumer, producer, control, page, capacity, record, inputs);
        if (live->has_detectors())
            __atomic_fetch_or(&live->control->flags, ring_detectors | (live->zeek ? ring_packets : 0), __ATOMIC_RELEASE);
        detector->live_mode = true;
        detector->live_select_allowed = false;
        return 0;
    } catch (const std::exception& error) {
        if (!live) {
            detector->inspector.close();
            if (detector->plugin_inspector) detector->plugin_inspector->close();
        }
        return fail(error);
    }
}

int falco_live_run(uint8_t role) {
    std::shared_ptr<LiveCapture> capture;
    {
        std::lock_guard<std::mutex> lock(live_mutex);
        capture = live;
        if (!capture || role > detection_role || !(capture->role_mask() & (1u << role)) ||
            (capture->roles.fetch_or(1u << role) & (1u << role)))
            return fail(std::runtime_error("invalid or already claimed live role"));
        if (capture->roles == capture->role_mask())
            __atomic_fetch_or(&capture->control->flags, ring_ready, __ATOMIC_RELEASE);
    }
    int result = 0;
    try {
        if (role == ingest_role) capture->ingest();
        else if (role == analysis_role) capture->analyze();
        else capture->detect();
    } catch (const std::exception& error) {
        capture->cancel();
        result = fail(error);
    }
    capture->completed.fetch_or(1u << role);
    return result;
}

// Wakes every role without ending the capture; the host still calls falco_live_finish once.
void falco_live_cancel() {
    std::lock_guard<std::mutex> lock(live_mutex);
    if (live) live->cancel();
}

int falco_live_finish() {
    std::lock_guard<std::mutex> lock(live_mutex);
    if (!live) return fail(std::runtime_error("live capture has not been configured"));
    if (live->roles != live->completed) {
        live->cancel();
        return fail(std::runtime_error("live capture still has running roles"));
    }
    auto capture = std::move(live);
    detector->live_mode = false;
    try {
        detector->inspector.close();
        if (detector->plugin_inspector) detector->plugin_inspector->close();
        capture->report();
        return capture->failed || capture->completed != capture->role_mask();
    } catch (const std::exception& error) {
        return fail(error);
    }
}
