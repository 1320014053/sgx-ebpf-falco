#include "Falco_t.h"
#include "../live/ring.hpp"
#include "../live/packet_record.h"
#include "../plugin/detectors.hpp"
#include "raven_syscalls.hpp"
#include <array>
#include <cstring>
#include <falco_engine.h>
#include <falco_engine_version.h>
#include <formats.h>
#include <functional>
#include <libscap/scap_savefile.h>
#include <libsinsp/dns_manager.h>
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
    std::string alerts;
    uint64_t alert_count = 0;
    uint64_t event_count = 0;
    size_t source, plugin_source = 0;
    bool container_runtime = false;
    rz::RavenOptions retention;
    std::deque<rz::Json> stream_pending;
    std::unique_ptr<rz::RavenStream> stream;

    Detector(const char* yaml, const char* host, bool live) : hostname(host) {
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
        if (rule_contents.size() >= paths.size() || path != paths[rule_contents.size()]) {
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
    }

    void ready() {
        if (rule_contents.size() != paths.size()) {
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
        emit(nlohmann::json{{"engine", FALCO_ENGINE_VERSION}, {"libs", SINSP_VERSION_STRING},
                            {"required_engine_version", desc.at("required_engine_version")},
                            {"loaded_rules", desc.at("rules").size()}, {"enabled", enabled}}.dump() + "\n", true);
        engine->complete_rule_loading();
    }

    void flush() {
        if (!alerts.empty()) {
            emit(alerts, false);
            alerts.clear();
        }
    }

    void process(sinsp_evt* evt, size_t expected_source) {
        ++event_count;
        if (evt->get_source_idx() != expected_source) throw std::runtime_error("unexpected Falco event source");
        auto matches = engine->process_event(expected_source, evt, matching);
        if (!matches) {
            return;
        }
        for (const auto& match : *matches) {
            alerts += formats->format_event(evt, match.rule, match.source,
                                           falco_common::format_priority(match.priority_num),
                                           match.format, match.tags, hostname, match.extra_output_fields);
            alerts += '\n';
            ++alert_count;
        }
        if (alerts.size() >= 64 * 1024) {
            flush();
        }
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
                flush();
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
            if (result == SCAP_EOF) {
                break;
            }
            if (record && evt && (result == SCAP_SUCCESS || result == SCAP_FILTERED_EVENT)) {
                record(*evt);
            }
            if (result == SCAP_FILTERED_EVENT || result == SCAP_TIMEOUT) {
                continue;
            }
            if (result != SCAP_SUCCESS) {
                throw std::runtime_error(inspector.getlasterr());
            }
            process(evt, source);
            if (on_syscall) on_syscall(*evt);
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

bool outside(uint64_t address, size_t size, size_t page) {
    return address != 0 && address % page == 0 && address <= UINT64_MAX - size &&
           oe_is_outside_enclave(reinterpret_cast<const void*>(address), size);
}

bool overlaps(uint64_t a, size_t a_size, uint64_t b, size_t b_size) {
    return a < b + b_size && b < a + a_size;
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
        detector->flush();
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
            detector->flush();
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
        detector->ready();
        auto& inspector = detector->inspector;
        inspector.open_raw_block(&bytes, &length);
        inspector.start_capture();
        detector->inspect_blocks();
        inspector.close();
        detector->flush();
        emit(nlohmann::json{{"events", detector->event_count}, {"alerts", detector->alert_count},
                            {"scap_bytes", size}}.dump() + "\n", true);
        return 0;
    } catch (const std::exception& error) {
        detector->inspector.close();
        return fail(error);
    }
}

int falco_live(uint8_t* snapshot, size_t bytes, uint64_t consumer, uint64_t producer,
               uint64_t control, size_t page, size_t capacity, uint8_t record, uint8_t record_inputs) {
    try {
        if (page != ring_page_bytes || capacity < page || capacity > max_ring_bytes ||
            (capacity & (capacity - 1)) != 0 || bytes == 0 || bytes > max_ring_bytes) {
            throw std::runtime_error("invalid ring or snapshot size");
        }
        const auto producer_size = page + 2 * capacity;
        if (!outside(consumer, page, page) || !outside(producer, producer_size, page) ||
            !outside(control, page, page) || overlaps(consumer, page, producer, producer_size) ||
            overlaps(consumer, page, control, page) || overlaps(producer, producer_size, control, page)) {
            throw std::runtime_error("invalid external ring mappings");
        }
        asm volatile("lfence" ::: "memory");
        auto* consumer_pos = reinterpret_cast<uint64_t*>(consumer);
        auto* producer_pos = reinterpret_cast<const uint64_t*>(producer);
        auto* flags = reinterpret_cast<uint32_t*>(control);
        auto* control_page = reinterpret_cast<const RingControl*>(control);
        const auto collector_pid = __atomic_load_n(&control_page->collector_pid, __ATOMIC_ACQUIRE);
        auto* ring = reinterpret_cast<const uint8_t*>(producer + page);
        const auto initial_consumer = __atomic_load_n(consumer_pos, __ATOMIC_ACQUIRE);
        auto cursor = initial_consumer;

        auto* input = snapshot;
        uint64_t input_bytes = bytes;
        detector->ready();
        auto& inspector = detector->inspector;
        inspector.open_raw_block(&input, &input_bytes, detector->container_runtime);
        inspector.start_capture();
        if (inspector.get_bytes_read() != bytes) {
            throw std::runtime_error("live input must begin with a metadata-only .scap snapshot");
        }

        constexpr uint32_t busy_bit = 1U << 31;
        constexpr uint32_t discard_bit = 1U << 30;
        constexpr size_t ring_header = 8;
        std::vector<uint8_t> batch(256 * 1024);
        std::vector<uint8_t> trace;
        std::array<uint64_t, PPM_EVENT_MAX> types{};
        uint64_t records = 0, accepted = 0, discarded = 0, rejected = 0, wrapped = 0;
        uint64_t copied = 0, scans = 0, headers = 0, writes = 0, busy = 0, stopped_busy = 0;
        uint64_t trace_bytes = 0;
        uint64_t tail = cursor;
        size_t min_event = max_event_bytes, max_event = 0;
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

        uint64_t packet_records = 0, raven_events = 0, last_tick = 0;
        std::deque<rz::Json> pending;
        auto publish = [&](const rz::Json& row) { pending.push_back(row); };
        std::unique_ptr<rz::RavenStream> raven;
        std::unique_ptr<rz::ZeekStream> zeek;
        RavenSyscalls syscalls;
        std::function<void(sinsp_evt&)> on_syscall;
        auto advance_live_time = [&](uint64_t ns, bool finish) {
            last_tick = std::max(last_tick, ns);
            double time = double(last_tick) / 1e9;
            raven->advance(time, finish);
            if (packet_records) zeek->advance(last_tick, finish);
        };
        auto archive = [&](const void* data, size_t size, uint64_t ns, uint32_t wire) {
            int result = -1;
            if (falco_record_input(&result, static_cast<const uint8_t*>(data), size, ns, wire) != OE_OK || result)
                throw std::runtime_error("could not save detector test input");
        };
        if (detector->plugin_inspector) {
            syscalls.seed_from_snapshot(inspector);
            rz::Inputs inputs{{},{},false,true,&pending};
            detector->open_plugin(inputs);
            raven = std::make_unique<rz::RavenStream>(publish, detector->retention);
            zeek = std::make_unique<rz::ZeekStream>(publish);
            on_syscall = [&](sinsp_evt& evt) {
                // A busy syscall ring may have no idle poll between TCP timeouts.
                auto ns = evt.get_ts();
                if (ns > last_tick && ns - last_tick >= 100000000) advance_live_time(ns, false);
                auto row = syscalls.translate(evt, collector_pid);
                if (row.is_null()) return;
                ++raven_events;
                if (record_inputs & record_host_events) {
                    auto line = row.dump(-1, ' ', false, rz::Json::error_handler_t::replace);
                    archive(line.data(), line.size(), evt.get_ts(), 0);
                }
                raven->event(row);
            };
        } else if (record_inputs) {
            throw std::runtime_error("recording detector inputs requires raven_zeek in load_plugins");
        }
        auto deliver = [&] {
            if (!pending.empty()) detector->inspect_plugin(true);
            if (raven) detector->flush();
        };
        __atomic_fetch_or(flags, ring_ready | (raven ? ring_detectors : 0), __ATOMIC_RELEASE);
        for (;;) {
            const bool stopping = __atomic_load_n(flags, __ATOMIC_ACQUIRE) & ring_stop;
            tail = __atomic_load_n(producer_pos, __ATOMIC_ACQUIRE);
            ++scans;
            if ((cursor & 7) || (tail & 7) || tail < cursor || tail - cursor > capacity) {
                throw std::runtime_error("invalid BPF ring positions");
            }
            if (stopping && tail == cursor && detector->container_runtime) {
                detector->inspect_blocks(record_merged, on_syscall);
            }
            if (tail == cursor && raven) {
                auto tick = __atomic_load_n(&control_page->realtime_ns, __ATOMIC_ACQUIRE);
                if (tick > last_tick || stopping) {
                    advance_live_time(tick, stopping);
                    deliver();
                }
            }
            if (stopping && tail == cursor) {
                break;
            }

            const auto before = cursor;
            size_t used = 0;
            auto consume_syscalls = [&] {
                if (!used) return;
                input = batch.data();
                input_bytes = used;
                inspector.fseek(0);
                detector->inspect_blocks(record_merged, on_syscall);
                if (record && !detector->container_runtime) {
                    trace.insert(trace.end(), batch.begin(), batch.begin() + used);
                    if (trace.size() >= 128 * 1024) flush_trace();
                }
                used = 0;
            };
            for (size_t i = 0; i < 256 && cursor < tail &&
                 batch.size() - used >= max_event_bytes + block_overhead; ++i) {
                const auto offset = cursor & (capacity - 1);
                auto* header = reinterpret_cast<const uint32_t*>(ring + offset);
                const auto word = __atomic_load_n(header, __ATOMIC_ACQUIRE);
                ++headers;
                if (word & busy_bit) {
                    ++busy;
                    if (stopping && ++stopped_busy == 1000000) {
                        throw std::runtime_error("BPF ring record stayed busy after capture stopped");
                    }
                    break;
                }

                const size_t size = word & ~(busy_bit | discard_bit);
                const size_t span = (size + ring_header + 7) & ~size_t(7);
                if (span > tail - cursor) {
                    throw std::runtime_error("BPF record extends beyond the published ring position");
                }
                cursor += span;
                ++records;
                wrapped += offset + span > capacity;
                stopped_busy = 0;
                if (word & discard_bit) {
                    ++discarded;
                    continue;
                }
                if (size < sizeof(scap_evt) || size > max_event_bytes) {
                    ++rejected;
                    continue;
                }

                auto* block = batch.data() + used;
                auto* payload = block + block_prefix;
                std::memcpy(payload, ring + offset + ring_header, size);
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
                    consume_syscalls();
                    auto* ip = payload + sizeof(packet);
                    zeek->packet(packet.timestamp_ns,
                                 {reinterpret_cast<const char*>(ip), packet.captured_bytes});
                    if (record_inputs & record_ip_packets)
                        archive(ip, packet.captured_bytes, packet.timestamp_ns, packet.wire_bytes);
                    ++packet_records;
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

            if (used) {
                consume_syscalls();
            } else if (detector->container_runtime) {
                detector->inspect_blocks(record_merged, on_syscall);
            }
            deliver();
            if (cursor != before) {
                __atomic_store_n(consumer_pos, cursor, __ATOMIC_RELEASE);
                ++writes;
            } else {
                __builtin_ia32_pause();
            }
        }

        inspector.close();
        if (detector->plugin_inspector) detector->plugin_inspector->close();
        detector->flush();
        flush_trace();
        if (raven && detector->retention.metrics) rz::retention_report({{"phase","flushed"}});
        nlohmann::json event_types = nlohmann::json::object();
        for (size_t i = 0; i < types.size(); ++i) {
            if (types[i]) {
                auto& count = event_types[scap_get_event_info_table()[i].name];
                count = (count.is_null() ? 0 : count.get<uint64_t>()) + types[i];
            }
        }
        emit(nlohmann::json{{"mode", "live"}, {"records", records}, {"accepted", accepted},
                            {"packet_records", packet_records}, {"raven_events", raven_events},
                            {"discarded", discarded}, {"format_rejected", rejected}, {"wrapped", wrapped},
                            {"busy_observations", busy}, {"payload_copy_bytes", copied},
                            {"index_read_bytes", 8 * (scans + 1)}, {"control_read_bytes", 4 * scans},
                            {"header_read_bytes", 4 * headers}, {"consumer_write_bytes", 8 * writes},
                            {"initial_consumer", initial_consumer}, {"consumer", cursor}, {"producer", tail},
                            {"events", detector->event_count}, {"alerts", detector->alert_count},
                            {"event_types", event_types}, {"min_event_bytes", accepted ? min_event : 0},
                            {"max_event_bytes", max_event}, {"snapshot_bytes", bytes},
                            {"trace_bytes", trace_bytes}}.dump() + "\n", true);
        return 0;
    } catch (const std::exception& error) {
        detector->inspector.close();
        if (detector->plugin_inspector) detector->plugin_inspector->close();
        return fail(error);
    }
}
