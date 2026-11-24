// Runs the live pipeline's two sources at once: each thread reads its own inspector, then matches and
// formats with the shared engine and formatter, as the analysis and detection roles do.
#include <array>
#include <atomic>
#include <cstring>
#include <exception>
#include <falco_engine.h>
#include <formats.h>
#include <functional>
#include <fstream>
#include <iostream>
#include <iterator>
#include <libsinsp/filter_check_list.h>
#include <libsinsp/sinsp.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <thread>
#include <vector>

extern "C" const void* raven_zeek_api();

namespace {

constexpr unsigned syscall_rounds = 100;
constexpr uint32_t event_block = 0x216; // EV_BLOCK_TYPE_V2, the framing used for live events.

std::vector<uint8_t> read_file(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error(std::string("cannot open ") + path);
    return {std::istreambuf_iterator<char>(file), {}};
}

// Returns the length of the metadata snapshot that precedes the first event block.
size_t snapshot_bytes(const std::vector<uint8_t>& capture) {
    size_t offset = 0;
    while (capture.size() - offset >= 8) {
        uint32_t kind, size;
        std::memcpy(&kind, capture.data() + offset, sizeof(kind));
        std::memcpy(&size, capture.data() + offset + 4, sizeof(size));
        if (kind == event_block) return offset;
        if (size < 12 || size > capture.size() - offset) break;
        offset += size;
    }
    throw std::runtime_error("capture has no event block after its metadata");
}

void drain(sinsp& inspector, const std::function<void(sinsp_evt*)>& deliver) {
    for (;;) {
        sinsp_evt* evt = nullptr;
        const auto status = inspector.next(&evt);
        if (status == SCAP_EOF) return;
        if (status == SCAP_TIMEOUT || status == SCAP_FILTERED_EVENT) continue;
        if (status != SCAP_SUCCESS) throw std::runtime_error(inspector.getlasterr());
        deliver(evt);
    }
}

} // namespace

int main(int argc, char** argv) try {
    if (argc != 3) {
        std::cerr << "usage: engine-concurrency CAPTURE.scap RAVEN_EVENTS.jsonl\n";
        return 2;
    }
    const auto capture = read_file(argv[1]);
    const auto split = snapshot_bytes(capture);
    std::vector<uint8_t> snapshot(capture.begin(), capture.begin() + split);
    std::vector<uint8_t> events(capture.begin() + split, capture.end());
    const auto params = nlohmann::json{{"format", "stream"}, {"events", argv[2]}}.dump();

    auto engine = std::make_shared<falco_engine>();
    sinsp syscall_inspector, plugin_inspector;
    sinsp_filter_check_list syscall_checks;
    filter_check_list plugin_checks;
    auto plugin = plugin_inspector.register_plugin(static_cast<const plugin_api*>(raven_zeek_api()));
    std::string error;
    if (!plugin->init("", error)) throw std::runtime_error(error);
    plugin_checks.add_filter_check(plugin_inspector.new_generic_filtercheck());
    plugin_checks.add_filter_check(sinsp_plugin::new_filtercheck(plugin));
    auto add_source = [&](const std::string& name, sinsp& inspector, filter_check_list& checks) {
        auto filter = std::make_shared<sinsp_filter_factory>(&inspector, checks);
        auto formatter = std::make_shared<sinsp_evt_formatter_factory>(&inspector, checks);
        formatter->set_output_format(sinsp_evt_formatter::OF_JSON);
        return engine->add_source(name, filter, formatter);
    };
    const std::array<std::string, 2> names{falco_common::syscall_source, "raven_zeek"};
    const std::array<size_t, 2> sources{add_source(names[0], syscall_inspector, syscall_checks),
                                        add_source(names[1], plugin_inspector, plugin_checks)};
    const std::string rules = R"(- rule: Every syscall
  desc: concurrency check
  condition: evt.num > 0
  output: syscall %evt.num %evt.type %proc.name %proc.cmdline %fd.name
  priority: NOTICE
- rule: Every detection
  source: raven_zeek
  desc: concurrency check
  condition: rz.rule != ""
  output: detection %evt.num %rz.rule %rz.state
  priority: WARNING
)";
    auto result = engine->load_rules(rules, "concurrency.yaml");
    if (!result->successful()) {
        throw std::runtime_error(result->as_string(true, {{"concurrency.yaml", std::cref(rules)}}));
    }
    engine->complete_rule_loading();
    falco_formats formats(engine, true, true, false, true, false);

    std::array<uint64_t, 2> alerts{}, rounds{};
    std::array<std::exception_ptr, 2> failures;
    std::atomic<unsigned> ready{0};
    std::atomic<bool> syscall_done{false}, stop{false};
    // Mirrors Detector::format_mutex in the enclave: libsinsp formats times with the non-reentrant gmtime().
    std::mutex format_mutex;
    auto deliver = [&](size_t i, sinsp_evt* evt) {
        auto matches = engine->process_event(sources[i], evt, falco_common::rule_matching::FIRST);
        if (!matches) return;
        for (const auto& match : *matches) {
            std::string text;
            {
                std::lock_guard<std::mutex> lock(format_mutex);
                text = formats.format_event(evt, match.rule, match.source,
                                            falco_common::format_priority(match.priority_num), match.format,
                                            match.tags, "tsan", match.extra_output_fields);
            }
            if (match.source != names[i] || text.empty()) throw std::runtime_error("alert from the wrong source");
            ++alerts[i];
        }
    };
    auto start = [&] {
        ++ready;
        while (ready != 2 && !stop) std::this_thread::yield();
        if (stop) throw std::runtime_error("the other source failed during setup");
    };
    auto run_syscalls = [&] {
        uint8_t* input = snapshot.data();
        uint64_t length = snapshot.size();
        syscall_inspector.open_raw_block(&input, &length);
        syscall_inspector.start_capture();
        if (syscall_inspector.get_bytes_read() != snapshot.size()) throw std::runtime_error("snapshot was not consumed");
        start();
        for (; rounds[0] < syscall_rounds && !stop; ++rounds[0]) {
            const auto before = alerts[0];
            input = events.data();
            length = events.size();
            syscall_inspector.fseek(0);
            drain(syscall_inspector, [&](sinsp_evt* evt) { deliver(0, evt); });
            if (alerts[0] == before) throw std::runtime_error("a syscall round produced no alerts");
        }
        // libsinsp keeps both pointers; leave them on a valid empty block before closing.
        input = snapshot.data();
        length = 0;
        syscall_inspector.fseek(0);
        syscall_inspector.close();
    };
    auto run_detections = [&] {
        start();
        // Keep reopening the stream until the syscall source has finished all of its rounds.
        while (!stop && (!syscall_done || rounds[1] < 2)) {
            const auto before = alerts[1];
            plugin_inspector.open_plugin("raven_zeek", params, sinsp_plugin_platform::SINSP_PLATFORM_GENERIC);
            plugin_inspector.start_capture();
            drain(plugin_inspector, [&](sinsp_evt* evt) { deliver(1, evt); });
            plugin_inspector.close();
            if (alerts[1] == before) throw std::runtime_error("a RAVEN round produced no detection alerts");
            ++rounds[1];
        }
    };
    auto guarded = [&](size_t i, const std::function<void()>& body) {
        try {
            body();
        } catch (...) {
            failures[i] = std::current_exception();
            stop = true;
        }
    };
    std::thread detection(guarded, 1, run_detections);
    guarded(0, run_syscalls);
    syscall_done = true;
    detection.join();
    for (const auto& failure : failures) if (failure) std::rethrow_exception(failure);
    std::cout << alerts[0] << " syscall alerts in " << rounds[0] << " rounds, " << alerts[1]
              << " raven_zeek alerts in " << rounds[1] << " rounds\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
