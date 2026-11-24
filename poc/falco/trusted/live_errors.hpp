#pragma once

#include "../plugin/detectors.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>

// Each live thread owns its stages, so one source cannot reset another source's failure run.
enum class Stage {
    batch, match, format, plugin_match, plugin_format, translate, raven, raven_advance, zeek, zeek_advance, count
};
constexpr std::array<const char*, static_cast<size_t>(Stage::count)> stage_names{
    "batch", "match", "format", "plugin_match", "plugin_format", "translate", "raven", "raven_advance", "zeek",
    "zeek_advance"
};

struct LiveErrors {
    struct Counter {
        uint64_t failures = 0, first_attempt = 0, window_failures = 0;
        std::atomic<uint64_t> attempts{0};
        std::mutex window_mutex;
        std::chrono::steady_clock::time_point window_start;
        std::atomic<unsigned> consecutive{0};
    };
    std::array<Counter, stage_names.size()> counts{};
#ifdef FALCO_SGX_FAULT_INJECTION
    std::string stage;
    uint64_t first = 1, repeat = 1;
#endif

    template<class Operation, class Report>
    bool run(Stage stage_id, Operation operation, Report report) {
        const auto index = static_cast<size_t>(stage_id);
        auto& counter = counts[index];
        [[maybe_unused]] const auto ordinal = counter.attempts.fetch_add(1, std::memory_order_relaxed) + 1;
        try {
#ifdef FALCO_SGX_FAULT_INJECTION
            if (stage == stage_names[index] && ordinal >= first && ordinal - first < repeat)
                throw std::runtime_error("injected failure");
#endif
            operation();
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const rz::RetentionReportError&) {
            throw;
        } catch (const std::exception& error) {
            std::lock_guard<std::mutex> lock(counter.window_mutex);
            ++counter.failures;
            const auto consecutive = counter.consecutive.fetch_add(1, std::memory_order_relaxed) + 1;
            const auto total = counter.attempts.load(std::memory_order_relaxed);
            const auto now = std::chrono::steady_clock::now();
            if (!counter.window_failures || now - counter.window_start >= std::chrono::seconds(1)) {
                counter.window_start = now;
                counter.first_attempt = total;
                counter.window_failures = 0;
            }
            ++counter.window_failures;
            const auto attempts = total - counter.first_attempt + 1;
            if (counter.failures <= 3) report(std::string(stage_names[index]) + ": " + error.what() + '\n');
            if (consecutive >= 16 || (attempts >= 64 && counter.window_failures > attempts / 2))
                throw std::runtime_error(std::string(stage_names[index]) + " error budget exceeded (" +
                                         std::to_string(counter.failures) + " failures)");
            return false;
        }
        counter.consecutive.store(0, std::memory_order_relaxed);
        return true;
    }
};
