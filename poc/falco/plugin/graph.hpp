#pragma once

#include "detectors.hpp"
#include <array>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace rz {
struct Event {
    std::string id, type, exe, name, user, path, operation, ip, image;
    std::optional<std::string> container;
    double ts;
    uint64_t sequence = 0;
    bool nonbenign = false, network = false;
    int64_t pid, ppid, uid, euid, port;
    Json args, tags, meta;
    bool tag(const char* key) const;
};

struct Process {
    int64_t parent = -1;
    std::string name;
    bool exited = false;
    size_t children = 0;
    size_t observations = 0;
    uint64_t created = 0;
};
using Tree = std::map<int64_t, Process>;

size_t json_charge(const Json& value);

class Graph {
    struct Node {
        Json row;
        size_t references = 0, cost = 0;
    };
    struct Edge {
        Json row;
        std::map<uint64_t, std::string> ids;
        size_t cost = 0;
    };
    struct Observation {
        int64_t pid;
        std::string id;
        std::vector<uint64_t> nodes, edges;
        size_t cost;
        uint64_t sequence;
    };
    uint64_t next = 0, sequence = 0;
    size_t bytes = 0;
    std::map<std::string, uint64_t> node_index;
    std::map<std::tuple<std::string, std::string, std::string>, uint64_t> edge_index;
    std::map<uint64_t, Node> nodes;
    std::map<uint64_t, Edge> edges;
    using Timeline = std::map<std::pair<double, uint64_t>, Observation>;
    Timeline history, pinned;
    std::multimap<std::string, const Observation*> by_event;
    Observation* current = nullptr;

    void touch(uint64_t key);
    std::string node(const std::string& kind, const std::string& value, const std::string& label);
    Json& edge(const std::string& src, const std::string& dst, const std::string& type, const Event& e);
public:
    void observe(const Event& e, size_t event_reservation);
    Json subgraph(const std::set<std::string>& ids) const;
    void refresh(Json& view) const;
    bool empty() const { return history.empty(); }
    bool has_pins() const { return !pinned.empty(); }
    const auto& oldest() const { return history.begin()->first; }
    double earliest(double fallback) const {
        if (!history.empty()) fallback = std::min(fallback, history.begin()->first.first);
        if (!pinned.empty()) fallback = std::min(fallback, pinned.begin()->first.first);
        return fallback;
    }
    void pin_oldest() { pinned.insert(history.extract(history.begin())); }
    void release_pins(const std::set<uint64_t>& protected_events);
    int64_t erase_oldest();
    size_t charge() const { return bytes; }
    size_t observations() const { return history.size() + pinned.size(); }
};
}
