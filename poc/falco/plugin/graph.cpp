#include "graph.hpp"

namespace rz {
size_t json_charge(const Json& j) {
    if (j.is_string()) return 48 + j.get_ref<const std::string&>().size();
    size_t n = 32;
    if (j.is_object()) {
        for (auto it = j.begin(); it != j.end(); ++it) n += 80 + it.key().size() + json_charge(*it);
    } else if (j.is_array()) {
        for (const auto& value : j) n += 16 + json_charge(value);
    }
    return n;
}

void Graph::touch(uint64_t key) {
    if (std::find(current->nodes.begin(), current->nodes.end(), key) == current->nodes.end()) {
        current->nodes.push_back(key);
        ++nodes.at(key).references;
        current->cost += 16;
    }
}

std::string Graph::node(const std::string& kind, const std::string& value, const std::string& label) {
    auto key = kind + ":" + value;
    auto [it, fresh] = node_index.emplace(key, next);
    if (fresh) {
        auto& n = nodes[next++];
        n.row = {{"key",key},{"kind",kind},{"value",value},{"label",label},
                 {"first_ts",1e18},{"last_ts",0.0},{"props",Json::object()}};
        n.cost = 144 + key.size() + json_charge(n.row);
        bytes += n.cost;
    }
    touch(it->second);
    return key;
}

Json& Graph::edge(const std::string& src, const std::string& dst, const std::string& type, const Event& e) {
    auto [it, fresh] = edge_index.emplace(std::make_tuple(src, dst, type), next);
    if (fresh) {
        auto& r = edges[next++];
        r.row = {{"src",src},{"dst",dst},{"type",type},{"ts",e.ts},{"last_ts",e.ts},
                 {"count",0},{"nodes",{src,dst}},{"from_ts",e.ts}};
        r.cost = 240 + src.size() + dst.size() + json_charge(r.row);
        bytes += r.cost;
    }
    auto& r = edges.at(it->second);
    auto& row = r.row;
    row["from_ts"] = row["ts"] = std::min(e.ts, row["ts"].get<double>());
    row["last_ts"] = std::max(e.ts, row["last_ts"].get<double>());
    row["count"] = row["count"].get<uint64_t>() + 1;
    r.ids.emplace(sequence, e.id);
    current->edges.push_back(it->second);
    current->cost += 112 + e.id.size();
    for (const auto* key : {&src, &dst}) {
        auto position = node_index.find(*key);
        if (position == node_index.end()) continue;
        touch(position->second);
        auto& n = nodes.at(position->second).row;
        n["first_ts"] = std::min(e.ts,n["first_ts"].get<double>());
        n["last_ts"] = std::max(e.ts,n["last_ts"].get<double>());
    }
    return row;
}

void Graph::observe(const Event& e, size_t event_reservation) {
    sequence = e.sequence;
    auto it = history.emplace(std::make_pair(e.ts,sequence),
                              Observation{e.pid, e.id, {}, {}, event_reservation + 256 + 2*e.id.size(), sequence}).first;
    current = &it->second;
    by_event.emplace(e.id, current);
    const auto pid = std::to_string(e.pid);
    const auto proc = "process:" + pid;
    const auto port = std::to_string(e.port);
    if (e.type == "process_exec") {
        node("process", pid, "pid:" + pid);
        auto& n = nodes.at(node_index.at(proc)).row;
        if (!e.name.empty() || !e.exe.empty()) n["label"] = e.name.empty() ? e.exe : e.name;
        if (!n["props"].contains("exe")) n["props"] = {{"exe", e.exe}, {"user", e.user},
            {"container", e.container ? Json(*e.container) : Json(nullptr)}};
        n["first_ts"] = std::min(e.ts, n["first_ts"].get<double>());
        n["last_ts"] = std::max(e.ts, n["last_ts"].get<double>());
        if (e.ppid > 0) {
            auto parent = std::to_string(e.ppid);
            edge(node("process", parent, "pid:" + parent), proc, "spawned", e);
        }
        if (!e.exe.empty()) edge(proc, node("file", e.exe, e.name.empty() ? e.exe : e.name), "executed", e);
        if (e.container && !e.container->empty())
            edge(node("container", *e.container, e.image.empty() ? *e.container : e.image), proc, "runs", e);
        if (!e.user.empty() && e.uid >= 0) edge(node("user", e.user, "user:" + e.user), proc, "runs_as", e);
    } else if (e.type == "process_exit" || e.type == "process_fork") {
        node("process", pid, "pid:" + pid);
    } else if ((e.type == "file_access" || e.type == "file_modify") && !e.path.empty()) {
        auto name = e.path.substr(e.path.rfind('/') + 1);
        auto& rel = edge(proc, node("file", e.path, name.empty() ? e.path : name),
                         e.type == "file_access" ? "accessed" : "modified", e);
        if (e.type == "file_modify" && !e.operation.empty()) rel["props"][e.operation] = true;
    } else if (e.type == "net_connect" && !e.ip.empty()) {
        auto ip = node("ip", e.ip, e.ip);
        edge(proc, ip, "connected_to", e);
        if (e.port > 0) edge(ip, node("port", port, port), "connected_to", e);
    } else if (e.type == "net_listen" && e.port > 0) {
        edge(proc, node("port", port, port), "listening", e);
    } else if (e.type == "privilege_change") {
        const auto new_user = e.meta.value("new_user", Json(nullptr));
        std::string target;
        if (new_user.is_string()) target = new_user.get<std::string>();
        else if (new_user.is_number() && new_user != 0) target = new_user.dump();
        if (target.empty()) target = e.user.empty() ? "uid:" + std::to_string(e.euid) : e.user;
        edge(proc, node("user", target, "user:" + target), "privilege_changed", e);
    }
    if (e.type == "process_exec" || e.type == "file_modify") {
        for (auto key : current->nodes) {
            auto& n = nodes.at(key);
            const size_t cost = 144 + json_charge(n.row) + n.row.at("key").get_ref<const std::string&>().size();
            bytes = bytes - n.cost + cost;
            n.cost = cost;
        }
        for (auto key : current->edges) {
            auto& r = edges.at(key);
            const size_t cost = 240 + json_charge(r.row) + r.row.at("src").get_ref<const std::string&>().size()
                              + r.row.at("dst").get_ref<const std::string&>().size();
            bytes = bytes - r.cost + cost;
            r.cost = cost;
        }
    }
    bytes += current->cost;
    current = nullptr;
}

void Graph::release_pins(const std::set<uint64_t>& protected_events) {
    for (auto it = pinned.begin(); it != pinned.end();) {
        auto item = it++;
        if (!protected_events.count(item->first.second)) history.insert(pinned.extract(item));
    }
}

int64_t Graph::erase_oldest() {
    auto first = history.begin();
    auto& obs = first->second;
    const auto pid = obs.pid;
    const auto range = by_event.equal_range(obs.id);
    for (auto it = range.first; it != range.second; ++it) {
        if (it->second == &obs) { by_event.erase(it); break; }
    }
    for (auto key : obs.edges) {
        auto& r = edges.at(key);
        r.ids.erase(first->first.second);
        if (r.ids.empty()) {
            edge_index.erase(std::make_tuple(r.row.at("src").get<std::string>(), r.row.at("dst").get<std::string>(),
                                             r.row.at("type").get<std::string>()));
            bytes -= r.cost;
            edges.erase(key);
        }
    }
    for (auto key : obs.nodes) {
        auto& n = nodes.at(key);
        if (--n.references == 0) {
            node_index.erase(n.row.at("key").get_ref<const std::string&>());
            bytes -= n.cost;
            nodes.erase(key);
        }
    }
    bytes -= obs.cost;
    history.erase(first);
    return pid;
}

Json Graph::subgraph(const std::set<std::string>& ids) const {
    std::map<uint64_t, std::map<uint64_t,std::string>> direct;
    for (const auto& id : ids) {
        auto range = by_event.equal_range(id);
        for (auto it = range.first; it != range.second; ++it)
            for (auto key : it->second->edges) direct[key].emplace(it->second->sequence,id);
    }
    std::set<std::string> selected;
    auto relationships = Json::array(), entities = Json::array();
    auto add = [&](uint64_t key) {
        auto row = edges.at(key).row;
        row["_generation"] = key;
        auto seeds = Json::array();
        auto found = direct.find(key);
        if (found != direct.end())
            for (const auto& p : found->second) seeds.push_back({p.first,p.second});
        row["_direct"] = std::move(seeds);
        relationships.push_back(std::move(row));
    };
    for (const auto& item : direct) {
        const auto& row = edges.at(item.first).row;
        selected.insert(row.at("src").get<std::string>());
        selected.insert(row.at("dst").get<std::string>());
        add(item.first);
    }
    std::set<uint64_t> others, members;
    for (const auto& src : selected) {
        auto n = node_index.find(src);
        if (n != node_index.end()) members.insert(n->second);
        for (const auto& dst : selected) {
            auto it = edge_index.lower_bound({src,dst,""});
            while (it != edge_index.end() && std::get<0>(it->first)==src && std::get<1>(it->first)==dst) {
                if (!direct.count(it->second)) others.insert(it->second);
                ++it;
            }
        }
    }
    for (auto key : others) add(key);
    for (auto key : members) {
        auto row = nodes.at(key).row;
        row["_generation"] = key;
        entities.push_back(std::move(row));
    }
    return {{"nodes",entities},{"edges",relationships}};
}

void Graph::refresh(Json& view) const {
    for (auto& row : view.at("nodes")) {
        auto n = nodes.find(row.at("_generation").get<uint64_t>());
        row.erase("_generation");
        if (n != nodes.end()) row = n->second.row;
    }
    for (auto& row : view.at("edges")) {
        auto found = edges.find(row.at("_generation").get<uint64_t>());
        row.erase("_generation");
        auto seeds = std::move(row.at("_direct"));
        row.erase("_direct");
        auto seed = seeds.begin();
        auto ids = Json::array();
        if (found != edges.end()) {
            for (const auto& entry : found->second.ids) {
                while (seed != seeds.end() && seed->at(0).get<uint64_t>() < entry.first) {
                    ids.push_back(seed->at(1)); ++seed;
                }
                if (seed != seeds.end() && seed->at(0).get<uint64_t>() == entry.first) ++seed;
                ids.push_back(entry.second);
            }
            if (row.contains("props")) row["props"] = found->second.row.at("props");
        }
        while (seed != seeds.end()) { ids.push_back(seed->at(1)); ++seed; }
        row["event_ids"] = std::move(ids);
    }
}
}
