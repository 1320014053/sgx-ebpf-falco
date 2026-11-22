#include "graph.hpp"
#include <arpa/inet.h>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <memory>
#include <unistd.h>
#ifdef RZ_ENCLAVE
#include <openenclave/enclave.h>
#include <openenclave/advanced/mallinfo.h>
extern "C" oe_result_t falco_emit(int*, const char*, size_t, int);
#else
#include <sys/random.h>
#endif

namespace rz {
RavenOptions RavenOptions::parse(const Json& config) {
    RavenOptions options;
    options.high = config.value("history_bytes", options.high);
    options.metrics = config.value("retention_metrics", false);
    if (options.high < 4096 || options.high > (1ULL << 31)) throw std::invalid_argument("invalid RAVEN history_bytes");
    return options;
}

void retention_report(const Json& sample) {
    Json out = sample;
#ifdef RZ_ENCLAVE
    oe_mallinfo_t info{};
    if (oe_allocator_mallinfo(&info) != OE_OK) throw std::runtime_error("cannot sample trusted heap");
    out["heap"] = info.current_allocated_heap_size;
    out["heap_peak"] = info.peak_allocated_heap_size;
    auto line = "RZRET " + out.dump() + "\n";
    int result = -1;
    if (falco_emit(&result,line.data(),line.size(),1) != OE_OK || result) throw std::runtime_error("cannot publish retention metrics");
#else
    FILE* file = std::fopen("/proc/self/smaps_rollup", "r");
    if (file) {
        char line[256];
        while (std::fgets(line,sizeof(line),file)) {
            size_t kib;
            if (std::sscanf(line,"Rss: %zu kB",&kib) == 1) { out["rss"] = kib*1024; break; }
        }
        std::fclose(file);
    }
    std::fprintf(stderr, "RZRET %s\n",out.dump().c_str());
#endif
}

namespace {
const std::set<std::string> shells{"bash","sh","dash","ash","zsh","ksh","csh","tcsh","busybox","fish","pwsh"};
const std::set<std::string> servers{"nginx","httpd","apache2","python","python3","uwsgi","gunicorn","node","deno","java","php-fpm","dev-server","file-processor","log-processor","db-client","web-server"};
const std::set<std::string> clients{"curl","wget","nc","ncat","socat","telnet","ftp","wget2","aria2c","axel"};
const std::set<std::string> interpreters{"python","python3","perl","ruby","node","deno","php","lua","tclsh"};
const std::set<std::string> known{
    "bash","sh","dash","ash","zsh","ls","cat","echo","sleep","date","grep","awk","sed","sort","wc","head","tail","cut","tr","uniq",
    "find","xargs","mkdir","rm","mv","cp","touch","chmod","chown","ln","tar","gzip","gunzip","zip","unzip","ps","top","htop","pgrep",
    "pkill","kill","df","du","free","stat","hostname","id","whoami","who","uptime","uname","nproc","env","printenv","which","dirname",
    "basename","printf","python","python3","perl","curl","wget","nc","socat","git","ssh","scp","rsync","ping","sudo","su","cron","nginx",
    "systemd","node","java","psql","sqlite3","mysql","file-processor","http-client","dev-server","log-processor","db-client","web-server",
    "backup-nanny","taskrunner","worker"};

std::string lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return s;
}

uint32_t next_codepoint(const std::string& text, size_t& i) {
    uint32_t code = static_cast<unsigned char>(text[i++]);
    if (code < 128) return code;
    unsigned tails = code < 224 ? 1 : code < 240 ? 2 : 3;
    code &= 0x7f >> (tails+1);
    // The JSON decoder has already validated the UTF-8 string.
    while (tails--) code = (code << 6) | (static_cast<unsigned char>(text[i++]) & 63);
    return code;
}

Json split_arguments(const std::string& text) {
    // The upstream adapter uses Python str.split(), including Unicode whitespace.
    Json words = Json::array();
    size_t start = text.npos;
    for (size_t i = 0; i < text.size();) {
        auto begin = i;
        uint32_t code = next_codepoint(text, i);
        bool space = (code >= 9 && code <= 13) || (code >= 28 && code <= 32) || code == 0x85 || code == 0xa0 ||
            code == 0x1680 || (code >= 0x2000 && code <= 0x200a) || code == 0x2028 || code == 0x2029 ||
            code == 0x202f || code == 0x205f || code == 0x3000;
        if (space && start != text.npos) {
            words.push_back(text.substr(start,begin-start));
            start = text.npos;
        } else if (!space && start == text.npos) start = begin;
    }
    if (start != text.npos) words.push_back(text.substr(start));
    return words;
}

std::string id() {
    unsigned char bytes[6];
#ifdef RZ_ENCLAVE
    if (oe_random(bytes, sizeof(bytes)) != OE_OK)
#else
    if (getentropy(bytes, sizeof(bytes)) != 0)
#endif
        throw std::runtime_error("cannot allocate RAVEN event ID");
    std::string out;
    for (auto b : bytes) {
        out += "0123456789abcdef"[b >> 4];
        out += "0123456789abcdef"[b & 15];
    }
    return out;
}

bool private_ip(std::string ip) {
    ip = ip.substr(0, ip.find(','));
    ip.erase(0, ip.find_first_not_of(" \r\n\t"));
    ip.erase(ip.find_last_not_of(" \r\n\t") + 1);
    std::array<uint8_t, 16> a{};
    auto v4 = [](const uint8_t* b) {
        return b[0] == 0 || b[0] == 10 || b[0] == 127 || (b[0] == 169 && b[1] == 254) ||
            (b[0] == 172 && (b[1] >> 4) == 1) || (b[0] == 192 && (b[1] == 168 ||
            (b[1] == 0 && (b[2] == 2 || (b[2] == 0 && b[3] != 9 && b[3] != 10))))) ||
            (b[0] == 198 && ((b[1] & 254) == 18 || (b[1] == 51 && b[2] == 100))) ||
            (b[0] == 203 && b[1] == 0 && b[2] == 113) || b[0] >= 240;
    };
    if (inet_pton(AF_INET, ip.c_str(), a.data()) == 1) return v4(a.data());
    if (inet_pton(AF_INET6, ip.substr(0, ip.find('%')).c_str(), a.data()) != 1) return false;
    auto prefix = [&](const char* addr, unsigned n) {
        std::array<uint8_t, 16> b{};
        inet_pton(AF_INET6, addr, b.data());
        return std::memcmp(a.data(), b.data(), n / 8) == 0 &&
            (!(n % 8) || ((a[n / 8] ^ b[n / 8]) >> (8 - n % 8)) == 0);
    };
    if (prefix("::ffff:0:0", 96)) return v4(a.data() + 12);
    if (prefix("2001:1::1", 128) || prefix("2001:1::2", 128) || prefix("2001:3::", 32) ||
        prefix("2001:4:112::", 48) || prefix("2001:20::", 28) || prefix("2001:30::", 28)) return false;
    return prefix("::", 127) || prefix("64:ff9b:1::", 48) || prefix("100::", 64) ||
        prefix("2001::", 23) || prefix("2001:db8::", 32) || prefix("2002::", 16) ||
        prefix("fc00::", 7) || prefix("fe80::", 10);
}

bool truth(const Json& v) {
    if (v.is_boolean()) return v.get<bool>();
    if (v.is_number()) return v.get<double>() != 0;
    if (v.is_string()) return !v.get_ref<const std::string&>().empty();
    return !v.is_null() && !v.empty();
}

int64_t tetragon_integer(const Json& obj, const char* key, int64_t fallback) {
    auto value = obj.value(key, Json(nullptr));
    if (!truth(value)) return fallback;
    if (value.is_boolean()) return 1;
    if (!value.is_string()) return value.get<int64_t>();
    const auto& text = value.get_ref<const std::string&>();
    auto invalid = [&] { return std::invalid_argument("invalid Tetragon " + std::string(key) + ": " + value.dump()); };
    auto words = split_arguments(text);
    if (words.size() != 1 || text.find_first_of("\x1c\x1d\x1e\x1f") != text.npos) throw invalid();
    const auto& word = words.front().get_ref<const std::string&>();
    std::string digits;
    size_t i = 0;
    if (word[0] == '+' || word[0] == '-') digits += word[i++];
    bool last_digit = false;
    while (i < word.size()) {
        auto code = next_codepoint(word, i);
        if (code == '_' && last_digit) {
            last_digit = false;
            continue;
        }
        if (code >= 128) {
            // First digit of each non-ASCII decimal block in the reference Python 3.10 Unicode database.
            static constexpr uint32_t zeros[] = {
                0x660,0x6f0,0x7c0,0x966,0x9e6,0xa66,0xae6,0xb66,0xbe6,0xc66,0xce6,0xd66,0xde6,
                0xe50,0xed0,0xf20,0x1040,0x1090,0x17e0,0x1810,0x1946,0x19d0,0x1a80,0x1a90,0x1b50,
                0x1bb0,0x1c40,0x1c50,0xa620,0xa8d0,0xa900,0xa9d0,0xa9f0,0xaa50,0xabf0,0xff10,
                0x104a0,0x10d30,0x11066,0x110f0,0x11136,0x111d0,0x112f0,0x11450,0x114d0,0x11650,
                0x116c0,0x11730,0x118e0,0x11950,0x11c50,0x11d50,0x11da0,0x16a60,0x16b50,0x1d7ce,
                0x1d7d8,0x1d7e2,0x1d7ec,0x1d7f6,0x1e140,0x1e2f0,0x1e950,0x1fbf0};
            auto next = std::upper_bound(std::begin(zeros), std::end(zeros), code);
            if (next == std::begin(zeros) || code - next[-1] > 9) throw invalid();
            code = '0' + (code - next[-1]);
        }
        if (code < '0' || code > '9') throw invalid();
        digits += static_cast<char>(code);
        last_digit = true;
    }
    if (!last_digit) throw invalid();
    return std::stoll(digits);
}

Event normalize(const Json& j) {
    Event e;
    auto event_id = j.find("event_id");
    if (event_id != j.end() && !event_id->is_null()) e.id = event_id->get<std::string>();
    if (e.id.empty()) e.id = id();
    e.type = j.value("event_type", "process_exec");
    e.ts = j.value("ts", 0.0);
    e.pid = j.value("pid", int64_t{-1}); e.ppid = j.value("ppid", int64_t{-1});
    e.uid = j.value("uid", int64_t{-1}); e.euid = j.value("euid", int64_t{-1});
    e.exe = j.value("exe", "");
    auto exe_name = j.find("exe_name");
    // An explicit null can only be filled from a nonempty executable path.
    if (exe_name != j.end() && (e.exe.empty() || !exe_name->is_null())) e.name = exe_name->get<std::string>();
    if (e.name.empty()) {
        auto path = e.exe.substr(0, e.exe.find_last_not_of('/') + 1);
        e.name = path.empty() ? e.exe : path.substr(path.rfind('/') + 1);
    }
    e.user = j.value("user", ""); e.path = j.value("file_path", ""); e.operation = j.value("file_op", "");
    e.ip = j.value("dst_ip", ""); e.port = j.value("dst_port", int64_t{0});
    auto container = j.find("container");
    // The graph preserves an explicit null. The upstream model defaults a missing container to "".
    if (container == j.end()) e.container.emplace();
    else if (!container->is_null()) e.container = container->get<std::string>();
    e.image = j.value("container_image", "");
    e.args = j.value("args", Json::array()); e.tags = j.value("tags", Json::object()); e.meta = j.value("metadata", Json::object());
    auto name = lower(e.name);
    auto starts = [](const std::string& text, std::initializer_list<const char*> prefixes) {
        return std::any_of(prefixes.begin(), prefixes.end(), [&](const char* p) { return text.compare(0, strlen(p), p) == 0; });
    };
    bool priv = private_ip(e.ip);
    e.tags.update(Json{{"is_shell", bool(shells.count(name))}, {"is_server", bool(servers.count(name))},
        {"is_net_client", bool(clients.count(name))}, {"is_interpreter", bool(interpreters.count(name))},
        {"is_known_exec", bool(known.count(e.name))}, {"is_unknown_exec", !known.count(e.name)},
        {"is_privilege_change", e.type == "privilege_change" && e.euid != -1 && e.euid != e.uid},
        {"is_sensitive", starts(e.path, {"/etc/shadow","/etc/sudoers","/etc/crontab","/etc/cron.d","/root/","/var/log/auth.log",
            "/var/log/secure","/proc/kcore","/proc/kallsyms","/proc/sched_debug","/proc/modules","/sys/kernel","/boot/"})},
        {"is_staged", starts(e.exe, {"/tmp/","/dev/shm/","/var/tmp/"})}, {"net_private", priv}, {"net_external", !e.ip.empty() && !priv}});
    if (e.type == "file_modify" && !e.meta.contains("created_executable")) {
        for (auto s : {".elf", ".py", ".bin", "downloaded"}) {
            if (lower(e.path).find(s) != std::string::npos) e.meta["created_executable"] = true;
        }
    }
    return e;
}

Json tetragon_event(const Json& raw) {
    auto time = raw.value("ts", Json(0));
    if (!truth(time)) time = raw.value("time", Json(0));
    double ts;
    if (time.is_string()) {
        auto words = split_arguments(time.get_ref<const std::string&>());
        auto invalid = [&] {
            auto quoted = time.dump();
            if (quoted.find('\'') == quoted.npos) quoted.front() = quoted.back() = '\'';
            return std::invalid_argument("could not convert string to float: " + quoted);
        };
        if (words.size() != 1) throw invalid();
        auto token = words.front().get<std::string>();
        // Python float accepts digit separators, but neither hex floats nor NaN payloads.
        if (token.find_first_of("xX(") != token.npos) throw invalid();
        for (auto i = token.find('_'); i != token.npos; i = token.find('_', i+1)) {
            if (!i || i+1 == token.size() || token[i-1] < '0' || token[i-1] > '9' ||
                token[i+1] < '0' || token[i+1] > '9') throw invalid();
        }
        token.erase(std::remove(token.begin(), token.end(), '_'), token.end());
        char* end;
        ts = std::strtod(token.c_str(), &end);
        if (end != token.c_str() + token.size()) throw invalid();
    } else {
        ts = time.is_boolean() ? double(time.get<bool>()) : time.get<double>();
        if (ts > 1e12) ts /= 1e9;
    }
    for (const auto& [key, type] : std::initializer_list<std::pair<const char*, const char*>>{
            {"process_exec","process_exec"}, {"process_exit","process_exit"}, {"process_clone","process_fork"},
            {"process_connect","net_connect"}, {"process_listen","net_listen"}, {"process_kprobe",""}}) {
        if (!raw.contains(key)) continue;
        const auto& data = raw.at(key);
        auto p = data.value("process", Json::object()), parent = data.value("parent", Json::object());
        auto uid = p.value("uid", Json("?"));
        auto optional_text = [](const Json& obj, const char* k) {
            auto it = obj.find(k);
            return it == obj.end() || it->is_null() ? std::string() : it->get<std::string>();
        };
        auto user = uid.is_string() ? uid.get<std::string>() : uid.is_null() ? "None" : uid.dump();
        Json e{{"ts",ts},{"event_type",type},{"pid",tetragon_integer(p,"pid",-1)},{"ppid",tetragon_integer(parent,"pid",-1)},
               {"uid",tetragon_integer(p,"uid",-1)},{"user",user},{"exe",optional_text(p,"binary")},
               {"args",split_arguments(optional_text(p,"arguments"))}};
        if (auto c = p.find("container"); c != p.end() && c->is_object()) {
            e["container"] = c->value("id", Json(""));
            e["container_image"] = optional_text(*c,"image");
        }
        if (e["event_type"] == "net_connect" || e["event_type"] == "net_listen") {
            if (e["event_type"] == "net_connect") {
                auto ip = optional_text(data,"ip"); e["dst_ip"] = ip.empty() ? optional_text(data,"address") : ip;
            }
            e["dst_port"] = tetragon_integer(data, "port", 0);
        } else if (e["event_type"] == "") {
            const auto name = data.value("function_name", "");
            if (name == "vfs_mkdir" || name == "vfs_create" || name == "vfs_write") {
                e["event_type"] = "file_modify"; e["file_op"] = name == "vfs_write" ? "write" : "create";
            } else if (name == "security_inode_permission" || name == "security_path_permission" || name == "security_file_open") {
                e["event_type"] = "file_access"; e["file_op"] = "read";
            } else return nullptr;
            for (const auto& a : data.value("args", Json::array())) {
                if (!a.is_object()) continue;
                auto kind = a.value("type","");
                if (kind != "file_arg" && kind != "path_arg" && kind != "fd_arg") continue;
                for (const auto* field : {"file_arg","path","value"}) {
                    if (a.contains(field) && truth(a.at(field))) { e["file_path"] = a.at(field); break; }
                }
                break;
            }
        }
        return e;
    }
    return nullptr;
}

struct Step { const char* type; const char* signal = ""; const char* relation = ""; };
struct Rule { const char* name; unsigned window, risk; std::vector<Step> steps; };
const Step server{"process_exec","is_server"}, shell{"process_exec","is_shell","child"};
const Rule rules[] = {
    {"sensitive_access_chain",5,30,{{"sensitive_access"}}},
    {"privilege_change_chain",5,40,{{"privilege_change"}}},
    {"server_spawns_shell",60,20,{server,shell}},
    {"server_spawns_outbound",60,50,{server,shell,{"network_connect","net_external","descendant"}}},
    {"server_launches_net_client",60,40,{server,{"process_exec","is_net_client","child"},{"network_connect","net_external","same"}}},
    {"staged_execution_chain",90,60,{server,shell,{"executable_create","","descendant"},{"process_exec","unknown_staged","descendant"},
                                    {"network_connect","net_external","descendant"}}},
    {"sensitive_then_privilege",60,50,{{"sensitive_access"},{"privilege_change","","descendant"}}}
};
using Chain = std::vector<std::shared_ptr<Event>>;

std::vector<int64_t> lineage(const Tree& tree, int64_t pid) {
    std::vector<int64_t> out;
    std::set<int64_t> visited;
    while (tree.count(pid) && visited.insert(pid).second) {
        out.push_back(pid);
        auto parent = tree.at(pid).parent;
        if (parent == -1) break;
        pid = parent;
    }
    return out;
}

bool matches(const Step& step, const Event& e, const Event* prev, const Tree& tree) {
    std::string_view type(step.type), signal(step.signal), rel(step.relation);
    if (type == "sensitive_access") { if (e.type != "file_access" || !e.tag("is_sensitive")) return false; }
    else if (type == "executable_create") {
        if (e.type != "file_modify" || !truth(e.meta.value("created_executable", Json(false)))) return false;
    } else if (e.type != (type == "network_connect" ? "net_connect" : type)) return false;
    if (signal == "unknown_staged") {
        if (!e.tag("is_unknown_exec") || !e.tag("is_staged")) return false;
    } else if (!signal.empty() && !e.tag(step.signal)) return false;
    if (!prev) return true;
    if (prev->id == e.id) return false;
    if (rel == "same") return prev->pid == e.pid;
    auto ancestor = [&](int64_t pid) {
        auto parents = lineage(tree, pid);
        return std::find(parents.begin(), parents.end(), prev->pid) != parents.end();
    };
    if (rel == "child") {
        if (ancestor(e.pid) && tree.at(e.pid).parent != -1) return prev->pid == tree.at(e.pid).parent;
        return e.ppid == prev->pid;
    }
    return rel != "descendant" || ancestor(e.pid) || (e.ppid != -1 && ancestor(e.ppid));
}

std::string clock_text(double ts) {
    char text[64];
    double seconds;
    const double usec = std::nearbyint(std::modf(ts, &seconds) * 1e6);
    if (usec < 0) --seconds;
    else if (usec == 1e6) ++seconds;
    if (seconds >= -62135596800.0 && seconds < 253402300800.0) {
        auto t = static_cast<time_t>(seconds);
        std::tm tm{};
        if (gmtime_r(&t, &tm) && strftime(text, sizeof(text), "%H:%M:%S", &tm)) return text;
    }
    std::snprintf(text, sizeof(text), "%.2fs", ts);
    return text;
}

std::string action(const Event& e) {
    if (e.type == "net_connect") return e.name + " connected to " + e.ip + ":" + std::to_string(e.port);
    if (e.type == "file_modify" || e.type == "file_access") return e.name + (e.type == "file_modify" ? " modified " : " accessed ") + e.path;
    if (e.type == "privilege_change") return e.name + " changed privileges on uid " + std::to_string(e.uid) + "->" + std::to_string(e.euid);
    return e.name + " started";
}

struct Engine {
    static constexpr double history_seconds = 600;
    explicit Engine(RavenOptions policy = {}) : options(policy) {
        if (options.metrics) sample("start");
    }
    RavenOptions options;
    Publish publish;
    Tree tree;
    Graph graph;
    std::map<int64_t, std::deque<std::shared_ptr<Event>>> ledger;
    std::deque<int64_t> pid_order;
    std::array<std::vector<Chain>, std::size(rules)> partials;
    using MatchKey = std::pair<std::string,std::set<std::string>>;
    std::set<MatchKey> emitted;
    std::map<uint64_t,std::vector<std::pair<decltype(emitted)::iterator,size_t>>> by_finish;
    std::deque<Json> detections;
    struct Snapshot { size_t cost; double time; uint64_t seq; };
    std::deque<Snapshot> snapshots;
    size_t tree_bytes = 0, match_bytes = 0, snapshot_bytes = 0, peak_bytes = 0;
    uint64_t seen = 0, delivered = 0, evicted = 0, cycles = 0, resets = 0, skipped = 0, segment_start = 1;
    uint64_t input_hash = 14695981039346656037ULL, cutoff_seq = 0;
    double start_time = 0, cutoff = -INFINITY;
    const char* reason = "none";
    uint64_t time_evicted = 0, budget_evicted = 0, ordinal_ids = 0;
    double now = -INFINITY, latest_event = -INFINITY;

    size_t charged() const {
        return graph.charge() + tree_bytes + match_bytes + snapshot_bytes + 1024*ledger.size();
    }
    double coverage() const { return std::max({start_time,now-history_seconds,cutoff}); }
    void sample(const char* phase) const {
        retention_report({{"phase",phase},{"seen",seen},{"published",delivered},{"hash",std::to_string(input_hash)},
                          {"now",now},{"start",coverage()},{"seconds",std::max(0.0,now-coverage())},
                          {"oldest_retained",graph.observations() ? Json(graph.earliest(now)) : Json(nullptr)},
                          {"time_evicted",time_evicted},{"budget_evicted",budget_evicted},{"ordinal_ids",ordinal_ids},
                          {"cutoff_seq",cutoff_seq},{"reason",reason},{"evicted",evicted},{"cycles",cycles},
                          {"resets",resets},{"skipped",skipped},{"charged",charged()},{"peak_charged",peak_bytes},
                          {"observations",graph.observations()},{"tree",tree.size()},{"snapshots",detections.size()}});
    }
    Json materialize(const Json& detection) const {
        Json row = detection;
        graph.refresh(row.at("reconstruction").at("graph"));
        if (evicted || resets)
            row["meta"]["retention"] = {{"start",coverage()},{"after_sequence",cutoff_seq},{"reason",reason},{"segment",resets}};
        return row;
    }
    void forget_match(uint64_t seq) {
        auto it = by_finish.find(seq);
        if (it == by_finish.end()) return;
        for (const auto& item : it->second) { emitted.erase(item.first); match_bytes -= item.second; }
        by_finish.erase(it);
    }
    void retire(int64_t pid) {
        auto it = tree.find(pid);
        while (it != tree.end() && it->second.exited && !it->second.observations && !it->second.children) {
            auto parent = it->second.parent;
            tree_bytes -= 192 + it->second.name.size();
            tree.erase(it);
            it = tree.find(parent);
            if (it != tree.end() && it->second.children) --it->second.children;
        }
    }
    void drop_snapshot() {
        snapshot_bytes -= snapshots.front().cost;
        snapshots.pop_front();
        detections.pop_front();
    }
    bool collect(size_t reserve, const Chain* completing = nullptr) {
        const size_t high = options.high, low = high-high/4;
        bool pressure = reserve > high || charged() > high-reserve;
        auto stale = [&](const std::pair<double,uint64_t>& key) {
            return key.first < now-history_seconds || key <= std::make_pair(cutoff,cutoff_seq);
        };
        auto release_reviews = [&] {
            while (publish && !snapshots.empty() && snapshots.front().time + 60 < now &&
                   stale({snapshots.front().time,snapshots.front().seq})) drop_snapshot();
        };
        release_reviews();
        if (!pressure && !graph.has_pins() && (graph.empty() || !stale(graph.oldest()))) return true;
        std::set<uint64_t> pins;
        for (const auto& list : partials) for (const auto& c : list) for (const auto& e : c) pins.insert(e->sequence);
        if (completing) for (auto& e : *completing) pins.insert(e->sequence);
        graph.release_pins(pins);
        bool removed = false;
        const auto previous_time_count = time_evicted;
        while (!graph.empty()) {
            auto key = graph.oldest();
            bool expired = stale(key);
            if (!expired && (!pressure || (reserve <= low && charged() <= low-reserve))) break;
            if (pins.count(key.second)) { graph.pin_oldest(); continue; }
            auto pid = graph.erase_oldest();
            if (std::make_pair(cutoff,cutoff_seq) < key) { cutoff=key.first; cutoff_seq=key.second; reason=expired?"time":"budget"; }
            if (key.first < now-history_seconds) ++time_evicted;
            else ++budget_evicted;
            release_reviews();
            auto l = ledger.find(pid);
            if (l != ledger.end() && !l->second.empty() && l->second.front()->sequence <= key.second) {
                auto& list = l->second;
                auto p = std::find_if(list.begin(),list.end(),[&](const auto& e){return e->sequence == key.second;});
                if (p != list.end()) list.erase(p);
                if (list.empty()) {
                    ledger.erase(l);
                    auto p = std::find(pid_order.begin(),pid_order.end(),pid);
                    if (p != pid_order.end()) pid_order.erase(p);
                }
            }
            auto t = tree.find(pid);
            if (t != tree.end() && key.second >= t->second.created && t->second.observations) {
                --t->second.observations; retire(pid);
            }
            forget_match(key.second);
            ++evicted; removed = true;
        }
        if (removed && pressure) { ++cycles; if (options.metrics) sample("collected"); }
        else if (options.metrics && time_evicted/10000 != previous_time_count/10000) sample("expired");
        return reserve <= high && charged() <= high-reserve;
    }
    struct SegmentFull {};
    void end_segment() {
        retention_report({{"phase","gap"},{"first",segment_start},{"last",seen},{"reason","protected_budget"},
                          {"unpublished",publish ? 0 : detections.size()},{"retained",graph.observations()}});
        for (auto& v : partials) std::vector<Chain>().swap(v);
        emitted.clear(); by_finish.clear(); detections.clear(); snapshots.clear();
        tree.clear(); ledger.clear(); pid_order.clear(); graph = Graph{};
        tree_bytes = match_bytes = snapshot_bytes = 0;
        cutoff=now; cutoff_seq=seen; reason="protected_budget"; segment_start=seen+1; ++resets; ++skipped;
    }

    void finish_match(const Rule& rule, const Chain& chain) {
        std::set<std::string> ids;
        for (auto& e : chain) ids.insert(e->id);
        const MatchKey match{rule.name,ids};
        if (emitted.count(match)) return;
        auto events = Json::array(), pattern = Json::array(), details = Json::array(), timeline = Json::array();
        std::set<std::pair<int64_t, std::string>> counted;
        std::vector<int64_t> pids;
        unsigned points = 0;
        std::string pattern_text;
        for (auto& s : rule.steps) {
            pattern.push_back(s.type);
            if (!pattern_text.empty()) pattern_text += " → ";
            pattern_text += s.type;
        }
        for (const auto& ptr : chain) {
            const auto& e = *ptr;
            if (e.pid > 0) pids.push_back(e.pid);
            auto score = [&](bool eligible, const char* reason, unsigned amount) {
                if (eligible && counted.emplace(e.pid, reason).second) {
                    points += amount;
                    details.push_back({{"reason",reason},{"points",amount},{"ev",e.name + ":" + std::to_string(e.pid)}});
                }
            };
            score(e.tag("is_unknown_exec"), "unknown exec", 20);
            score(e.type == "privilege_change", "privilege change", 40);
            score(e.tag("is_sensitive"), "sensitive file access", 30);
            score(e.type == "net_connect" && e.tag("net_external"), "suspicious network connection", 15);
            score(e.tag("is_shell") && e.ppid > 0 && tree.count(e.ppid) && servers.count(tree.at(e.ppid).name), "shell spawned by server", 20);
            auto tags = Json::object(), args = Json::array();
            for (auto i = e.tags.begin(); i != e.tags.end(); ++i) if (i->is_boolean()) tags[i.key()] = *i;
            for (size_t i = 0; i < std::min<size_t>(8,e.args.size()); ++i) args.push_back(e.args.at(i));
            events.push_back({{"id",e.id},{"ts",e.ts},{"type",e.type},{"pid",e.pid},{"ppid",e.ppid},{"exe",e.name},
                {"args",args},{"user",e.user},{"file_path",e.path},{"dst_ip",e.ip},{"dst_port",e.port},{"tags",tags}});
        }
        int64_t root = pids.empty() ? -1 : pids.front();
        for (auto candidate : lineage(tree, root)) {
            if (std::all_of(pids.begin(), pids.end(), [&](int64_t pid) {
                auto a = lineage(tree, pid);
                return a.empty() || std::find(a.begin(), a.end(), candidate) != a.end();
            })) { root = candidate; break; }
        }
        std::string root_name;
        if (!pids.empty() && tree.count(root)) root_name = tree.at(root).name.empty() ? "pid:" + std::to_string(root) : tree.at(root).name;
        auto ordered = chain;
        std::stable_sort(ordered.begin(), ordered.end(), [](auto& a, auto& b) { return a->ts < b->ts; });
        const auto& first = *chain.front();
        auto story = (first.name.empty() ? root_name : first.name) + " (prc " + std::to_string(root) + ") is the root of the detected chain.";
        for (auto& e : ordered) {
            auto t = clock_text(e->ts), desc = action(*e);
            timeline.push_back({{"time",t},{"ts",e->ts},{"pid",e->pid},{"ppid",e->ppid},{"exe",e->name},{"action",desc}});
            story += "\n" + t + " " + e->name + " (pid " + std::to_string(e->pid) + ") " + desc;
        }
        auto total = rule.risk + points;
        auto level = total >= 80 ? "CRITICAL" : total >= 50 ? "HIGH" : total >= 25 ? "MEDIUM" : "LOW";
        auto end = chain.back()->ts;
        Json d{{"id","det-" + id()},{"rule",rule.name},{"rule_source","raven/rules/rule_defs/temporal.yaml"},{"method","full"},
            {"risk",total},{"severity",level},{"ts",end},{"start_ts",first.ts},{"end_ts",end},{"span",end-first.ts},
            {"root_pid",first.pid},{"root_exe",first.name},{"pattern",pattern},{"state","active"},{"reason_note",""},
            {"breakdown",{{"chain_rule_risk",rule.risk},{"primitive_total",points},{"primitive_details",details},{"level",level}}},
            {"reconstruction",{{"root_process",{{"pid",root},{"exe",root_name}}},{"pattern",pattern_text},{"timeline",timeline},
                               {"narrative",story},{"graph",graph.subgraph(ids)}}},
            {"scenario_run",""},{"meta",{{"chain",true}}},{"events",events}};
        settle(d);
        size_t key_cost = 224 + match.first.size();
        for (const auto& x : ids) key_cost += 96 + x.size();
        // A directly sensitive, privileged or external event can never become a benign review.
        const bool reviewable = d.at("state") == "active" && std::none_of(chain.begin(),chain.end(),[](const auto& e) {
            return e->tag("is_sensitive") || e->type == "privilege_change" ||
                   (e->type=="process_exec" && (e->tag("is_unknown_exec") || e->tag("is_staged"))) ||
                   (e->type=="net_connect" && !e->tag("net_private"));
        });
        const bool retain = !publish || reviewable;
        size_t cost = retain ? 128 + json_charge(d) : 0;
        if (!collect(key_cost+cost,&chain)) throw SegmentFull{};
        auto key = emitted.insert(match).first;
        by_finish[seen].push_back({key,key_cost});
        match_bytes += key_cost;
        if (publish) { publish(materialize(d)); ++delivered; }
        if (retain) {
            detections.push_back(std::move(d));
            snapshots.push_back({cost,end,seen});
            snapshot_bytes += cost;
            if (detections.size() > 4000) drop_snapshot();
        }
    }

    void settle(Json& d) const {
        if (d["state"] != "active") return;
        bool net = false;
        auto benign = [&](const std::string& type, const Json& tags) {
            if (type == "net_connect") { net = true; if (!tags.at("net_private").get<bool>()) return false; }
            return !(type == "process_exec" && (tags.at("is_unknown_exec").get<bool>() || tags.at("is_staged").get<bool>())) &&
                !tags.at("is_sensitive").get<bool>() && type != "privilege_change";
        };
        std::set<int64_t> roots;
        for (const auto& e : d.at("events")) {
            if (!benign(e.at("type"), e.at("tags"))) return;
            if (e.at("pid") > 0) roots.insert(e.at("pid").get<int64_t>());
        }
        for (const auto& [pid, recent] : ledger) {
            auto parents = lineage(tree, pid);
            auto end = parents.begin() + std::min<size_t>(4, parents.size());
            if (!roots.count(pid) && std::none_of(parents.begin(), end, [&](int64_t p){ return roots.count(p); })) continue;
            for (const auto& e : recent) if (!benign(e->type,e->tags)) return;
        }
        if (net) {
            d["state"] = "context_filtered";
            d["reason_note"] = "context-filtered as benign: behavior-graph context shows internal-only network, no unknown/staged executables, no sensitive access, no privilege change";
        }
    }

    void feed(const Json& raw) try {
        auto type = raw.find("event_type");
        if (type != raw.end() && type->is_null()) return;
        auto e = std::make_shared<Event>(normalize(raw));
        if (e->type.empty()) return;
        e->sequence = ++seen;
        if (options.metrics && e->id == "ring-" + std::to_string(seen)) ++ordinal_ids;
        if (seen==1) start_time=e->ts;
        now = std::max(now,e->ts);
        for (unsigned char c : e->id) { input_hash ^= c; input_hash *= 1099511628211ULL; }
        input_hash *= 1099511628211ULL;
        const size_t container_bytes = e->container ? e->container->size() : 0;
        size_t event_cost = 1536 + container_bytes + json_charge(e->args) + json_charge(e->tags) + json_charge(e->meta);
        for (auto* s : {&e->id,&e->type,&e->exe,&e->name,&e->user,&e->path,&e->operation,&e->ip,&e->image})
            event_cost += s->size();
        // Reserve the bounded number of new node/edge/index records before mutating the graph.
        const size_t reserve = event_cost + 24576 + 18*(e->exe.size()+e->name.size()+e->path.size()+
                               container_bytes+e->image.size()+e->user.size()+e->id.size()+e->ip.size()+e->operation.size()) +
                               8*json_charge(e->meta);
        expire_chains(std::max(e->ts, now - history_seconds));
        if (!collect(reserve)) throw SegmentFull{};
        if (e->type == "process_exit") {
            if (tree.count(e->pid)) tree.at(e->pid).exited = true;
        } else if (e->type == "process_exec" || e->type == "process_fork" || (e->pid > 0 && !tree.count(e->pid))) {
            auto [pos,fresh] = tree.try_emplace(e->pid);
            auto& n = pos->second;
            if (fresh) { tree_bytes += 192; n.created=seen; }
            if (tree.count(e->ppid) && e->ppid != e->pid && n.parent != e->ppid) {
                auto old = tree.find(n.parent);
                if (old != tree.end() && old->second.children) --old->second.children;
                n.parent = e->ppid; ++tree.at(e->ppid).children;
                if (old != tree.end() && old->first != e->pid) retire(old->first);
            }
            if (e->type == "process_exec") {
                tree_bytes = tree_bytes - n.name.size() + e->name.size();
                n.name = e->name; n.exited = false;
            }
        }
        if (tree.count(e->pid)) ++tree.at(e->pid).observations;
        graph.observe(*e,event_cost);
        if (!ledger.count(e->pid)) pid_order.push_back(e->pid);
        auto& history = ledger[e->pid];
        history.push_back(e);
        if (history.size() > 400) history.pop_front();
        if (pid_order.size() > 2048) { ledger.erase(pid_order.front()); pid_order.pop_front(); }
        for (size_t i = 0; i < std::size(rules); ++i) {
            const auto& r = rules[i];
            auto& open = partials[i];
            open.erase(std::remove_if(open.begin(), open.end(), [&](Chain& c) {
                if (!matches(r.steps[c.size()], *e, c.back().get(), tree)) return false;
                c.push_back(e);
                if (c.size() < r.steps.size()) return false;
                finish_match(r, c);
                return true;
            }), open.end());
            if (matches(r.steps[0], *e, nullptr, tree)) {
                if (r.steps.size() == 1) finish_match(r, {e});
                // Only start a new multi-event chain inside the retained time range.
                else if (e->ts >= std::max(now - history_seconds, cutoff)) open.push_back({e});
            }
        }
        advance_history(e->ts);
        latest_event = std::max(latest_event, e->ts);
        review(false);
        if (charged() > options.high) throw SegmentFull{};
        peak_bytes = std::max(peak_bytes,charged());
        if (options.metrics && seen%10000==0) sample("events");
    } catch (const SegmentFull&) {
        end_segment();
    }

    void expire_chains(double match_time) {
        for (size_t i=0; i<partials.size(); ++i) {
            auto& open = partials[i];
            open.erase(std::remove_if(open.begin(),open.end(),[&](const Chain& c) {
                return c.front()->ts + rules[i].window < match_time;
            }),open.end());
        }
    }
    void advance_history(double ts) {
        now = std::max(now, ts);
        if (seen && (graph.has_pins() || (!graph.empty() && (graph.oldest().first < now-history_seconds ||
                graph.oldest() <= std::make_pair(cutoff,cutoff_seq))))) {
            // An idle tick can reclaim history, but a later-arriving event can still complete a retained chain.
            expire_chains(now - history_seconds);
            collect(0);
        }
    }
    void review(bool finish) {
        for (auto& d : detections) {
            if (d.at("state") != "active") continue;
            const auto& evidence = d.at("events");
            if (finish || latest_event - d.at("end_ts").get<double>() >= 60 || std::all_of(evidence.begin(), evidence.end(), [&](const Json& x) {
                int64_t pid = x.at("pid"); return pid <= 0 || (tree.count(pid) && tree.at(pid).exited);
            })) {
                settle(d);
                if (publish && d.at("state") == "context_filtered") {
                    publish(materialize(d)); ++delivered;
                }
            }
        }
        if (finish && options.metrics) sample("finish");
    }
};
}

bool Event::tag(const char* key) const { return tags.value(key, false); }

struct RavenStream::State : Engine { using Engine::Engine; };
RavenStream::RavenStream(Publish publish,RavenOptions options) : state(std::make_unique<State>(options)) {
    state->publish = std::move(publish);
}
RavenStream::~RavenStream() = default;
void RavenStream::event(const Json& row) { state->feed(row); }
void RavenStream::line(std::string_view line) {
    if (line.find_first_not_of(" \t\r") == line.npos) return;
    auto row = Json::parse(line.begin(),line.end());
    if (row.contains("events")) {
        for (const auto& item : row.at("events").get_ref<const Json::array_t&>()) event(item);
    } else event(row);
}
void RavenStream::advance(double ts, bool finish) {
    state->advance_history(ts);
    if (finish) state->review(true);
}

Json raven(std::string_view text, bool tetragon,RavenOptions options) {
    Engine engine(options);
    size_t line_number = 0;
    while (!text.empty()) {
        auto pos = text.find('\n');
        auto line = text.substr(0, pos);
        text.remove_prefix(pos == text.npos ? text.size() : pos + 1);
        ++line_number;
        if (line.find_first_not_of(" \t\r") == line.npos) continue;
        try {
            auto row = Json::parse(line.begin(), line.end());
            if (tetragon) {
                auto e = tetragon_event(row);
                if (!e.is_null()) engine.feed(e);
            } else if (row.contains("events")) {
                for (const auto& e : row.at("events").get_ref<const Json::array_t&>()) engine.feed(e);
            } else engine.feed(row);
        } catch (const std::exception& error) {
            throw std::runtime_error("RAVEN line " + std::to_string(line_number) + ": " + error.what());
        }
    }
    for (auto& d : engine.detections) {
        engine.settle(d);
        d = engine.materialize(d);
    }
    return engine.detections;
}
}
