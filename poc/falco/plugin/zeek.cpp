#include "detectors.hpp"
#include <arpa/inet.h>
#include <array>
#include <cmath>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <vector>

namespace rz {
namespace {
using Bytes = std::string_view;
uint8_t octet(Bytes b, size_t i) { return static_cast<uint8_t>(b[i]); }
uint16_t be16(Bytes b, size_t i) { return (octet(b,i) << 8) | octet(b,i+1); }
uint32_t be32(Bytes b, size_t i) { return (uint32_t(be16(b,i)) << 16) | be16(b,i+2); }

struct Address {
    std::array<unsigned char, 16> bytes{};
    bool v6 = false;
    bool operator<(const Address& other) const { return std::tie(v6,bytes) < std::tie(other.v6,other.bytes); }
    bool operator==(const Address& other) const { return v6 == other.v6 && bytes == other.bytes; }
    std::string text() const {
        char buf[INET6_ADDRSTRLEN];
        return inet_ntop(v6 ? AF_INET6 : AF_INET, bytes.data(), buf, sizeof(buf));
    }
    bool local() const {
        auto a = bytes.data();
        if (v6 && !(a[0] == 0x20 && a[1] == 2)) {
            unsigned char zero[16]{};
            return (memcmp(a,zero,15) == 0 && a[15] <= 1) ||
                (a[0] == 0 && a[1] == 0x64 && a[2] == 0xff && a[3] == 0x9b && a[4] == 0 && a[5] == 1) ||
                (a[0] == 1 && memcmp(a+1,zero,7) == 0) ||
                (a[0] == 0x20 && a[1] == 1 && (a[2] <= 1 || (a[2] == 0xd && a[3] == 0xb8))) ||
                (a[0] >> 1) == 0x7e || (a[0] == 0xfe && (a[1] & 0xc0) == 0x80);
        }
        if (v6) a += 2;
        return a[0] == 0 || a[0] == 10 || a[0] == 127 || a[0] >= 240 ||
            (a[0] == 100 && (a[1] & 0xc0) == 64) || (a[0] == 169 && a[1] == 254) ||
            (a[0] == 172 && (a[1] >> 4) == 1) || (a[0] == 192 && (a[1] == 168 || (a[1] == 0 && (a[2] == 0 || a[2] == 2)))) ||
            (a[0] == 198 && ((a[1] & 254) == 18 || (a[1] == 51 && a[2] == 100))) || (a[0] == 203 && a[1] == 0 && a[2] == 113);
    }
};
using Endpoint = std::pair<Address,uint16_t>;
using Flow = std::pair<Endpoint,Endpoint>;
enum State { inactive, syn_sent, syn_ack, established, partial, closed, reset };
struct Timer {
    enum Kind { session, attempt, inactivity, remove, suppression, address_epoch, port_epoch, periodic, script } kind = periodic;
    double interval = 10;
    double due = 0;
    size_t slot = SIZE_MAX;
    const Flow* flow = nullptr;
};

// Zeek's indexed heap has a single child at the root and prefers the right child on ties.
// Equal TCP deadlines can cancel one another, so their dispatch order affects the 300-timer limit.
struct TimerQueue {
    std::vector<Timer*> heap;

    void place(size_t slot, Timer* timer) {
        heap[slot] = timer;
        timer->slot = slot;
    }
    void cancel(Timer& timer) {
        if (timer.slot == SIZE_MAX) return;
        for (size_t i = timer.slot; i; i /= 2) place(i, heap[i / 2]);
        auto last = heap.back();
        heap.pop_back();
        timer.slot = SIZE_MAX;
        if (heap.empty()) return;
        size_t i = 0;
        for (size_t child = 1; child < heap.size(); child = i * 2) {
            if (i && child + 1 < heap.size() && heap[child + 1]->due <= heap[child]->due) ++child;
            if (heap[child]->due >= last->due) break;
            place(i, heap[child]);
            i = child;
        }
        place(i, last);
    }
    void schedule(Timer& timer, double due) {
        cancel(timer);
        timer.due = due;
        size_t i = heap.size();
        heap.push_back(&timer);
        while (i && due < heap[i / 2]->due) {
            place(i, heap[i / 2]);
            i /= 2;
        }
        place(i, &timer);
    }
};

struct Connection {
    Endpoint origin;
    std::array<State,2> state{};
    std::array<bool,2> syn{}, synack{};
    bool data = false, active = true;
    double last = 0;
    Timer session{Timer::session,6}, attempt{Timer::attempt,5}, inactivity{Timer::inactivity,60}, remove{Timer::remove,5};
    std::array<uint32_t,2> initial_seq{};
};
struct Group {
    std::set<std::string> values;
    double first = 0;
};

struct Fragments {
    std::map<size_t,std::string> pieces;
    std::optional<size_t> length;
    std::string header;
};

struct Scan {
    Publish publish;
    std::map<Flow,Connection> connections;
    TimerQueue timers;
    std::map<std::pair<Address,std::string>,Group> addresses, ports;
    using NoticeKey = std::pair<Address,bool>;
    std::set<NoticeKey> suppression;
    std::deque<std::pair<double,NoticeKey>> suppression_expiry;
    Timer sweep{Timer::suppression}, heartbeat{Timer::periodic,1};
    Timer address_epoch{Timer::address_epoch,300}, port_epoch{Timer::port_epoch,300};
    // The pinned scan policy has 26 table expiry timers, including Notice's table.
    // Its heartbeat and scheduled script events share the same queue as TCP.
    std::array<Timer,25> other_tables{};
    Timer broker_flush{Timer::script,1}, checksum_check{Timer::script,10}, telemetry_sync{Timer::script,10},
          filter_tracking{Timer::script,300};
    std::vector<Timer*> scheduled_events;
    std::map<std::tuple<Address,Address,uint32_t,unsigned>, Fragments> fragments;
    double timestamp = 0, now = 0;

    std::optional<std::string> reassemble(Address src, Address dst, uint32_t id, unsigned next,
            size_t offset, bool more, Bytes data, std::string header) {
        if (data.size() > 65535-offset || (more && (data.size() % 8 || data.empty()))) return {};
        auto key = std::make_tuple(src,dst,id,next);
        auto& f = fragments[key];
        if (!offset && f.header.empty()) f.header = std::move(header);
        if (!more) f.length = offset + data.size();
        f.pieces.try_emplace(offset,data);
        if (!f.length || f.header.empty()) return {};
        std::string packet = f.header;
        size_t end = 0;
        for (const auto& [start,piece] : f.pieces) {
            if (start > end) return {};
            if (start + piece.size() > end) {
                packet.append(piece,end-start);
                end = start + piece.size();
            }
        }
        if (end < *f.length) return {};
        packet.resize(f.header.size() + *f.length);
        fragments.erase(key);
        return packet;
    }

    void observe(const Endpoint& scanner, const Endpoint& victim) {
        auto host = victim.first.text(), port = std::to_string(victim.second) + "/tcp";
        for (bool address : {true,false}) {
            auto& group = (address ? addresses : ports)[{scanner.first, address ? port : host}];
            size_t threshold = address ? 25 : 15;
            if (group.values.size() >= threshold) continue;
            if (group.values.empty()) group.first = now;
            group.values.insert(address ? host : port);
            if (group.values.size() < threshold) continue;
            auto key = std::make_pair(scanner.first,address);
            if (!suppression.insert(key).second) continue;
            suppression_expiry.emplace_back(now + 3600, key);
            auto seconds = static_cast<uint64_t>(std::rint(now - group.first));
            auto msg = scanner.first.text() + " scanned at least " + std::to_string(threshold) +
                (address ? " unique hosts on port " + port : " unique ports of host " + host) +
                " in " + std::to_string(seconds/60) + "m" + std::to_string(seconds%60) + "s";
            Json n{{"ts",std::round(now*1e6)/1e6},{"note",address ? "Scan::Address_Scan" : "Scan::Port_Scan"},
                {"msg",msg},{"src",scanner.first.text()},{"sub",scanner.first.local() ? "local" : "remote"},
                {"actions",{"Notice::ACTION_LOG"}},{"email_dest",Json::array()},{"suppress_for",3600.0}};
            if (address) { n["p"] = victim.second; n["proto"] = "tcp"; }
            else n["dst"] = host;
            if (publish) publish(n);
        }
    }

    void erase_connection(std::map<Flow,Connection>::iterator it) {
        auto& c = it->second;
        for (auto timer : {&c.inactivity, &c.session, &c.attempt, &c.remove}) timers.cancel(*timer);
        connections.erase(it);
    }

    void close_after_delay(Connection& c) {
        timers.cancel(c.session);
        timers.cancel(c.attempt);
        timers.schedule(c.remove, timestamp + c.remove.interval);
    }

    void dispatch(Timer& timer, bool eof) {
        if (timer.kind == Timer::suppression) {
            while (!suppression_expiry.empty() && suppression_expiry.front().first <= now) {
                suppression.erase(suppression_expiry.front().second);
                suppression_expiry.pop_front();
            }
        }
        if (timer.kind == Timer::periodic || timer.kind == Timer::suppression) {
            if (!eof) timers.schedule(timer, now + timer.interval);
            return;
        }
        if (!timer.flow) {
            if (timer.kind == Timer::address_epoch) addresses.clear();
            if (timer.kind == Timer::port_epoch) ports.clear();
            if (!eof) scheduled_events.push_back(&timer);
            return;
        }
        auto it = connections.find(*timer.flow);
        auto& c = it->second;
        if (timer.kind == Timer::session) {
            if (!eof) timers.schedule(timer, now + timer.interval);
        } else if (timer.kind == Timer::inactivity && c.last + timer.interval > now) {
            if (!eof) timers.schedule(timer, c.last + timer.interval);
        } else if (timer.kind == Timer::attempt) {
            if (!c.active || (c.state[0] != syn_sent && c.state[0] != syn_ack) || c.state[1] != inactive) return;
            auto other = c.origin == it->first.first ? it->first.second : it->first.first;
            if (c.synack[0]) observe(other,c.origin); else observe(c.origin,other);
            erase_connection(it);
        } else {
            erase_connection(it);
        }
    }

    void advance(double ts, bool eof = false) {
        // Script events reschedule after the previous packet has been processed.
        for (auto timer : scheduled_events) timers.schedule(*timer, now + timer->interval);
        scheduled_events.clear();
        timestamp = ts;
        now = std::max(now,ts);
        if (sweep.due == 0) {
            timers.schedule(heartbeat, now + 1);
            timers.schedule(sweep, now >= 1 ? now + 10 : 1);
            for (auto& table : other_tables) timers.schedule(table, sweep.due);
            scheduled_events = {&broker_flush, &checksum_check, &telemetry_sync, &filter_tracking, &port_epoch, &address_epoch};
        }
        // max_timer_expires applies to all due timers in a packet dispatch. EOF drains pending attempts.
        constexpr unsigned max_timer_expires = 300;
        for (unsigned count = 0; !timers.heap.empty() && (eof || count < max_timer_expires); ++count) {
            auto& timer = *timers.heap.front();
            if (!eof && timer.due > now) break;
            timers.cancel(timer);
            if (!eof || timer.due <= now || timer.kind == Timer::attempt) dispatch(timer, eof);
        }
        if (eof) {
            for (const auto& [key,c] : connections) {
                if (c.active) observe_failure(c, c.origin == key.first ? key.second : key.first);
            }
        }
    }

    void observe_failure(const Connection& c, const Endpoint& other) {
        auto failed = [&](int i) {
            return (c.state[i] == syn_sent && c.state[1-i] == reset) ||
                (c.state[i] == reset && !c.data && (c.state[1-i] == syn_ack || (c.state[1-i] == established && c.syn[i])));
        };
        if (failed(0)) observe(c.origin,other);
        else if (failed(1)) observe(other,c.origin);
    }

    void tcp(const Endpoint& src, const Endpoint& dst, uint32_t seq, uint32_t ack_seq, uint8_t flags, size_t payload) {
        static const std::set<uint16_t> services{21,22,25,53,79,80,81,88,135,139,143,443,445,502,563,585,587,614,631,636,
            989,990,992,993,995,1080,1883,2811,3128,3389,5222,5223,5269,6666,6667,6668,6669,8000,8080,8888,20000};
        Flow key = src < dst ? Flow{src,dst} : Flow{dst,src};
        const bool syn = flags & 2, ack = flags & 16, rst = flags & 4, fin = flags & 1;
        bool connection_established = false;
        auto it = connections.find(key);
        if (it != connections.end() && syn) {
            auto& c = it->second;
            if (!ack && !(src == c.origin) && c.state[0] == syn_ack && c.state[1] == inactive && seq == c.initial_seq[1]) {
                // The SYN-ACK arrived first. Its ACK identified the peer's initial sequence.
                c.origin = src;
                std::swap(c.initial_seq[0], c.initial_seq[1]);
                std::swap(c.syn[0], c.syn[1]);
                std::swap(c.synack[0], c.synack[1]);
                c.state = {established, established};
                connection_established = true;
            } else if ((!ack || c.state[0] == inactive) && (c.initial_seq[ack ? 1 : 0] != seq ||
                       c.state[0] == reset || c.state[1] == reset || c.state[0] == closed || c.state[1] == closed)) {
                erase_connection(it);
                it = connections.end();
            }
        }
        if (it == connections.end()) {
            bool flip = (!syn || ack) && services.count(src.second) && (!services.count(dst.second) || (!syn && src.second < dst.second));
            it = connections.try_emplace(key).first;
            auto& c = it->second;
            c.origin = flip ? dst : src;
            for (auto timer : {&c.session, &c.attempt, &c.inactivity, &c.remove}) timer->flow = &it->first;
            timers.schedule(c.session, now + 5);
            timers.schedule(c.inactivity, timestamp + c.inactivity.interval);
        }
        auto& c = it->second;
        int side = src == c.origin ? 0 : 1;
        auto other = side ? src : dst;
        auto& state = c.state[side];
        auto& peer = c.state[1-side];
        State before = state;
        c.last = timestamp;
        c.syn[side] |= syn && !ack;
        c.synack[side] |= syn && ack;
        c.data |= payload != 0 && !rst && !syn && !fin;
        if (before == inactive) {
            c.initial_seq[side] = syn ? seq : seq - 1;
            if (ack && peer == inactive) c.initial_seq[1-side] = ack_seq - 1;
            if (syn && !side) {
                state = ack ? syn_ack : syn_sent;
                timers.schedule(c.attempt, timestamp + c.attempt.interval);
            } else if (syn) {
                if (peer == syn_sent) peer = established;
                state = established;
                connection_established = peer != partial;
            } else if (!(fin || rst || (side && !payload && peer == syn_sent))) {
                state = ack && peer == established ? established : partial;
            }
        } else if (state == partial && syn && !ack && peer == inactive) {
            state = syn_sent;
        }
        if (c.inactivity.interval == 60 && (state == partial || state == established || peer == established || fin || rst)) {
            c.inactivity.interval = 300;
            timers.schedule(c.inactivity, timestamp + c.inactivity.interval);
        }
        if (connection_established) {
            auto port = other.second;
            if (c.state[0] == inactive && !services.count(port) && services.count(c.origin.second))
                port = c.origin.second;
            if (port == 21 || port == 22 || port == 23 || port == 513) {
                c.inactivity.interval = 3600;
                timers.schedule(c.inactivity, timestamp + c.inactivity.interval);
            }
        }
        if (fin) {
            state = closed;
            if (peer == closed || peer == reset || peer == inactive) {
                c.active = false;
                close_after_delay(c);
            }
        }
        if (!rst) return;
        state = reset;
        bool rejected = before == inactive && ((!side && peer == established) || (side && (peer == syn_sent || peer == syn_ack)));
        if (rejected) {
            if (c.syn[1]) observe(other,c.origin); else observe(c.origin,other);
        } else if (before != inactive && before != reset) {
            c.active = false;
            observe_failure(c,other);
        }
        if (c.remove.slot == SIZE_MAX) close_after_delay(c);
    }
};

uint32_t checksum_sum(Bytes bytes) {
    uint32_t sum = 0;
    size_t i = 0;
    for (; i + 1 < bytes.size(); i += 2) sum += be16(bytes,i);
    if (i < bytes.size()) sum += octet(bytes,i) << 8;
    return sum;
}
bool good_checksum(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return sum == 0xffff;
}

void parse_packet(Scan& scan, Bytes raw, uint32_t link, bool host_capture = false) {
    size_t offset = 0;
    unsigned proto = 0;
    const bool has_ethertype = link == 1 || link == 113 || link == 276;
    bool infer_ip_version = !has_ethertype;
    bool mpls = false;
    if (has_ethertype) {
        offset = link == 1 ? 14 : link == 113 ? 16 : 20;
        if (raw.size() < offset) return;
        proto = be16(raw,link == 276 ? 0 : offset-2);
        if (link == 1 && (proto == 0x8100 || proto == 0x88a8 || proto == 0x9100)) {
            do {
                if (raw.size() - offset < 4) return;
                proto = be16(raw,offset+2);
                offset += 4;
            } while (proto == 0x8100);
        }
        mpls = link == 1 && proto == 0x8847;
        if (link == 1 && proto == 0x8864) {
            if (raw.size() - offset <= 8) return;
            auto protocol = be16(raw, offset + 6);
            if (protocol != 0x0021 && protocol != 0x0057) return;
            offset += 8;
            infer_ip_version = true;
        }
    } else if (link == 50) {
        if (raw.size() <= 4) return;
        unsigned protocol = be16(raw,2);
        offset = 4;
        mpls = protocol == 0x0281;
        if (!mpls && protocol != 0x0021 && protocol != 0x0057) return;
    } else if (link == 0 || link == 108) {
        offset = 4;
    }
    if (mpls) {
        do {
            if (raw.size() - offset <= 4) return;
            offset += 4;
        } while (!(octet(raw,offset-2) & 1));
    }
    if (mpls || infer_ip_version) {
        if (raw.size() <= offset) return;
        unsigned version = octet(raw,offset) >> 4;
        proto = version == 4 ? 0x800 : version == 6 ? 0x86dd : 0;
    }
    auto ip = raw.substr(offset);
    Address src, dst;
    size_t length = 0, header = 0;
    uint32_t pseudo = 0;
    if (proto == 0x800) {
        if (ip.size() < 20 || (octet(ip,0) >> 4) != 4) return;
        header = (octet(ip,0) & 15) * 4;
        length = be16(ip,2);
        if (length == 0) length = ip.size();
        if (header < 20 || header > ip.size() || length < header || octet(ip,9) != 6) return;
        if (!good_checksum(checksum_sum(ip.substr(0,header)))) return;
        memcpy(src.bytes.data(),ip.data()+12,4); memcpy(dst.bytes.data(),ip.data()+16,4);
        auto frag = be16(ip,6);
        if (frag & 0x3fff) {
            if (ip.size() < length) return;
            auto joined = scan.reassemble(src,dst,be16(ip,4),6,(frag & 8191)*8,frag & 8192,
                                          ip.substr(header,length-header),std::string(ip.substr(0,header)));
            if (!joined || joined->size() > 65535) return;
            auto& b = *joined;
            b[2] = char(b.size() >> 8); b[3] = char(b.size());
            b[6] = b[7] = b[10] = b[11] = 0;
            auto sum = checksum_sum(Bytes(b).substr(0,(uint8_t(b[0]) & 15)*4));
            while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
            b[10] = char(~sum >> 8); b[11] = char(~sum);
            parse_packet(scan,b,101,host_capture);
            return;
        }
        pseudo = checksum_sum(ip.substr(12,8));
    } else if (proto == 0x86dd) {
        if (ip.size() < 40 || (octet(ip,0) >> 4) != 6) return;
        length = 40 + be16(ip,4); header = 40;
        src.v6 = dst.v6 = true;
        memcpy(src.bytes.data(),ip.data()+8,16); memcpy(dst.bytes.data(),ip.data()+24,16);
        size_t previous = 6;
        auto next = octet(ip,6);
        while (next == 0 || next == 43 || next == 60 || next == 51 || next == 44) {
            if (header + 8 > std::min(ip.size(),length)) return;
            size_t size = (octet(ip,header+1)+1)*8;
            if (next == 44) {
                auto frag = be16(ip,header+2);
                if (frag & 0xfff9) {
                    if (ip.size() < length) return;
                    auto prefix = std::string(ip.substr(0,header));
                    prefix[previous] = ip[header];
                    auto joined = scan.reassemble(src,dst,be32(ip,header+4),octet(ip,header),frag & 0xfff8,frag & 1,
                                                  ip.substr(header+8,length-header-8),std::move(prefix));
                    if (!joined || joined->size()-40 > 65535) return;
                    (*joined)[4] = char((joined->size()-40) >> 8); (*joined)[5] = char(joined->size()-40);
                    parse_packet(scan,*joined,101,host_capture);
                    return;
                }
                size = 8;
            } else if (next == 51) size = (octet(ip,header+1)+2)*4;
            previous = header;
            next = octet(ip,header); header += size;
        }
        if (next != 6) return;
        pseudo = checksum_sum(ip.substr(8,32));
    } else return;
    if (header + 20 > std::min(length,ip.size())) return;
    auto tcp = ip.substr(header,length-header);
    size_t th = (octet(tcp,12) >> 4) * 4;
    if (th < 20 || th > tcp.size()) return;
    // Local taps can see CHECKSUM_PARTIAL before the NIC completes the TCP checksum.
    auto seed = pseudo + 6 + uint32_t(length-header);
    while (seed >> 16) seed = (seed & 0xffff) + (seed >> 16);
    if (ip.size() >= length && !(host_capture && be16(tcp,16) == seed) &&
        !good_checksum(seed + checksum_sum(tcp))) return;
    scan.tcp({src,be16(tcp,0)}, {dst,be16(tcp,2)}, be32(tcp,4), be32(tcp,8), octet(tcp,13),length-header-th);
}

bool supported(uint32_t link) {
    return link == 1 || link == 0 || link == 50 || link == 108 || link == 101 || link == 228 ||
           link == 229 || link == 113 || link == 276;
}

void pcapng(Bytes input, bool host_capture, Scan& scan) {
    struct Interface { uint16_t link; uint64_t frequency = 1000000; bool binary = false; int64_t offset = 0; };
    std::vector<Interface> interfaces;
    std::optional<uint16_t> file_link;
    uint32_t file_snaplen = 0;
    const bool little = be32(input,8) == 0x4d3c2b1a;
    while (!input.empty()) {
        if (input.size() < 12) throw std::runtime_error("truncated PCAPNG block");
        bool section = be32(input,0) == 0x0a0d0d0a;
        if (section) {
            auto bom = be32(input,8);
            if (bom != 0x1a2b3c4d && bom != 0x4d3c2b1a) throw std::runtime_error("invalid PCAPNG byte order");
            if ((bom == 0x4d3c2b1a) != little) throw std::runtime_error("PCAPNG sections have different byte orders");
            interfaces.clear();
        }
        auto u32 = [&](size_t p) { auto n = be32(input,p); return little ? __builtin_bswap32(n) : n; };
        auto u16 = [&](size_t p) { auto n = be16(input,p); return little ? __builtin_bswap16(n) : n; };
        auto kind = u32(0), size = u32(4);
        if (size < 12 || size > input.size() || size % 4 || u32(size-4) != size) throw std::runtime_error("invalid PCAPNG block size");
        if (section) {
            if (size < 28 || u16(12) != 1) throw std::runtime_error("unsupported PCAPNG section version");
        } else if (kind == 1) {
            if (size < 20) throw std::runtime_error("truncated PCAPNG interface");
            Interface iface{u16(8)};
            if (!supported(iface.link)) throw std::runtime_error("unsupported PCAPNG link type");
            if (file_link && *file_link != iface.link)
                throw std::runtime_error("PCAPNG interfaces have different link types");
            uint32_t snaplen = u32(12);
            // libpcap uses a 256 KiB default for every link type supported here.
            if (!snaplen || snaplen > INT32_MAX) snaplen = 256 * 1024;
            if (file_snaplen && file_snaplen != snaplen)
                throw std::runtime_error("PCAPNG interfaces have different snapshot lengths");
            file_link = iface.link;
            file_snaplen = snaplen;
            for (size_t pos = 16; pos+4 <= size-4;) {
                auto opt = u16(pos), n = u16(pos+2);
                pos += 4;
                if (pos+n > size-4) throw std::runtime_error("invalid PCAPNG interface option");
                if (!opt) break;
                if (opt == 9 && n == 1) {
                    unsigned resolution = octet(input,pos), exponent = resolution & 127;
                    iface.binary = resolution & 128;
                    if (exponent > (iface.binary ? 63U : 19U)) throw std::runtime_error("invalid PCAPNG timestamp resolution");
                    iface.frequency = 1;
                    for (unsigned i = 0; i < exponent; ++i) iface.frequency *= iface.binary ? 2 : 10;
                }
                if (opt == 14 && n == 8) {
                    uint32_t high = u32(pos + (little ? 4 : 0)), low = u32(pos + (little ? 0 : 4));
                    iface.offset = static_cast<int64_t>((uint64_t(high) << 32) | low);
                }
                pos += (size_t(n)+3) & ~size_t(3);
            }
            interfaces.push_back(iface);
        } else if (kind == 6 || kind == 2 || kind == 3) {
            if (size < (kind == 3 ? 16U : 32U)) throw std::runtime_error("truncated PCAPNG packet");
            auto index = kind == 6 ? u32(8) : kind == 2 ? u16(8) : 0;
            if (index >= interfaces.size()) throw std::runtime_error("unknown PCAPNG interface");
            const auto& iface = interfaces[index];
            size_t pos = kind == 3 ? 12 : 28;
            size_t cap = kind == 3 ? std::min(u32(8),size-16) : u32(20);
            if (cap > size-4-pos || (kind != 3 && cap > u32(24))) throw std::runtime_error("invalid PCAPNG capture length");
            uint64_t ticks = kind == 3 ? 0 : (uint64_t(u32(12)) << 32) | u32(16);
            auto fraction = ticks % iface.frequency;
            auto us = !iface.binary && iface.frequency >= 1000000 ? fraction / (iface.frequency / 1000000)
                                                                  : fraction * 1000000 / iface.frequency;
            auto seconds = static_cast<int64_t>(ticks / iface.frequency + iface.offset);
            scan.advance(seconds + us / 1e6);
            parse_packet(scan,input.substr(pos,cap),iface.link,host_capture);
        }
        input.remove_prefix(size);
    }
    scan.advance(scan.now,true);
}
}

struct ZeekStream::State : Scan {};
ZeekStream::ZeekStream(Publish publish) : state(std::make_unique<State>()) {
    state->publish = std::move(publish);
}
ZeekStream::~ZeekStream() = default;
void ZeekStream::packet(uint64_t ns, std::string_view ip) {
    advance(ns);
    parse_packet(*state, ip, 101, true);
}
void ZeekStream::advance(uint64_t ns, bool finish) {
    state->advance(ns / 1000000000 + ((ns % 1000000000) / 1000) / 1e6, finish);
}

void zeek(std::string_view input, bool host_capture, Publish publish) {
    if (input.size() < 24) throw std::runtime_error("truncated PCAP header");
    Scan scan;
    scan.publish = std::move(publish);
    auto magic = be32(input,0);
    if (magic == 0x0a0d0d0a) return pcapng(input,host_capture,scan);
    bool little = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
    bool nano = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
    if (!little && magic != 0xa1b2c3d4 && !nano) throw std::runtime_error("expected classic PCAP");
    auto u32 = [&](size_t p) { auto x = be32(input,p); return little ? __builtin_bswap32(x) : x; };
    auto u16 = [&](size_t p) { auto x = be16(input,p); return little ? __builtin_bswap16(x) : x; };
    const auto minor = u16(6);
    if (u16(4) != 2 || (minor != 3 && minor != 4)) throw std::runtime_error("unsupported PCAP version");
    auto link = u32(20) & 0xffff;
    if (!supported(link))
        throw std::runtime_error("unsupported PCAP link type " + std::to_string(link));
    input.remove_prefix(24);
    while (!input.empty()) {
        if (input.size() < 16) throw std::runtime_error("truncated PCAP packet header");
        auto cap = u32(8), wire = u32(12);
        // PCAP 2.3 writers used both orders for the captured and original lengths.
        if (minor == 3 && cap > wire) std::swap(cap, wire);
        if (cap > input.size()-16 || cap > wire) throw std::runtime_error("invalid PCAP packet length");
        auto usec = nano ? u32(4) / 1000 : u32(4);
        scan.advance(u32(0) + usec / 1e6);
        parse_packet(scan,input.substr(16,cap),link,host_capture);
        input.remove_prefix(16+size_t(cap));
    }
    scan.advance(scan.now,true);
}

Json zeek(std::string_view input, bool host_capture) {
    Json notices = Json::array();
    zeek(input, host_capture, [&](const Json& notice) { notices.push_back(notice); });
    return notices;
}
}
