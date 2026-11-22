#include "zeek.cpp"
#include <fstream>
#include <iostream>
#include <iterator>

int main(int argc, char** argv) {
    const bool sessions = argc == 3 && std::string_view(argv[1]) == "--sessions";
    if (argc != 2 && !sessions) return 1;
    std::ifstream input(argv[argc-1], std::ios::binary);
    std::string contents{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    std::string_view p(contents);
    if (p.size() < 24 || rz::be32(p, 0) != 0xd4c3b2a1) return 1;
    p.remove_prefix(24);
    rz::Scan scan;
    unsigned session_checks = 0;
    while (p.size() >= 16) {
        auto le32 = [&](size_t i) { return __builtin_bswap32(rz::be32(p, i)); };
        if (le32(8) > p.size() - 16) return 1;
        scan.advance(le32(0) + le32(4) / 1e6);
        auto packet = p.substr(16, le32(8));
        rz::parse_packet(scan, packet, 1);
        if (sessions && packet.size() >= 54 && rz::be32(packet, 26) == 0xc00002fa) {
            bool ssh = false, http = false;
            for (const auto& entry : scan.connections) {
                ssh |= entry.second.origin.second == 45000;
                http |= entry.second.origin.second == 45001;
            }
            const auto port = rz::be16(packet, 34);
            std::cout << port << ' ' << ssh << ' ' << http << '\n';
            if (port != 49001 + session_checks || !ssh || http != (session_checks == 0)) return 1;
            ++session_checks;
        } else if (!sessions && packet.size() >= 54 && rz::be32(packet, 26) == 0xc00002fb && rz::octet(packet, 47) == 2) {
            std::cout << rz::be16(packet, 34) - 50000 << ' ' << scan.suppression.size() << '\n';
            if (scan.suppression.size() != scan.suppression_expiry.size()) return 1;
        }
        p.remove_prefix(16 + packet.size());
    }
    if (sessions) return !p.empty() || session_checks != 2;
    return !p.empty() || !scan.suppression.empty() || !scan.suppression_expiry.empty();
}
