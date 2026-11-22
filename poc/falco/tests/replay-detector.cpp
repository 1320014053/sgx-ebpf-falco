#include "detectors.hpp"
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

// The archived per-packet tests use little-endian Ethernet II PCAPs from x86-64.
static void replay_ip(std::ifstream& input, rz::Publish publish) {
    std::array<uint32_t, 6> global{};
    if (!input.read(reinterpret_cast<char*>(global.data()), sizeof(global)) ||
        (global[0] != 0xa1b2c3d4 && global[0] != 0xa1b23c4d) || global[5] != 1)
        throw std::runtime_error("expected a little-endian Ethernet PCAP");
    rz::ZeekStream detector(publish);
    uint64_t ns = 0;
    while (input.peek() != std::char_traits<char>::eof()) {
        std::array<uint32_t, 4> frame{};
        if (!input.read(reinterpret_cast<char*>(frame.data()), sizeof(frame)) ||
            frame[2] < 14 || frame[2] > 65535)
            throw std::runtime_error("invalid test frame header");
        std::string data(frame[2], '\0');
        if (!input.read(data.data(), data.size())) throw std::runtime_error("short test frame");
        ns = uint64_t(frame[0]) * 1000000000 + uint64_t(frame[1]) * (global[0] == 0xa1b2c3d4 ? 1000 : 1);
        detector.packet(ns, std::string_view(data).substr(14));
    }
    detector.advance(ns, true);
}

int main(int argc, char** argv) try {
    if (argc != 3) return 2;
    const std::string mode = argv[1];
    std::ifstream input(argv[2], std::ios::binary);
    if (!input) return 2;
    const auto publish = [](const rz::Json& row) { std::cout << row.dump() << '\n'; };
    if (mode == "ip") {
        replay_ip(input, publish);
    } else if (mode == "stream") {
        rz::RavenStream detector(publish);
        std::string line;
        while (std::getline(input, line)) detector.line(line);
        detector.advance(0, true);
    } else {
        const std::string data{std::istreambuf_iterator<char>(input), {}};
        if (mode == "zeek") rz::zeek(data, false, publish);
        else if (mode == "raven" || mode == "tetragon")
            for (const auto& row : rz::raven(data, mode == "tetragon")) publish(row);
        else return 2;
    }
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
