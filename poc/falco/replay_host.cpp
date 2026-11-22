#include "host.hpp"
#include <iostream>
#include <stdexcept>
#include <string_view>

int main(int argc, char** argv) {
    if (argc < 5) {
        std::cerr << "usage: falco-sgx ENCLAVE CONFIG CAPTURE [--dns-hosts FILE] "
                     "[--plugin|--plugin-tetragon|--plugin-host EVENTS PCAP | --plugin-stream EVENTS] RULES...\n";
        return 2;
    }
    try {
        auto trace = read(argv[3]);
        if (trace.compare(0, 4, "\x0a\x0d\x0d\x0a") != 0 || trace.size() > 64 * 1024 * 1024) {
            throw std::runtime_error("expected an uncompressed .scap of at most 64 MiB");
        }
        int first_rule = 4;
        std::string dns_hosts;
        if (std::string_view(argv[4]) == "--dns-hosts") {
            if (argc < 7) {
                throw std::runtime_error("expected a DNS hosts file and at least one rule file");
            }
            dns_hosts = read(argv[5]);
            if (dns_hosts.size() > 64 * 1024 || dns_hosts.find('\0') != std::string::npos) {
                throw std::runtime_error("expected a text DNS hosts file of at most 64 KiB");
            }
            first_rule = 6;
        }
        const auto plugin = PluginInputs::parse(argc, argv, first_rule);
        auto enclave = load_enclave(argv[1], argv[2], argv + first_rule, argc - first_rule);
        int result = -1;
        const auto status = falco_replay(enclave.get(), &result,
                                         reinterpret_cast<uint8_t*>(trace.data()), trace.size(), dns_hosts.c_str());
        check(status, result, "Falco replay");
        plugin.replay(enclave.get());
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
