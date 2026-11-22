#pragma once

#include <fstream>
#include <stdexcept>
#include <string>

namespace rz {
inline std::string read_capture(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    auto size = file.tellg();
    if (size < 0 || size > 64 * 1024 * 1024)
        throw std::runtime_error("cannot open capture or capture exceeds 64 MiB: " + path);
    std::string bytes(static_cast<size_t>(size), '\0');
    file.seekg(0);
    if (!file.read(bytes.data(), size)) throw std::runtime_error("cannot read " + path);
    return bytes;
}
}
