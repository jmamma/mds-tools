#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace mds {

struct Dump {
    uint8_t slot = 0;
    std::vector<uint8_t> bytes;
};

bool decode_sysex(const std::vector<uint8_t>& bytes, std::vector<Dump>& dumps, std::string& error);

}
