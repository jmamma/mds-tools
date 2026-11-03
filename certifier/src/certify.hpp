#pragma once

#include "package.hpp"
#include "timing.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace mds {

enum class CheckMode { Full, Quick };

struct Report {
    bool certified = false;
    bool development_only = false;
    bool development_checks_passed = false;
    std::string error;

    std::array<uint64_t, kModels> track{};

    std::array<uint64_t, kModels> machine{};

    std::array<uint64_t, kModels> block{};

    std::array<uint64_t, kModels> init{};

    // MKI with the program in SRAM; track, machine, block and init above
    // cover every placement.
    uint64_t sram_track = 0, sram_machine = 0, sram_block = 0, sram_init = 0;

    // The certified figures above are the larger of two: the standard vectors'
    // worst block (`standard`) and the peaks the transition pass and the
    // random tail find (`peak`).
    std::array<uint64_t, kModels> standard{}, peak{};
    uint64_t sram_standard = 0, sram_peak = 0;
    std::array<std::string, kModels> peak_detail;
    std::string sram_peak_detail;

    uint64_t nominal = 0;
    size_t vectors = 0, placements = 0, blocks = 0;

    std::vector<std::string> warnings;
};

Report certify(const Package& package, const std::function<void(const std::string&)>& progress = {},
               CheckMode mode = CheckMode::Full);

std::vector<std::string> scan_loops(const Package& package);

}
