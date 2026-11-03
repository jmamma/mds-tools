#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace mds {

enum Conversion : uint8_t {
    kRaw14 = 0, kUnipolar = 1, kSquared = 2, kBipolar = 3, kPitch = 4,
    kBoolean = 5, kIndex = 6, kDecay = 7, kTempo = 8,
};

struct Parameter {
    std::string name;
    uint8_t default_value = 0, minimum = 0, maximum = 127;
    uint8_t style = 0;
    Conversion conversion() const { return static_cast<Conversion>(style & 0x0f); }
};

struct Import {
    uint16_t word = 0;
    uint8_t kind = 0, symbol = 0;
};

struct Package {
    std::vector<uint8_t> bytes;
    std::vector<uint32_t> program;
    std::vector<bool> relocated;
    std::vector<Import> imports;
    std::vector<Parameter> parameters;
    uint16_t x_words = 0, y_words = 0;
    uint16_t init = 0, trig = 0, render = 0;
    uint16_t mk2_cycles = 0, mk1_cycles = 0, mk1_sram_cycles = 0;
    bool tonal = false, continuous_retrigger = false, neighbour = false, stereo_pair = false;
    std::string category, code, name;

    bool imports_symbol(uint8_t symbol) const;
};

bool parse_package(const std::vector<uint8_t>& bytes, Package& package, std::string& error);

std::vector<uint8_t> stamp_cycles(const Package& package, uint16_t mk1, uint16_t mk2, uint16_t mk1_sram);

uint32_t parameter_value(const Parameter& parameter, uint8_t setting, uint32_t bpm = 120);

}
