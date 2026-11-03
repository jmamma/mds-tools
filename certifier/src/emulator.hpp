#pragma once

#include "layout.hpp"
#include "package.hpp"
#include "timing.hpp"

#include "dsp56kEmu/dsp.h"
#include "dsp56kEmu/memory.h"
#include "dsp56kEmu/peripherals.h"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace mds {

enum class Routine : uint8_t { Init, Trig, Render };

struct Permissions {
    uint32_t track = 0;
    Routine routine = Routine::Render;
    uint32_t output = 0;
    uint16_t x_words = 0, y_words = 0;
    uint32_t state_from = 1;
    bool temp_x = false, temp_y = false, track_memory = false, trigger_info = false;
    uint32_t loan = 0, loan_words = 0;
    uint32_t output_written = 0;
};

struct Costs {
    std::array<uint64_t, kModels> cycles{};
    uint64_t nominal = 0;
    uint64_t service = 0;
    uint64_t instructions = 0;
    int64_t max_stack = 0;
};

class Emulator;

class ServiceProvider {
public:
    virtual ~ServiceProvider() = default;

    virtual uint64_t call(unsigned index, Emulator& emulator, Permissions& permissions) = 0;
};

class Tracer;

class Emulator {
public:
    Emulator();
    ~Emulator();
    Emulator(const Emulator&) = delete;
    Emulator& operator=(const Emulator&) = delete;

    uint32_t get(dsp56k::EMemArea area, uint32_t address);
    void set(dsp56k::EMemArea area, uint32_t address, uint32_t value);
    uint32_t reg(dsp56k::EReg reg);
    void set_reg(dsp56k::EReg reg, uint32_t value);
    void set_accumulator(dsp56k::EReg reg, uint64_t value56);
    void set_accumulator1(dsp56k::EReg reg, uint32_t value24);

    void install(const Package& package, uint32_t base, ServiceProvider& services);

    std::vector<std::string> scan_loops();

    void begin_track();

    bool call(uint32_t entry, Permissions& permissions, Costs& costs, std::string& error);

private:
    friend class Tracer;
    dsp56k::DefaultMemoryValidator validator_;
    std::unique_ptr<dsp56k::Memory> memory_;
    dsp56k::Peripherals56303 peripherals_x_;
    dsp56k::PeripheralsNop peripherals_y_;
    std::unique_ptr<dsp56k::DSP> dsp_;
    std::unique_ptr<Tracer> tracer_;
};

}
