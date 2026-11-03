#pragma once

#include "emulator.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace mds {

enum class Hardware : uint8_t { NonUW, Mk1UW, Mk2UW };

class Services final : public ServiceProvider {
public:

    explicit Services(Hardware hardware = Hardware::Mk2UW) : hardware_(hardware) {}

    void reset(uint32_t seed, bool recordings);

    uint64_t call(unsigned index, Emulator& emulator, Permissions& permissions) override;

    static constexpr uint32_t kSampleFrames = 65536;
    static constexpr uint32_t kRecordingCapacity = 2 * kRamSlotWords - 32;

private:
    struct Slot {
        bool recording = false;
        uint32_t owner = 0xffffffffu, step = 0;
        std::vector<uint32_t> frames;
        uint32_t holder = 0xffffffffu;
        unsigned calls_without_holder = 0;
    };

    uint64_t sample_info(Emulator& emulator);
    uint64_t sample_read(Emulator& emulator);
    uint64_t ram_workspace(Emulator& emulator, Permissions& permissions);
    uint64_t ram_record(Emulator& emulator, Permissions& permissions);
    void scramble(Emulator& emulator, bool a, bool b, bool x1);
    uint32_t noise();

    uint32_t userwave_slots() const { return hardware_ == Hardware::NonUW ? 0u : hardware_ == Hardware::Mk1UW ? 32u : 48u; }
    uint32_t ram_slots() const { return hardware_ == Hardware::NonUW ? 0u : hardware_ == Hardware::Mk1UW ? 2u : 4u; }
    Hardware hardware_;
    uint32_t seed_ = 1, state_ = 1;
    std::array<Slot, kRamSlots> slots_{};
};

}
