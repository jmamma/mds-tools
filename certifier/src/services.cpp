#include "services.hpp"

#include <algorithm>

namespace mds {
namespace {

using dsp56k::MemArea_X;
using dsp56k::MemArea_Y;

constexpr uint64_t kSampleInfoClocks = 328;
constexpr uint64_t kSampleReadClocks = 487, kSampleReadPerFrame = 41;
constexpr uint64_t kRamWorkspaceClocks = 403;
constexpr uint64_t kRamRecordStartClocks = 572;
constexpr uint64_t kRamRecordClocks = 1045, kRamRecordPerFrame = 59;

constexpr uint32_t kInternalSlots = 21;

int32_t signed24(uint32_t value) {
    return static_cast<int32_t>(value << 8) >> 8;
}

uint32_t synthetic_frame(uint32_t bank, uint32_t slot, uint32_t frame) {
    uint32_t value = frame * 0x9e3779b1u ^ (bank * 64 + slot) * 0x85ebca6bu;
    value ^= value >> 15;
    return (value * 0x2c1b3c6du >> 8) & kMask24;
}

}

void Services::reset(uint32_t seed, bool recordings) {
    seed_ = state_ = seed | 1;
    for (uint32_t index = 0; index != kRamSlots; ++index) {
        Slot& slot = slots_[index];
        slot = Slot{};
        if (recordings && index < ram_slots()) {
            slot.recording = true;
            slot.step = 0x010000;
            for (uint32_t frame = 0; frame != 4096; ++frame) slot.frames.push_back(synthetic_frame(2, index, frame));
        }
    }
}

uint32_t Services::noise() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 17;
    state_ ^= state_ << 5;
    return state_ & kMask24;
}

void Services::scramble(Emulator& emulator, bool a, bool b, bool x1) {
    using namespace dsp56k;
    for (EReg reg : {Reg_R0, Reg_R1, Reg_R2, Reg_R3, Reg_R4, Reg_R5, Reg_N0, Reg_N1, Reg_N2, Reg_N3, Reg_N4,
                     Reg_N5, Reg_N6, Reg_N7, Reg_Y1})
        emulator.set_reg(reg, noise());
    for (EReg reg : {Reg_M0, Reg_M1, Reg_M2, Reg_M3, Reg_M4, Reg_M5}) emulator.set_reg(reg, kMask24);
    if (!x1) emulator.set_reg(Reg_X1, noise());
    if (!a) emulator.set_accumulator(Reg_A, static_cast<uint64_t>(noise()) << 24 | noise());
    if (!b) emulator.set_accumulator(Reg_B, static_cast<uint64_t>(noise()) << 24 | noise());
}

uint64_t Services::call(unsigned index, Emulator& emulator, Permissions& permissions) {
    switch (index) {
    case 0: return sample_info(emulator);
    case 1: return sample_read(emulator);
    case 2: return ram_workspace(emulator, permissions);
    default: return ram_record(emulator, permissions);
    }
}

uint64_t Services::sample_info(Emulator& emulator) {
    const uint32_t bank = emulator.reg(dsp56k::Reg_X0), slot = emulator.reg(dsp56k::Reg_Y0);
    uint32_t length = 0, step = 0, loop = kMask24;
    if (bank == 0 && slot < kInternalSlots) {
        length = kSampleFrames;
        step = 0x010000;
    } else if (bank == 1 && slot < userwave_slots()) {
        length = kSampleFrames;
        step = 0x008000 + slot * 0x000400;
        loop = (slot & 1) != 0 ? kSampleFrames / 2 : kMask24;
    } else if (bank == 2 && slot < ram_slots() && slots_[slot].recording) {
        length = static_cast<uint32_t>(slots_[slot].frames.size());
        step = slots_[slot].step;
    }
    emulator.set_accumulator1(dsp56k::Reg_A, length);
    emulator.set_accumulator1(dsp56k::Reg_B, step);
    emulator.set_reg(dsp56k::Reg_X1, loop);
    scramble(emulator, true, true, true);
    return kSampleInfoClocks;
}

uint64_t Services::sample_read(Emulator& emulator) {
    const uint32_t bank = emulator.reg(dsp56k::Reg_X0), slot = emulator.reg(dsp56k::Reg_Y0);
    const uint32_t count = emulator.reg(dsp56k::Reg_N0);
    const bool valid = count >= 1 && count <= kBlock &&
                       ((bank == 0 && slot < kInternalSlots) || (bank == 1 && slot < userwave_slots()) ||
                        (bank == 2 && slot < ram_slots() && slots_[slot].recording));
    for (uint32_t word = 0; word != kBlock; ++word) {
        uint32_t value = 0;
        if (valid && word < count) {
            const int32_t position = signed24(emulator.get(MemArea_Y, kTemp + word));
            const uint32_t length = bank == 2 ? static_cast<uint32_t>(slots_[slot].frames.size()) : kSampleFrames;
            if (position >= 0 && static_cast<uint32_t>(position) < length)
                value = bank == 2 ? slots_[slot].frames[position] : synthetic_frame(bank, slot, position);
        }
        emulator.set(MemArea_X, kTemp + word, value);
    }
    emulator.set_accumulator1(dsp56k::Reg_A, valid ? 1 : 0);
    scramble(emulator, true, false, false);
    return kSampleReadClocks + kSampleReadPerFrame * std::clamp<uint32_t>(count, 1, kBlock);
}

uint64_t Services::ram_workspace(Emulator& emulator, Permissions& permissions) {
    const uint32_t index = emulator.reg(dsp56k::Reg_X0);
    uint32_t begin = 0, words = 0;
    permissions.loan = permissions.loan_words = 0;
    if (index < ram_slots() && !slots_[index].recording) {
        Slot& slot = slots_[index];
        if (slot.holder == permissions.track) {
            slot.calls_without_holder = 0;
        } else if (slot.holder == 0xffffffffu || ++slot.calls_without_holder > 16) {
            slot.holder = permissions.track;
            slot.calls_without_holder = 0;
        }
        if (slot.holder == permissions.track) {
            begin = ram_slot(index);
            words = kRamSlotWords;
            permissions.loan = begin;
            permissions.loan_words = words;
        }
    }
    emulator.set_accumulator1(dsp56k::Reg_A, begin);
    emulator.set_accumulator1(dsp56k::Reg_B, words);
    scramble(emulator, true, true, false);
    return kRamWorkspaceClocks;
}

uint64_t Services::ram_record(Emulator& emulator, Permissions& permissions) {
    const uint32_t index = emulator.reg(dsp56k::Reg_X0), count = emulator.reg(dsp56k::Reg_N0);
    uint32_t length = 0, room = 0;
    uint64_t clocks = kRamRecordClocks + kRamRecordPerFrame * std::clamp<uint32_t>(count, 1, kBlock);
    if (index < ram_slots()) {
        Slot& slot = slots_[index];
        if (count == 0) {
            clocks = kRamRecordStartClocks;
            const uint32_t step = emulator.reg(dsp56k::Reg_Y0);
            if (step >= 1 && step <= 0x010000) {
                slot.recording = true;
                slot.owner = permissions.track;
                slot.step = step;
                slot.frames.clear();
                slot.holder = 0xffffffffu;
                if (permissions.loan == ram_slot(index)) permissions.loan = permissions.loan_words = 0;
                room = kRecordingCapacity;
            }
        } else if (count <= kBlock && slot.recording && slot.owner == permissions.track) {
            for (uint32_t word = 0; word != count && slot.frames.size() < kRecordingCapacity; ++word)
                slot.frames.push_back(emulator.get(MemArea_X, kTemp + word));
            length = static_cast<uint32_t>(slot.frames.size());
            room = kRecordingCapacity - length;
        }
    }
    emulator.set_accumulator1(dsp56k::Reg_A, length);
    emulator.set_accumulator1(dsp56k::Reg_B, room);
    scramble(emulator, true, true, false);
    return clocks;
}

}
