#pragma once

#include <array>
#include <cstdint>

namespace mds {

constexpr uint32_t kMask24 = 0xffffffu;
constexpr uint32_t kTracks = 16u;
constexpr uint32_t kBlock = 32u;

constexpr uint32_t kCallStub = 0x000100u;
constexpr uint32_t kReturnSentinel = 0x000102u;
constexpr uint32_t kAbortEnddo = 0x000104u;
constexpr uint32_t kAbortNop = 0x000105u;
constexpr std::array<uint32_t, 4> kServiceEntry{{0x000110u, 0x000112u, 0x000114u, 0x000116u}};

constexpr uint32_t kTemp = 0x000000u;
constexpr uint32_t kInputCursor = 0x0000f0u;
constexpr uint32_t kMainOutputCursor = 0x0000f1u;
constexpr uint32_t kTriggerInfo = 0x0000f2u;
constexpr uint32_t kInputRing = 0x000100u;
constexpr uint32_t kMainOutputRing = 0x000200u;
constexpr uint32_t kRingWords = 256u;
constexpr std::array<uint32_t, 4> kOutputBuffer{{0x000100u, 0x000120u, 0x000140u, 0x000160u}};
constexpr uint32_t kDescriptors = 0x000180u;
constexpr uint32_t kDescriptorWord = 0x0007f0u;
constexpr uint32_t kWorkset = 0x000800u;
constexpr uint32_t kWorksetWords = 64u;
constexpr uint32_t kInternalProgramEnd = 0x000400u;
constexpr uint32_t kInternalDataEnd = 0x000c00u;

constexpr uint32_t kExternal = 0x100000u;
constexpr uint32_t kProgramRegion = 0x100000u;
constexpr uint32_t kProgramRegionWords = 0x20000u;
constexpr uint32_t kTrackMemory = 0x120000u;
constexpr uint32_t kTrackMemoryWords = 1536u;
constexpr uint32_t kSramBegin = 0x140000u;
constexpr uint32_t kSramEnd = 0x150000u;
constexpr uint32_t kSineTable = 0x140000u;
constexpr uint32_t kSineWords = 32768u;
// Where MKI SRAM placements put the program: the SRAM after the sine table.
constexpr uint32_t kSramProgramRegion = kSineTable + kSineWords;
constexpr uint32_t kSampleMemory = 0x180000u;
constexpr uint32_t kRamSlots = 4u;
constexpr uint32_t kRamSlotWords = 0x10000u;
constexpr uint32_t kMemoryEnd = 0x200000u;
constexpr uint32_t kPeripherals = 0xffff80u;

constexpr uint32_t workset(uint32_t track) { return kWorkset + track * kWorksetWords; }
constexpr uint32_t track_memory(uint32_t track) { return kTrackMemory + track * kTrackMemoryWords; }
constexpr uint32_t ram_slot(uint32_t slot) { return kSampleMemory + slot * kRamSlotWords; }

enum Symbol : uint8_t {
    kSymSine = 1, kSymInputRing = 2, kSymInputCursor = 3, kSymMainRing = 4,
    kSymMainCursor = 5, kSymTrackMemory = 6, kSymTempX = 7, kSymTempY = 8,
    kSymSampleInfo = 9, kSymSampleRead = 10, kSymRamWorkspace = 11, kSymRamRecord = 12,
    kSymTriggerInfo = 13,
};

}
