#pragma once

#include "layout.hpp"

#include <algorithm>
#include <array>
#include <cstdint>

namespace mds {

enum Model : uint8_t { kMk1 = 0, kMk2 = 1, kModels = 2 };
constexpr std::array<const char*, kModels> kModelNames{{"mk1", "mk2"}};

// Ring: the input and main-output rings, internal X on MKI and external
// SRAM (one wait state) on MKII.
enum class Region : uint8_t { Internal, Sram, Dram, Sample, Peripheral, Ring };

inline Region program_region(uint32_t address) {
    return address < kInternalProgramEnd ? Region::Internal
         : address >= kSramBegin && address < kSramEnd ? Region::Sram
         : address >= kSampleMemory ? Region::Sample
         : Region::Dram;
}

inline Region data_region(uint32_t address) {
    if (address < kInternalDataEnd) return Region::Internal;
    if (address >= kPeripherals) return Region::Peripheral;
    return program_region(address);
}

class InstructionCache {
public:
    InstructionCache() { clear(); }

    void clear() {
        for (unsigned index = 0; index != kSectors; ++index) {
            sectors_[index].tag = kEmpty;
            sectors_[index].valid.fill(false);
            order_[index] = static_cast<uint8_t>(index);
        }
    }

    bool miss(uint32_t address) {
        const uint32_t tag = address / kSectorWords, word = address % kSectorWords;
        for (unsigned index = 0; index != kSectors; ++index) {
            Sector& sector = sectors_[index];
            if (sector.tag != tag) continue;
            touch(static_cast<uint8_t>(index));
            if (sector.valid[word]) return false;
            sector.valid[word] = true;
            return true;
        }
        const uint8_t victim = order_[kSectors - 1];
        sectors_[victim].tag = tag;
        sectors_[victim].valid.fill(false);
        sectors_[victim].valid[word] = true;
        touch(victim);
        return true;
    }

    void evict(unsigned count) {
        for (unsigned index = 0; index != std::min(count, kSectors); ++index) {
            Sector& sector = sectors_[order_[kSectors - 1 - index]];
            sector.tag = kEmpty;
            sector.valid.fill(false);
        }
    }

private:
    static constexpr unsigned kSectors = 8;
    static constexpr uint32_t kSectorWords = 128;
    static constexpr uint32_t kEmpty = 0xffffffffu;
    struct Sector {
        uint32_t tag;
        std::array<bool, kSectorWords> valid;
    };

    void touch(uint8_t sector) {
        unsigned position = 0;
        while (order_[position] != sector) ++position;
        for (; position != 0; --position) order_[position] = order_[position - 1];
        order_[0] = sector;
    }

    std::array<Sector, kSectors> sectors_{};
    std::array<uint8_t, kSectors> order_{};
};

class Bus {
public:
    explicit Bus(Model model) : model_(model) {}

    void cold() {
        clock_ = 0;
        free_ = 0;
        page_open_ = false;
        next_refresh_ = 0;
    }

    uint64_t access(Region region, uint32_t address, uint64_t offset) {
        uint64_t at = clock_ + offset;
        if (model_ == kMk1) {
            while (next_refresh_ <= at) {
                free_ = std::max(free_, next_refresh_) + kRefreshClocks;
                next_refresh_ += kRefreshPeriod;
                page_open_ = false;
            }
        }
        const uint64_t held = at < free_ ? free_ - at : 0;
        at += held;
        uint64_t waits = kSramWaits, trailing = 0;
        if (model_ == kMk2) {
            if (region == Region::Sample) {
                waits = kMk2SampleWaits;
                trailing = 1;
            }
        } else if (region == Region::Dram || region == Region::Sample) {
            const uint32_t page = address >> kPageShift;
            waits = page_open_ && page == page_ ? kInPageWaits : kOutOfPageWaits;
            page_open_ = true;
            page_ = page;
        }
        free_ = at + 1 + waits + trailing;
        return held + waits;
    }

    void elapse(uint64_t clocks) {
        clock_ += clocks;
        free_ = std::max(free_, clock_);
        page_open_ = false;
    }

    void advance(uint64_t clocks) { clock_ += clocks; }

private:
    static constexpr uint64_t kSramWaits = 1, kMk2SampleWaits = 4;
    static constexpr uint64_t kInPageWaits = 2, kOutOfPageWaits = 8;
    static constexpr uint32_t kPageShift = 9;
    static constexpr uint64_t kRefreshPeriod = 1472, kRefreshClocks = 9;

    Model model_;
    uint64_t clock_ = 0, free_ = 0, next_refresh_ = 0;
    bool page_open_ = false;
    uint32_t page_ = 0;
};

}
