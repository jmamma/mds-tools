#include "emulator.hpp"

#include "dsp56kEmu/debuggerinterface.h"
#include "dsp56kEmu/disasm.h"
#include "dsp56kEmu/logging.h"
#include "dsp56kEmu/opcodecycles.h"
#include "dsp56kEmu/opcodes.h"
#include "dsp56kEmu/opcodeanalysis.h"
#include "dsp56kEmu/pipelinetiming.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <regex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mds {
namespace {

using dsp56k::EMemArea;
using dsp56k::Instruction;

constexpr uint32_t kJsrLong = 0x0bf080u;
constexpr uint32_t kRts = 0x00000cu;
constexpr uint32_t kEnddo = 0x00008cu;
constexpr uint32_t kNop = 0x000000u;
constexpr uint64_t kInstructionBound = 4000000u;
constexpr unsigned kServiceSectors = 4;

std::string hex(uint32_t value) {
    char text[16];
    std::snprintf(text, sizeof text, "$%06x", value & kMask24);
    return text;
}

bool in(uint32_t address, uint32_t begin, uint32_t words) {
    return address >= begin && address - begin < words;
}

bool restricted(Instruction instruction) {
    switch (instruction) {
    case dsp56k::Andi: case dsp56k::Ori:
    case dsp56k::Movep_ppea: case dsp56k::Movep_Xqqea: case dsp56k::Movep_Yqqea: case dsp56k::Movep_eapp:
    case dsp56k::Movep_eaqq: case dsp56k::Movep_Spp: case dsp56k::Movep_SXqq: case dsp56k::Movep_SYqq:
    case dsp56k::Reset: case dsp56k::Rti: case dsp56k::Stop: case dsp56k::Trap: case dsp56k::Trapcc:
    case dsp56k::Wait: case dsp56k::Debug: case dsp56k::Debugcc: case dsp56k::Illegal:
    case dsp56k::Pflush: case dsp56k::Pflushun: case dsp56k::Pfree: case dsp56k::Plock:
    case dsp56k::Plockr: case dsp56k::Punlock: case dsp56k::Punlockr:
        return true;
    default:
        return false;
    }
}

bool unsupported(Instruction instruction) {
    switch (instruction) {
    case dsp56k::BRKcc: case dsp56k::DoForever: case dsp56k::DorForever:
    case dsp56k::Lra_Rn: case dsp56k::Norm: case dsp56k::Rep_ea: case dsp56k::Rep_aa:
    case dsp56k::ADC: case dsp56k::Extract_S1S2: case dsp56k::Extract_CoS2: case dsp56k::Merge:
    case dsp56k::Mpyr_SD: case dsp56k::Mpyri: case dsp56k::Ror: case dsp56k::Sbc: case dsp56k::Vsl:
    case dsp56k::Movem_aa:
        return true;
    default:
        return false;
    }
}

bool loop_start(Instruction instruction) {
    switch (instruction) {
    case dsp56k::Do_ea: case dsp56k::Do_aa: case dsp56k::Do_xxx: case dsp56k::Do_S:
    case dsp56k::Dor_ea: case dsp56k::Dor_aa: case dsp56k::Dor_xxx: case dsp56k::Dor_S:
        return true;
    default:
        return false;
    }
}

struct Decoded {
    Instruction first = dsp56k::Invalid, second = dsp56k::Invalid;
    uint32_t length = 1, op = 0, op_b = 0;
    std::string text, mnemonic;
    bool flow = false;
    bool control_write = false, control_read = false, stack_read = false, test_ssh = false;
    bool protected_write = false;
    bool io = false;
};

}

class Tracer final : public dsp56k::DebuggerInterface {
public:
    Tracer(dsp56k::DSP& dsp, Emulator& emulator)
        : DebuggerInterface(dsp), emulator_(emulator), disassembler_(dsp.opcodes()) {}

    void program(uint32_t base, uint32_t words, ServiceProvider& services, std::array<bool, 4> imported, const Package& package) {
        base_ = base;
        words_ = words;
        services_ = &services;
        imported_ = imported;
        resources_ = 0;
        for (const auto& item : package.imports) resources_ |= 1u << item.symbol;
        neighbour_ = package.neighbour;
        decoded_.clear();
        loops_checked_.clear();
    }

    void begin_track() {
        cache_.clear();
        for (auto& bus : buses_) bus.cold();
    }

    void forget(uint32_t address) { decoded_.erase(address); }

    void begin(Permissions& permissions, Costs& costs) {
        permissions_ = &permissions;
        costs_ = &costs;
        error_.clear();
        aborting_ = false;
        instructions_ = 0;
        pipeline_.reset();
        calls_.clear();
        call_pending_ = return_pending_ = false;
        pending_valid_ = false;
        loop_body_ = kNone;
        active_ = true;
    }

    void end() {
        finalize();
        active_ = false;
        costs_->instructions += instructions_;
    }

    bool aborting() const { return aborting_; }
    const std::string& error() const { return error_; }

    struct Guard {
        explicit Guard(Tracer& tracer) : tracer(tracer) { ++tracer.guard_; }
        ~Guard() { --tracer.guard_; }
        Tracer& tracer;
    };

    void onExec(dsp56k::TWord pc) override {
        if (!active_) return;
        const uint32_t address = pc & kMask24;
        if (return_pending_ && !calls_.empty()) calls_.pop_back();
        if (call_pending_ && emulator_.reg(dsp56k::Reg_SP) != call_stack_) {
            if (std::find(calls_.begin(), calls_.end(), address) != calls_.end())
                fail("uses recursion at P:" + hex(address - base_));
            else calls_.push_back(address);
        }
        call_pending_ = return_pending_ = false;
        if (pending_valid_ && !pending_free_ &&
            std::find(kServiceEntry.begin(), kServiceEntry.end(), address) != kServiceEntry.end() &&
            (pending_->mnemonic.compare(0, 2, "js") == 0 ||
             pending_->mnemonic.compare(0, 2, "bs") == 0))
            pending_free_ = true;
        finalize();
        if (aborting_) {
            redirect(address);
            return;
        }
        if (++instructions_ > kInstructionBound) {
            fail("ran more than " + std::to_string(kInstructionBound) + " instructions without returning");
            redirect(address);
            return;
        }
        for (unsigned index = 0; index != kServiceEntry.size(); ++index) {
            if (address != kServiceEntry[index]) continue;
            service(index, address);
            return;
        }
        if (!in(address, base_, words_) && address != kCallStub) {
            fail("control flow left the program, to P:" + hex(address));
            redirect(address);
            return;
        }
        const Decoded& instruction = decode(address);
        if (loop_body_ != kNone) {
            if (address == loop_body_ && (emulator_.reg(dsp56k::Reg_SR) & dsp56k::SR_LF) != 0)
                check_loop(loop_body_, emulator_.reg(dsp56k::Reg_LA));
            loop_body_ = kNone;
        }
        if (aborting_) {
            redirect(address);
            return;
        }
        if (address != kCallStub) {
            if (restricted(instruction.first) || restricted(instruction.second) || instruction.io || instruction.protected_write) {
                fail("uses an instruction the standard forbids at P:" + hex(address - base_) + " (" +
                     instruction.text + ")");
                redirect(address);
                return;
            }
            if (unsupported(instruction.first) || unsupported(instruction.second)) {
                fail("uses an instruction the emulator does not implement at P:" + hex(address - base_) + " (" +
                     instruction.text + ")");
                redirect(address);
                return;
            }
            if (loop_start(instruction.first)) loop_body_ = address + instruction.length;
        }
        pending_valid_ = true;
        pending_free_ = false;
        pending_address_ = address;
        pending_ = &instruction;
        call_pending_ = instruction.mnemonic.compare(0, 2, "js") == 0 ||
                        instruction.mnemonic.compare(0, 2, "bs") == 0;
        call_stack_ = emulator_.reg(dsp56k::Reg_SP);
        return_pending_ = instruction.first == dsp56k::Rts;
    }

    void onMemoryRead(EMemArea area, dsp56k::TWord address) override {
        if (!active_ || guard_ != 0 || aborting_) return;
        if (area == dsp56k::MemArea_X && (address & kMask24) == kTriggerInfo &&
            (!permissions_->trigger_info || permissions_->routine != Routine::Trig)) {
            fail("TRIGGER_INFO may only be read in TRIG through its import");
            return;
        }
        const uint32_t word = address & kMask24;
        if (!readable(area, word)) {
            static const char* const names[] = {"P", "X", "Y"};
            std::string where;
            if (pending_valid_ && !pending_free_ && in(pending_address_, base_, words_))
                where = " at P:" + hex(pending_address_ - base_) + " (" + pending_->text + ")";
            fail(std::string("reads outside its memory or imports, from ") + names[area] + ":" + hex(word) + where);
            return;
        }
        record(area, word);
    }

    bool onPeripheralAccess(EMemArea, dsp56k::TWord, bool) override {
        if (!active_ || guard_ != 0) return false;
        fail("accesses a peripheral register");
        return true;
    }

    void onMemoryWrite(EMemArea area, dsp56k::TWord address, dsp56k::TWord) override {
        if (!active_ || guard_ != 0 || aborting_) return;
        const uint32_t word = address & kMask24;
        record(area, word);
        if (!writable(area, word)) {
            static const char* const names[] = {"P", "X", "Y"};
            std::string where;
            if (pending_valid_ && !pending_free_ && in(pending_address_, base_, words_))
                where = " at P:" + hex(pending_address_ - base_) + " (" + pending_->text + ")";
            fail(std::string("writes outside its memory, to ") + names[area] + ":" + hex(word) + where);
        }
    }

private:
    static constexpr uint32_t kNone = 0xffffffffu;

    void fail(const std::string& message) {
        if (error_.empty()) error_ = message;
        aborting_ = true;
    }

    void redirect(uint32_t address) {
        if (address == kAbortEnddo || address == kAbortNop) return;
        const bool in_loop = (emulator_.reg(dsp56k::Reg_SR) & dsp56k::SR_LF) != 0;
        dsp().setPC(in_loop ? kAbortEnddo : kAbortNop);
    }

    void record(EMemArea area, uint32_t address) {
        const Region region = area == dsp56k::MemArea_P ? program_region(address) : data_region(address);
        if (region != Region::Internal) accesses_.push_back({region, address});
        else if (area == dsp56k::MemArea_X &&
                 (in(address, kInputRing, kRingWords) || in(address, kMainOutputRing, kRingWords)))
            accesses_.push_back({Region::Ring, address});
    }

    bool readable(EMemArea area, uint32_t address) const {
        const Permissions& p = *permissions_;
        if (area == dsp56k::MemArea_P)
            return in(address, base_, words_) ||
                   (pending_address_ == kCallStub && in(address, kCallStub, 2));
        const bool x = area == dsp56k::MemArea_X;
        if (in(address, workset(p.track), x ? p.x_words : p.y_words)) return true;
        if (address >= kExternal) {
            if (in(address, base_, words_)) return true;
            if (p.track_memory && in(address, track_memory(p.track), kTrackMemoryWords)) return true;
            if (p.loan_words && in(address, p.loan, p.loan_words)) return true;
            return x && (resources_ & (1u << kSymSine)) && in(address, kSineTable, kSineWords);
        }
        if (in(address, kTemp, kBlock) && (x ? p.temp_x : p.temp_y)) return true;
        if (x) {
            if ((resources_ & (1u << kSymInputRing)) && in(address, kInputRing, kRingWords)) return true;
            if ((resources_ & (1u << kSymMainRing)) && in(address, kMainOutputRing, kRingWords)) return true;
            if ((resources_ & (1u << kSymInputCursor)) && address == kInputCursor) return true;
            if ((resources_ & (1u << kSymMainCursor)) && address == kMainOutputCursor) return true;
            return p.trigger_info && p.routine == Routine::Trig && address == kTriggerInfo;
        }
        if (p.routine != Routine::Render) return false;
        if (in(address, p.output, kBlock)) return true;
        if (!neighbour_) return false;
        return address == kDescriptorWord || in(address, kDescriptors + 4 * (p.track % 4), 4) ||
               in(address, kOutputBuffer.front(), 4 * kBlock);
    }

    bool writable(EMemArea area, uint32_t address) {
        Permissions& p = *permissions_;
        if (area == dsp56k::MemArea_P) return false;
        if (address >= kExternal)
            return address < kMemoryEnd &&
                   ((p.track_memory && in(address, track_memory(p.track), kTrackMemoryWords)) ||
                    (p.loan_words != 0 && in(address, p.loan, p.loan_words)));
        if (address >= kInternalDataEnd) return false;
        const uint32_t own = workset(p.track);
        if (area == dsp56k::MemArea_X) return in(address, own, p.x_words) || (p.temp_x && address < kTemp + kBlock);
        if (in(address, own, p.y_words)) return address - own >= p.state_from;
        if (p.routine == Routine::Render && in(address, p.output, kBlock)) {
            p.output_written |= 1u << (address - p.output);
            return true;
        }
        return p.temp_y && address < kTemp + kBlock;
    }

    void finalize() {
        if (!pending_valid_) return;
        pending_valid_ = false;
        if (pending_free_) {
            accesses_.clear();
            return;
        }
        std::array<uint64_t, kModels> stall{};
        const auto charge = [this, &stall](Region region, uint32_t address) {
            for (unsigned model = 0; model != kModels; ++model)
                if (region != Region::Ring || model == kMk2)
                    stall[model] += buses_[model].access(region, address, stall[model]);
        };
        for (uint32_t word = 0; word != pending_->length; ++word) {
            const uint32_t address = (pending_address_ + word) & kMask24;
            const Region region = program_region(address);
            if (region != Region::Internal && cache_.miss(address)) charge(region, address);
        }
        for (const auto& access : accesses_)
            if (access.region != Region::Peripheral) charge(access.region, access.address);
        accesses_.clear();
        // The instruction's clocks and the interlocks its predecessors cause;
        // an instruction's clocks depend on the ones executed before it.
        const uint32_t nominal =
            pipeline_.execute(pending_->first, pending_->second, pending_address_, pending_->op,
                              pending_->op_b);
        for (unsigned model = 0; model != kModels; ++model) {
            buses_[model].advance(nominal + stall[model]);
            costs_->cycles[model] += nominal + stall[model];
        }
        costs_->nominal += nominal;
    }

    void service(unsigned index, uint32_t address) {
        if (!imported_[index]) {
            fail("calls a service it does not import, at P:" + hex(address));
            redirect(address);
            return;
        }
        uint64_t clocks;
        {
            Guard guard(*this);
            clocks = services_->call(index, emulator_, *permissions_);
        }
        for (unsigned model = 0; model != kModels; ++model) {
            buses_[model].elapse(clocks);
            costs_->cycles[model] += clocks;
        }
        costs_->service += clocks;
        cache_.evict(kServiceSectors);
        // The service's own instructions follow anything that could interlock.
        pipeline_.reset();

        pending_valid_ = true;
        pending_free_ = true;
        pending_address_ = address;
        return_pending_ = true;
    }

    const Decoded& decode(uint32_t address) {
        auto found = decoded_.find(address);
        if (found != decoded_.end()) return found->second;
        Decoded result;
        uint32_t op, op_b;
        {
            Guard guard(*this);
            op = emulator_.get(dsp56k::MemArea_P, address);
            op_b = emulator_.get(dsp56k::MemArea_P, address + 1);
        }
        dsp().opcodes().getInstructionTypes(op, result.first, result.second);
        result.length = std::max<uint32_t>(1, disassembler_.disassemble(result.text, op, op_b, 0, 0, address));
        result.op = op;
        result.op_b = op_b;
        std::string lower = result.text;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const size_t space = lower.find_first_of(" \t");
        result.mnemonic = lower.substr(0, space);
        const std::string& m = result.mnemonic;
        const bool bit_op = m == "bchg" || m == "bclr" || m == "bset" || m == "btst";
        result.flow = (!m.empty() && (m[0] == 'j' || (m[0] == 'b' && !bit_op))) || m == "rts" || m == "rti" ||
                      m == "do" || m == "dor" || m == "rep" || m == "enddo";
        using RM = dsp56k::RegisterMask;
        RM written = RM::None, read = RM::None;
        bool move = false, test = false;
        switch (result.first) {
        case dsp56k::Movec_ea: case dsp56k::Movec_aa:
        case dsp56k::Movec_S1D2: case dsp56k::Movec_xx:
        case dsp56k::Movem_ea: case dsp56k::Movem_aa:
            dsp56k::getRegisters(written, read, result.first, op);
            move = true;
            break;
        case dsp56k::Bchg_D: case dsp56k::Bclr_D: case dsp56k::Bset_D:
        case dsp56k::Btst_D: {
            const auto reg = dsp56k::getRegister(result.first, dsp56k::Field_DDDDDD, op);
            if (reg == dsp56k::Register::Invalid) result.protected_write = true;
            else read = dsp56k::convert(reg);
            test = result.first == dsp56k::Btst_D;
            if (!test) written = read;
            break;
        }
        default: break;
        }
        const RM loop_regs = RM::LA | RM::LC | RM::SP | RM::SC | RM::SSH | RM::SSL |
                             RM::SZ | dsp56k::convert(dsp56k::Register::VBA) | RM::OMR;
        result.control_write = dsp56k::any(written, loop_regs);
        result.control_read = dsp56k::any(read, loop_regs);
        result.stack_read = move && dsp56k::any(read, RM::SSH | RM::SSL);
        result.test_ssh = test && dsp56k::any(read, RM::SSH);
        result.protected_write = result.protected_write || dsp56k::any(written, loop_regs | RM::SR | RM::EP);
        static const std::regex peripheral(R"([xy]:[<>]*\$ffff[89a-f][0-9a-f])");
        result.io = lower.find("<<") != std::string::npos || std::regex_search(lower, peripheral);
        return decoded_.emplace(address, std::move(result)).first->second;
    }

    void check_loop(uint32_t body, uint32_t last) {
        if (!loops_checked_.insert(body).second) return;
        const std::string problem = loop_problem(body, last);
        if (!problem.empty()) fail(problem);
    }

public:

    std::vector<std::string> scan_loops() {
        std::vector<std::string> problems;
        for (uint32_t address = base_; address < base_ + words_;) {
            const Decoded& instruction = decode(address);
            if (loop_start(instruction.first) && instruction.length == 2) {
                const uint32_t operand = emulator_.get(dsp56k::MemArea_P, address + 1);
                const bool relative = instruction.first == dsp56k::Dor_ea || instruction.first == dsp56k::Dor_aa ||
                                      instruction.first == dsp56k::Dor_xxx || instruction.first == dsp56k::Dor_S;
                const uint32_t last = relative ? (address + operand) & kMask24 : operand;
                if (last >= address + 2 && in(last, base_, words_)) {
                    const std::string problem = loop_problem(address + 2, last);
                    if (!problem.empty()) problems.push_back(problem);
                }
            }
            address += instruction.length;
        }
        return problems;
    }

private:
    std::string loop_problem(uint32_t body, uint32_t last) {
        if (last < body || !in(last, base_, words_)) return {};
        std::vector<std::pair<uint32_t, const Decoded*>> instructions;
        for (uint32_t address = body; address <= last;) {
            const Decoded& instruction = decode(address);
            instructions.emplace_back(address, &instruction);
            address += instruction.length;
        }
        const auto where = [this](uint32_t address, const Decoded& instruction) {
            return "P:" + hex(address - base_) + " (" + instruction.text + ")";
        };
        const auto [end_address, end] = instructions.back();
        if (end_address + end->length - 1 != last)
            return "a DO loop ends inside an instruction at " + where(end_address, *end);
        for (const auto& [address, instruction] : instructions) {
            const uint32_t distance = last - address;
            const std::string& m = instruction->mnemonic;
            const bool movem = m == "movem", mode = m == "andi" || m == "ori";
            bool forbidden = false;
            if (distance == 0)
                forbidden = instruction->flow || instruction->control_write || instruction->stack_read ||
                            instruction->test_ssh || movem ||
                            (m == "movep" && instruction->text.find("p:") != std::string::npos) || mode;
            else if (distance <= 2)
                forbidden = instruction->flow || instruction->control_write || instruction->control_read || movem || mode;
            else if (distance == 3)
                forbidden = instruction->control_write || instruction->stack_read ||
                            m == "jset" || m == "jclr" || m == "jsset" || m == "jsclr" ||
                            (instruction->length == 2 && ((!m.empty() && m[0] == 'j') || movem));
            else if (distance <= 5)
                forbidden = instruction->control_write;
            if (forbidden)
                return "a DO loop has an instruction " +
                       (distance == 0 ? std::string("at its last word") : std::to_string(distance) + " words before its end") +
                       " that DSP56300FM A.3.1 forbids there: " + where(address, *instruction);
        }
        return {};
    }

    struct Access {
        Region region;
        uint32_t address;
    };

    Emulator& emulator_;
    dsp56k::Disassembler disassembler_;
    ServiceProvider* services_ = nullptr;
    std::array<bool, 4> imported_{};
    uint32_t base_ = 0, words_ = 0, resources_ = 0;
    bool neighbour_ = false;
    std::vector<uint32_t> calls_;
    bool call_pending_ = false, return_pending_ = false;
    uint32_t call_stack_ = 0;
    std::unordered_map<uint32_t, Decoded> decoded_;
    dsp56k::PipelineTiming pipeline_;
    std::unordered_set<uint32_t> loops_checked_;

    Permissions* permissions_ = nullptr;
    Costs* costs_ = nullptr;
    bool active_ = false, aborting_ = false;
    int guard_ = 0;
    uint64_t instructions_ = 0;
    std::string error_;

    bool pending_valid_ = false, pending_free_ = false;
    uint32_t pending_address_ = 0;
    const Decoded* pending_ = nullptr;
    std::vector<Access> accesses_;
    uint32_t loop_body_ = kNone;

    InstructionCache cache_;
    std::array<Bus, kModels> buses_{{Bus(kMk1), Bus(kMk2)}};
};

Emulator::Emulator()
    : memory_((Logging::setLogFunc([](const std::string&) {}),
               std::make_unique<dsp56k::Memory>(validator_, kMemoryEnd, kMemoryEnd, kExternal))) {
    dsp_ = std::make_unique<dsp56k::DSP>(*memory_, &peripherals_x_, &peripherals_y_);
    tracer_ = std::make_unique<Tracer>(*dsp_, *this);
    dsp_->setDebugger(tracer_.get());
}

Emulator::~Emulator() {
    dsp_->setDebugger(nullptr);
}

uint32_t Emulator::get(dsp56k::EMemArea area, uint32_t address) {
    Tracer::Guard guard(*tracer_);
    return memory_->get(area, address) & kMask24;
}

void Emulator::set(dsp56k::EMemArea area, uint32_t address, uint32_t value) {
    Tracer::Guard guard(*tracer_);
    memory_->set(area, address, value & kMask24);
}

uint32_t Emulator::reg(dsp56k::EReg reg) {
    dsp56k::TReg24 value;
    dsp_->readReg(reg, value);
    return static_cast<uint32_t>(value.var) & kMask24;
}

void Emulator::set_reg(dsp56k::EReg reg, uint32_t value) {
    dsp56k::TReg24 word;
    word.var = static_cast<int32_t>(value & kMask24);
    dsp_->writeReg(reg, word);
}

void Emulator::set_accumulator(dsp56k::EReg reg, uint64_t value56) {
    dsp56k::TReg56 value;
    value.var = static_cast<int64_t>(value56 & 0x00ffffffffffffffull);
    dsp_->writeReg(reg, value);
}

void Emulator::set_accumulator1(dsp56k::EReg reg, uint32_t value24) {
    const uint64_t high = (value24 & 0x800000u) != 0 ? 0xffull : 0;
    set_accumulator(reg, high << 48 | static_cast<uint64_t>(value24 & kMask24) << 24);
}

void Emulator::install(const Package& package, uint32_t base, ServiceProvider& services) {
    static const std::array<uint32_t, 14> resource{
        0, kSineTable, kInputRing, kInputCursor, kMainOutputRing, kMainOutputCursor, kTrackMemory, kTemp, kTemp,
        0, 0, 0, 0, kTriggerInfo};
    size_t next_import = 0;
    std::array<bool, 4> imported{};
    for (uint32_t index = 0; index != package.program.size(); ++index) {
        uint32_t word = package.program[index];
        if (package.relocated[index]) word = (word + base) & kMask24;
        if (next_import != package.imports.size() && package.imports[next_import].word == index) {
            const Import& item = package.imports[next_import++];
            if (item.kind == 5) {
                word = kServiceEntry[item.symbol - kSymSampleInfo];
                imported[item.symbol - kSymSampleInfo] = true;
            } else {
                word = (resource[item.symbol] + word) & kMask24;
            }
        }
        set(dsp56k::MemArea_P, base + index, word);
    }
    set(dsp56k::MemArea_P, kReturnSentinel, kNop);
    set(dsp56k::MemArea_P, kAbortEnddo, kEnddo);
    set(dsp56k::MemArea_P, kAbortNop, kNop);
    for (uint32_t entry : kServiceEntry) set(dsp56k::MemArea_P, entry, kRts);
    tracer_->program(base, static_cast<uint32_t>(package.program.size()), services, imported, package);
    dsp_->clearOpcodeCache();
}

std::vector<std::string> Emulator::scan_loops() {
    return tracer_->scan_loops();
}

void Emulator::begin_track() {
    tracer_->begin_track();
}

bool Emulator::call(uint32_t entry, Permissions& permissions, Costs& costs, std::string& error) {
    set(dsp56k::MemArea_P, kCallStub, kJsrLong);
    set(dsp56k::MemArea_P, kCallStub + 1, entry);
    dsp_->clearOpcodeCache(kCallStub);
    dsp_->clearOpcodeCache(kCallStub + 1);
    tracer_->forget(kCallStub);
    int64_t stack_before = 0, stack_after = 0;
    dsp_->readRegToInt(dsp56k::Reg_SP, stack_before);
    dsp_->setPC(kCallStub);
    tracer_->begin(permissions, costs);
    for (;;) {
        const uint32_t pc = dsp_->getPC().toWord() & kMask24;
        if (pc == kReturnSentinel || tracer_->aborting()) break;
        dsp_->exec();
    }
    tracer_->end();
    if (!tracer_->error().empty()) {
        error = tracer_->error();
        return false;
    }
    dsp_->readRegToInt(dsp56k::Reg_SP, stack_after);
    if (stack_after != stack_before) {
        error = "returned with calls or loops unbalanced";
        return false;
    }
    return true;
}

}
