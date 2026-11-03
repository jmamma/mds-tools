#include "emulator.hpp"
#include "package.hpp"
#include "services.hpp"

#include <iostream>
#include <stdexcept>

namespace {
void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

class Services final : public mds::ServiceProvider {
    uint64_t call(unsigned, mds::Emulator&, mds::Permissions&) override { return 330; }
};

bool run(const std::vector<uint32_t>& program, std::string& error) {
    mds::Package package;
    package.program = program;
    package.relocated.resize(program.size(), false);
    Services services;
    mds::Emulator emulator;
    emulator.install(package, 0x200, services);
    emulator.begin_track();
    mds::Permissions permissions;
    permissions.routine = mds::Routine::Init;
    mds::Costs costs;
    return emulator.call(0x200, permissions, costs, error);
}

void loop_reads() {
    for (uint32_t op : {0x0444bfu, 0x0444bau, 0x0444b9u}) {
        for (unsigned distance = 0; distance <= 5; ++distance) {
            std::vector<uint32_t> program{0x060280u, 0x202u + distance, op};
            program.insert(program.end(), distance, 0u);
            program.push_back(0x00000cu);
            const bool allowed = op == 0x0444b9u || distance == 0 || distance >= 3;
            std::string error;
            require(run(program, error) == allowed,
                    "control-register read at LA-" + std::to_string(distance) + ": " + error);
            if (!allowed) require(error.find("A.3.1") != std::string::npos, error);
        }
    }
}

void register_writes() {
    for (uint32_t code : {0x10u, 0x11u, 0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu}) {
        for (uint32_t opcode : {0x04c4a0u | code, 0x0500a0u | code}) {
            std::string error;
            require(!run({opcode, 0x00000cu}, error), "protected MOVEC destination accepted");
            require(error.find("forbids") != std::string::npos, error);
        }
    }
    for (uint32_t op : {0x0af960u, 0x0af940u, 0x0bf940u}) {
        std::string error;
        require(!run({op, 0x00000cu}, error), "protected bit-operation destination accepted");
        require(error.find("forbids") != std::string::npos, error);
    }
    for (uint32_t op : {0x0ac460u, 0x0ac440u, 0x0bc440u, 0x0bf960u}) {
        std::string error;
        require(run({op, 0x00000cu}, error), "ordinary bit operation rejected: " + error);
    }
}

bool read_memory(uint32_t address, bool y, mds::Permissions permissions, uint8_t symbol = 0,
                 bool neighbour = false, uint32_t base = 0x200) {
    mds::Package package;
    package.program = {0x60f400, address, y ? 0x5ee000u : 0x56e000u, 0xc, 0};
    package.relocated.resize(package.program.size(), false);
    package.neighbour = neighbour;
    if (symbol) package.imports.push_back({4, 1, symbol});
    Services services;
    mds::Emulator emulator;
    emulator.install(package, base, services);
    emulator.begin_track();
    mds::Costs costs;
    std::string error;
    return emulator.call(base, permissions, costs, error);
}

void memory_permissions() {
    mds::Permissions p;
    p.routine = mds::Routine::Init;
    p.track = 3;
    p.x_words = p.y_words = 4;
    for (bool y : {false, true}) {
        require(read_memory(mds::workset(3) + 3, y, p), "own workset read rejected");
        require(!read_memory(mds::workset(3) + 4, y, p), "undeclared workset read accepted");
        require(!read_memory(mds::workset(2), y, p), "other track read accepted");
        require(!read_memory(mds::kTemp, y, p), "unimported scratch read accepted");
    }
    for (bool y : {false, true}) {
        require(read_memory(mds::kProgramRegion + 4, y, p, 0, false, mds::kProgramRegion), "own program table rejected");
        require(!read_memory(mds::kProgramRegion + 5, y, p, 0, false, mds::kProgramRegion), "program table overrun accepted");
    }
    p.temp_x = true;
    require(read_memory(mds::kTemp + 31, false, p), "X scratch read rejected");
    require(!read_memory(mds::kTemp + 31, true, p), "X scratch grants Y access");
    p.temp_y = true;
    require(read_memory(mds::kTemp + 31, true, p), "Y scratch read rejected");
    require(!read_memory(mds::kTemp + 32, false, p), "scratch overrun accepted");
    p.track_memory = true;
    for (bool y : {false, true}) {
        require(read_memory(mds::track_memory(3) + 1535, y, p), "own external memory rejected");
        require(!read_memory(mds::track_memory(3) + 1536, y, p), "external memory overrun accepted");
    }
    p.loan = mds::ram_slot(0);
    p.loan_words = 16;
    require(read_memory(p.loan + 15, true, p), "loan read rejected");
    require(!read_memory(p.loan + 16, false, p), "loan overrun accepted");
    for (auto resource : {std::pair<uint8_t, uint32_t>{mds::kSymSine, mds::kSineTable},
                          {mds::kSymInputRing, mds::kInputRing}, {mds::kSymInputCursor, mds::kInputCursor},
                          {mds::kSymMainRing, mds::kMainOutputRing}, {mds::kSymMainCursor, mds::kMainOutputCursor}}) {
        require(read_memory(resource.second, false, p, resource.first), "imported resource rejected");
        require(!read_memory(resource.second, false, p), "unimported resource accepted");
        require(!read_memory(resource.second, true, p, resource.first), "X import grants Y access");
    }
    p.routine = mds::Routine::Render;
    p.output = mds::kOutputBuffer[3];
    require(read_memory(p.output, true, p), "own output read rejected");
    require(!read_memory(mds::kDescriptorWord, true, p), "descriptor read without neighbour accepted");
    require(read_memory(mds::kDescriptorWord, true, p, 0, true), "neighbour descriptor rejected");
    require(read_memory(mds::kDescriptors + 12, true, p, 0, true), "own descriptor rejected");
    require(!read_memory(mds::kDescriptors, true, p, 0, true), "another descriptor accepted");
    require(read_memory(mds::kOutputBuffer[0], true, p, 0, true), "neighbour buffer rejected");
    p.routine = mds::Routine::Trig;
    require(!read_memory(mds::kDescriptorWord, true, p, 0, true), "neighbour descriptor outside RENDER accepted");
}

// BCHG with a memory operand: encodings 0000101101MMMRRR0S0bbbbb (BCHG) and
// 0000101001MMMRRR0S1bbbbb (BSET), through (R0) and through an absolute address.
std::vector<uint32_t> bit_program(uint32_t base_opcode, uint32_t address, bool y, bool absolute) {
    const uint32_t area = y ? 0x40u : 0u;
    if (absolute) return {base_opcode | 0x7000u | area | 3u, address, 0x00000cu};
    return {0x60f400u, address, base_opcode | 0x6000u | area | 3u, 0x00000cu};
}

struct BitResult {
    bool ok = false;
    uint32_t value = 0, carry = 0;
    mds::Costs costs;
    std::string error;
};

BitResult run_bit_program(const std::vector<uint32_t>& program, uint32_t address, bool y, uint32_t start) {
    mds::Package package;
    package.program = program;
    package.relocated.resize(program.size(), false);
    Services services;
    mds::Emulator emulator;
    emulator.install(package, 0x200, services);
    emulator.begin_track();
    const auto area = y ? dsp56k::MemArea_Y : dsp56k::MemArea_X;
    emulator.set(area, address, start);
    mds::Permissions permissions;
    permissions.routine = mds::Routine::Init;
    permissions.track = 3;
    permissions.x_words = permissions.y_words = 4;
    BitResult result;
    result.ok = emulator.call(0x200, permissions, result.costs, result.error);
    result.value = emulator.get(area, address);
    result.carry = emulator.reg(dsp56k::Reg_SR) & 1u;
    return result;
}

void bit_change_memory() {
    const uint32_t own = mds::workset(3) + 1;
    for (bool y : {false, true}) {
        for (bool absolute : {false, true}) {
            const auto bchg = bit_program(0x0b0000u, own, y, absolute);
            // Bit 3 clear: it becomes set, the other bits stay, and C holds the old bit.
            auto result = run_bit_program(bchg, own, y, 0x123450u);
            require(result.ok, "BCHG on own memory rejected: " + result.error);
            require(result.value == 0x123458u, "BCHG did not set the bit");
            require(result.carry == 0u, "BCHG reported the wrong old bit (clear)");
            // Bit 3 set: it becomes clear.
            result = run_bit_program(bchg, own, y, 0x123458u);
            require(result.ok, "BCHG on own memory rejected: " + result.error);
            require(result.value == 0x123450u, "BCHG did not clear the bit");
            require(result.carry == 1u, "BCHG reported the wrong old bit (set)");
            // The manual gives BCHG and BSET the same timing, for the same operand.
            const auto bset = bit_program(0x0a0020u, own, y, absolute);
            const auto reference = run_bit_program(bset, own, y, 0x123450u);
            require(reference.ok, "BSET on own memory rejected: " + reference.error);
            const auto measured = run_bit_program(bchg, own, y, 0x123450u);
            require(measured.costs.nominal == reference.costs.nominal &&
                        measured.costs.instructions == reference.costs.instructions,
                    "BCHG costs differently from BSET");
            // The same memory rules apply: not another track's workset, not a peripheral.
            const uint32_t other = mds::workset(2);
            result = run_bit_program(bit_program(0x0b0000u, other, y, absolute), other, y, 0u);
            require(!result.ok, "BCHG on another track's workset accepted");
        }
        std::string error;
        require(!run(bit_program(0x0b0000u, 0xffff90u, y, true), error), "BCHG on a peripheral accepted");
        require(error.find("forbids") != std::string::npos, error);
    }
}

void service_hardware() {
    using namespace dsp56k;
    for (mds::Hardware hardware : {mds::Hardware::NonUW, mds::Hardware::Mk1UW, mds::Hardware::Mk2UW}) {
        mds::Services services(hardware);
        mds::Emulator emulator;
        mds::Permissions p;
        const unsigned userwaves = hardware == mds::Hardware::NonUW ? 0 : hardware == mds::Hardware::Mk1UW ? 32 : 48;
        const unsigned ram = hardware == mds::Hardware::NonUW ? 0 : hardware == mds::Hardware::Mk1UW ? 2 : 4;
        for (unsigned bank : {0u, 1u, 2u}) {
            const unsigned available = bank == 0 ? 21 : bank == 1 ? userwaves : ram;
            for (unsigned slot : {0u, 1u, 2u, 3u, 20u, 21u, 31u, 32u, 47u, 48u}) {
                services.reset(1, true);
                emulator.set_reg(Reg_X0, bank);
                emulator.set_reg(Reg_Y0, slot);
                services.call(0, emulator, p);
                require((emulator.reg(Reg_A1) != 0) == (slot < available), "SAMPLE_INFO availability");
                emulator.set_reg(Reg_N0, 1);
                emulator.set(MemArea_Y, mds::kTemp, 0);
                services.call(1, emulator, p);
                require((emulator.reg(Reg_A1) != 0) == (slot < available), "SAMPLE_READ availability");
            }
        }
        for (unsigned slot = 0; slot <= 4; ++slot) {
            services.reset(1, false);
            p.loan = p.loan_words = 0;
            emulator.set_reg(Reg_X0, slot);
            services.call(2, emulator, p);
            require((emulator.reg(Reg_A1) != 0) == (slot < ram), "RAM_WORKSPACE availability");
            require((p.loan_words != 0) == (slot < ram), "RAM_WORKSPACE permissions");
            emulator.set_reg(Reg_N0, 0);
            emulator.set_reg(Reg_Y0, 0x10000);
            services.call(3, emulator, p);
            require((emulator.reg(Reg_B1) != 0) == (slot < ram), "RAM_RECORD availability");
            require(p.loan_words == 0, "recording did not revoke workspace access");
            services.reset(1, false);
            services.call(2, emulator, p);
            emulator.set_reg(Reg_X0, 4);
            services.call(2, emulator, p);
            require(p.loan_words == 0, "refused workspace retained access");
        }
    }
}

void tempo_values() {
    mds::Parameter parameter;
    parameter.style = 0x08;
    require(mds::parameter_value(parameter, 64) == 88192u, "120 BPM conversion");
    require(mds::parameter_value(parameter, 64, 20) == 529152u, "20 BPM conversion");
    require(mds::parameter_value(parameter, 64, 280) == 37760u, "280 BPM conversion");
    require(mds::parameter_value(parameter, 0, 20) == 0u, "zero Tempo setting");
    require(mds::parameter_value(parameter, 127, 20) == 1050036u, "maximum Tempo setting");
}
}

int main() {
    try {
        loop_reads();
        register_writes();
        bit_change_memory();
        tempo_values();
        memory_permissions();
        service_hardware();
        std::cout << "Instruction guards and Tempo conversion passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
