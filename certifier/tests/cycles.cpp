#include "emulator.hpp"
#include "package.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class FixedService final : public mds::ServiceProvider {
public:
    unsigned calls = 0;
    uint64_t call(unsigned index, mds::Emulator&, mds::Permissions&) override {
        require(index == 0, "wrong service");
        ++calls;
        return 330;
    }
};

mds::Costs run(unsigned calls, FixedService& services) {
    mds::Package package;
    for (unsigned index = 0; index < calls; ++index) {
        package.program.push_back(0x0bf080);
        package.program.push_back(0);
        package.imports.push_back({static_cast<uint16_t>(2 * index + 1), 5, mds::kSymSampleInfo});
    }
    package.program.push_back(0x00000c);
    package.relocated.resize(package.program.size(), false);
    mds::Emulator emulator;
    emulator.install(package, 0x200, services);
    emulator.begin_track();
    mds::Permissions permissions;
    permissions.routine = mds::Routine::Init;
    mds::Costs costs;
    std::string error;
    require(emulator.call(0x200, permissions, costs, error), error.c_str());
    return costs;
}

int main(int argc, char** argv) {
    try {
        require(argc == 2, "expected sine fixture");
        std::ifstream file(argv[1], std::ios::binary);
        require(static_cast<bool>(file), "cannot open fixture");
        std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
        mds::Package package, parsed;
        std::string error;
        require(mds::parse_package(bytes, package, error), error.c_str());
        const auto stamped = mds::stamp_cycles(package, 791, 731, 745);
        require(stamped[70] == 0x02 && stamped[71] == 0xdb &&
                stamped[72] == 0x03 && stamped[73] == 0x17 &&
                stamped[74] == 0x02 && stamped[75] == 0xe9, "wrong cycle stamp");
        require(mds::parse_package(stamped, parsed, error), error.c_str());
        require(parsed.mk1_cycles == 791 && parsed.mk2_cycles == 731 && parsed.mk1_sram_cycles == 745,
                "wrong model order");
        require(mds::stamp_cycles(parsed, 791, 731, 745) == stamped, "restamping changed package");
        auto invalid = stamped;
        invalid[74] = 0x03;
        invalid[75] = 0x18;
        require(!mds::parse_package(invalid, parsed, error) && error.find("exceed") != std::string::npos,
                "MKI SRAM cycles above MKI's accepted");
        const auto mkii_only = mds::stamp_cycles(package, 0, 1104, 0);
        require(mds::parse_package(mkii_only, parsed, error), error.c_str());
        require(parsed.mk1_cycles == 0 && parsed.mk2_cycles == 1104, "MKII-only stamp changed");
        invalid = stamped;
        invalid[70] = invalid[71] = 0;
        require(!mds::parse_package(invalid, parsed, error), "MKI stamp without MKII accepted");

        FixedService services;
        const auto baseline = run(0, services);
        for (unsigned count : {1u, 2u}) {
            const auto measured = run(count, services);
            for (unsigned model = 0; model < mds::kModels; ++model)
                require(measured.cycles[model] - baseline.cycles[model] == 330 * count,
                        "service JSR-through-return counted more than once");
        }
        require(services.calls == 3, "wrong service call count");
        std::cout << "Cycle stamps and inclusive service costs passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
