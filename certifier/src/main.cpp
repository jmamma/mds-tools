#include "certify.hpp"
#include "package.hpp"
#include "sysex.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>

namespace {

void usage() {
    std::cerr << "usage: mds-certifier [--stamp OUT.mds] [--json REPORT.json] [--quiet] [--quick|--loops] MACHINE.mds|MACHINE.syx\n"
                 "\n"
                 "Checks execution against the MDS specification and measures MKI/MKII cycles.\n"
                 "SysEx input also checks the transfer and existing cycle declarations.\n"
                 "--stamp writes a newly measured MDS file for a single machine.\n"
                 "--quick runs development-only checks; it cannot certify or stamp a machine.\n"
                 "--loops only checks DO loop endings against DSP56300FM A.3.1.\n";
}

bool read_file(const char* path, std::vector<uint8_t>& data) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return !file.bad();
}

bool same_file(const char* a, const char* b) {
    if (!a || !b) return false;
    std::error_code error;
    if (std::filesystem::equivalent(a, b, error) && !error) return true;
    const auto first = std::filesystem::weakly_canonical(a, error);
    if (error) return std::string(a) == b;
    const auto second = std::filesystem::weakly_canonical(b, error);
    return !error && first == second;
}

std::string json_string(const std::string& text) {
    std::string result = "\"";
    for (char c : text) {
        if (c == '"' || c == '\\') result += '\\';
        if (static_cast<unsigned char>(c) >= 0x20) result += c;
    }
    return result + '"';
}

struct Check {
    mds::Package package;
    mds::Report report;
    bool measured = false;
    std::string declaration = "not_checked";
    std::string name() const { return package.category + "-" + package.code; }
};

void write_report(std::ostream& out, const Check& check) {
    const auto& report = check.report;
    out << "{\"machine\":" << json_string(check.name()) << ",\"certified\":" << (report.certified ? "true" : "false")
        << ",\"declaration_check\":" << json_string(check.declaration)
        << ",\"declared_mk1_cycles\":" << check.package.mk1_cycles
        << ",\"declared_mk2_cycles\":" << check.package.mk2_cycles
        << ",\"declared_mk1_sram_cycles\":" << check.package.mk1_sram_cycles;
    if (report.development_only)
        out << ",\"scope\":\"development_only\",\"development_checks_passed\":"
            << (report.development_checks_passed ? "true" : "false");
    if (!report.certified && !report.development_checks_passed) out << ",\"error\":" << json_string(report.error);
    if (check.measured) {
        out << ",\"vectors\":" << report.vectors << ",\"placements\":" << report.placements
            << ",\"blocks\":" << report.blocks << ",\"nominal_machine_cycles\":" << report.nominal;
        out << ",\"warnings\":[";
        for (size_t index = 0; index != report.warnings.size(); ++index)
            out << (index ? "," : "") << json_string(report.warnings[index]);
        out << ']';
        for (unsigned model = 0; model != mds::kModels; ++model)
            out << ",\"" << mds::kModelNames[model] << "\":{\"track_cycles\":" << report.track[model]
                << ",\"machine_cycles\":" << report.machine[model] << ",\"block_cycles\":" << report.block[model]
                << ",\"init_cycles\":" << report.init[model] << ",\"standard_cycles\":" << report.standard[model]
                << ",\"peak_cycles\":" << report.peak[model]
                << ",\"peak_detail\":" << json_string(report.peak_detail[model]) << '}';
        out << ",\"mk1_sram\":{\"track_cycles\":" << report.sram_track << ",\"machine_cycles\":" << report.sram_machine
            << ",\"block_cycles\":" << report.sram_block << ",\"init_cycles\":" << report.sram_init
            << ",\"standard_cycles\":" << report.sram_standard << ",\"peak_cycles\":" << report.sram_peak
            << ",\"peak_detail\":" << json_string(report.sram_peak_detail) << '}';
    }
    out << '}';
}

}

int main(int argc, char** argv) {
    const char *input = nullptr, *stamp = nullptr, *json = nullptr;
    bool quiet = false, loops = false, quick = false;
    for (int index = 1; index < argc; ++index) {
        if (!std::strcmp(argv[index], "--stamp") && index + 1 < argc) stamp = argv[++index];
        else if (!std::strcmp(argv[index], "--json") && index + 1 < argc) json = argv[++index];
        else if (!std::strcmp(argv[index], "--quiet")) quiet = true;
        else if (!std::strcmp(argv[index], "--loops")) loops = true;
        else if (!std::strcmp(argv[index], "--quick")) quick = true;
        else if (argv[index][0] != '-' && input == nullptr) input = argv[index];
        else { usage(); return 2; }
    }
    if (!input) { usage(); return 2; }
    if (quick && (stamp || loops)) {
        std::cerr << "--quick is development-only and cannot be combined with --stamp or --loops\n";
        return 2;
    }
    if (same_file(input, stamp) || same_file(input, json) || same_file(stamp, json)) {
        std::cerr << "input, stamp and report must be different files\n";
        return 2;
    }
    if (loops && (stamp || json)) {
        std::cerr << "--loops cannot be combined with --stamp or --json\n";
        return 2;
    }
    std::vector<uint8_t> bytes;
    if (!read_file(input, bytes)) {
        std::cerr << "cannot read " << input << '\n';
        return 2;
    }
    const bool sysex = bytes.size() < 4 || std::memcmp(bytes.data(), "MDS1", 4) != 0;
    std::string error;
    std::vector<mds::Dump> dumps;
    if (sysex) {
        if (!mds::decode_sysex(bytes, dumps, error)) {
            std::cerr << input << ": " << error << '\n';
            return 1;
        }
    } else dumps.push_back({0, std::move(bytes)});
    if (stamp && dumps.size() != 1) {
        std::cerr << "--stamp requires exactly one machine dump\n";
        return 2;
    }
    std::vector<Check> checks(dumps.size());
    for (size_t i = 0; i != dumps.size(); ++i) {
        if (!mds::parse_package(dumps[i].bytes, checks[i].package, error)) {
            std::cerr << input << ": dump " << i + 1 << ": " << error << '\n';
            return 1;
        }
    }
    bool passed = true;
    for (auto& check : checks) {
        const auto& package = check.package;
        const auto name = check.name();
        if (loops) {
            const auto problems = mds::scan_loops(package);
            for (const auto& problem : problems) std::cout << name << ": possibly " << problem << '\n';
            if (problems.empty()) std::cout << name << ": no DO loop ends with an instruction A.3.1 forbids\n";
            passed = passed && problems.empty();
            continue;
        }
        if (quick) std::cout << name << ": DEVELOPMENT ONLY: quick checks do not certify a machine or verify release cycle declarations\n";
        if (!quiet) std::cerr << name << " (" << package.name << "): " << package.program.size() << " words\n";
        auto& report = check.report;
        report = mds::certify(package, [quiet](const std::string& step) {
            if (!quiet) std::cerr << "  " << step << '\n';
        }, quick ? mds::CheckMode::Quick : mds::CheckMode::Full);
        check.measured = report.certified || report.development_checks_passed;
        if (check.measured && sysex && !quick) {
            if (!package.mk2_cycles) {
                check.declaration = "missing";
                error = "no installable cycle declaration";
            } else if (!package.mk1_cycles) {
                check.declaration = "legacy";
                error = "MKII-only cycle declaration needs remeasurement; use --stamp OUT.mds";
            } else if (package.mk1_cycles < report.track[mds::kMk1] || package.mk2_cycles < report.track[mds::kMk2] ||
                       (package.mk1_sram_cycles && package.mk1_sram_cycles < report.sram_track)) {
                check.declaration = "understated";
                error = "declared cycles are below measured costs: MKI " + std::to_string(package.mk1_cycles) +
                        " (measured " + std::to_string(report.track[mds::kMk1]) + "), MKII " +
                        std::to_string(package.mk2_cycles) + " (measured " + std::to_string(report.track[mds::kMk2]) + ")";
                if (package.mk1_sram_cycles)
                    error += ", MKI SRAM " + std::to_string(package.mk1_sram_cycles) + " (measured " +
                             std::to_string(report.sram_track) + ")";
            } else check.declaration = "valid";
            if (!stamp && check.declaration != "valid") { report.certified = false; report.error = error; }
        }
        if (stamp && report.certified && (report.track[mds::kMk1] > 0xffff || report.track[mds::kMk2] > 0xffff)) {
            report.certified = false;
            report.error = "cycles per track do not fit the header's 16-bit fields";
        }
        for (const auto& warning : report.warnings)
            std::cout << name << ": warning: in code no run reached, possibly " << warning << '\n';
        if (check.measured)
            std::cout << name << (quick ? ": observed development cycles per track MKI " : ": cycles per track MKI ")
                      << report.track[mds::kMk1] << ", MKII " << report.track[mds::kMk2]
                      << ", MKI SRAM " << report.sram_track << " (" << report.vectors << " parameter settings, " << report.placements << " placements, "
                      << report.blocks << " blocks)\n";
        if (check.measured && !quick)
            std::cout << name << ": standard vectors MKI " << report.standard[mds::kMk1] << ", MKII "
                      << report.standard[mds::kMk2] << ", MKI SRAM " << report.sram_standard << "; peaks MKI "
                      << report.peak[mds::kMk1] << ", MKII " << report.peak[mds::kMk2] << ", MKI SRAM "
                      << report.sram_peak << '\n';
        if (check.measured && !quick)
            for (unsigned model = 0; model != mds::kModels; ++model)
                if (report.peak[model] > report.standard[model])
                    std::cout << name << ": " << (model == mds::kMk1 ? "MKI" : "MKII") << " peak " << report.peak[model]
                              << ": " << report.peak_detail[model] << '\n';
        if (quick)
            std::cout << name << (report.development_checks_passed ? ": DEVELOPMENT CHECKS PASSED; NOT CERTIFIED\n"
                                                                : ": DEVELOPMENT CHECKS FAILED; NOT CERTIFIED: " + report.error + '\n');
        else if (!report.certified) std::cout << name << ": NOT CERTIFIED: " << report.error << '\n';
        else if (sysex && !stamp) std::cout << name << ": transfer and cycle declarations verified\n";
        passed = passed && (quick ? report.development_checks_passed : report.certified);
    }
    if (json) {
        std::ofstream out(json);
        if (checks.size() != 1) out << '[';
        for (size_t i = 0; i != checks.size(); ++i) {
            if (i) out << ',';
            write_report(out, checks[i]);
        }
        if (checks.size() != 1) out << ']';
        out << '\n';
        out.close();
        if (!out) { std::cerr << "cannot write " << json << '\n'; return 2; }
    }
    if (!passed) return 1;
    if (stamp) {
        const auto& check = checks.front();
        // Every placement counts for MKI's figure, SRAM ones too, so the
        // SRAM figure never exceeds it.
        const auto stamped = mds::stamp_cycles(check.package, static_cast<uint16_t>(check.report.track[mds::kMk1]),
                                               static_cast<uint16_t>(check.report.track[mds::kMk2]),
                                               static_cast<uint16_t>(check.report.sram_track));
        std::ofstream out(stamp, std::ios::binary);
        out.write(reinterpret_cast<const char*>(stamped.data()), static_cast<std::streamsize>(stamped.size()));
        out.close();
        if (!out) { std::cerr << "cannot write " << stamp << '\n'; return 2; }
        std::cout << "wrote " << stamp << '\n';
    }
    return 0;
}
