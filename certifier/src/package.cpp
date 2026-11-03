#include "package.hpp"

#include "layout.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace mds {
namespace {

uint16_t be16(const std::vector<uint8_t>& data, size_t at) {
    return static_cast<uint16_t>(data[at] << 8 | data[at + 1]);
}

uint32_t be32(const std::vector<uint8_t>& data, size_t at) {
    return static_cast<uint32_t>(data[at]) << 24 | static_cast<uint32_t>(data[at + 1]) << 16 |
           static_cast<uint32_t>(data[at + 2]) << 8 | data[at + 3];
}

void put16(std::vector<uint8_t>& data, size_t at, uint16_t value) {
    data[at] = static_cast<uint8_t>(value >> 8);
    data[at + 1] = static_cast<uint8_t>(value);
}

void put32(std::vector<uint8_t>& data, size_t at, uint32_t value) {
    for (unsigned index = 0; index != 4; ++index)
        data[at + index] = static_cast<uint8_t>(value >> (24 - 8 * index));
}

bool inside(size_t offset, size_t bytes, size_t total) {
    return offset <= total && bytes <= total - offset;
}

uint32_t crc32(const uint8_t* data, size_t size) {
    uint32_t crc = 0xffffffffu;
    for (size_t index = 0; index != size; ++index) {
        crc ^= data[index];
        for (int bit = 0; bit != 8; ++bit)
            crc = crc & 1u ? crc >> 1 ^ 0xedb88320u : crc >> 1;
    }
    return ~crc;
}

class Sha256 {
public:
    void update(const uint8_t* data, size_t size) {
        for (size_t index = 0; index != size; ++index) {
            block_[used_++] = data[index];
            if (used_ == 64) {
                compress();
                used_ = 0;
            }
        }
        bytes_ += size;
    }

    std::array<uint8_t, 32> finish() {
        const uint64_t bits = bytes_ * 8;
        const uint8_t one = 0x80, zero = 0;
        update(&one, 1);
        while (used_ != 56) update(&zero, 1);
        uint8_t length[8];
        for (int index = 0; index != 8; ++index) length[index] = static_cast<uint8_t>(bits >> (56 - 8 * index));
        update(length, 8);
        std::array<uint8_t, 32> digest{};
        for (int index = 0; index != 32; ++index)
            digest[index] = static_cast<uint8_t>(state_[index / 4] >> (24 - 8 * (index % 4)));
        return digest;
    }

private:
    static uint32_t rotr(uint32_t value, int bits) { return value >> bits | value << (32 - bits); }

    void compress() {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        uint32_t w[64];
        for (int index = 0; index != 16; ++index)
            w[index] = static_cast<uint32_t>(block_[4 * index]) << 24 | block_[4 * index + 1] << 16 |
                       block_[4 * index + 2] << 8 | block_[4 * index + 3];
        for (int index = 16; index != 64; ++index) {
            const uint32_t s0 = rotr(w[index - 15], 7) ^ rotr(w[index - 15], 18) ^ w[index - 15] >> 3;
            const uint32_t s1 = rotr(w[index - 2], 17) ^ rotr(w[index - 2], 19) ^ w[index - 2] >> 10;
            w[index] = w[index - 16] + s0 + w[index - 7] + s1;
        }
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (int index = 0; index != 64; ++index) {
            const uint32_t t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[index] + w[index];
            const uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }

    uint32_t state_[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t block_[64] = {};
    size_t used_ = 0;
    uint64_t bytes_ = 0;
};

std::array<uint8_t, 32> content_digest(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> zeroed = data;
    std::fill(zeroed.begin() + 84, zeroed.begin() + 120, 0);
    Sha256 sha;
    sha.update(zeroed.data(), zeroed.size());
    const uint32_t program_at = be32(data, 32), program_bytes = be32(data, 36);
    sha.update(&data[program_at], program_bytes);
    return sha.finish();
}

struct ImportRule {
    uint8_t kind;
    uint32_t words;
};
const ImportRule* import_rule(uint8_t symbol) {
    static const ImportRule rules[] = {
        {1, kSineWords}, {1, kRingWords}, {1, 1}, {1, kRingWords}, {1, 1},
        {2, kTrackMemoryWords}, {3, kBlock}, {4, kBlock}, {5, 0}, {5, 0}, {5, 0}, {5, 0}, {1, 1}};
    return symbol >= 1 && symbol <= 13 ? &rules[symbol - 1] : nullptr;
}

bool valid_text(const std::vector<uint8_t>& data, size_t at, size_t size, bool uppercase = false,
                uint8_t first = 0x20) {
    if (data[at] == 0) return false;
    bool terminated = false;
    for (size_t index = at; index != at + size; ++index) {
        const uint8_t c = data[index];
        if (c == 0) terminated = true;
        else if (terminated || c < first || c > 0x7e || (uppercase && c >= 'a' && c <= 'z')) return false;
    }
    return true;
}

bool alnum(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

bool valid_style(uint8_t style) {
    static const uint8_t styles[] = {0x00, 0x10, 0x20, 0x01, 0x21, 0x02, 0x22, 0x13, 0x54, 0x35, 0x46, 0x07, 0x08};
    return std::find(std::begin(styles), std::end(styles), style) != std::end(styles);
}

std::string text(const std::vector<uint8_t>& data, size_t at, size_t bytes) {
    std::string result;
    for (size_t index = 0; index != bytes && data[at + index] != 0; ++index)
        result.push_back(static_cast<char>(data[at + index]));
    return result;
}

}

bool Package::imports_symbol(uint8_t symbol) const {
    return std::any_of(imports.begin(), imports.end(), [symbol](const Import& item) { return item.symbol == symbol; });
}

bool parse_package(const std::vector<uint8_t>& data, Package& out, std::string& error) {
    Package package;
    package.bytes = data;
    const auto fail = [&error](const char* message) {
        error = message;
        return false;
    };
    if (data.size() < 128 || std::memcmp(data.data(), "MDS1", 4) != 0) return fail("not an MDS1 package");
    // MDS 1.0 stores 1; 1.1 stores $0101 (major high byte, minor low).
    const uint16_t version = be16(data, 4);
    if ((version != 0x0001 && version != 0x0101) || be16(data, 6) != 128)
        return fail("unsupported MDS version or header size");
    if (be32(data, 8) != data.size() || data.size() > 44812) return fail("header size field does not match the file");
    if (be32(data, 12) != 0 || be16(data, 16) != 0x5603 || be16(data, 18) != 1 || data[20] != 0 || data[21] != 0)
        return fail("unsupported flags, target, required value or codec");
    if (be32(data, 60) != 0 || be16(data, 54) != 0)
        return fail("reserved header bytes are not zero");
    if (be16(data, 72) != 0 && be16(data, 70) == 0)
        return fail("MKI cycles require a nonzero MKII declaration");
    if (be16(data, 74) > be16(data, 72))
        return fail("MKI SRAM cycles exceed the MKI declaration");
    if (version == 0x0101 && be16(data, 70) != 0 && (be16(data, 72) == 0 || be16(data, 74) == 0))
        return fail("an MDS 1.1 stamp gives MKII, MKI and MKI SRAM cycles");
    if (be32(data, 120) != 0 || be32(data, 124) != 0)
        return fail("bytes 120-127 are not zero: a signed package, which this certifier does not handle");
    const uint16_t words = be16(data, 22), import_count = be16(data, 24);
    package.x_words = be16(data, 26);
    package.y_words = be16(data, 28);
    const uint32_t program_at = be32(data, 32), program_bytes = be32(data, 36);
    const uint32_t relocation_at = be32(data, 44), imports_at = be32(data, 48);
    const uint32_t description_bytes = be16(data, 52), description_at = be32(data, 56);
    if (words == 0 || words > 14052 || program_at != 128 || program_bytes != words * 3u || be32(data, 40) != program_bytes)
        return fail("program size or position is invalid");
    if (import_count > 64 || package.x_words > 64 || package.y_words > 64)
        return fail("import count or workset size is out of range");
    if (!inside(program_at, program_bytes, data.size()) ||
        !inside(relocation_at, (words + 7u) / 8u, data.size()) ||
        !inside(imports_at, import_count * 4u, data.size()) ||
        description_bytes < 128 || description_bytes > 384 || (description_bytes - 128) % 8 != 0 ||
        !inside(description_at, description_bytes, data.size()))
        return fail("a section lies outside the package");

    const auto align4 = [](uint32_t n) { return (n + 3u) & ~3u; };
    const uint32_t relocation_bytes = (words + 7u) / 8u;
    const uint32_t sprite_at = align4(description_at + description_bytes);
    if (relocation_at != align4(program_at + program_bytes) ||
        imports_at != align4(relocation_at + relocation_bytes) ||
        description_at != align4(imports_at + import_count * 4u))
        return fail("noncanonical section layout");
    if (sprite_at + 128u != data.size()) return fail("package has trailing or missing bytes");
    for (const auto& range : {std::pair<uint32_t, uint32_t>{program_at + program_bytes, relocation_at},
                             {relocation_at + relocation_bytes, imports_at},
                             {imports_at + import_count * 4u, description_at}})
        if (std::any_of(data.begin() + range.first, data.begin() + range.second,
                        [](uint8_t value) { return value != 0; }))
            return fail("section alignment padding is not zero");
    if ((words & 7u) && (data[relocation_at + relocation_bytes - 1] & ~((1u << (words & 7u)) - 1u)))
        return fail("relocation bitmap has nonzero trailing bits");
    for (uint32_t at = sprite_at + 3; at < data.size(); at += 4)
        if (data[at]) return fail("machine sprite has nonzero pixels below row 23");

    std::vector<uint8_t> crc_copy = data;
    std::fill(crc_copy.begin() + 84, crc_copy.begin() + 88, 0);
    if (crc32(crc_copy.data(), crc_copy.size()) != be32(data, 84)) return fail("package CRC does not match");
    if (crc32(&data[program_at], program_bytes) != be32(data, 76)) return fail("program CRC does not match");
    if (crc32(&data[description_at], description_bytes) != be32(data, 80))
        return fail("machine-description CRC does not match");
    const auto digest = content_digest(data);
    if (!std::equal(digest.begin(), digest.end(), data.begin() + 88))
        return fail("content ID does not match");

    for (uint32_t index = 0; index != words; ++index) {
        const size_t at = program_at + index * 3u;
        package.program.push_back(static_cast<uint32_t>(data[at]) << 16 | data[at + 1] << 8 | data[at + 2]);
        package.relocated.push_back((data[relocation_at + index / 8] >> (index % 8) & 1u) != 0);
        if (package.relocated.back() && package.program.back() >= words)
            return fail("a relocated word does not hold a program address");
    }
    package.init = be16(data, 64);
    package.trig = be16(data, 66);
    package.render = be16(data, 68);
    if (package.init >= words || package.trig >= words || package.render >= words)
        return fail("a routine offset is outside the program");
    package.mk2_cycles = be16(data, 70);
    package.mk1_cycles = be16(data, 72);
    package.mk1_sram_cycles = be16(data, 74);

    for (uint16_t index = 0; index != import_count; ++index) {
        const size_t at = imports_at + index * 4u;
        const Import item{be16(data, at), data[at + 2], data[at + 3]};
        const ImportRule* rule = import_rule(item.symbol);
        if (rule == nullptr || rule->kind != item.kind) return fail("an import's kind or symbol is not supported");
        if (item.word >= words || package.relocated[item.word]) return fail("an import patches an invalid word");
        if (!package.imports.empty() && item.word <= package.imports.back().word)
            return fail("imports are not in ascending program-word order");
        const uint32_t operand = package.program[item.word];
        if (rule->words == 0 ? operand != 0 : operand >= rule->words)
            return fail("an import's offset is outside its resource");
        package.imports.push_back(item);
    }

    const size_t d = description_at;
    if (std::memcmp(&data[d], "MDM1", 4) != 0 || data[d + 4] != 1) return fail("not an MDM1 machine description");
    const uint8_t count = data[d + 5], flags = data[d + 6];
    if (count > 8 || (flags & ~0x1du) != 0) return fail("parameter count or capability flags are invalid");
    const uint8_t links = data[d + 7];
    if (links & ~0x77u) return fail("invalid parameter links");
    for (unsigned index = 0; index != 8; ++index)
        if ((links & (1u << index)) && index + 1 >= count)
            return fail("parameter link has no following parameter");
    if (!valid_text(data, d + 8, 4, true) || data[d + 11] != 0 ||
        !valid_text(data, d + 12, 3, true) || data[d + 14] != 0 ||
        !alnum(data[d + 12]) || !alnum(data[d + 13]) || data[d + 15] == 255 ||
        !valid_text(data, d + 16, 16) || !valid_text(data, d + 32, 32))
        return fail("invalid machine identity or name");
    const auto category = text(data, d + 8, 4);
    if ((category != "P-I" && !std::all_of(category.begin(), category.end(), alnum)) ||
        category == "MID" || category == "CTR" || category == "CTL")
        return fail("invalid or reserved category");
    const auto id = text(data, d + 32, 32);
    if (!alnum(id.front()) || !std::all_of(id.begin(), id.end(), [](uint8_t c) {
            return (alnum(c) && !(c >= 'A' && c <= 'Z')) || c == '.' || c == '-' || c == '_';
        })) return fail("invalid machine ID");
    for (size_t at = d + 64 + count * 8; at != d + 128; ++at)
        if (data[at]) return fail("unused parameter descriptor is not zero");
    package.tonal = flags & 0x01;
    package.continuous_retrigger = flags & 0x04;
    package.neighbour = flags & 0x08;
    package.stereo_pair = flags & 0x10;
    if (package.stereo_pair && (!package.neighbour || package.y_words < 10))
        return fail("STEREO PAIR needs NEIGHBOUR and at least 10 Y workset words");
    if (count != 0 && package.y_words < count + 1u) return fail("the Y workset cannot hold the parameters");
    package.category = text(data, d + 8, 4);
    package.code = text(data, d + 12, 2);
    package.name = text(data, d + 16, 16);
    for (uint8_t index = 0; index != count; ++index) {
        const size_t at = d + 64 + index * 8u;
        if (!valid_text(data, at, 4, true)) return fail("invalid parameter name");
        Parameter parameter;
        parameter.name = text(data, at, 4);
        parameter.default_value = data[at + 4];
        parameter.minimum = data[at + 5];
        parameter.maximum = data[at + 6];
        parameter.style = data[at + 7];
        if (!valid_style(parameter.style) || parameter.minimum >= parameter.maximum || parameter.maximum > 127 ||
            parameter.default_value < parameter.minimum || parameter.default_value > parameter.maximum)
            return fail("a parameter description is invalid");
        if ((parameter.conversion() == kPitch && (parameter.minimum != 0 || parameter.maximum != 127)) ||
            (parameter.conversion() == kBoolean && (parameter.minimum != 0 || parameter.maximum != 1)))
            return fail("invalid parameter range for its conversion");
        package.parameters.push_back(parameter);
    }
    if (package.tonal && std::none_of(package.parameters.begin(), package.parameters.end(),
                                    [](const Parameter& p) { return p.conversion() == kPitch; }))
        return fail("a tonal machine requires a pitch parameter");
    int previous_parameter = -1, previous_end = -1;
    for (size_t at = d + 128; at < d + description_bytes; at += 8) {
        const uint8_t parameter = data[at], lo = data[at + 1], hi = data[at + 2];
        if (parameter >= count || parameter < previous_parameter || data[at + 3] ||
            !valid_text(data, at + 4, 4, false, 0x21)) return fail("invalid value-text entry");
        const auto& p = package.parameters[parameter];
        if (lo < p.minimum || hi > p.maximum || lo > hi ||
            (parameter == previous_parameter && lo <= previous_end))
            return fail("invalid or overlapping value-text range");
        previous_parameter = parameter;
        previous_end = hi;
    }
    out = std::move(package);
    return true;
}

std::vector<uint8_t> stamp_cycles(const Package& package, uint16_t mk1, uint16_t mk2, uint16_t mk1_sram) {
    std::vector<uint8_t> data = package.bytes;
    put16(data, 70, mk2);
    put16(data, 72, mk1);
    put16(data, 74, mk1_sram);
    // A stamp with all three counts is MDS 1.1, which firmware without MDS 1.1
    // support refuses.
    if (mk1 && mk1_sram) put16(data, 4, 0x0101);

    const auto digest = content_digest(data);
    std::copy(digest.begin(), digest.end(), data.begin() + 88);
    std::fill(data.begin() + 84, data.begin() + 88, 0);
    put32(data, 84, crc32(data.data(), data.size()));
    return data;
}

uint32_t parameter_value(const Parameter& parameter, uint8_t setting, uint32_t bpm) {
    const uint32_t v = setting;
    switch (parameter.conversion()) {
    case kRaw14: return v << 7;
    case kUnipolar: return v >= 127 ? 0x7fffffu : v << 16;
    case kSquared: return (v * v) << 9;
    case kBipolar: return ((v << 17) - 0x800000u) & kMask24;
    case kPitch: {

        const double ratio = std::log2(538240.0 / 1625.0) * static_cast<double>(v) / 127.0;
        return static_cast<uint32_t>(std::lround(1625.0 * std::exp2(ratio)));
    }
    case kTempo: return ((270950400u / (24u * bpm)) * 60u / 4096u) * v;
    case kBoolean: return v != 0 ? 1u : 0u;
    case kIndex: return v - parameter.minimum;
    case kDecay: {

        const double coefficient = 1.0 - std::pow(2.0, -(1.0 + 21.0 * static_cast<double>(v) / 127.0));
        return std::min<uint32_t>(0x7fffffu, static_cast<uint32_t>(std::lround(coefficient * 8388608.0)));
    }
    }
    return 0;
}

}
