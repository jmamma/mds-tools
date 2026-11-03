#include "sysex.hpp"

#include <algorithm>
#include <array>

namespace mds {
namespace {
uint32_t be32(const std::vector<uint8_t>& bytes, size_t at) {
    return uint32_t(bytes[at]) << 24 | uint32_t(bytes[at + 1]) << 16 |
           uint32_t(bytes[at + 2]) << 8 | bytes[at + 3];
}
}

bool decode_sysex(const std::vector<uint8_t>& bytes, std::vector<Dump>& dumps, std::string& error) {
    const auto fail = [&](const std::string& message) { error = "SysEx: " + message; return false; };
    const std::array<uint8_t, 8> prefix{{0xf0, 0, 0x20, 0x3c, 2, 0, 0x74, 1}};
    std::vector<Dump> result;
    std::vector<uint8_t> packet, header, descriptor, last_data, last_end;
    Dump current;
    bool active = false;
    uint16_t transaction = 0;
    uint32_t size = 0;
    unsigned count = 0, next = 0;
    for (uint8_t byte : bytes) {
        if (byte >= 0xf8) continue;
        if (packet.empty() && byte != 0xf0) return fail("expected a message start");
        if (!packet.empty() && byte >= 0x80 && byte != 0xf7) return fail("invalid byte inside a message");
        packet.push_back(byte);
        if (packet.size() > 499) return fail("message exceeds 499 bytes");
        if (byte != 0xf7) continue;
        const size_t n = packet.size();
        if (n < 19 || !std::equal(prefix.begin(), prefix.end(), packet.begin()))
            return fail("not an MDS version 1 message");
        if (size_t((packet[n - 3] << 7) | packet[n - 2]) != n - 10)
            return fail("message length does not match");
        unsigned checksum = 0;
        for (size_t i = 9; i < n - 5; ++i) checksum += packet[i];
        if ((checksum & 0x3fffu) != unsigned((packet[n - 5] << 7) | packet[n - 4]))
            return fail("message checksum does not match");
        if (packet[11] > 15 || packet[13]) return fail("invalid slot or flags");
        std::vector<uint8_t> body;
        for (size_t at = 14; at < n - 5;) {
            const uint8_t mask = packet[at++];
            const size_t words = std::min<size_t>(7, n - 5 - at);
            if (words == 0 || (mask & ((1u << (7 - words)) - 1u)))
                return fail("invalid 7-bit packing");
            for (size_t i = 0; i < words; ++i)
                body.push_back(packet[at++] | (((mask >> (6 - i)) & 1u) << 7));
        }
        const uint8_t command = packet[8], sequence = packet[12];
        const uint16_t id = (packet[9] << 7) | packet[10];
        if (command == 1) {
            if (active) {
                if (packet != header) return fail("new header before the previous dump ended");
            } else {
                if (sequence != 127 || body.size() != 42 || body[5]) return fail("invalid dump header");
                size = be32(body, 0);
                count = body[4];
                if (size < 128 || size > 44812 || count != (size + 419) / 420)
                    return fail("invalid package size or packet count");
                current = Dump{packet[11], {}};
                current.bytes.reserve(size);
                transaction = id;
                next = 0;
                active = true;
                header = packet;
                descriptor = body;
                last_data.clear();
                last_end.clear();
            }
        } else if (command == 2 || command == 0x7b) {
            if (!active) {
                if (command != 0x7b || packet != last_end) return fail("packet without an active dump");
            } else {
                if (id != transaction || packet[11] != current.slot) return fail("transaction or slot changed");
                if (command == 2) {
                    if (packet != last_data) {
                        if (sequence != next || next >= count) return fail("missing or out-of-order data packet");
                        if (body.size() != std::min<size_t>(420, size - current.bytes.size()))
                            return fail("wrong data packet size");
                        current.bytes.insert(current.bytes.end(), body.begin(), body.end());
                        last_data = packet;
                        ++next;
                    }
                } else {
                    if (sequence != count || !body.empty() || next != count || current.bytes.size() != size)
                        return fail("incomplete dump or invalid end message");
                    if (be32(descriptor, 0) != be32(current.bytes, 8) ||
                        !std::equal(descriptor.begin() + 6, descriptor.end(), current.bytes.begin() + 84))
                        return fail("transfer descriptor does not match the package");
                    result.push_back(std::move(current));
                    active = false;
                    last_end = packet;
                }
            }
        } else return fail("expected a dump header, data packet or end message");
        packet.clear();
    }
    if (!packet.empty() || active) return fail("truncated dump");
    if (result.empty()) return fail("no machine dumps found");
    dumps = std::move(result);
    return true;
}

}
