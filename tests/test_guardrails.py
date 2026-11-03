import hashlib
import struct
import unittest
import zlib

import test_certifier_rules as rules

CERTIFIER, machine, RTS = rules.CERTIFIER, rules.machine, rules.RTS
from mds_pack import make_package
from lib.mds_format import FormatError, parse_package


def integrity(data):
    data = bytearray(data)
    program, size = struct.unpack_from('>II', data, 32)
    description = struct.unpack_from('>I', data, 56)[0]
    description_size = struct.unpack_from('>H', data, 52)[0]
    struct.pack_into('>I', data, 80, zlib.crc32(data[description:description + description_size]))
    data[84:120] = bytes(36)
    data[88:120] = hashlib.sha256(data + data[program:program + size]).digest()
    struct.pack_into('>I', data, 84, zlib.crc32(data))
    return data


def sample_machine(failure, success=(), bank=1, slot=40):
    init = [0x44F400, bank, 0x46F400, slot, 0x0BF080, 0, 0x200003, 0x0AF0A2,
            9 + len(failure), *failure, *success, RTS]
    render = len(init) + 1
    words = [*init, RTS, 0x240000, 0x062080, render + 3, 0x4C5F00, RTS]
    doc = {'id': 'org.test.services', 'display_name': 'SERVICE TEST', 'category': 'GND', 'short_label': 'ST',
           'program': {'relocations': ['BRANCH', 'LOOP'], 'imports': [{'symbol': 'SERVICE', 'abi_symbol': 9}]}}
    return make_package(doc, b''.join(w.to_bytes(3, 'big') for w in words),
                        {'INIT': 0, 'TRIG': len(init), 'RENDER': render, 'BRANCH': 7, 'LOOP': render + 1, 'SERVICE': 4})


@unittest.skipUnless(CERTIFIER.is_file(), 'build the certifier to test guardrails')
class Guardrails(unittest.TestCase):
    certify = rules.CertifierRules.certify

    def test_memory_and_peripheral_access(self):
        for address in (0x840, 0xC00, 0x140000):
            with self.subTest(address=hex(address)):
                self.certify(machine(init=(0x60F400, address, 0x56E000, RTS)), 'reads outside')
        for address in (0xFFFF80, 0xFFFFC0, 0xFFFFFF):
            for opcode in (0x56E000, 0x5EE000, 0x446000, 0x4C6000):
                with self.subTest(address=hex(address), opcode=hex(opcode)):
                    self.certify(machine(init=(0x60F400, address, 0x240000, opcode, RTS)), 'peripheral')

    def test_recursion(self):
        init = (0x44F400, 2, 0x0BF080, 5, RTS, 0x208E00, 0x014184, 0x218400,
                0x0AF0AA, 12, 0x0BF080, 5, RTS)
        self.certify(machine(init=init, relocations=(3, 9, 11)), 'recursion')
        self.certify(machine(init=(0x0BF080, 4, RTS, 0, 0x0BF080, 0, RTS), relocations=(1, 5)), 'recursion')

    def test_balanced_sequential_and_nested_calls(self):
        init = (0x0BF080, 5, 0x0BF080, 5, RTS, 0x0BF080, 8, RTS, RTS)
        self.certify(machine(init=init, relocations=(1, 3, 6)))

    def test_service_failure_paths(self):
        self.certify(sample_machine((0x0444BA, 0x04C4BA)), 'non-UW:')

    def test_mki_service_failure_paths(self):
        for bank, slot in ((1, 40), (2, 2)):
            with self.subTest(bank=bank):
                words = [0x44F400, bank, 0x46F400, 0, 0x0BF080, 0, 0x200003, 0x0AF0AA, 18,
                         0x46F400, slot, 0x0BF080, 0, 0x200003, 0x0AF0A2, 18,
                         0x0444BA, 0x04C4BA, RTS, RTS, 0x240000, 0x062080, 23, 0x4C5F00, RTS]
                doc = {'id': 'org.test.models', 'display_name': 'MODEL TEST', 'category': 'GND', 'short_label': 'MT',
                       'program': {'relocations': ['FIRST', 'SECOND', 'LOOP'],
                                   'imports': [{'symbol': 'SERVICE1', 'abi_symbol': 9},
                                               {'symbol': 'SERVICE2', 'abi_symbol': 9}]}}
                data = make_package(doc, b''.join(w.to_bytes(3, 'big') for w in words),
                                    {'INIT': 0, 'TRIG': 19, 'RENDER': 20, 'FIRST': 7, 'SECOND': 14,
                                     'LOOP': 21, 'SERVICE1': 4, 'SERVICE2': 11})
                self.certify(data, 'MKI UW:')

    def test_valid_service_paths_and_cycle_maxima(self):
        baseline = self.certify(sample_machine(()))
        failure = self.certify(sample_machine((0,) * 24))
        success = self.certify(sample_machine((), (0,) * 24))
        for model in ('mk1', 'mk2'):
            self.assertGreater(failure[model]['track_cycles'], baseline[model]['track_cycles'])
            self.assertGreater(success[model]['track_cycles'], baseline[model]['track_cycles'])

    def test_sram_cost_includes_non_uw_failure_paths(self):
        baseline = self.certify(sample_machine((), slot=0))
        failure = self.certify(sample_machine((0,) * 100, slot=0))
        self.assertGreater(failure['mk1_sram']['track_cycles'], baseline['mk1_sram']['track_cycles'])
        self.assertLessEqual(failure['mk1_sram']['track_cycles'], failure['mk1']['track_cycles'])

    def test_malformed_files(self):
        base = machine()
        d = struct.unpack_from('>I', base, 56)[0]
        r = struct.unpack_from('>I', base, 44)[0]
        end = 128 + struct.unpack_from('>I', base, 36)[0]
        cases = [
            ('tonal without pitch', d + 6, b'\x01'),
            ('invalid parameter link', d + 7, b'\x80'),
            ('link without next parameter', d + 7, b'\x01'),
            ('reserved category', d + 8, b'MID\0'),
            ('invalid name', d + 16, b'\x01'),
            ('invalid ID', d + 32, b'A'),
            ('unused parameter', d + 64, b'\x01'),
            ('unused relocation bit', r, bytes([base[r] | 0x80])),
            ('nonzero padding', end, b'\x01'),
            ('invalid sprite', len(base) - 1, b'\x01'),
            ('overlapping sections', 44, struct.pack('>I', 128)),
        ]
        for name, offset, value in cases:
            with self.subTest(name=name):
                data = bytearray(base)
                data[offset:offset + len(value)] = value
                data = integrity(data)
                with self.assertRaises(FormatError):
                    parse_package(data)
                self.certify(data, '')
        data = bytearray(base[:-128])
        struct.pack_into('>I', data, 8, len(data))
        self.certify(integrity(data), 'missing bytes')

    def test_parameter_semantics_and_value_text(self):
        for transform, maximum in (('pitch', 127), ('boolean', 1)):
            base = machine(params=[{'name': 'TEST', 'default': 0, 'transform': transform}])
            d = struct.unpack_from('>I', base, 56)[0]
            data = bytearray(base)
            data[d + 70] = maximum - 1 if maximum == 127 else 2
            self.certify(integrity(data), 'parameter range')
        base = machine(params=[{'name': 'TEST', 'transform': 'raw14',
                                'value_text': [{'min': 0, 'max': 3, 'text': 'LOW'}, {'value': 4, 'text': 'HIGH'}]}])
        self.certify(base)
        d = struct.unpack_from('>I', base, 56)[0]
        for offset, value in ((d + 128, 1), (d + 129, 5), (d + 131, 1), (d + 132, 0x20), (d + 137, 3)):
            data = bytearray(base)
            data[offset] = value
            self.certify(integrity(data), 'value-text')


if __name__ == '__main__':
    unittest.main()
