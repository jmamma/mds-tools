import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from test_certifier_rules import CERTIFIER, machine
from lib.mds_format import PackageParts, build_package, parse_package
from mds_to_syx import convert


def stamped(data, mk1=5000, mk2=5000, mk1_sram=0):
    p = parse_package(data)
    return build_package(PackageParts(
        p['program'], p['manifest_bytes'], p['bitmap'], p['relocations'], p['imports'],
        p['init_word'], p['mutate_word'], p['execute_word'], p['abi_version'],
        p['x_workset_words'], p['y_workset_words'], max_track_cycles=mk2, mk1_track_cycles=mk1,
        mk1_sram_track_cycles=mk1_sram))


def packets(data):
    return [part + b'\xf7' for part in data.split(b'\xf7')[:-1]]


def repair(packet):
    p = bytearray(packet)
    checksum = sum(p[9:-5]) & 0x3fff
    length = len(p) - 10
    p[-5:-1] = bytes((checksum >> 7, checksum & 127, length >> 7, length & 127))
    return bytes(p)


def packet(command, sequence, body=b'', slot=0, transaction=1):
    data = bytearray((0xf0, 0, 0x20, 0x3c, 2, 0, 0x74, 1, command,
                      transaction >> 7, transaction & 127, slot, sequence, 0))
    for at in range(0, len(body), 7):
        group = body[at:at + 7]
        data.append(sum((value >> 7) << (6 - i) for i, value in enumerate(group)))
        data.extend(value & 127 for value in group)
    data.extend((0, 0, 0, 0, 0xf7))
    return repair(data)


@unittest.skipUnless(CERTIFIER.is_file(), 'build the certifier to test SysEx input')
class SysEx(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.source = self.work / 'machine.syx'
        self.report = self.work / 'report.json'
        self.output = self.work / 'new.mds'
        self.mds = stamped(machine())
        self.syx = convert(self.mds)

    def run_check(self, data, *options, success=True):
        self.source.write_bytes(data)
        self.report.unlink(missing_ok=True)
        self.output.write_bytes(b'previous output')
        result = subprocess.run([str(CERTIFIER), '--quiet', '--json', str(self.report),
                                 *map(str, options), str(self.source)], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.assertEqual(self.source.read_bytes(), data)
        if not success:
            self.assertEqual(self.output.read_bytes(), b'previous output')
        return result, json.loads(self.report.read_text()) if self.report.exists() else None

    def test_valid_transfer_and_exact_declarations(self):
        result, report = self.run_check(self.syx)
        self.assertTrue(report['certified'])
        self.assertEqual(report['declaration_check'], 'valid')
        self.assertIn('transfer and cycle declarations verified', result.stdout)
        exact = stamped(self.mds, report['mk1']['track_cycles'], report['mk2']['track_cycles'],
                        report['mk1_sram']['track_cycles'])
        self.run_check(convert(exact))

    def test_multiple_data_packets(self):
        self.run_check(convert(stamped(machine(init=(0,) * 200 + (0xc,)))))

    def test_missing_declaration_and_corrupt_package(self):
        head, _, end = packets(self.syx)
        damaged = bytearray(self.mds)
        damaged[128] ^= 1
        result, _ = self.run_check(head + packet(2, 0, damaged) + end, success=False)
        self.assertIn('CRC', result.stderr)
        draft = machine()
        descriptor = struct.pack('>IBBI32s', len(draft), 1, 0,
                                 int.from_bytes(draft[84:88], 'big'), draft[88:120])
        _, report = self.run_check(packet(1, 127, descriptor) + packet(2, 0, draft) + end, success=False)
        self.assertEqual(report['declaration_check'], 'missing')

    def test_realtime_bytes_and_retransmissions(self):
        head, data, end = packets(self.syx)
        retry = head + head + data + head + data + end + end
        with_realtime = b''.join(bytes((b, 0xf8, 0xfe)) for b in retry)
        self.run_check(with_realtime)

    def test_multiple_dumps(self):
        _, report = self.run_check(self.syx + convert(self.mds, 16))
        self.assertEqual(len(report), 2)
        self.assertTrue(all(row['certified'] for row in report))
        self.run_check(self.syx * 2, '--stamp', self.output, success=False)
        _, report = self.run_check(self.syx + convert(stamped(self.mds, 1, 1), 2), success=False)
        self.assertTrue(report[0]['certified'])
        self.assertFalse(report[1]['certified'])

    def test_understated_declarations_and_restamping(self):
        for mk1, mk2, mk1_sram in ((1, 5000, 0), (5000, 1, 0), (5000, 5000, 1)):
            data = convert(stamped(self.mds, mk1, mk2, mk1_sram))
            _, report = self.run_check(data, success=False)
            self.assertFalse(report['certified'])
            self.assertEqual(report['declaration_check'], 'understated')
            self.assertIn('measured', report['error'])
        _, report = self.run_check(data, '--stamp', self.output)
        self.assertTrue(report['certified'])
        parsed = parse_package(self.output.read_bytes())
        self.assertEqual(parsed['board_track_cycles'], (report['mk1']['track_cycles'], report['mk2']['track_cycles']))
        self.assertEqual(parsed['mk1_sram_track_cycles'], report['mk1_sram']['track_cycles'])
        self.assertLessEqual(parsed['mk1_sram_track_cycles'], parsed['mk1_track_cycles'])

    def test_legacy_requires_remeasurement(self):
        data = convert(stamped(self.mds, 0, 5000))
        _, report = self.run_check(data, success=False)
        self.assertEqual(report['declaration_check'], 'legacy')
        self.assertIn('remeasurement', report['error'])
        self.run_check(data, '--stamp', self.output)
        self.assertTrue(all(parse_package(self.output.read_bytes())['board_track_cycles']))

    def test_bad_packets(self):
        ps = packets(convert(stamped(machine(init=(0,) * 200 + (0xc,)))))
        mutations = {}
        for name, index, value in [('version', 7, 2), ('flags', 13, 1), ('slot', 11, 16),
                                   ('header sequence', 12, 0), ('command', 8, 3)]:
            changed = bytearray(ps[0]); changed[index] = value
            mutations[name] = repair(changed) + b''.join(ps[1:])
        for name, index, value in [('transaction change', 10, 2), ('slot change', 11, 1), ('sequence', 12, 1)]:
            changed = bytearray(ps[1]); changed[index] = value
            mutations[name] = ps[0] + repair(changed) + b''.join(ps[2:])
        changed = bytearray(ps[1]); changed[-5] ^= 1
        mutations['checksum'] = ps[0] + changed + b''.join(ps[2:])
        changed = bytearray(ps[1]); changed[-2] ^= 1
        mutations['length'] = ps[0] + changed + b''.join(ps[2:])
        changed = bytearray(ps[1]); changed[14] = 0x80
        mutations['high bit'] = ps[0] + changed + b''.join(ps[2:])
        mutations.update({'missing header': b''.join(ps[1:]), 'missing end': b''.join(ps[:-1]),
                          'missing packet': ps[0] + b''.join(ps[2:]), 'truncated': self.syx[:-1],
                          'trailing junk': self.syx + b'\x00', 'empty': b'',
                          'reordered': ps[0] + ps[2] + ps[1] + b''.join(ps[3:]),
                          'oversized': b'\xf0' + bytes(499) + b'\xf7',
                          'mask without data': repair(ps[0][:-5] + b'\0' + ps[0][-5:]) + b''.join(ps[1:])})
        for name, data in mutations.items():
            with self.subTest(name=name):
                result, _ = self.run_check(data, '--stamp', self.output, success=False)
                self.assertIn('SysEx:', result.stderr)

    def test_descriptor_and_packing(self):
        head, data, end = packets(self.syx)
        descriptor = struct.pack('>IBBI32s', len(self.mds), 1, 0,
                                 int.from_bytes(self.mds[84:88], 'big'), self.mds[88:120])
        for offset in (3, 4, 5, 6, 10):
            changed = bytearray(descriptor); changed[offset] ^= 1
            self.run_check(packet(1, 127, changed) + data + end, success=False)
        changed = bytearray(packet(2, 0, b'\0')); changed[14] = 1
        result, _ = self.run_check(head + repair(changed) + end, success=False)
        self.assertIn('7-bit packing', result.stderr)
        self.run_check(head + packet(2, 0, self.mds[:-1]) + end, success=False)
        self.run_check(head + data + packet(0x7b, 0), success=False)

    def test_invalid_retransmission(self):
        head, data, end = packets(self.syx)
        changed = bytearray(data); changed[15] ^= 1
        self.run_check(head + data + repair(changed) + end, success=False)
        changed_header = bytearray(head); changed_header[10] ^= 1
        self.run_check(head + data + repair(changed_header) + end, success=False)

    def test_outputs_cannot_overwrite_input(self):
        self.run_check(self.syx, '--stamp', self.source, success=False)
        self.run_check(self.syx, '--json', self.source, success=False)
        self.run_check(self.syx, '--stamp', self.report, success=False)
        self.source.write_bytes(self.syx)
        alias = self.work / 'alias'
        os.link(self.source, alias)
        self.run_check(self.syx, '--stamp', alias, success=False)


if __name__ == '__main__':
    unittest.main()
