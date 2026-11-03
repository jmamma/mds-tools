import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from lib.mds_format import FormatError, PackageParts, build_package, parse_package

spec = importlib.util.spec_from_file_location("mds_to_syx", ROOT / "tools/mds_to_syx.py")
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)


class CycleCosts(unittest.TestCase):
    def setUp(self):
        self.original = (ROOT / "tests/fixtures/sine.mds").read_bytes()
        self.parsed = parse_package(self.original)

    def package(self, mk1=791, mk2=731, mk1_sram=0):
        p = self.parsed
        parts = PackageParts(
            p["program"], p["manifest_bytes"], p["bitmap"], p["relocations"],
            p["imports"], p["init_word"], p["mutate_word"], p["execute_word"],
            p["abi_version"], p["x_workset_words"], p["y_workset_words"],
            max_track_cycles=mk2, mk1_track_cycles=mk1, mk1_sram_track_cycles=mk1_sram)
        return build_package(parts)

    def test_model_stamp_and_integrity(self):
        data = self.package()
        parsed = parse_package(data)
        self.assertEqual(data[70:76], bytes.fromhex("02db03170000"))
        self.assertEqual(parsed["board_track_cycles"], (791, 731))
        self.assertEqual(zlib.crc32(data[:84] + bytes(4) + data[88:]),
                         struct.unpack_from(">I", data, 84)[0])
        digest = hashlib.sha256(data[:84] + bytes(36) + data[120:] + parsed["program"]).digest()
        self.assertEqual(data[88:120], digest)
        self.assertTrue(converter.convert(data).endswith(b"\xf7"))

    def test_mkii_only_stamp_remains_valid(self):
        self.assertEqual(self.parsed["mk1_track_cycles"], 0)
        self.assertTrue(converter.convert(self.original))
        data = self.package(0, 1104)
        self.assertEqual(parse_package(data)["board_track_cycles"], (0, 1104))
        self.assertEqual(data[74:76], bytes(2))
        self.assertTrue(converter.convert(data))

    def test_mki_sram_stamp(self):
        data = self.package(mk1_sram=736)
        self.assertEqual(data[70:76], bytes.fromhex("02db031702e0"))
        self.assertEqual(parse_package(data)["mk1_sram_track_cycles"], 736)
        self.assertTrue(converter.convert(data).endswith(b"\xf7"))
        self.assertEqual(parse_package(self.package(mk1_sram=791))["mk1_sram_track_cycles"], 791)

    def test_sram_above_mki_and_missing_mkii_are_rejected(self):
        with self.assertRaises(FormatError):
            self.package(791, 0)
        for mk1, mk1_sram in ((791, 792), (0, 1)):
            with self.assertRaises(FormatError):
                self.package(mk1, 731, mk1_sram)
        for field, value in ((74, 792), (70, 0)):
            data = bytearray(self.package())
            struct.pack_into(">H", data, field, value)
            with self.assertRaises(FormatError):
                parse_package(bytes(data))
            with self.assertRaises(ValueError):
                converter.convert(bytes(data))


if __name__ == "__main__":
    unittest.main()
