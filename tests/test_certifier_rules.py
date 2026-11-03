import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from lib.mds_format import parse_package
from mds_pack import make_package

CERTIFIER = Path(os.environ.get("MDS_CERTIFIER", ROOT / "build/mds-certifier"))
RTS = 0x00000C
TEMPO = [{"name": "TIME", "default": 64, "min": 63, "max": 64, "transform": "tempo"}]


def machine(init=(RTS,), trig=(RTS,), render_prefix=(), params=(), relocations=(), imports=(),
            import_symbol=13, clear_output=True):
    render = len(init) + len(trig)
    loop = render + len(render_prefix) + 1
    words = [*init, *trig, *render_prefix, 0x240000 if clear_output else 0, 0x062080, loop + 2, 0x4C5F00, RTS]
    symbols = {"INIT": 0, "TRIG": len(init), "RENDER": render, "OUTPUT_LOOP": loop}
    patches = [{"symbol": "OUTPUT_LOOP"}]
    imported = []
    for index, offset in enumerate(relocations):
        name = f"RELOC_{index}"
        symbols[name] = offset
        patches.append({"symbol": name, "word_delta": 0})
    for index, offset in enumerate(imports):
        name = f"IMPORT_{index}"
        symbols[name] = offset
        imported.append({"symbol": name, "word_delta": 0, "abi_symbol": import_symbol})
    document = {
        "id": "org.test.rules", "display_name": "RULE TEST", "category": "GND", "short_label": "RT",
        "params": list(params),
        "program": {"y_workset_words": 1 + len(params) if params else 0,
                    "relocations": patches, "imports": imported},
    }
    return make_package(document, b"".join(word.to_bytes(3, "big") for word in words), symbols)


@unittest.skipUnless(CERTIFIER.is_file(), "build the certifier to test instruction rules")
class CertifierRules(unittest.TestCase):
    def certify(self, data, error=None):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            source, stamp, report = work / "input.mds", work / "output.mds", work / "report.json"
            source.write_bytes(data)
            stamp.write_bytes(b"previous output")
            result = subprocess.run(
                [str(CERTIFIER), "--quiet", "--stamp", str(stamp), "--json", str(report), str(source)],
                capture_output=True, text=True, timeout=120,
            )
            output = result.stdout + result.stderr
            if error is not None:
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn(error, output)
                self.assertEqual(stamp.read_bytes(), b"previous output")
                if report.exists():
                    self.assertFalse(json.loads(report.read_text())["certified"])
                return
            self.assertEqual(result.returncode, 0, output)
            details = json.loads(report.read_text())
            self.assertTrue(details["certified"])
            self.assertEqual(details["warnings"], [])
            parsed = parse_package(stamp.read_bytes())
            self.assertTrue(all(parsed["board_track_cycles"]))
            return details

    def test_zero_y_workset_without_parameters(self):
        self.certify(machine())

    def test_legal_control_reads_near_loop_end(self):
        for op in (0x0444BF, 0x0444BA):
            with self.subTest(op=hex(op)):
                self.certify(machine(init=(0x060280, 7, op, 0, 0, 0, 0, 0, RTS), relocations=(1,)))

    def test_protected_register_writes(self):
        for read, write in ((0x0444B9, 0x04C4B9), (0x0444BA, 0x04C4BA)):
            with self.subTest(op=hex(write)):
                self.certify(machine(init=(read, write, RTS)), "forbids")

    def test_content_id_checked_independently_of_crc(self):
        data = bytearray(machine())
        data[88] ^= 1
        data[84:88] = bytes(4)
        struct.pack_into(">I", data, 84, zlib.crc32(data))
        self.certify(data, "content ID does not match")

    def test_tempo_parameter(self):
        self.certify(machine(params=TEMPO))

    def test_tempo_execution_paths(self):
        for threshold, branch in ((200000, 0x0AF0AF), (50000, 0x0AF0A1)):
            with self.subTest(threshold=threshold):
                init = (0x0206FE, 0x0140C5, threshold, branch, 7, 0x0444BA, 0x04C4BA, RTS)
                self.certify(machine(init=init, params=TEMPO, relocations=(4,)), "forbids")

    def test_trigger_info_read_in_trig(self):
        self.certify(machine(trig=(0x60F400, 0, 0x56E000, RTS), imports=(2,)))

    def test_repeat_trigger_execution_path(self):
        trig = (0x60F400, 0, 0x56E000, 0x0ACC10, 8, 0x0444BA, 0x04C4BA, RTS)
        self.certify(machine(trig=trig, imports=(2,), relocations=(5,)), "forbids")

    def test_trigger_info_access_restrictions(self):
        read = (0x60F400, 0, 0x56E000)
        self.certify(machine(init=(*read, RTS), imports=(1,)), "TRIGGER_INFO")
        self.certify(machine(render_prefix=read, imports=(3,)), "TRIGGER_INFO")
        self.certify(machine(trig=(0x60F400, 0, 0x446000, RTS), imports=(2,)), "writes")


if __name__ == "__main__":
    unittest.main()
