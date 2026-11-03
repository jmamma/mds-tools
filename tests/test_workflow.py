import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from lib.mds_format import parse_package

CERTIFIER = Path(os.environ.get("MDS_CERTIFIER", ROOT / "build/mds-certifier"))


class Workflow(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.fixture = parse_package((ROOT / "tests/fixtures/sine.mds").read_bytes())

    def command(self, *args, check=True):
        return subprocess.run(
            [str(arg) for arg in args], cwd=self.work,
            check=check, capture_output=True, text=True
        )

    def pack(self, *options, check=True):
        program = self.work / "sine.bin"
        draft = self.work / "sine.mds"
        program.write_bytes(self.fixture["program"])
        result = self.command(
            sys.executable, "-B", ROOT / "tools/mds_pack.py",
            ROOT / "tests/fixtures/sine.json", program,
            "--symbols", ROOT / "tests/fixtures/sine.symbols.json",
            "-o", draft, *options, check=check
        )
        return draft, result

    def test_pack_cli_builds_a_draft(self):
        draft, result = self.pack()
        parsed = parse_package(draft.read_bytes())
        self.assertEqual(parsed["program"], self.fixture["program"])
        self.assertEqual(parsed["relocations"], self.fixture["relocations"])
        self.assertEqual(parsed["imports"], self.fixture["imports"])
        self.assertEqual(parsed["board_track_cycles"], (0, 0))
        self.assertEqual(draft.read_bytes()[74:76], bytes(2))
        self.assertIn("warning: packaged without certification", result.stderr)
        self.assertIn("DRAFT", result.stdout)

    def test_declared_cycles_do_not_imply_certification(self):
        draft, result = self.pack("--max-track-cycles", "731")
        self.assertEqual(parse_package(draft.read_bytes())["max_track_cycles"], 731)
        self.assertIn("warning: packaged without certification", result.stderr)
        self.assertIn("not certified", result.stdout)

    def test_certification_options_require_certify(self):
        for option, value in (("--report", self.work / "report.json"), ("--certifier", CERTIFIER)):
            with self.subTest(option=option):
                draft, result = self.pack(option, value, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("require --certify", result.stderr)
                self.assertFalse(draft.exists())

    def test_missing_certifier_leaves_output_untouched(self):
        draft = self.work / "sine.mds"
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    draft.write_bytes(b"previous output")
                _, result = self.pack("--certify", "--certifier", self.work / "missing", check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("certifier executable not found", result.stderr)
                if existing:
                    self.assertEqual(draft.read_bytes(), b"previous output")
                else:
                    self.assertFalse(draft.exists())

    def test_certifier_failure_leaves_output_and_report_untouched(self):
        draft, report = self.work / "sine.mds", self.work / "report.json"
        draft.write_bytes(b"previous output")
        report.write_bytes(b"previous report")
        _, result = self.pack(
            "--certify", "--certifier", sys.executable, "--report", report, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("certification failed", result.stderr)
        self.assertEqual(draft.read_bytes(), b"previous output")
        self.assertEqual(report.read_bytes(), b"previous report")

    def test_report_cannot_overwrite_output_or_inputs(self):
        for path in (self.work / "sine.mds", self.work / "sine.bin"):
            with self.subTest(path=path):
                _, result = self.pack(
                    "--certify", "--certifier", sys.executable, "--report", path, check=False
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("report must differ", result.stderr)
                self.assertFalse((self.work / "sine.mds").exists())
                self.assertEqual((self.work / "sine.bin").read_bytes(), self.fixture["program"])

    @unittest.skipUnless(CERTIFIER.is_file(), "build the certifier to test the complete workflow")
    def test_pack_certify_stamp_and_convert(self):
        report_path = self.work / "sine-report.json"
        stamped, result = self.pack("--certify", "--certifier", CERTIFIER, "--report", report_path)
        sysex = self.work / "sine.syx"
        self.assertNotIn("packaged without certification", result.stderr)
        self.assertIn("certified cycles: MKI=954, MKII=894, MKI SRAM=899", result.stdout)
        parsed = parse_package(stamped.read_bytes())
        report = json.loads(report_path.read_text())
        self.assertTrue(report["certified"])
        self.assertNotIn("scope", report)
        self.assertNotIn("development_checks_passed", report)
        self.assertEqual((report["vectors"], report["placements"], report["blocks"]), (9, 16, 63516))
        for board in ("mk1", "mk2", "mk1_sram"):
            figures = report[board]
            self.assertEqual(figures["track_cycles"], max(figures["standard_cycles"], figures["peak_cycles"]))
            self.assertIsInstance(figures["peak_detail"], str)
        self.assertEqual(stamped.read_bytes()[74:76], (899).to_bytes(2, "big"))
        self.assertEqual(parsed["mk1_sram_track_cycles"], report["mk1_sram"]["track_cycles"])
        self.assertEqual(parsed["board_track_cycles"], (954, 894))
        self.assertEqual(
            parsed["board_track_cycles"],
            (report["mk1"]["track_cycles"], report["mk2"]["track_cycles"])
        )
        self.command(
            sys.executable, "-B", ROOT / "tools/mds_to_syx.py",
            stamped, "--slot", "2", "-o", sysex
        )
        encoded = sysex.read_bytes()
        self.assertTrue(encoded.startswith(bytes.fromhex("f000203c0200740101")))
        self.assertTrue(encoded.endswith(bytes([0xf7])))
        self.assertEqual(encoded[11], 1)
        self.assertEqual(
            encoded.count(bytes([0xf0])),
            (len(stamped.read_bytes()) + 419) // 420 + 2
        )


if __name__ == "__main__":
    unittest.main()
