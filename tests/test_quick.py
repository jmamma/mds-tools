import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_certifier_rules import CERTIFIER, ROOT, RTS, TEMPO, machine
from mds_to_syx import convert


@unittest.skipUnless(CERTIFIER.is_file(), "build the certifier to test development checks")
class QuickChecks(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.work = Path(directory.name)
        self.source = self.work / "input.mds"
        self.report = self.work / "report.json"
        self.source.write_bytes((ROOT / "tests/fixtures/sine.mds").read_bytes())

    def run_check(self, *options, data=None, quick=True, env=None):
        if data is not None:
            self.source.write_bytes(data)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("MDS_CERTIFIER_")}
        environment.update(env or {})
        return subprocess.run(
            [str(CERTIFIER), "--quiet", *(["--quick"] if quick else []),
             *map(str, options), str(self.source)],
            cwd=self.work, env=environment, capture_output=True, text=True, timeout=120,
        )

    def check_report(self, data, error=None, env=None):
        result = self.run_check("--json", self.report, data=data, env=env)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1 if error else 0, output)
        details = json.loads(self.report.read_text())
        self.assertFalse(details["certified"])
        self.assertEqual(details["scope"], "development_only")
        self.assertEqual(details["development_checks_passed"], error is None)
        self.assertIn("DEVELOPMENT ONLY", output)
        self.assertIn("NOT CERTIFIED", output)
        if error:
            self.assertIn(error, details["error"])
        else:
            self.assertNotIn("error", details)
        self.assertLess(self.report.stat().st_size, 4096)
        self.assertEqual(self.source.read_bytes(), data)
        self.assertEqual({path.name for path in self.work.iterdir()}, {"input.mds", "report.json"})
        return details

    def test_quick_success_is_not_certification_and_keeps_bounded_schedule(self):
        details = self.check_report(
            self.source.read_bytes(),
            env={"MDS_CERTIFIER_BLOCKS": "999999", "MDS_CERTIFIER_PLACEMENTS": "999999"},
        )
        self.assertEqual((details["vectors"], details["placements"], details["blocks"]), (3, 2, 24))
        self.assertGreater(details["mk1_sram"]["init_cycles"], 0)
        for model in ("mk1", "mk2", "mk1_sram"):
            self.assertEqual(details[model]["block_cycles"], 16 * details[model]["track_cycles"])

    def test_no_report_means_no_retained_files(self):
        before = self.source.read_bytes()
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DEVELOPMENT CHECKS PASSED", result.stdout)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(list(self.work.iterdir()), [self.source])

    def test_cannot_stamp_or_combine_with_loops(self):
        stamp = self.work / "stamp.mds"
        stamp.write_bytes(b"previous stamp")
        self.report.write_bytes(b"previous report")
        for options in (("--quick", "--stamp", stamp), ("--stamp", stamp, "--quick"),
                        ("--quick", "--loops")):
            with self.subTest(options=options):
                result = self.run_check(*options, "--json", self.report, quick=False)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("cannot be combined", result.stderr)
                self.assertEqual(stamp.read_bytes(), b"previous stamp")
                self.assertEqual(self.report.read_bytes(), b"previous report")
        stamp.unlink()
        result = self.run_check("--stamp", stamp)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(stamp.exists())

    def test_memory_register_and_control_flow_checks_remain_active(self):
        cases = (
            (machine(init=(0x60F400, 0, 0x56E000, RTS)), "reads"),
            (machine(init=(0x0444BA, 0x04C4BA, RTS)), "forbids"),
            (machine(init=(0x0AF080, 0xFFFFFF)), "control flow left the program"),
        )
        for data, error in cases:
            with self.subTest(error=error):
                self.check_report(data, error)

    def test_uninitialized_output_is_rejected_using_both_seeds(self):
        self.check_report(machine(clear_output=False), "depends on memory or registers")

    def test_repeat_trigger_failure_at_block_two(self):
        trig = (0x60F400, 0, 0x56E000, 0x0ACC10, 8, 0x0444BA, 0x04C4BA, RTS)
        details = self.check_report(machine(trig=trig, imports=(2,), relocations=(5,)), "forbids")
        self.assertIn("TRIG", details["error"])
        self.assertIn("block 2", details["error"])

    def test_tempo_profiles_and_distinct_vectors(self):
        details = self.check_report(machine(params=TEMPO))
        self.assertEqual((details["vectors"], details["placements"], details["blocks"]), (2, 2, 48))
        for threshold, branch in ((200000, 0x0AF0AF), (50000, 0x0AF0A1)):
            with self.subTest(threshold=threshold):
                init = (0x0206FE, 0x0140C5, threshold, branch, 7, 0x0444BA, 0x04C4BA, RTS)
                self.check_report(machine(init=init, params=TEMPO, relocations=(4,)), "forbids")

    def test_all_sample_hardware_profiles_remain_in_schedule(self):
        # Select factory bank/slot zero before SAMPLE_INFO; its result is ignored.
        details = self.check_report(machine(
            init=(0x240000, 0x260000, 0x0BF080, 0, RTS), imports=(3,), import_symbol=9,
        ))
        self.assertEqual((details["vectors"], details["placements"], details["blocks"]), (1, 2, 24))

    def test_sysex_quick_does_not_claim_declaration_verification(self):
        result = self.run_check("--json", self.report, data=convert(self.source.read_bytes()))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        details = json.loads(self.report.read_text())
        self.assertFalse(details["certified"])
        self.assertTrue(details["development_checks_passed"])
        self.assertEqual(details["declaration_check"], "not_checked")
        self.assertNotIn("transfer and cycle declarations verified", result.stdout)


if __name__ == "__main__":
    unittest.main()
