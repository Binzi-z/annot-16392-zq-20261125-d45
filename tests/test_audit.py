import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from forensic_audit.cli import main, run_all, verify_demo_invariants
from forensic_audit.concurrency import run_concurrency_checks
from forensic_audit.engine import build_demo_engine
from forensic_audit.scale import verify_scale
from forensic_audit.small_model import (
    all_short_interleavings,
    verify_short_interleavings,
    verify_small_model,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


class RootEntryPointTests(unittest.TestCase):
    def test_run_audit_script_with_windows_python(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                [sys.executable, "run_audit.py", "--output", tmp],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
            )
            self.assertTrue((Path(tmp) / "audit_report.json").exists())


class CoreAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = build_demo_engine()

    def test_demo_invariants(self) -> None:
        report = verify_demo_invariants(self.engine)
        failed = [c for c in report["checks"] if not c["ok"]]
        self.assertTrue(report["ok"], msg=failed)

    def test_historical_watermark_is_stable_after_revocation(self) -> None:
        before = self.engine.evaluate("CASE-ALPHA", "EV-SHARED", 17)
        after_replay = self.engine.evaluate("CASE-ALPHA", "EV-SHARED", 17)
        self.assertTrue(before.releasable)
        self.assertEqual(before.proof, after_replay.proof)

        revoked = self.engine.evaluate("CASE-ALPHA", "EV-SHARED", 19)
        self.assertTrue(revoked.releasable)
        self.assertEqual(
            {s.reviewer_id for s in revoked.proof.seats}, {"ito", "sato"}
        )

    def test_shared_root_cannot_make_two_seats(self) -> None:
        decision = self.engine.evaluate("CASE-ALPHA", "EV-SHARED", 16)
        self.assertTrue(decision.releasable)
        reviewers = {s.reviewer_id for s in decision.proof.seats}
        self.assertNotEqual(reviewers, {"chen", "patel"})

        chen = next(
            c for c in decision.diagnostics["seat_candidates"]
            if c["signoff_id"] == "SIG-CHEN"
        )
        patel = next(
            c for c in decision.diagnostics["seat_candidates"]
            if c["signoff_id"] == "SIG-PATEL"
        )
        self.assertEqual(chen["root_id"], patel["root_id"])
        self.assertEqual(chen["controller_id"], patel["controller_id"])

    def test_case_isolation(self) -> None:
        beta = self.engine.evaluate("CASE-BETA", "EV-SHARED", 19)
        self.assertFalse(beta.releasable)
        self.assertIn("NO_ROOT_FOR_CASE", [r.code for r in beta.reasons])

        not_member = self.engine.evaluate("CASE-BETA", "EV-ALPHA-ONLY")
        self.assertFalse(not_member.releasable)
        self.assertIn(
            "EVIDENCE_NOT_IN_CASE", [r.code for r in not_member.reasons]
        )


class CliReportTests(unittest.TestCase):
    def test_run_all_writes_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, report = run_all(Path(tmp))
            report_file = Path(tmp) / "audit_report.json"
            self.assertEqual(code, 0, msg=report)
            self.assertTrue(report["ok"])
            self.assertTrue(report_file.exists())
            self.assertGreaterEqual(report["summary"]["watermark_count"], 20)

    def test_main_entry_point_writes_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main(["--output", tmp]), 0)
            self.assertTrue((Path(tmp) / "audit_report.json").exists())


class ConcurrencyTests(unittest.TestCase):
    def test_races_faults_and_preemption(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = run_concurrency_checks(Path(tmp))
            failed = [c for c in report["checks"] if not c["ok"]]
            self.assertTrue(report["ok"], msg=failed)


class SmallModelTests(unittest.TestCase):
    def test_thirty_short_interleavings(self) -> None:
        interleavings = all_short_interleavings()
        self.assertEqual(len(interleavings), 30)
        report = verify_short_interleavings()
        self.assertTrue(report["ok"], msg=report["failures"][:3])

    def test_full_independent_enumeration(self) -> None:
        report = verify_small_model()
        self.assertTrue(report["ok"], msg=report)


class ScaleTests(unittest.TestCase):
    def test_50k_paths_incremental_matches_full(self) -> None:
        report = verify_scale()
        self.assertTrue(report["ok"], msg=report)
        self.assertEqual(report["path_count"], 50_000)
        self.assertEqual(
            report["path_item_comparison"]["compared_items"], 50_000
        )
        self.assertEqual(
            report["revocation"]["relevant_cases"], ["C-025"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
