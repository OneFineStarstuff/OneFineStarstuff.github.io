import json
import subprocess
import sys
import tempfile
import unittest
from importlib.util import find_spec
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VALIDATE = ROOT / "validate_run_report.py"
SCHEMA = ROOT / "validation_run_report.schema.json"
HAS_JSONSCHEMA = find_spec("jsonschema") is not None


@unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is required for run report validation tests")
class ValidateRunReportTests(unittest.TestCase):
    def test_validation_report_schema_pass(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "report.json"
            payload = {
                "overall_status": "pass",
                "passed_checks": 1,
                "failed_checks": 0,
                "checks": [
                    {
                        "command": "make governance-validate",
                        "status": "pass",
                        "return_code": 0,
                        "stdout_tail": "ok",
                        "stderr_tail": "",
                    }
                ],
            }
            with report.open("w", encoding="utf-8") as f:
                json.dump(payload, f)

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--report",
                    str(report),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(val.returncode, 0)

    def test_validation_report_schema_pass_legacy_without_summary_counts(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "legacy_report.json"
            payload = {
                "overall_status": "pass",
                "checks": [
                    {
                        "command": "make governance-validate",
                        "status": "pass",
                        "return_code": 0,
                        "stdout_tail": "ok",
                        "stderr_tail": "",
                    }
                ],
            }
            with report.open("w", encoding="utf-8") as f:
                json.dump(payload, f)

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--report",
                    str(report),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(val.returncode, 0)

    def test_validation_report_summary_counts_mismatch_fail(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "bad_summary_report.json"
            payload = {
                "overall_status": "pass",
                "passed_checks": 99,
                "failed_checks": 0,
                "checks": [
                    {
                        "command": "make governance-validate",
                        "status": "pass",
                        "return_code": 0,
                        "stdout_tail": "ok",
                        "stderr_tail": "",
                    }
                ],
            }
            with report.open("w", encoding="utf-8") as f:
                json.dump(payload, f)

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--report",
                    str(report),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(val.returncode, 0)
            self.assertIn("semantic check failed", val.stdout)

    def test_validation_report_failed_checks_mismatch_fail(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "bad_failed_count_report.json"
            payload = {
                "overall_status": "fail",
                "passed_checks": 0,
                "failed_checks": 0,
                "checks": [
                    {
                        "command": "make governance-validate",
                        "status": "fail",
                        "return_code": 2,
                        "stdout_tail": "",
                        "stderr_tail": "boom",
                    }
                ],
            }
            with report.open("w", encoding="utf-8") as f:
                json.dump(payload, f)

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--report",
                    str(report),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(val.returncode, 0)
            self.assertIn("failed_checks mismatch", val.stdout)

    def test_validation_report_overall_status_inconsistent_with_failures(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "bad_overall_report.json"
            payload = {
                "overall_status": "pass",
                "passed_checks": 0,
                "failed_checks": 1,
                "checks": [
                    {
                        "command": "make governance-validate",
                        "status": "fail",
                        "return_code": 2,
                        "stdout_tail": "",
                        "stderr_tail": "boom",
                    }
                ],
            }
            with report.open("w", encoding="utf-8") as f:
                json.dump(payload, f)

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--report",
                    str(report),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(val.returncode, 0)
            self.assertIn("overall_status pass is inconsistent", val.stdout)

    def test_validation_report_overall_status_fail_without_failed_checks(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "bad_overall_fail_report.json"
            payload = {
                "overall_status": "fail",
                "passed_checks": 1,
                "failed_checks": 0,
                "checks": [
                    {
                        "command": "make governance-validate",
                        "status": "pass",
                        "return_code": 0,
                        "stdout_tail": "ok",
                        "stderr_tail": "",
                    }
                ],
            }
            with report.open("w", encoding="utf-8") as f:
                json.dump(payload, f)

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--report",
                    str(report),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(val.returncode, 0)
            self.assertIn("overall_status fail is inconsistent", val.stdout)

    def test_validation_report_schema_fail(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "bad_report.json"
            with report.open("w", encoding="utf-8") as f:
                json.dump({"overall_status": "pass"}, f)

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--report",
                    str(report),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(val.returncode, 0)
            self.assertIn("[FAIL]", val.stdout)

    def test_validation_report_missing_file_failure(self):
        val = subprocess.run(
            [
                sys.executable,
                str(VALIDATE),
                "--repo-root",
                str(ROOT.parent.parent),
                "--report",
                "docs/schemas/does_not_exist.json",
                "--schema",
                str(SCHEMA),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(val.returncode, 0)
        self.assertIn("Validation report file not found", val.stdout)

    def test_validation_report_invalid_json_failure(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "bad_report.json"
            report.write_text("{invalid", encoding="utf-8")

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--report",
                    str(report),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(val.returncode, 0)
            self.assertIn("Invalid JSON in validation report file", val.stdout)


if __name__ == "__main__":
    unittest.main()
