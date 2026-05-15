#!/usr/bin/env python3
"""Unit tests for run_validation_suite.py behavior."""

from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("run_validation_suite.py")
spec = importlib.util.spec_from_file_location("run_validation_suite", MODULE_PATH)
rs = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(rs)


class RunValidationSuiteTests(unittest.TestCase):
    def test_build_steps_without_json_report(self) -> None:
        steps = rs.build_steps(json_report=False, skip_selftest=False)
        expected = [
            [sys.executable, "governance_blueprint/validation/generate_artifact_manifest.py", "--check"],
            [sys.executable, "governance_blueprint/validation/validate_artifacts.py"],
            [sys.executable, "governance_blueprint/validation/lint_python_sources.py"],
            [sys.executable, "governance_blueprint/validation/validate_dashboard_links.py"],
            [sys.executable, "governance_blueprint/validation/selftest_validate_artifacts.py"],
            [sys.executable, "governance_blueprint/validation/selftest_run_validation_suite.py"],
        ]
        self.assertEqual(steps, expected)

    def test_build_steps_with_json_and_skip_selftest(self) -> None:
        steps = rs.build_steps(json_report=True, skip_selftest=True)
        expected = [
            [sys.executable, "governance_blueprint/validation/generate_artifact_manifest.py", "--check"],
            [sys.executable, "governance_blueprint/validation/validate_artifacts.py", "--json"],
            [sys.executable, "governance_blueprint/validation/lint_python_sources.py"],
            [sys.executable, "governance_blueprint/validation/validate_dashboard_links.py"],
        ]
        self.assertEqual(steps, expected)

    def test_suite_writes_json_report_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"

            def fake_run(cmd, cwd=None, stdout=None):
                class R:
                    returncode = 0

                if stdout is not None:
                    stdout.write('{"ok": true}\n')
                return R()

            with patch.object(rs.subprocess, "run", side_effect=fake_run):
                with patch("sys.argv", ["run_validation_suite.py", "--json-report", str(report), "--skip-selftest", "--quiet"]):
                    rc = rs.main()

            self.assertEqual(rc, 0)
            self.assertTrue(report.exists())
            self.assertIn('"ok": true', report.read_text(encoding="utf-8"))

    def test_suite_writes_suite_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator_report = Path(tmp) / "validator.json"
            suite_report = Path(tmp) / "suite.json"

            def fake_run(cmd, cwd=None, stdout=None):
                class R:
                    returncode = 0

                if stdout is not None:
                    stdout.write('{"ok": true}\n')
                return R()

            with patch.object(rs.subprocess, "run", side_effect=fake_run):
                with patch(
                    "sys.argv",
                    [
                        "run_validation_suite.py",
                        "--json-report",
                        str(validator_report),
                        "--suite-report",
                        str(suite_report),
                        "--skip-selftest",
                        "--quiet",
                    ],
                ):
                    rc = rs.main()

            self.assertEqual(rc, 0)
            self.assertTrue(suite_report.exists())
            suite_payload = json.loads(suite_report.read_text(encoding="utf-8"))
            self.assertTrue(suite_payload["ok"])
            self.assertEqual(len(suite_payload["steps"]), 4)
            self.assertEqual(suite_payload["validator_report"], {"ok": True})

    def test_failure_writes_suite_report_with_failed_step(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            suite_report = Path(tmp) / "suite-fail.json"

            with patch.object(rs, "_run", return_value=2):
                with patch("sys.argv", ["run_validation_suite.py", "--suite-report", str(suite_report), "--skip-selftest", "--quiet"]):
                    rc = rs.main()

            self.assertEqual(rc, 2)
            self.assertTrue(suite_report.exists())
            payload = json.loads(suite_report.read_text(encoding="utf-8"))
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["steps"][0]["name"], "generate_artifact_manifest.py")
            self.assertEqual(payload["steps"][0]["returncode"], 2)


    def test_malformed_validator_json_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "bad-validator.json"
            suite_report = Path(tmp) / "suite.json"

            def fake_run(cmd, cwd=None, stdout=None):
                class R:
                    returncode = 0

                if stdout is not None:
                    stdout.write('{not-json}\n')
                return R()

            with patch.object(rs.subprocess, "run", side_effect=fake_run):
                with patch(
                    "sys.argv",
                    [
                        "run_validation_suite.py",
                        "--json-report",
                        str(report),
                        "--suite-report",
                        str(suite_report),
                        "--skip-selftest",
                        "--quiet",
                    ],
                ):
                    with redirect_stdout(io.StringIO()):
                        rc = rs.main()

            self.assertEqual(rc, 3)
            payload = json.loads(suite_report.read_text(encoding="utf-8"))
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["steps"][1]["name"], "validate_artifacts.py")
            self.assertEqual(payload["steps"][1]["returncode"], 3)


    def test_no_fail_fast_runs_all_steps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            suite_report = Path(tmp) / "suite-no-fail-fast.json"

            with patch.object(rs, "_run", side_effect=[2, 0, 0, 0]):
                with patch(
                    "sys.argv",
                    [
                        "run_validation_suite.py",
                        "--suite-report",
                        str(suite_report),
                        "--skip-selftest",
                        "--quiet",
                        "--no-fail-fast",
                    ],
                ):
                    rc = rs.main()

            self.assertEqual(rc, 2)
            payload = json.loads(suite_report.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["steps"]), 4)
            self.assertEqual(payload["steps"][0]["returncode"], 2)
            self.assertEqual(payload["steps"][-1]["returncode"], 0)



if __name__ == "__main__":
    unittest.main()
