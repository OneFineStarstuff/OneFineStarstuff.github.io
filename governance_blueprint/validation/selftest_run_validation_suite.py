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
    def test_is_selftest_step_uses_script_name(self) -> None:
        self.assertTrue(rs._is_selftest_step([sys.executable, "governance_blueprint/validation/selftest_validate_artifacts.py"]))
        self.assertFalse(rs._is_selftest_step([sys.executable, "governance_blueprint/validation/validate_artifacts.py", "--flag=selftest_x"]))
        self.assertFalse(rs._is_selftest_step([sys.executable]))

    def test_selftest_script_discovery_uses_git_ls_files_when_available(self) -> None:
        class _R:
            returncode = 0
            stdout = (
                "governance_blueprint/validation/selftest_validate_artifacts.py\n"
                "../bad.py\n"
            )

        with patch.object(rs.subprocess, "run", return_value=_R()):
            scripts = rs._selftest_scripts()
        self.assertEqual(scripts, ["governance_blueprint/validation/selftest_validate_artifacts.py"])

    def test_selftest_script_discovery_is_sorted(self) -> None:
        scripts = rs._selftest_scripts()
        self.assertEqual(scripts, sorted(scripts))
        self.assertTrue(all(s.endswith(".py") for s in scripts))

    def test_selftest_script_discovery_falls_back_on_git_failure(self) -> None:
        class _R:
            returncode = 1
            stdout = ""

        with patch.object(rs.subprocess, "run", return_value=_R()):
            scripts = rs._selftest_scripts()
        self.assertTrue(any(s.endswith("selftest_run_validation_suite.py") for s in scripts))

    def test_build_steps_without_json_report(self) -> None:
        steps = rs.build_steps(json_report=False, skip_selftest=False, opa_bin="", require_opa=False)
        selftests = rs._selftest_scripts()
        expected = [
            [sys.executable, "governance_blueprint/validation/generate_artifact_manifest.py", "--check"],
            [sys.executable, "governance_blueprint/validation/validate_artifacts.py"],
            [sys.executable, "governance_blueprint/validation/lint_python_sources.py"],
            [sys.executable, "governance_blueprint/validation/validate_dashboard_links.py"],
            [sys.executable, "governance_blueprint/validation/selftest_validate_artifacts.py"],
            [sys.executable, "governance_blueprint/validation/selftest_generate_artifact_manifest.py"],
            [sys.executable, "governance_blueprint/validation/selftest_run_validation_suite.py"],
        ]
        expected.extend([[sys.executable, p] for p in selftests])
        self.assertEqual(steps, expected)

    def test_build_steps_with_json_and_skip_selftest(self) -> None:
        steps = rs.build_steps(json_report=True, skip_selftest=True, opa_bin="", require_opa=False)
        expected = [
            [sys.executable, "governance_blueprint/validation/generate_artifact_manifest.py", "--check"],
            [sys.executable, "governance_blueprint/validation/validate_artifacts.py", "--json"],
            [sys.executable, "governance_blueprint/validation/lint_python_sources.py"],
            [sys.executable, "governance_blueprint/validation/validate_dashboard_links.py"],
        ]
        self.assertEqual(steps, expected)

    def test_build_steps_without_json_and_skip_selftest_has_no_selftests(self) -> None:
        steps = rs.build_steps(json_report=False, skip_selftest=True)
        self.assertTrue(all("selftest_" not in cmd[1] for cmd in steps))
        self.assertEqual(
            steps,
            [
                [sys.executable, "governance_blueprint/validation/generate_artifact_manifest.py", "--check"],
                [sys.executable, "governance_blueprint/validation/validate_artifacts.py"],
                [sys.executable, "governance_blueprint/validation/lint_python_sources.py"],
                [sys.executable, "governance_blueprint/validation/validate_dashboard_links.py"],
            ],
        )

    def test_build_steps_with_selftests_includes_all_three_modules(self) -> None:
        steps = rs.build_steps(json_report=False, skip_selftest=False)
        selftest_steps = [cmd[1] for cmd in steps if "selftest_" in cmd[1]]
        self.assertEqual(
            selftest_steps,
            [
                "governance_blueprint/validation/selftest_validate_artifacts.py",
                "governance_blueprint/validation/selftest_generate_artifact_manifest.py",
                "governance_blueprint/validation/selftest_run_validation_suite.py",
            ],
        )

    def test_build_steps_with_json_and_selftests_uses_json_validator(self) -> None:
        steps = rs.build_steps(json_report=True, skip_selftest=False)
        self.assertEqual(
            steps[1],
            [sys.executable, "governance_blueprint/validation/validate_artifacts.py", "--json"],
        )
        self.assertEqual(
            [cmd[1] for cmd in steps if "selftest_" in cmd[1]],
            [
                "governance_blueprint/validation/selftest_validate_artifacts.py",
                "governance_blueprint/validation/selftest_generate_artifact_manifest.py",
                "governance_blueprint/validation/selftest_run_validation_suite.py",
            ],
        )

    def test_build_steps_with_opa_bin(self) -> None:
        steps = rs.build_steps(json_report=False, skip_selftest=True, opa_bin="/tmp/opa", require_opa=False)
        self.assertEqual(
            steps[1],
            [
                sys.executable,
                "governance_blueprint/validation/validate_artifacts.py",
                "--opa-bin",
                "/tmp/opa",
            ],
        )


    def test_build_steps_with_json_and_opa_bin(self) -> None:
        steps = rs.build_steps(json_report=True, skip_selftest=True, opa_bin="/tmp/opa", require_opa=False)
        self.assertEqual(
            steps[1],
            [
                sys.executable,
                "governance_blueprint/validation/validate_artifacts.py",
                "--json",
                "--opa-bin",
                "/tmp/opa",
            ],
        )


    def test_build_steps_with_require_opa(self) -> None:
        steps = rs.build_steps(json_report=False, skip_selftest=True, opa_bin="", require_opa=True)
        self.assertEqual(
            steps[1],
            [
                sys.executable,
                "governance_blueprint/validation/validate_artifacts.py",
                "--require-opa",
            ],
        )


    def test_build_steps_with_json_and_require_opa(self) -> None:
        steps = rs.build_steps(json_report=True, skip_selftest=True, opa_bin="/tmp/opa", require_opa=True)
        self.assertEqual(
            steps[1],
            [
                sys.executable,
                "governance_blueprint/validation/validate_artifacts.py",
                "--json",
                "--opa-bin",
                "/tmp/opa",
                "--require-opa",
            ],
        )


    def test_suite_writes_json_report_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"

            def fake_run(cmd, cwd=None, stdout=None, **kwargs):
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

    def test_json_report_mode_works_with_opa_bin_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report-with-opa.json"

            def fake_run(cmd, cwd=None, stdout=None, **kwargs):
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
                        str(report),
                        "--opa-bin",
                        "/tmp/opa",
                        "--skip-selftest",
                        "--quiet",
                    ],
                ):
                    rc = rs.main()

            self.assertEqual(rc, 0)
            self.assertTrue(report.exists())
            self.assertIn('"ok": true', report.read_text(encoding="utf-8"))


    def test_json_report_uses_opa_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report-env.json"
            seen_envs = []

            def fake_run(cmd, cwd=None, stdout=None, **kwargs):
                class R:
                    returncode = 0

                seen_envs.append(kwargs.get("env"))
                if stdout is not None:
                    stdout.write('{"ok": true}\n')
                return R()

            with patch.object(rs.subprocess, "run", side_effect=fake_run):
                with patch(
                    "sys.argv",
                    [
                        "run_validation_suite.py",
                        "--json-report",
                        str(report),
                        "--opa-bin",
                        "/tmp/opa",
                        "--skip-selftest",
                        "--quiet",
                    ],
                ):
                    rc = rs.main()

            self.assertEqual(rc, 0)
            self.assertTrue(any(env and env.get("OPA_BIN") == "/tmp/opa" for env in seen_envs))


    def test_suite_writes_suite_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            validator_report = Path(tmp) / "validator.json"
            suite_report = Path(tmp) / "suite.json"

            def fake_run(cmd, cwd=None, stdout=None, **kwargs):
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

            def fake_run(cmd, cwd=None, stdout=None, **kwargs):
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

    def test_no_selftests_discovered_returns_specific_code(self) -> None:
        with patch.object(rs, "_selftest_scripts", return_value=[]):
            with patch("sys.argv", ["run_validation_suite.py", "--quiet"]):
                with redirect_stdout(io.StringIO()):
                    rc = rs.main()
        self.assertEqual(rc, rs.NO_SELFTESTS_DISCOVERED_RC)

    def test_no_selftests_discovered_writes_suite_report_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            suite_report = Path(tmp) / "suite-no-selftests.json"
            with patch.object(rs, "_selftest_scripts", return_value=[]):
                with patch("sys.argv", ["run_validation_suite.py", "--quiet", "--suite-report", str(suite_report)]):
                    with redirect_stdout(io.StringIO()):
                        rc = rs.main()
            self.assertEqual(rc, rs.NO_SELFTESTS_DISCOVERED_RC)
            self.assertTrue(suite_report.exists())
            payload = json.loads(suite_report.read_text(encoding="utf-8"))
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["steps"][0]["name"], "selftest_discovery")
            self.assertEqual(payload["steps"][0]["returncode"], rs.NO_SELFTESTS_DISCOVERED_RC)



if __name__ == "__main__":
    unittest.main()
