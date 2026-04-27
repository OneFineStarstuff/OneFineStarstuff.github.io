import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUN = ROOT / "run_governance_checks.py"
SPEC = importlib.util.spec_from_file_location("run_governance_checks", RUN)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RunGovernanceChecksTests(unittest.TestCase):
    def test_default_commands_include_post_generation_checks(self):
        self.assertIn("make --no-print-directory governance-artifact-inventory", MODULE.DEFAULT_COMMANDS)
        self.assertIn("make --no-print-directory governance-report-schema", MODULE.DEFAULT_COMMANDS)
        self.assertIn("make --no-print-directory governance-check-generated", MODULE.DEFAULT_COMMANDS)

    def test_report_redacts_absolute_repo_root(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUN),
                    "--output",
                    str(out),
                    "--command",
                    "python -c \"import pathlib; print(pathlib.Path.cwd())\"",
                ],
                capture_output=True,
                text=True,
                check=False,
                cwd=td,
            )
            self.assertEqual(proc.returncode, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            output_tail = data["checks"][0]["stdout_tail"]
            self.assertIn("$REPO_ROOT", output_tail)
            self.assertNotIn(str(MODULE.REPO_ROOT), output_tail)

    def test_report_normalizes_test_runtime_lines(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUN),
                    "--output",
                    str(out),
                    "--command",
                    "python -c \"import sys; sys.stderr.write(\'Ran 2 tests in 0.123s\\n\')\"",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            stderr_tail = data["checks"][0]["stderr_tail"]
            self.assertIn("Ran 2 tests in <redacted>s", stderr_tail)

    def test_report_marks_truncated_output(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUN),
                    "--output",
                    str(out),
                    "--max-tail-chars",
                    "20",
                    "--command",
                    "python -c \"import sys; sys.stdout.write('x' * 120)\"",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            output_tail = data["checks"][0]["stdout_tail"]
            self.assertIn("[truncated", output_tail)
            self.assertEqual(output_tail.splitlines()[-1], "x" * 20)

    def test_custom_commands_pass(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUN),
                    "--output",
                    str(out),
                    "--command",
                    "echo ok",
                    "--command",
                    "python -c \"print('done')\"",
                    "--max-tail-chars",
                    "20",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["overall_status"], "pass")
            self.assertEqual(len(data["checks"]), 2)
            self.assertEqual(data["passed_checks"], 2)
            self.assertEqual(data["failed_checks"], 0)
            self.assertFalse(data["checks"][0]["timed_out"])
            self.assertFalse(data["checks"][1]["timed_out"])

    def test_command_timeout_fails_with_marker(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUN),
                    "--output",
                    str(out),
                    "--timeout-seconds",
                    "1",
                    "--command",
                    "python -c \"import time; time.sleep(2)\"",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            check = data["checks"][0]
            self.assertEqual(check["status"], "fail")
            self.assertEqual(check["return_code"], -1)
            self.assertTrue(check["timed_out"])
            self.assertIn("[timeout]", check["stderr_tail"])

    def test_continue_on_failure_runs_all_commands(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUN),
                    "--output",
                    str(out),
                    "--continue-on-failure",
                    "--command",
                    "python -c \"import sys; sys.exit(1)\"",
                    "--command",
                    "echo should_run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["overall_status"], "fail")
            self.assertEqual(len(data["checks"]), 2)
            self.assertEqual(data["passed_checks"], 1)
            self.assertEqual(data["failed_checks"], 1)
            self.assertEqual(data["checks"][0]["status"], "fail")
            self.assertEqual(data["checks"][1]["status"], "pass")

    def test_custom_commands_fail_fast(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUN),
                    "--output",
                    str(out),
                    "--command",
                    "python -c \"import sys; sys.exit(1)\"",
                    "--command",
                    "echo should_not_run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["overall_status"], "fail")
            self.assertEqual(len(data["checks"]), 1)
            self.assertEqual(data["passed_checks"], 0)
            self.assertEqual(data["failed_checks"], 1)


if __name__ == "__main__":
    unittest.main()
