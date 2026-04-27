import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "check_dependencies.py"


class CheckDependenciesTests(unittest.TestCase):
    def run_script(self, *args: str):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False)

    def test_passes_when_modules_exist(self):
        result = self.run_script("--module", "sys")
        self.assertEqual(result.returncode, 0)
        self.assertIn("[OK]", result.stdout)

    def test_fails_with_install_hint_when_missing(self):
        result = self.run_script("--module", "module_that_does_not_exist_12345")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("[FAIL] Missing Python dependencies", result.stdout)
        self.assertIn("python -m pip install -r", result.stdout)

    def test_resolves_relative_requirements_against_repo_root(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            result = self.run_script(
                "--module",
                "module_that_does_not_exist_12345",
                "--repo-root",
                str(repo_root),
                "--requirements",
                "requirements.txt",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("python -m pip install -r $REPO_ROOT/requirements.txt", result.stdout)

    def test_absolute_requirements_outside_repo_root_kept_absolute(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td) / "repo"
            repo_root.mkdir()
            external_requirements = Path(td) / "external_requirements.txt"
            result = self.run_script(
                "--module",
                "module_that_does_not_exist_12345",
                "--repo-root",
                str(repo_root),
                "--requirements",
                str(external_requirements),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"python -m pip install -r {external_requirements}", result.stdout)

    def test_duplicate_modules_are_deduplicated_in_ok_output(self):
        result = self.run_script("--module", "sys", "--module", "sys")
        self.assertEqual(result.returncode, 0)
        self.assertIn("available: sys", result.stdout)

    def test_empty_module_name_fails(self):
        result = self.run_script("--module", "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Module names must be non-empty", result.stdout)

    def test_whitespace_module_name_is_trimmed(self):
        result = self.run_script("--module", " sys ")
        self.assertEqual(result.returncode, 0)
        self.assertIn("available: sys", result.stdout)

    def test_missing_modules_are_reported_in_sorted_order(self):
        result = self.run_script(
            "--module",
            "zzz_missing_module",
            "--module",
            "aaa_missing_module",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing Python dependencies: aaa_missing_module, zzz_missing_module", result.stdout)


if __name__ == "__main__":
    unittest.main()
