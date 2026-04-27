import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import check_generated_artifacts as module


class CheckGeneratedArtifactsTests(unittest.TestCase):
    def test_run_executes_command_in_given_cwd(self):
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td)
            marker = cwd / "cwd.txt"
            module.run(
                [sys.executable, "-c", f"import pathlib; pathlib.Path('{marker}').write_text(str(pathlib.Path.cwd()))"],
                cwd=cwd,
            )
            self.assertEqual(marker.read_text(encoding="utf-8"), str(cwd))

    def test_run_raises_on_failure(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as ctx:
                module.run([sys.executable, "-c", "import sys; sys.exit(3)"], cwd=Path(td))
            self.assertIn("rc=3", str(ctx.exception))
            self.assertIn("import sys; sys.exit(3)", str(ctx.exception))

    def test_main_succeeds_outside_repo_root(self):
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.run(
                [sys.executable, str(Path(module.__file__))],
                cwd=td,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertIn("[OK] Generated governance artifacts are up to date", proc.stdout)


if __name__ == "__main__":
    unittest.main()
