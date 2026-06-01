from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_selftest_validate_artifacts_script_passes() -> None:
    root = Path(__file__).resolve().parents[2]
    script = root / "governance_blueprint" / "validation" / "selftest_validate_artifacts.py"
    result = subprocess.run([sys.executable, str(script)], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
