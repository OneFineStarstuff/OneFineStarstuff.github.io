from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_generate_artifact_manifest_check_passes() -> None:
    root = Path(__file__).resolve().parents[2]
    script = root / "governance_blueprint" / "validation" / "generate_artifact_manifest.py"
    # Ensure deterministic expected state before check.
    subprocess.run([sys.executable, str(script)], cwd=root, check=True)
    result = subprocess.run([sys.executable, str(script), "--check"], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
