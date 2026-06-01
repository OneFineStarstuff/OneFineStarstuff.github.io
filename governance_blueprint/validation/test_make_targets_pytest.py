from __future__ import annotations

import subprocess
from pathlib import Path


def test_make_gov_json_check_target_passes() -> None:
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(["make", "gov-json-check"], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + "\n" + result.stderr


def test_make_gov_clean_removes_reports() -> None:
    root = Path(__file__).resolve().parents[2]
    report = root / "governance-artifact-validation-report.json"
    suite = root / "governance-validation-suite-report.json"
    report.write_text("{}", encoding="utf-8")
    suite.write_text("{}", encoding="utf-8")

    result = subprocess.run(["make", "gov-clean"], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + "\n" + result.stderr

    assert not report.exists(), f"{report} should be removed by gov-clean"
    assert not suite.exists(), f"{suite} should be removed by gov-clean"
