from pathlib import Path
import subprocess
import sys


def test_summarize_script_reports_counts(tmp_path):
    report = tmp_path / "governance-tests.xml"
    report.write_text(
        '<testsuite tests="10" failures="1" errors="0" skipped="2"></testsuite>'
    )

    script = Path(__file__).resolve().parent / "scripts" / "summarize_governance_test_results.py"
    result = subprocess.run(
        [sys.executable, str(script), "--report", str(report)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "10 total" in result.stdout
    assert "1 failures" in result.stdout
    assert "2 skipped" in result.stdout


def test_summarize_script_fails_for_missing_report(tmp_path):
    missing = tmp_path / "missing.xml"
    script = Path(__file__).resolve().parent / "scripts" / "summarize_governance_test_results.py"
    result = subprocess.run(
        [sys.executable, str(script), "--report", str(missing)],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "report not found" in (result.stdout + result.stderr).lower()


def test_summarize_version_command_succeeds():
    script = Path(__file__).resolve().parent / "scripts" / "summarize_governance_test_results.py"
    result = subprocess.run([sys.executable, str(script), "--version"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "summarize_governance_test_results.py" in (result.stdout + result.stderr)
