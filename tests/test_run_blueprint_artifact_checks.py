import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_blueprint_artifact_checks.sh"


def test_unknown_option_returns_usage_error():
    proc = subprocess.run(["bash", str(SCRIPT), "--unknown-option"], capture_output=True, text=True)
    assert proc.returncode == 2
    assert "Usage:" in proc.stderr


def test_list_checks_mode_emits_check_names():
    proc = subprocess.run(
        ["bash", str(SCRIPT), "--skip-install", "--skip-pytest", "--list-checks"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "presence: Required artifact files exist" in proc.stdout
    assert "yaml_examples: YAML examples parse and satisfy required semantics" in proc.stdout
    assert "[PASS]" not in proc.stdout


def test_output_json_path_is_supported(tmp_path: Path):
    output = tmp_path / "validator-output.json"
    subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--skip-install",
            "--skip-pytest",
            "--output-json",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert output.exists()
    payload = output.read_text()
    assert "manifest_structure" in payload


def test_output_json_missing_value_returns_usage_error():
    proc = subprocess.run(["bash", str(SCRIPT), "--output-json"], capture_output=True, text=True)
    assert proc.returncode == 2
    assert "Missing value for --output-json" in proc.stderr


def test_help_option_returns_usage():
    proc = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "Usage:" in proc.stdout
    assert "--output-json" in proc.stdout
