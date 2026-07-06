import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_blueprint_artifact_checks.sh"


def test_unknown_option_returns_usage_error():
    proc = subprocess.run(
        ["bash", str(SCRIPT), "--unknown-option"], capture_output=True, text=True
    )
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
    assert "presence: Required YAML/JSON/Rego/schema artifacts exist" in proc.stdout
    assert "rego_guardrails: Rego deny-by-default and Tier-4 guardrails exist" in proc.stdout
    assert (
        "yaml_examples: YAML examples parse and satisfy required semantics"
        in proc.stdout
    )
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
    proc = subprocess.run(
        ["bash", str(SCRIPT), "--output-json"], capture_output=True, text=True
    )
    assert proc.returncode == 2
    assert "Missing value for --output-json" in proc.stderr


def test_help_option_returns_usage():
    proc = subprocess.run(
        ["bash", str(SCRIPT), "--help"], capture_output=True, text=True
    )
    assert proc.returncode == 0
    assert "Usage:" in proc.stdout
    assert "--output-json" in proc.stdout


def test_regulator_output_json_path_is_supported(tmp_path: Path):
    output = tmp_path / "regulator-validator-output.json"
    subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--skip-install",
            "--skip-pytest",
            "--regulator-output-json",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert output.exists()
    payload = output.read_text()
    assert '"checks"' in payload


def test_regulator_output_json_missing_value_returns_usage_error():
    proc = subprocess.run(["bash", str(SCRIPT), "--regulator-output-json"], capture_output=True, text=True)
    assert proc.returncode == 2
    assert "Missing value for --regulator-output-json" in proc.stderr


def test_list_checks_uses_regulator_base_dir_option(tmp_path: Path):
    alt = tmp_path / "alt-artifacts"
    alt.mkdir()
    proc = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--skip-install",
            "--skip-pytest",
            "--list-checks",
            "--regulator-base-dir",
            str(alt),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "presence: Required YAML/JSON/Rego/schema artifacts exist" in proc.stdout


def test_runner_fails_with_invalid_regulator_base_dir(tmp_path: Path):
    missing = tmp_path / "missing-regulator-dir"
    proc = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--skip-install",
            "--skip-pytest",
            "--regulator-base-dir",
            str(missing),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "[FAIL] presence: Required YAML/JSON/Rego/schema artifacts exist" in proc.stdout


def test_help_includes_regulator_flags():
    proc = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "--regulator-base-dir" in proc.stdout
    assert "--regulator-output-json" in proc.stdout
