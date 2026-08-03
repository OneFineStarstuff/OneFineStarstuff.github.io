from pathlib import Path
import json
import subprocess
import sys

import yaml


def run_exporter(root: Path, yaml_path: str | None = None, json_path: str | None = None, verify: bool = False):
    script = Path(__file__).resolve().parent / "scripts" / "export_governance_artifact_json.py"
    cmd = [sys.executable, str(script), "--root", str(root)]
    if yaml_path is not None:
        cmd.extend(["--yaml", yaml_path])
    if json_path is not None:
        cmd.extend(["--json", json_path])
    if verify:
        cmd.append("--verify")
    return subprocess.run(cmd, capture_output=True, text=True)


def test_exporter_generates_expected_json(tmp_path):
    root = tmp_path / "repo"
    (root / "docs/artifacts").mkdir(parents=True, exist_ok=True)

    artifact = {
        "meta": {
            "document_id": "DOC-1",
            "version": "1.0",
            "date": "2026-04-24",
            "horizon": "2026-2030",
            "sectors": ["x"],
        },
        "pillars": [],
    }
    yaml_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml"
    yaml_path.write_text(yaml.safe_dump(artifact, sort_keys=False))

    result = run_exporter(root)

    assert result.returncode == 0, result.stdout + result.stderr
    json_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json"
    assert json_path.exists()

    exported = json.loads(json_path.read_text())
    assert exported["meta"]["document_id"] == "DOC-1"


def test_exporter_is_idempotent(tmp_path):
    root = tmp_path / "repo"
    (root / "docs/artifacts").mkdir(parents=True, exist_ok=True)
    yaml_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml"
    yaml_path.write_text("meta:\n  document_id: DOC-1\n")

    first = run_exporter(root)
    assert first.returncode == 0
    json_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json"
    first_bytes = json_path.read_bytes()

    second = run_exporter(root)
    assert second.returncode == 0
    second_bytes = json_path.read_bytes()

    assert first_bytes == second_bytes


def test_exporter_fails_when_yaml_missing(tmp_path):
    root = tmp_path / "repo"
    result = run_exporter(root)
    assert result.returncode != 0
    assert "yaml artifact not found" in (result.stdout + result.stderr).lower()


def test_exporter_normalizes_yaml_date_to_string(tmp_path):
    root = tmp_path / "repo"
    (root / "docs/artifacts").mkdir(parents=True, exist_ok=True)
    yaml_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml"
    yaml_path.write_text("meta:\n  date: 2026-04-24\n")

    result = run_exporter(root)
    assert result.returncode == 0, result.stdout + result.stderr

    json_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json"
    exported = json.loads(json_path.read_text())
    assert exported["meta"]["date"] == "2026-04-24"


def test_exporter_supports_custom_output_path(tmp_path):
    root = tmp_path / "repo"
    (root / "docs/artifacts").mkdir(parents=True, exist_ok=True)
    yaml_path = root / "docs/artifacts/custom.yaml"
    yaml_path.write_text("meta:\n  document_id: DOC-2\n")

    result = run_exporter(root, yaml_path="docs/artifacts/custom.yaml", json_path="docs/artifacts/custom.json")
    assert result.returncode == 0, result.stdout + result.stderr

    out = root / "docs/artifacts/custom.json"
    assert out.exists()
    exported = json.loads(out.read_text())
    assert exported["meta"]["document_id"] == "DOC-2"


def test_exporter_verify_mode_passes_when_json_is_current(tmp_path):
    root = tmp_path / "repo"
    (root / "docs/artifacts").mkdir(parents=True, exist_ok=True)
    yaml_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml"
    yaml_path.write_text("meta:\n  document_id: DOC-3\n")

    generate = run_exporter(root)
    assert generate.returncode == 0, generate.stdout + generate.stderr

    verify = run_exporter(root, verify=True)
    assert verify.returncode == 0, verify.stdout + verify.stderr
    assert "json verified" in (verify.stdout + verify.stderr).lower()


def test_exporter_verify_mode_detects_stale_json(tmp_path):
    root = tmp_path / "repo"
    (root / "docs/artifacts").mkdir(parents=True, exist_ok=True)
    yaml_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml"
    yaml_path.write_text("meta:\n  document_id: DOC-4\n")

    generate = run_exporter(root)
    assert generate.returncode == 0, generate.stdout + generate.stderr

    json_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json"
    json_path.write_text("{\"meta\":{\"document_id\":\"mutated\"}}\n")

    verify = run_exporter(root, verify=True)
    assert verify.returncode != 0
    assert "json artifact is stale" in (verify.stdout + verify.stderr).lower()


def test_exporter_verify_mode_message_includes_custom_paths(tmp_path):
    root = tmp_path / "repo"
    (root / "docs/artifacts").mkdir(parents=True, exist_ok=True)
    yaml_path = root / "docs/artifacts/custom.yaml"
    yaml_path.write_text("meta:\n  document_id: DOC-5\n")

    generate = run_exporter(root, yaml_path="docs/artifacts/custom.yaml", json_path="docs/artifacts/custom.json")
    assert generate.returncode == 0, generate.stdout + generate.stderr

    json_path = root / "docs/artifacts/custom.json"
    json_path.write_text("{\"meta\":{\"document_id\":\"mutated\"}}\n")

    verify = run_exporter(root, yaml_path="docs/artifacts/custom.yaml", json_path="docs/artifacts/custom.json", verify=True)
    output = verify.stdout + verify.stderr
    assert verify.returncode != 0
    assert "--yaml docs/artifacts/custom.yaml" in output
    assert "--json docs/artifacts/custom.json" in output


def test_exporter_verify_mode_quotes_paths_with_spaces(tmp_path):
    root = tmp_path / "repo"
    (root / "docs/artifacts/custom dir").mkdir(parents=True, exist_ok=True)
    yaml_rel = "docs/artifacts/custom dir/input.yaml"
    json_rel = "docs/artifacts/custom dir/output.json"
    (root / yaml_rel).write_text("meta:\n  document_id: DOC-6\n")

    generate = run_exporter(root, yaml_path=yaml_rel, json_path=json_rel)
    assert generate.returncode == 0, generate.stdout + generate.stderr

    (root / json_rel).write_text("{\"meta\":{\"document_id\":\"mutated\"}}\n")
    verify = run_exporter(root, yaml_path=yaml_rel, json_path=json_rel, verify=True)
    output = verify.stdout + verify.stderr

    assert verify.returncode != 0
    assert "--yaml 'docs/artifacts/custom dir/input.yaml'" in output
    assert "--json 'docs/artifacts/custom dir/output.json'" in output


def test_exporter_help_command_succeeds():
    script = Path(__file__).resolve().parent / "scripts" / "export_governance_artifact_json.py"
    result = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    output = (result.stdout + result.stderr).lower()
    assert "--yaml" in output
    assert "--json" in output


def test_exporter_version_command_succeeds():
    script = Path(__file__).resolve().parent / "scripts" / "export_governance_artifact_json.py"
    result = subprocess.run([sys.executable, str(script), "--version"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "export_governance_artifact_json.py" in (result.stdout + result.stderr)
