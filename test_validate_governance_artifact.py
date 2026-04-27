from pathlib import Path
import json
import hashlib
import subprocess
import sys

import yaml


def run_validator(root: Path, extra_args: list[str] | None = None):
    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent / "scripts" / "validate_governance_artifact.py"),
        "--root",
        str(root),
        "--skip-manifest",
    ]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(cmd, cwd=Path(__file__).resolve().parent, capture_output=True, text=True)


def write_valid_package(root: Path):
    (root / "docs/artifacts/examples").mkdir(parents=True, exist_ok=True)
    (root / "docs/artifacts/schemas").mkdir(parents=True, exist_ok=True)

    artifact = {
        "meta": {
            "document_id": "MR-AGI-ASI-ENT-2026-2030",
            "version": "1.0.0",
            "date": "2026-04-24",
            "horizon": "2026-2030",
            "sectors": ["fortune500"],
        },
        "pillars": [{"id": f"P{i}", "name": f"Pillar {i}"} for i in range(1, 6)],
        "regulatory_alignment": [{"framework": f"F{i}", "artifacts": ["a"]} for i in range(1, 6)],
        "control_stack": {"runtime": {"orchestrator": "kubernetes"}},
        "cicd_policy_gates": [
            "code_gate",
            "data_gate",
            "model_gate",
            "risk_gate",
            "compliance_gate",
        ],
        "kpis": {"k1": ">=99%", "k2": "<=10ms", "k3": "<=24h"},
        "control_catalog": [
            {"id": "C1", "domain": "d", "requirement": "r", "enforcement": "e", "evidence": "x"},
            {"id": "C2", "domain": "d", "requirement": "r", "enforcement": "e", "evidence": "x"},
            {"id": "C3", "domain": "d", "requirement": "r", "enforcement": "e", "evidence": "x"},
        ],
        "deterministic_replay_workflow": ["a", "b", "c", "d", "e"],
    }
    schema = {
        "type": "object",
        "required": [
            "meta",
            "pillars",
            "regulatory_alignment",
            "control_stack",
            "cicd_policy_gates",
            "kpis",
            "control_catalog",
            "deterministic_replay_workflow",
        ],
        "properties": {
            "meta": {
                "type": "object",
                "required": ["document_id", "version", "date", "horizon", "sectors"],
                "properties": {
                    "document_id": {"type": "string"},
                    "version": {"type": "string"},
                    "date": {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}$"},
                    "horizon": {"type": "string"},
                    "sectors": {"type": "array", "items": {"type": "string"}},
                },
            },
            "pillars": {"type": "array", "minItems": 5},
            "regulatory_alignment": {"type": "array", "minItems": 5},
            "cicd_policy_gates": {"type": "array", "minItems": 5},
            "kpis": {"type": "object", "minProperties": 3},
            "control_catalog": {"type": "array", "minItems": 3},
            "deterministic_replay_workflow": {"type": "array", "minItems": 5},
        },
    }

    manifest = {
        "required_gates": [
            {"name": "code_gate"},
            {"name": "data_gate"},
            {"name": "model_gate"},
            {"name": "risk_gate"},
            {"name": "compliance_gate"},
            {"name": "release_gate"},
            {"name": "runtime_gate"},
        ],
        "policy_decision_export": {"sink": "kafka"},
    }

    report = """<title>T</title><abstract>A</abstract><content><section id=\"s\">x</section></content>"""

    (root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml").write_text(
        yaml.safe_dump(artifact, sort_keys=False)
    )
    (root / "docs/artifacts/schemas/enterprise_ai_governance_artifact.schema.json").write_text(
        json.dumps(schema)
    )
    (root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json").write_text(
        json.dumps(artifact, sort_keys=True)
    )
    (root / "docs/artifacts/examples/cicd_policy_gate_manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False))
    (root / "docs/artifacts/examples/regulator_report_template.xml").write_text(report)
    files = [
        "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml",
        "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json",
        "docs/artifacts/schemas/enterprise_ai_governance_artifact.schema.json",
        "docs/artifacts/examples/cicd_policy_gate_manifest.yaml",
        "docs/artifacts/examples/regulator_report_template.xml",
    ]
    entries = []
    for rel in files:
        digest = hashlib.sha256((root / rel).read_bytes()).hexdigest()
        entries.append({"path": rel, "sha256": digest})
    manifest = {"version": 1, "algorithm": "sha256", "entries": entries}
    (root / "docs/artifacts/manifest.json").write_text(json.dumps(manifest))


def test_governance_validator_script_passes_with_minimal_package(tmp_path):
    root = tmp_path / "repo"
    write_valid_package(root)
    result = run_validator(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "validation passed" in result.stdout.lower()


def test_governance_validator_fails_on_missing_required_key(tmp_path):
    root = tmp_path / "repo"
    write_valid_package(root)

    artifact_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml"
    artifact = yaml.safe_load(artifact_path.read_text())
    artifact.pop("meta", None)
    artifact_path.write_text(yaml.safe_dump(artifact, sort_keys=False))

    result = run_validator(root)
    assert result.returncode != 0
    assert "missing required top-level keys" in (result.stdout + result.stderr)


def test_governance_validator_fails_on_bad_cicd_gate(tmp_path):
    root = tmp_path / "repo"
    write_valid_package(root)

    manifest_path = root / "docs/artifacts/examples/cicd_policy_gate_manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text())
    manifest["required_gates"] = [g for g in manifest["required_gates"] if g.get("name") != "runtime_gate"]
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))

    result = run_validator(root)
    assert result.returncode != 0
    assert "missing required gates" in (result.stdout + result.stderr)


def test_governance_validator_fails_with_readable_schema_error(tmp_path):
    root = tmp_path / "repo"
    write_valid_package(root)

    artifact_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml"
    artifact = yaml.safe_load(artifact_path.read_text())
    artifact["meta"]["date"] = "not-a-date"
    artifact_path.write_text(yaml.safe_dump(artifact, sort_keys=False))

    result = run_validator(root)
    assert result.returncode != 0
    assert "meta.date" in (result.stdout + result.stderr) or "schema validation failed" in (result.stdout + result.stderr)


def test_governance_validator_fails_with_readable_xml_error(tmp_path):
    root = tmp_path / "repo"
    write_valid_package(root)

    report_path = root / "docs/artifacts/examples/regulator_report_template.xml"
    report_path.write_text("<title>bad<title>")

    result = run_validator(root)
    assert result.returncode != 0
    assert "report template xml is invalid" in (result.stdout + result.stderr).lower()


def test_governance_validator_fails_on_yaml_json_parity_mismatch(tmp_path):
    root = tmp_path / "repo"
    write_valid_package(root)

    json_artifact_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json"
    json_artifact = json.loads(json_artifact_path.read_text())
    json_artifact["meta"]["version"] = "9.9.9"
    json_artifact_path.write_text(json.dumps(json_artifact, sort_keys=True))

    result = run_validator(root)
    assert result.returncode != 0
    assert "yaml/json artifact mismatch" in (result.stdout + result.stderr).lower()


def test_validator_help_command_succeeds():
    script = Path(__file__).resolve().parent / "scripts" / "validate_governance_artifact.py"
    result = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "validate governance artifact package" in (result.stdout + result.stderr).lower()


def test_validator_supports_custom_paths(tmp_path):
    root = tmp_path / "repo"
    write_valid_package(root)

    # move files to custom locations
    (root / "custom").mkdir(parents=True, exist_ok=True)
    (root / "custom/examples").mkdir(parents=True, exist_ok=True)
    (root / "custom/schemas").mkdir(parents=True, exist_ok=True)

    (root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml").replace(root / "custom/artifact.yaml")
    (root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json").replace(root / "custom/artifact.json")
    (root / "docs/artifacts/schemas/enterprise_ai_governance_artifact.schema.json").replace(root / "custom/schemas/schema.json")
    (root / "docs/artifacts/examples/cicd_policy_gate_manifest.yaml").replace(root / "custom/examples/cicd.yaml")
    (root / "docs/artifacts/examples/regulator_report_template.xml").replace(root / "custom/examples/report.xml")
    (root / "docs/artifacts/manifest.json").replace(root / "custom/manifest.json")

    result = run_validator(
        root,
        extra_args=[
            "--yaml", "custom/artifact.yaml",
            "--json", "custom/artifact.json",
            "--schema", "custom/schemas/schema.json",
            "--cicd", "custom/examples/cicd.yaml",
            "--report", "custom/examples/report.xml",
            "--manifest", "custom/manifest.json",
        ],
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_validator_mismatch_message_uses_custom_paths(tmp_path):
    root = tmp_path / "repo"
    write_valid_package(root)

    (root / "custom").mkdir(parents=True, exist_ok=True)
    (root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml").replace(root / "custom/artifact.yaml")
    (root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json").replace(root / "custom/artifact.json")

    json_artifact_path = root / "custom/artifact.json"
    json_artifact = json.loads(json_artifact_path.read_text())
    json_artifact["meta"]["version"] = "2.0.0"
    json_artifact_path.write_text(json.dumps(json_artifact, sort_keys=True))

    result = run_validator(
        root,
        extra_args=[
            "--yaml", "custom/artifact.yaml",
            "--json", "custom/artifact.json",
        ],
    )
    assert result.returncode != 0
    output = (result.stdout + result.stderr)
    assert "--yaml custom/artifact.yaml" in output
    assert "--json custom/artifact.json" in output


def test_validator_version_command_succeeds():
    script = Path(__file__).resolve().parent / "scripts" / "validate_governance_artifact.py"
    result = subprocess.run([sys.executable, str(script), "--version"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "validate_governance_artifact.py" in (result.stdout + result.stderr)


def test_validator_enforces_manifest_by_default(tmp_path):
    root = tmp_path / "repo"
    write_valid_package(root)

    # remove manifest and call validator without --skip-manifest
    (root / "docs/artifacts/manifest.json").unlink()
    script = Path(__file__).resolve().parent / "scripts" / "validate_governance_artifact.py"
    result = subprocess.run([sys.executable, str(script), "--root", str(root)], capture_output=True, text=True)

    assert result.returncode != 0
    assert "required file missing" in (result.stdout + result.stderr).lower()


def test_validator_rejects_manifest_with_missing_tracked_entry(tmp_path):
    root = tmp_path / "repo"
    write_valid_package(root)

    manifest_path = root / "docs/artifacts/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["entries"] = manifest["entries"][:-1]
    manifest_path.write_text(json.dumps(manifest))

    script = Path(__file__).resolve().parent / "scripts" / "validate_governance_artifact.py"
    result = subprocess.run([sys.executable, str(script), "--root", str(root)], capture_output=True, text=True)

    assert result.returncode != 0
    assert "manifest entries do not match expected tracked files" in (result.stdout + result.stderr).lower()
