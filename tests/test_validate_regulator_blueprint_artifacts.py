import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_regulator_blueprint_artifacts.py"


def test_validator_passes_on_repo_artifacts():
    proc = subprocess.run(["python", str(VALIDATOR)], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "PASS: artifact validation checks passed" in proc.stdout


def test_validator_list_checks_mode():
    proc = subprocess.run(["python", str(VALIDATOR), "--list-checks"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "presence:" in proc.stdout
    assert "report_schema:" in proc.stdout
    assert "rego_guardrails:" in proc.stdout


def test_validator_json_output_mode():
    proc = subprocess.run(["python", str(VALIDATOR), "--json"], capture_output=True, text=True)
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    names = {c["name"] for c in payload["checks"]}
    assert {"presence", "parseability", "yaml_invariants", "json_invariants", "report_schema", "rego_guardrails"}.issubset(names)


def test_validator_fails_for_missing_base_dir(tmp_path: Path):
    missing = tmp_path / "does-not-exist"
    proc = subprocess.run(["python", str(VALIDATOR), "--base-dir", str(missing)], capture_output=True, text=True)
    assert proc.returncode == 1
    assert "[FAIL] presence" in proc.stdout


def test_validator_json_conforms_to_report_schema():
    proc = subprocess.run(["python", str(VALIDATOR), "--json"], capture_output=True, text=True)
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)

    schema_path = ROOT / "docs" / "reports" / "artifacts" / "regulator_validator_report_schema.json"
    schema = json.loads(schema_path.read_text())

    assert payload.keys() == {"ok", "checks"}
    assert isinstance(payload["ok"], bool)
    assert isinstance(payload["checks"], list) and payload["checks"]

    for item in payload["checks"]:
        assert set(item.keys()) == {"name", "status", "detail"}
        assert isinstance(item["name"], str) and item["name"]
        assert item["status"] in {"PASS", "FAIL"}
        assert isinstance(item["detail"], str) and item["detail"]

    # light contract check that schema and payload remain aligned
    assert set(schema["required"]) == {"ok", "checks"}
    names = {c["name"] for c in payload["checks"]}
    assert "report_schema" in names


def test_validator_unknown_option_errors():
    proc = subprocess.run(["python", str(VALIDATOR), "--not-a-real-flag"], capture_output=True, text=True)
    assert proc.returncode == 2
    assert "unrecognized arguments" in proc.stderr


def test_validator_fails_on_invalid_json_artifact(tmp_path: Path):
    # Build minimal artifact set with malformed JSON to force parseability failure.
    (tmp_path / "gsifi_governance_policy_profile_2030.yaml").write_text("profile: {}\n")
    (tmp_path / "tier3_annex_iv_evidence_template.json").write_text("{invalid-json")
    (tmp_path / "tiered_release_gate.rego").write_text("package x\ndefault allow := false\n")
    (tmp_path / "regulator_validator_report_schema.json").write_text('{"required": ["ok", "checks"], "properties": {"checks": {"type": "array"}}}')

    proc = subprocess.run(["python", str(VALIDATOR), "--base-dir", str(tmp_path)], capture_output=True, text=True)
    assert proc.returncode == 1
    assert "[FAIL] parseability" in proc.stdout


def test_validator_fails_on_invalid_schema_json(tmp_path: Path):
    (tmp_path / "gsifi_governance_policy_profile_2030.yaml").write_text("profile: {}\n")
    (tmp_path / "tier3_annex_iv_evidence_template.json").write_text('{"artifact_type": "annex_iv_technical_documentation", "regulatory_scope": ["EU_AI_Act_Annex_IV"], "monitoring": {"drift": {"threshold": 0.2}}}')
    (tmp_path / "tiered_release_gate.rego").write_text("package x\ndefault allow := false\n")
    (tmp_path / "regulator_validator_report_schema.json").write_text("{not-json")

    proc = subprocess.run(["python", str(VALIDATOR), "--base-dir", str(tmp_path)], capture_output=True, text=True)
    assert proc.returncode == 1
    assert "[FAIL] parseability" in proc.stdout


def test_validator_json_mode_reports_failure_for_missing_dir(tmp_path: Path):
    missing = tmp_path / "missing"
    proc = subprocess.run(
        ["python", str(VALIDATOR), "--json", "--base-dir", str(missing)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    assert payload["checks"][0]["name"] == "presence"
    assert payload["checks"][0]["status"] == "FAIL"


def test_validator_json_check_order_is_stable():
    proc = subprocess.run(["python", str(VALIDATOR), "--json"], capture_output=True, text=True)
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    names = [c["name"] for c in payload["checks"]]
    assert names == [
        "presence",
        "parseability",
        "yaml_invariants",
        "json_invariants",
        "report_schema",
        "rego_guardrails",
    ]


def test_validator_list_checks_order_is_stable():
    proc = subprocess.run(["python", str(VALIDATOR), "--list-checks"], capture_output=True, text=True)
    assert proc.returncode == 0
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    names = [line.split(":", 1)[0] for line in lines]
    assert names == [
        "presence",
        "parseability",
        "yaml_invariants",
        "json_invariants",
        "report_schema",
        "rego_guardrails",
    ]


def test_validator_json_output_contains_only_json():
    proc = subprocess.run(["python", str(VALIDATOR), "--json"], capture_output=True, text=True)
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert isinstance(payload, dict)
    assert "PASS: artifact validation checks passed" not in proc.stdout
    assert "[PASS]" not in proc.stdout


def test_validator_json_failure_output_contains_only_json(tmp_path: Path):
    missing = tmp_path / "missing-dir"
    proc = subprocess.run(
        ["python", str(VALIDATOR), "--json", "--base-dir", str(missing)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    assert "FAIL:" not in proc.stdout
    assert "[FAIL]" not in proc.stdout
