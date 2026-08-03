import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]


def test_oscal_control_ids_are_unique_and_mapped():
    catalog_path = ROOT / "governance_artifacts/oscal/sentinel_control_catalog_v1.yaml"
    catalog = yaml.safe_load(catalog_path.read_text())

    control_ids = []
    for family in catalog["control_families"]:
        for control in family.get("controls", []):
            control_ids.append(control["id"])

    assert len(control_ids) == len(set(control_ids)), "Control IDs must be unique"

    mapped_control_ids = {m["control_id"] for m in catalog.get("mapping", [])}
    for cid in mapped_control_ids:
        assert cid in control_ids, f"Mapped control {cid} not found in catalog"


def test_rego_release_gate_references_catalog_controls():
    rego_path = ROOT / "governance_artifacts/rego/release_gate.rego"
    rego = rego_path.read_text()

    # Ensure core containment control and model validation control are hard-gated.
    assert 'input.controls["SAF-OMNI-001"] == true' in rego
    assert 'input.controls["MOD-SR11-7-VAL"] == true' in rego
    assert 'input.supervision.quorum >= 2' in rego


def test_proof_statement_example_matches_schema():
    schema_path = ROOT / "governance_artifacts/zk/proof_statement_schema.json"
    example_path = ROOT / "governance_artifacts/examples/proof_statement_example.json"

    schema = json.loads(schema_path.read_text())
    example = json.loads(example_path.read_text())

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(example), key=lambda e: e.path)
    assert not errors, "Proof statement example must validate against schema"


def test_regulatory_profile_controls_exist_in_catalog():
    profile_path = ROOT / "governance_artifacts/regulatory_profiles/eu_ai_act_annex_iv_profile.yaml"
    catalog_path = ROOT / "governance_artifacts/oscal/sentinel_control_catalog_v1.yaml"

    profile = yaml.safe_load(profile_path.read_text())
    catalog = yaml.safe_load(catalog_path.read_text())

    catalog_controls = {
        c["id"]
        for fam in catalog["control_families"]
        for c in fam.get("controls", [])
    }

    selected_controls = {entry["control"] for entry in profile["profile"].get("selects", [])}
    missing = selected_controls - catalog_controls
    assert not missing, f"Profile selects missing controls: {missing}"

def test_kafka_audit_event_schema_has_required_fields():
    schema_path = ROOT / "governance_artifacts/kafka/audit_event_schema.json"
    schema = json.loads(schema_path.read_text())

    required = set(schema.get("required", []))
    assert {"event_id", "timestamp", "control_id", "decision", "signature"}.issubset(required)


def test_release_gate_deny_fixture_is_non_compliant():
    deny_input_path = ROOT / "governance_artifacts/conftest/release_gate_policy_deny_test.yaml"
    deny_input = yaml.safe_load(deny_input_path.read_text())

    assert deny_input["controls"]["MOD-SR11-7-VAL"] is False
    assert deny_input["supervision"]["quorum"] < 2

def test_proof_schema_rejects_unknown_fields():
    schema_path = ROOT / "governance_artifacts/zk/proof_statement_schema.json"
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(schema)

    invalid = {
        "proof_id": "p1",
        "statement": "s",
        "proving_system": "groth16",
        "public_inputs": [],
        "verification": {"gc_ir_verifier": "v", "key_fingerprint": "k"},
        "unexpected": "nope"
    }

    errors = list(validator.iter_errors(invalid))
    assert errors, "Schema should reject additional top-level properties"


def test_kafka_schema_rejects_unknown_fields():
    schema_path = ROOT / "governance_artifacts/kafka/audit_event_schema.json"
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(schema)

    invalid = {
        "event_id": "e1",
        "timestamp": "2026-01-01T00:00:00Z",
        "control_id": "SAF-OMNI-001",
        "decision": "allow",
        "signature": {"algorithm": "ml-dsa", "value": "abc"},
        "extraneous": "nope"
    }

    errors = list(validator.iter_errors(invalid))
    assert errors, "Kafka schema should reject additional top-level properties"

def test_release_gate_allow_fixture_is_compliant():
    allow_input_path = ROOT / "governance_artifacts/conftest/release_gate_policy_test.yaml"
    allow_input = yaml.safe_load(allow_input_path.read_text())

    assert allow_input["controls"]["MOD-SR11-7-VAL"] is True
    assert allow_input["supervision"]["quorum"] >= 2
    assert allow_input["containment"]["mode"] == "ENFORCED"

def test_validator_writes_pass_report(tmp_path):
    import subprocess

    report_path = tmp_path / "report.json"
    subprocess.run(
        ["python", "tools/validate_governance_artifacts.py", "--report", str(report_path)],
        check=True,
        cwd=ROOT,
    )
    report = json.loads(report_path.read_text())
    assert report["status"] == "pass"
    assert "timestamp_utc" in report
