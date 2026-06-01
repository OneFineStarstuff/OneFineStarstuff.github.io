#!/usr/bin/env python3
"""Deterministic validator for Sentinel governance artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path):
    return json.loads(path.read_text())


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text())


def check_catalog_mappings(report: dict) -> None:
    catalog = load_yaml(ROOT / "governance_artifacts/oscal/sentinel_control_catalog_v1.yaml")
    control_ids = [c["id"] for fam in catalog["control_families"] for c in fam.get("controls", [])]
    assert len(control_ids) == len(set(control_ids)), "Duplicate control IDs found"
    report["control_count"] = len(control_ids)

    for mapping in catalog.get("mapping", []):
        assert mapping["control_id"] in control_ids, f"Mapping references unknown control: {mapping['control_id']}"
    report["mapping_count"] = len(catalog.get("mapping", []))


def check_profiles_reference_controls(report: dict) -> None:
    catalog = load_yaml(ROOT / "governance_artifacts/oscal/sentinel_control_catalog_v1.yaml")
    profile = load_yaml(ROOT / "governance_artifacts/regulatory_profiles/eu_ai_act_annex_iv_profile.yaml")
    control_ids = {c["id"] for fam in catalog["control_families"] for c in fam.get("controls", [])}
    selected = {s["control"] for s in profile["profile"].get("selects", [])}
    missing = selected - control_ids
    assert not missing, f"Regulatory profile selects missing controls: {sorted(missing)}"
    report["profile_selected_controls"] = sorted(selected)


def check_json_schemas(report: dict) -> None:
    zk_schema = load_json(ROOT / "governance_artifacts/zk/proof_statement_schema.json")
    zk_example = load_json(ROOT / "governance_artifacts/examples/proof_statement_example.json")
    errors = list(Draft202012Validator(zk_schema).iter_errors(zk_example))
    assert not errors, f"zk example fails schema: {[e.message for e in errors]}"

    kafka_schema = load_json(ROOT / "governance_artifacts/kafka/audit_event_schema.json")
    required = set(kafka_schema.get("required", []))
    expected = {"event_id", "timestamp", "control_id", "decision", "signature"}
    assert expected.issubset(required), "Kafka schema missing required keys"
    report["schema_checks"] = {"zk_example_valid": True, "kafka_required_fields": sorted(expected)}


def check_tla_invariants(report: dict) -> None:
    tla = (ROOT / "governance_artifacts/tla/containment_invariants.tla").read_text()
    markers = ["NoUnsanctionedHighRisk", 'containmentState = "ENFORCED"', "supervisoryQuorum >= 2"]
    for marker in markers:
        assert marker in tla, f"Missing TLA+ invariant marker: {marker}"
    report["tla_markers"] = markers


def check_release_gate_fixtures(report: dict) -> None:
    allow_fx = load_yaml(ROOT / "governance_artifacts/conftest/release_gate_policy_test.yaml")
    deny_fx = load_yaml(ROOT / "governance_artifacts/conftest/release_gate_policy_deny_test.yaml")

    required_paths = [
        ("model", "risk_tier"),
        ("controls", "SAF-OMNI-001"),
        ("controls", "MOD-SR11-7-VAL"),
        ("supervision", "quorum"),
        ("containment", "mode"),
        ("signatures", "bundle_verified"),
    ]

    for fx_name, fx in [("allow", allow_fx), ("deny", deny_fx)]:
        for p1, p2 in required_paths:
            assert p1 in fx and p2 in fx[p1], f"{fx_name} fixture missing {p1}.{p2}"

    assert allow_fx["controls"]["MOD-SR11-7-VAL"] is True
    assert allow_fx["supervision"]["quorum"] >= 2
    assert deny_fx["controls"]["MOD-SR11-7-VAL"] is False
    assert deny_fx["supervision"]["quorum"] < 2
    report["fixture_checks"] = {"allow_expected": True, "deny_expected": True}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, help="Optional path to write JSON validation report")
    args = parser.parse_args()

    report: dict = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "pass",
    }

    try:
        check_catalog_mappings(report)
        check_profiles_reference_controls(report)
        check_json_schemas(report)
        check_tla_invariants(report)
        check_release_gate_fixtures(report)
        print("Governance artifact validation passed.")
    except Exception as exc:
        report["status"] = "fail"
        report["error"] = str(exc)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        raise

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
