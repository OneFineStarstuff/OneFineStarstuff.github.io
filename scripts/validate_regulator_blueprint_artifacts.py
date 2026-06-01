#!/usr/bin/env python3
"""Validate regulator blueprint artifacts and emit human/JSON results."""

import argparse
import json
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ART = ROOT / "docs" / "reports" / "artifacts"


def run_checks(artifacts_dir: Path) -> list[dict[str, str]]:
    yaml_file = artifacts_dir / "gsifi_governance_policy_profile_2030.yaml"
    json_file = artifacts_dir / "tier3_annex_iv_evidence_template.json"
    rego_file = artifacts_dir / "tiered_release_gate.rego"
    schema_file = artifacts_dir / "regulator_validator_report_schema.json"

    checks: list[dict[str, str]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    presence_ok = all([yaml_file.exists(), json_file.exists(), rego_file.exists(), schema_file.exists()])
    record("presence", presence_ok, "Required YAML/JSON/Rego/schema artifacts exist")
    if not presence_ok:
        return checks

    try:
        with yaml_file.open() as f:
            y = yaml.safe_load(f)
        with json_file.open() as f:
            j = json.load(f)
        r = rego_file.read_text()
        schema = json.loads(schema_file.read_text())
        record("parseability", True, "YAML/JSON/schema parse and Rego file read succeeded")
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        record("parseability", False, f"Artifact parse/read failure: {exc}")
        return checks

    profile = y.get("profile", {}) if isinstance(y, dict) else {}
    yaml_ok = (
        profile.get("name") == "gsifi-tiered-governance"
        and "Tier-4" in profile.get("tier_controls", {})
        and profile.get("thresholds", {}).get("drift_psi_max") == 0.20
        and profile.get("thresholds", {}).get("sev1_regulator_notification_hours") == 24
    )
    record("yaml_invariants", yaml_ok, "Profile name, tier controls, and thresholds match expected contract")

    json_ok = (
        j.get("artifact_type") == "annex_iv_technical_documentation"
        and "EU_AI_Act_Annex_IV" in j.get("regulatory_scope", [])
        and j.get("monitoring", {}).get("drift", {}).get("threshold") == 0.20
    )
    record("json_invariants", json_ok, "Artifact type, Annex IV scope, and drift threshold match expected contract")

    schema_ok = (
        isinstance(schema, dict)
        and set(schema.get("required", [])) == {"ok", "checks"}
        and schema.get("properties", {}).get("checks", {}).get("type") == "array"
    )
    record("report_schema", schema_ok, "Validator report schema exposes ok/checks contract")

    rego_ok = (
        "default allow := false" in r
        and 'input.tier == "Tier-4"' in r
        and "input.frontier.containment_certified" in r
        and "input.board.systemic_signoff" in r
    )
    record("rego_guardrails", rego_ok, "Deny-by-default and Tier-4 containment/signoff guards are present")

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate regulator blueprint artifacts")
    parser.add_argument("--json", action="store_true", help="Emit JSON check results")
    parser.add_argument("--list-checks", action="store_true", help="List checks without executing")
    parser.add_argument("--base-dir", type=Path, default=DEFAULT_ART, help="Artifact directory to validate")
    args = parser.parse_args()

    check_names = [
        ("presence", "Required YAML/JSON/Rego/schema artifacts exist"),
        ("parseability", "YAML/JSON/schema parse and Rego read succeed"),
        ("yaml_invariants", "YAML contract values are correct"),
        ("json_invariants", "JSON contract values are correct"),
        ("report_schema", "Validator report schema contract is correct"),
        ("rego_guardrails", "Rego deny-by-default and Tier-4 guardrails exist"),
    ]

    if args.list_checks:
        for name, detail in check_names:
            print(f"{name}: {detail}")
        return 0

    checks = run_checks(args.base_dir)
    failed = [c for c in checks if c["status"] != "PASS"]

    if args.json:
        print(json.dumps({"checks": checks, "ok": not failed}, indent=2))
    else:
        for c in checks:
            print(f"[{c['status']}] {c['name']}: {c['detail']}")

    if failed:
        if not args.json:
            print(f"FAIL: {len(failed)} check(s) failed")
        return 1

    if not args.json:
        print("PASS: artifact validation checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
