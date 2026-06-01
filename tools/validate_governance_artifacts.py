#!/usr/bin/env python3
"""Deterministic validator for Sentinel governance artifacts."""
"""Validate governance documentation artifacts stay synchronized and well-formed."""

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
import re
from datetime import datetime
from pathlib import Path

DOC = Path('DAILY_GSIFI_AGI_ASI_GOVERNANCE_2026_2030.md')
JSON_EXAMPLE = Path('artifacts/daily_governance_report.example.json')
JSON_SCHEMA = Path('artifacts/daily_governance_report.schema.json')
REGO_POLICY = Path('policies/sentinel_governance.rego')


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Validate governance artifacts and markdown parity.')
    parser.add_argument('--doc', default=str(DOC), help='Path to governance markdown document')
    parser.add_argument('--json-example', default=str(JSON_EXAMPLE), help='Path to canonical JSON example')
    parser.add_argument('--json-schema', default=str(JSON_SCHEMA), help='Path to canonical JSON schema')
    parser.add_argument('--rego-policy', default=str(REGO_POLICY), help='Path to canonical Rego policy')
    return parser


def _extract_single_fenced_block(markdown: str, language: str) -> str:
    matches = re.findall(rf"```{language}\n(.*?)\n```", markdown, re.DOTALL)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one fenced {language} block, found {len(matches)}")
    return matches[0].strip()


def _validate_example_against_schema(example: dict, schema: dict) -> None:
    if schema.get('type') != 'object':
        raise ValueError('Schema top-level type must be object')

    for key in schema.get('required', []):
        if key not in example:
            raise ValueError(f'Missing required top-level key: {key}')

    type_map = {'string': str, 'integer': int, 'boolean': bool, 'array': list, 'object': dict}
    for key, prop in schema.get('properties', {}).items():
        if key not in example:
            raise ValueError(f'Missing property: {key}')
        t = prop.get('type')
        if t in type_map and not isinstance(example[key], type_map[t]):
            raise ValueError(f'Property {key} has wrong type')

        if t == 'object':
            for sub_key in prop.get('required', []):
                if sub_key not in example[key]:
                    raise ValueError(f'Missing nested property: {key}.{sub_key}')
            for sub_key, sub_prop in prop.get('properties', {}).items():
                if sub_key in example[key]:
                    sub_t = sub_prop.get('type')
                    if sub_t in type_map and not isinstance(example[key][sub_key], type_map[sub_t]):
                        raise ValueError(f'Nested property {key}.{sub_key} has wrong type')


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    doc = Path(args.doc)
    json_example_path = Path(args.json_example)
    json_schema_path = Path(args.json_schema)
    rego_policy_path = Path(args.rego_policy)

    markdown = doc.read_text(encoding='utf-8')
    json_snippet = _extract_single_fenced_block(markdown, 'json')
    rego_snippet = _extract_single_fenced_block(markdown, 'rego')

    json_example_text = json_example_path.read_text(encoding='utf-8').strip()
    rego_policy_text = rego_policy_path.read_text(encoding='utf-8').strip()

    example = json.loads(json_example_text)
    schema = json.loads(json_schema_path.read_text(encoding='utf-8'))

    # snippet parity checks
    if json.loads(json_snippet) != example:
        raise ValueError('JSON snippet does not match canonical JSON example')
    if rego_snippet != rego_policy_text:
        raise ValueError('Rego snippet does not match canonical policy file')

    # schema & format checks
    _validate_example_against_schema(example, schema)
    datetime.strptime(example['report_date'], '%Y-%m-%d')
    ts = example['approvals']['timestamp_utc']
    if not ts.endswith('Z'):
        raise ValueError('timestamp_utc must end with Z')
    datetime.fromisoformat(ts.replace('Z', '+00:00'))

    # basic policy-structure checks
    if len(re.findall(r'deny\[msg\]\s*\{', rego_policy_text)) != 3:
        raise ValueError('Expected exactly 3 deny[msg] rules')

    print('Governance artifacts validation passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
