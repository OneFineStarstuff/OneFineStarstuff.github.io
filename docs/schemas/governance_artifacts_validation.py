#!/usr/bin/env python3
"""Validate AGI/ASI governance YAML/JSON artifacts using schema + semantic checks."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from _validation_deps import require_jsonschema

ROOT = Path(__file__).resolve().parent
DEFAULT_YAML = ROOT / "agi_asi_governance_profile_2026_2030.yaml"
DEFAULT_JSON = ROOT / "compliance_control_mapping.json"
DEFAULT_YAML_SCHEMA = ROOT / "agi_asi_governance_profile.schema.json"
DEFAULT_JSON_SCHEMA = ROOT / "compliance_control_mapping.schema.json"

EXPECTED_FRAMEWORK_KEYS = {
    "EU_AI_ACT",
    "NIST_AI_RMF_1_0",
    "NIST_AI_600_1",
    "ISO_IEC_42001",
    "OECD_AI_PRINCIPLES",
    "GDPR_ART_22",
    "FCRA_ECOA",
    "BASEL_S11_7",
    "NIS2",
    "FCA_DUTY_SMCR",
    "MAS_HKMA_FEAT",
}

EXPECTED_CANONICAL_DOMAINS = {
    "GOV", "RISK", "DATA", "DEV", "VAL", "DEP", "OPS", "HUMAN", "SEC", "THIRD", "DISC", "AUDIT"
}


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def validate_schema(instance: dict, schema: dict, label: str) -> None:
    try:
        Draft202012Validator = require_jsonschema()
    except SystemExit as exc:
        fail(str(exc).replace("[FAIL] ", ""))

    errors = sorted(Draft202012Validator(schema).iter_errors(instance), key=lambda e: e.path)
    if errors:
        first = errors[0]
        path = ".".join(str(p) for p in first.absolute_path) or "<root>"
        fail(f"{label} schema validation failed at {path}: {first.message}")


def semantic_checks(yaml_doc: dict, json_doc: dict) -> None:
    risk_tiers = yaml_doc.get("risk_tiers", {})
    for tier in ("L1", "L2", "L3"):
        if tier not in risk_tiers:
            fail(f"YAML risk_tiers missing {tier}")

    framework_keys = set(yaml_doc.get("framework_crosswalk", {}).keys())
    missing_frameworks = EXPECTED_FRAMEWORK_KEYS - framework_keys
    if missing_frameworks:
        fail(f"YAML framework_crosswalk missing keys: {sorted(missing_frameworks)}")

    canonical_domains = set(json_doc.get("canonical_domains", []))
    missing_domains = EXPECTED_CANONICAL_DOMAINS - canonical_domains
    if missing_domains:
        fail(f"JSON canonical_domains missing: {sorted(missing_domains)}")

    controls = json_doc.get("controls", [])
    if len(controls) < 5:
        fail("JSON controls must contain at least five control entries")

    seen_ids = set()
    for idx, control in enumerate(controls, start=1):
        cid = control.get("control_id")
        if not cid:
            fail(f"Control #{idx} missing control_id")
        if cid in seen_ids:
            fail(f"Duplicate control_id detected: {cid}")
        seen_ids.add(cid)

        domain = control.get("domain")
        if domain not in canonical_domains:
            fail(f"Control {cid} uses domain '{domain}' not present in canonical_domains")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yaml", type=Path, default=DEFAULT_YAML, help="Path to governance profile YAML")
    parser.add_argument("--json", type=Path, default=DEFAULT_JSON, help="Path to compliance mapping JSON")
    parser.add_argument("--yaml-schema", type=Path, default=DEFAULT_YAML_SCHEMA, help="Path to YAML JSON-Schema")
    parser.add_argument("--json-schema", type=Path, default=DEFAULT_JSON_SCHEMA, help="Path to JSON JSON-Schema")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    required = [args.yaml, args.json, args.yaml_schema, args.json_schema]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        fail(f"Required files missing: {missing}")

    yaml_doc = load_yaml(args.yaml)
    json_doc = load_json(args.json)
    yaml_schema = load_json(args.yaml_schema)
    json_schema = load_json(args.json_schema)

    validate_schema(yaml_doc, yaml_schema, "YAML profile")
    validate_schema(json_doc, json_schema, "JSON control mapping")
    semantic_checks(yaml_doc, json_doc)

    print("[OK] Governance YAML/JSON artifacts validated (schema + semantic checks)")


if __name__ == "__main__":
    main()
