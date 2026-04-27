#!/usr/bin/env python3
"""Validate blueprint starter pack structure and sample data."""

from __future__ import annotations

import argparse
import csv
import json
import yaml
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ART = ROOT / "docs" / "reports" / "blueprint_artifacts"

REQUIRED_FILES = [
    "README.md",
    "T1_Executive_Attestation.md",
    "T2_Control_Crosswalk.csv",
    "T3_Model_Risk_Register.csv",
    "T4_Incident_Notification_Playbook.md",
    "T5_RedTeam_Closure_Report.md",
    "T6_Evidence_Manifest.json",
    "T6_Evidence_Manifest.schema.json",
    "T7_Runtime_Policy.rego",
    "T8_Kafka_Audit_ACL_Example.yaml",
    "T9_K8s_NetworkPolicy_Example.yaml",
]


CHECK_SEQUENCE: list[tuple[str, str]] = [
    ("presence", "Required artifact files exist"),
    ("manifest_structure", "Manifest top-level/object structure is valid"),
    ("manifest_timestamp", "Manifest timestamp is valid ISO-8601"),
    ("schema_metadata", "Schema metadata and top-level type are valid"),
    ("schema_contract", "Manifest/schema required keys align"),
    ("schema_constraints", "Manifest satisfies schema keyword constraints"),
    ("csv_semantics", "CSV headers and sample-row semantics are valid"),
    ("rego_guardrails", "Rego policy contains minimum guardrails"),
    ("yaml_examples", "YAML examples parse and satisfy required semantics"),
]

@dataclass
class ValidationResult:
    name: str
    ok: bool
    detail: str


def load_manifest(base_dir: Path = DEFAULT_ART) -> dict:
    return json.loads((base_dir / "T6_Evidence_Manifest.json").read_text())


def load_schema(base_dir: Path = DEFAULT_ART) -> dict:
    return json.loads((base_dir / "T6_Evidence_Manifest.schema.json").read_text())


def validate_presence(base_dir: Path = DEFAULT_ART) -> ValidationResult:
    missing = [f for f in REQUIRED_FILES if not (base_dir / f).exists()]
    if missing:
        return ValidationResult("presence", False, f"Missing files: {missing}")
    return ValidationResult("presence", True, "All required files present")


def validate_json_manifest(base_dir: Path = DEFAULT_ART) -> ValidationResult:
    manifest = load_manifest(base_dir)
    expected_top = {"manifest_id", "generated_at", "institution", "artifacts"}
    if set(manifest.keys()) != expected_top:
        return ValidationResult("manifest_structure", False, "Unexpected manifest keys")
    if not isinstance(manifest["artifacts"], list) or not manifest["artifacts"]:
        return ValidationResult("manifest_structure", False, "Manifest artifacts must be a non-empty list")
    for item in manifest["artifacts"]:
        required = {"name", "location", "hash", "signature"}
        if set(item.keys()) != required:
            return ValidationResult("manifest_structure", False, f"Invalid artifact item keys: {item}")
        for key in required:
            if not isinstance(item[key], str) or not item[key].strip():
                return ValidationResult("manifest_structure", False, f"Artifact field '{key}' must be non-empty")
    return ValidationResult("manifest_structure", True, "Manifest structure is valid")


def validate_manifest_timestamp(base_dir: Path = DEFAULT_ART) -> ValidationResult:
    manifest = load_manifest(base_dir)
    ts = manifest["generated_at"]
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return ValidationResult("manifest_timestamp", False, f"Invalid generated_at timestamp: {ts}")
    return ValidationResult("manifest_timestamp", True, "generated_at timestamp is valid ISO-8601")


def validate_schema_metadata(base_dir: Path = DEFAULT_ART) -> ValidationResult:
    schema = load_schema(base_dir)
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        return ValidationResult("schema_metadata", False, "Unexpected $schema URI")
    if schema.get("type") != "object":
        return ValidationResult("schema_metadata", False, "Top-level schema type must be object")
    return ValidationResult("schema_metadata", True, "Schema metadata is valid")


def validate_manifest_against_schema_contract(base_dir: Path = DEFAULT_ART) -> ValidationResult:
    schema = load_schema(base_dir)
    manifest = load_manifest(base_dir)

    schema_required = set(schema.get("required", []))
    manifest_keys = set(manifest.keys())
    if schema_required != manifest_keys:
        return ValidationResult(
            "schema_contract",
            False,
            f"Manifest/schema required key mismatch: schema={schema_required}, manifest={manifest_keys}",
        )

    artifact_req = set(schema["properties"]["artifacts"]["items"].get("required", []))
    for item in manifest["artifacts"]:
        if artifact_req != set(item.keys()):
            return ValidationResult(
                "schema_contract",
                False,
                f"Artifact item/schema required key mismatch: schema={artifact_req}, item={set(item.keys())}",
            )
    return ValidationResult("schema_contract", True, "Manifest matches schema contract keys")


def validate_schema_constraints(base_dir: Path = DEFAULT_ART) -> ValidationResult:
    schema = load_schema(base_dir)
    manifest = load_manifest(base_dir)

    for key in schema.get("required", []):
        if key not in manifest:
            return ValidationResult("schema_constraints", False, f"Missing required field: {key}")

    # top-level string minLength checks
    properties = schema.get("properties", {})
    for key in ("manifest_id", "generated_at", "institution"):
        rule = properties.get(key, {})
        min_len = rule.get("minLength", 0)
        value = manifest.get(key, "")
        if not isinstance(value, str) or len(value) < min_len:
            return ValidationResult("schema_constraints", False, f"Field {key} violates minLength/type")

    artifacts = manifest.get("artifacts", [])
    min_items = properties.get("artifacts", {}).get("minItems", 0)
    if not isinstance(artifacts, list) or len(artifacts) < min_items:
        return ValidationResult("schema_constraints", False, "artifacts violates minItems/type")

    item_props = properties.get("artifacts", {}).get("items", {}).get("properties", {})
    item_required = properties.get("artifacts", {}).get("items", {}).get("required", [])
    for idx, item in enumerate(artifacts, start=1):
        for req in item_required:
            if req not in item:
                return ValidationResult("schema_constraints", False, f"artifacts[{idx}] missing field {req}")
        for req in item_required:
            rule = item_props.get(req, {})
            min_len = rule.get("minLength", 0)
            value = item.get(req, "")
            if not isinstance(value, str) or len(value) < min_len:
                return ValidationResult("schema_constraints", False, f"artifacts[{idx}].{req} violates minLength/type")

    return ValidationResult("schema_constraints", True, "Manifest satisfies schema keyword constraints")


def _valid_date(value: str) -> bool:
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def validate_csv_headers(base_dir: Path = DEFAULT_ART) -> ValidationResult:
    with (base_dir / "T2_Control_Crosswalk.csv").open(newline="") as f:
        crosswalk_rows = list(csv.reader(f))
    headers = crosswalk_rows[0]
    if headers != ["control_id", "framework", "obligation", "artifact"]:
        return ValidationResult("csv_semantics", False, "Crosswalk CSV header mismatch")
    if len(crosswalk_rows) < 2:
        return ValidationResult("csv_semantics", False, "Crosswalk CSV must include at least one data row")

    with (base_dir / "T3_Model_Risk_Register.csv").open(newline="") as f:
        rows = list(csv.reader(f))
    headers = rows[0]
    expected = [
        "model_id",
        "owner",
        "use_case",
        "risk_tier",
        "validation_status",
        "last_validation_date",
        "monitoring_status",
        "next_review_date",
    ]
    if headers != expected:
        return ValidationResult("csv_semantics", False, "Model risk register CSV header mismatch")

    allowed_tiers = {"low", "medium", "high", "systemic", "frontier"}
    for idx, row in enumerate(rows[1:], start=2):
        if len(row) != len(expected):
            return ValidationResult("csv_semantics", False, f"Model risk row {idx} has wrong column count")
        risk_tier = row[3].strip().lower()
        if risk_tier not in allowed_tiers:
            return ValidationResult("csv_semantics", False, f"Model risk row {idx} has invalid risk_tier: {row[3]}")
        if not _valid_date(row[5]) or not _valid_date(row[7]):
            return ValidationResult("csv_semantics", False, f"Model risk row {idx} has invalid date format")

    return ValidationResult("csv_semantics", True, "CSV headers and sample rows are valid")


def validate_rego_guardrails(base_dir: Path = DEFAULT_ART) -> ValidationResult:
    rego = (base_dir / "T7_Runtime_Policy.rego").read_text()
    required_fragments = [
        "default allow = false",
        'input.risk_tier != "prohibited"',
        "input.hitl_approved == true",
    ]
    missing = [frag for frag in required_fragments if frag not in rego]
    if missing:
        return ValidationResult("rego_guardrails", False, f"Missing Rego guardrails: {missing}")
    return ValidationResult("rego_guardrails", True, "Rego guardrails present")


def validate_yaml_examples(base_dir: Path = DEFAULT_ART) -> ValidationResult:
    kafka_obj = yaml.safe_load((base_dir / "T8_Kafka_Audit_ACL_Example.yaml").read_text())
    k8s_obj = yaml.safe_load((base_dir / "T9_K8s_NetworkPolicy_Example.yaml").read_text())

    if not isinstance(kafka_obj, dict):
        return ValidationResult("yaml_examples", False, "Kafka ACL YAML must be a mapping")
    if "principals" not in kafka_obj or "constraints" not in kafka_obj:
        return ValidationResult("yaml_examples", False, "Kafka ACL YAML missing principals/constraints")
    if not isinstance(kafka_obj["principals"], list) or len(kafka_obj["principals"]) == 0:
        return ValidationResult("yaml_examples", False, "Kafka ACL YAML principals must be a non-empty list")

    constraints = kafka_obj.get("constraints", [])
    if not any(isinstance(item, dict) and item.get("enforce_mtls") is True for item in constraints):
        return ValidationResult("yaml_examples", False, "Kafka ACL YAML missing enforce_mtls: true constraint")

    if not isinstance(k8s_obj, dict):
        return ValidationResult("yaml_examples", False, "K8s YAML must be a mapping")
    if k8s_obj.get("kind") != "NetworkPolicy":
        return ValidationResult("yaml_examples", False, "K8s YAML kind must be NetworkPolicy")

    spec = k8s_obj.get("spec", {})
    policy_types = spec.get("policyTypes", [])
    if "Egress" not in policy_types:
        return ValidationResult("yaml_examples", False, "K8s YAML policyTypes must include Egress")

    return ValidationResult("yaml_examples", True, "YAML examples parse and satisfy required semantics")


def safe_run(name: str, fn: Callable[[Path], ValidationResult], base_dir: Path) -> ValidationResult:
    try:
        return fn(base_dir)
    except Exception as exc:  # defensive: convert unexpected errors into check failures
        return ValidationResult(name, False, f"Unhandled exception: {type(exc).__name__}: {exc}")


def run_validations(base_dir: Path = DEFAULT_ART) -> list[ValidationResult]:
    check_map: dict[str, Callable[[Path], ValidationResult]] = {
        "presence": validate_presence,
        "manifest_structure": validate_json_manifest,
        "manifest_timestamp": validate_manifest_timestamp,
        "schema_metadata": validate_schema_metadata,
        "schema_contract": validate_manifest_against_schema_contract,
        "schema_constraints": validate_schema_constraints,
        "csv_semantics": validate_csv_headers,
        "rego_guardrails": validate_rego_guardrails,
        "yaml_examples": validate_yaml_examples,
    }

    results: list[ValidationResult] = []
    seen: set[str] = set()
    for name, _desc in CHECK_SEQUENCE:
        if name in seen:
            results.append(ValidationResult(name, False, f"Duplicate check ID in CHECK_SEQUENCE: {name}"))
            continue
        seen.add(name)

        fn = check_map.get(name)
        if fn is None:
            results.append(ValidationResult(name, False, f"No handler registered for check ID: {name}"))
            continue

        results.append(safe_run(name, fn, base_dir))

    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate blueprint artifact starter pack")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON results")
    parser.add_argument("--base-dir", type=str, default=str(DEFAULT_ART), help="Override artifact directory")
    parser.add_argument("--list-checks", action="store_true", help="List stable check IDs and exit")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.list_checks:
        for name, desc in CHECK_SEQUENCE:
            print(f"{name}: {desc}")
        return

    results = run_validations(Path(args.base_dir))
    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        for r in results:
            prefix = "[PASS]" if r.ok else "[FAIL]"
            print(f"{prefix} {r.name}: {r.detail}")

    if any(not r.ok for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
