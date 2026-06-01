#!/usr/bin/env python3
"""Static validator for governance blueprint machine-readable artifacts.

Runs dependency-light checks so CI can validate artifacts without requiring
external tooling (OPA/yq/etc.).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "governance_blueprint"


def _validate_against_min_schema(data: object, schema: dict) -> list[str]:
    """Minimal local schema validator for object/array/string shapes."""
    errors: list[str] = []
    schema_type = schema.get("type")

    if schema_type == "object":
        if not isinstance(data, dict):
            return [f"Expected object, got {type(data).__name__}"]
        required = schema.get("required", [])
        for key in required:
            if key not in data:
                errors.append(f"Missing required key: {key}")
        properties = schema.get("properties", {})
        for key, subschema in properties.items():
            if key in data:
                errors.extend([f"{key}: {e}" for e in _validate_against_min_schema(data[key], subschema)])
        return errors

    if schema_type == "array":
        if not isinstance(data, list):
            return [f"Expected array, got {type(data).__name__}"]
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(data) < min_items:
            errors.append(f"Array has {len(data)} items, expected at least {min_items}")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(data):
                errors.extend([f"[{idx}]: {e}" for e in _validate_against_min_schema(item, item_schema)])
        return errors

    if schema_type == "string":
        if not isinstance(data, str):
            return [f"Expected string, got {type(data).__name__}"]
        min_len = schema.get("minLength")
        if isinstance(min_len, int) and len(data) < min_len:
            errors.append(f"String shorter than minLength={min_len}")
        return errors

    return errors


def validate_csv() -> list[str]:
    errors: list[str] = []
    path = ARTIFACTS / "control_mapping_matrix.csv"
    required_headers = {
        "control_family",
        "control_id",
        "description",
        "eu_ai_act_anchor",
        "nist_ai_rmf_anchor",
        "iso_42001_anchor",
        "financial_anchor",
        "evidence_artifacts",
        "control_owner",
        "review_frequency",
    }

    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            errors.append("CSV has no header row.")
            return errors

        missing = required_headers.difference(reader.fieldnames)
        if missing:
            errors.append(f"CSV missing required headers: {sorted(missing)}")

        rows = list(reader)
        if len(rows) < 5:
            errors.append("CSV must contain at least 5 control rows.")

        for i, row in enumerate(rows, start=2):
            for key in required_headers:
                if not (row.get(key) or "").strip():
                    errors.append(f"CSV row {i} has empty value for '{key}'.")

    return errors


def validate_json_schema() -> list[str]:
    errors: list[str] = []
    path = ARTIFACTS / "evidence_event_schema.json"
    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    required_top_level = {"$schema", "title", "type", "required", "properties"}
    missing = required_top_level.difference(data.keys())
    if missing:
        errors.append(f"JSON schema missing top-level keys: {sorted(missing)}")

    properties = data.get("properties", {})
    for field in [
        "event_id",
        "timestamp_utc",
        "event_type",
        "model_id",
        "model_version",
        "risk_tier",
        "policy_bundle_hash",
        "trace_id",
        "jurisdiction_code",
    ]:
        if field not in properties:
            errors.append(f"JSON schema missing required property definition: {field}")

    return errors


def validate_rego() -> list[str]:
    errors: list[str] = []
    path = ARTIFACTS / "opa" / "release_gate.rego"
    text = path.read_text(encoding="utf-8")

    expected_tokens = [
        "package aigov.release",
        "default allow = false",
        "baseline_requirements",
        "input.risk_tier <= 2",
        "input.risk_tier >= 3",
        "input.risk_tier == 4",
    ]
    for token in expected_tokens:
        if token not in text:
            errors.append(f"Rego policy missing expected token: {token}")

    allow_count = text.count("allow {")
    if allow_count < 3:
        errors.append("Rego policy must define at least three allow blocks.")

    return errors


def validate_yaml_shape() -> list[str]:
    """Structure checks without external YAML parser dependency."""
    errors: list[str] = []
    path = ARTIFACTS / "roadmap_2026_2030.yaml"
    text = path.read_text(encoding="utf-8")

    required_tokens = [
        "program:",
        "version:",
        "horizon:",
        "phases:",
        "workstreams:",
        "name: foundation",
        "name: industrialization",
        "name: advanced_assurance",
        "name: resilience_and_advantage",
    ]
    for token in required_tokens:
        if token not in text:
            errors.append(f"YAML roadmap missing expected token: {token}")

    phase_names = re.findall(r"^\s*-\s+name:\s*([a-zA-Z0-9_]+)\s*$", text, flags=re.MULTILINE)
    expected_phases = [
        "foundation",
        "industrialization",
        "advanced_assurance",
        "resilience_and_advantage",
    ]
    if phase_names[:4] != expected_phases:
        errors.append(f"YAML roadmap phase order mismatch: expected {expected_phases}, got {phase_names[:4]}")

    workstream_entries = re.findall(r"^\s*-\s+([a-zA-Z0-9_]+)\s*$", text.split("workstreams:")[-1], flags=re.MULTILINE)
    if len(workstream_entries) < 3:
        errors.append("YAML roadmap must define at least 3 workstreams.")

    # Lightweight indentation sanity for list entries.
    for ln, line in enumerate(text.splitlines(), start=1):
        if "\t" in line:
            errors.append(f"YAML roadmap has tab indentation at line {ln}; use spaces only.")

    return errors


def validate_manifest_hashes() -> list[str]:
    errors: list[str] = []
    manifest_path = ARTIFACTS / "artifact_manifest.json"
    if not manifest_path.exists():
        return ["artifact_manifest.json not found."]

    with manifest_path.open(encoding="utf-8") as f:
        manifest = json.load(f)

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        return ["artifact_manifest.json must contain a non-empty 'artifacts' object."]

    for rel_path, expected_hash in artifacts.items():
        artifact_path = ARTIFACTS / rel_path
        if not artifact_path.exists():
            errors.append(f"Manifest references missing file: {rel_path}")
            continue
        actual_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            errors.append(
                f"Hash mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}"
            )
    return errors


def validate_systemic_artifacts() -> list[str]:
    errors: list[str] = []
    base = ARTIFACTS / "systemic_artifacts"
    required_files = [
        "README.md",
        "schemas/control_crosswalk.schema.json",
        "schemas/deterministic_replay_manifest.schema.json",
        "ai_system_registry.yaml",
        "control_crosswalk.json",
        "agent_lifecycle_policy.rego",
        "containment_safety_case.jsonld",
        "systemic_risk_bbn_model.bif",
        "crisis_simulation_catalog.yaml",
        "deterministic_replay_manifest.json",
        "regulator_submission_bundle.toml",
    ]
    for rel in required_files:
        path = base / rel
        if not path.exists():
            errors.append(f"Missing systemic artifact: systemic_artifacts/{rel}")
            continue
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            errors.append(f"Systemic artifact is empty: systemic_artifacts/{rel}")
            continue

        if rel in {"control_crosswalk.json", "containment_safety_case.jsonld", "deterministic_replay_manifest.json"}:
            try:
                obj = json.loads(text)
            except json.JSONDecodeError as exc:
                errors.append(f"Invalid JSON in systemic_artifacts/{rel}: {exc}")
                continue
            if rel == "control_crosswalk.json":
                mappings = obj.get("control_mappings")
                if not isinstance(mappings, list) or not mappings:
                    errors.append("control_crosswalk.json must include non-empty control_mappings list.")
                else:
                    for i, item in enumerate(mappings):
                        if not isinstance(item, dict):
                            errors.append(f"control_crosswalk.json mapping {i} must be an object.")
                            continue
                        if not isinstance(item.get("control_id"), str) or not item["control_id"].strip():
                            errors.append(f"control_crosswalk.json mapping {i} missing non-empty control_id.")
                        frameworks = item.get("frameworks")
                        if not isinstance(frameworks, list) or not frameworks:
                            errors.append(f"control_crosswalk.json mapping {i} must include non-empty frameworks array.")
            if rel == "containment_safety_case.jsonld":
                if "@context" not in obj or "claims" not in obj:
                    errors.append("containment_safety_case.jsonld must include @context and claims.")
                elif not isinstance(obj.get("claims"), list) or not obj["claims"]:
                    errors.append("containment_safety_case.jsonld claims must be a non-empty list.")
            if rel == "deterministic_replay_manifest.json":
                required = obj.get("required_artifacts")
                if not isinstance(required, list) or not required:
                    errors.append("deterministic_replay_manifest.json must include non-empty required_artifacts.")
                elif not all(isinstance(v, str) and v.strip() for v in required):
                    errors.append("deterministic_replay_manifest.json required_artifacts entries must be non-empty strings.")
            schema_name = {
                "control_crosswalk.json": "control_crosswalk.schema.json",
                "deterministic_replay_manifest.json": "deterministic_replay_manifest.schema.json",
            }.get(rel)
            if schema_name:
                schema_path = base / "schemas" / schema_name
                if not schema_path.exists():
                    errors.append(f"Missing JSON schema for systemic artifact: systemic_artifacts/schemas/{schema_name}")
                else:
                    try:
                        schema_obj = json.loads(schema_path.read_text(encoding="utf-8"))
                    except json.JSONDecodeError as exc:
                        errors.append(f"Invalid JSON schema in systemic_artifacts/schemas/{schema_name}: {exc}")
                    else:
                        if schema_obj.get("type") != "object":
                            errors.append(f"Schema {schema_name} must declare top-level type=object.")
                        if "required" not in schema_obj:
                            errors.append(f"Schema {schema_name} must include a required array.")
                        else:
                            schema_errors = _validate_against_min_schema(obj, schema_obj)
                            errors.extend(
                                [f"{rel} schema validation: {msg}" for msg in schema_errors]
                            )

        elif rel == "regulator_submission_bundle.toml":
            try:
                obj = tomllib.loads(text)
            except tomllib.TOMLDecodeError as exc:
                errors.append(f"Invalid TOML in systemic_artifacts/{rel}: {exc}")
                continue
            if "jurisdictions" not in obj:
                errors.append("regulator_submission_bundle.toml must define [jurisdictions].")

        else:
            token_requirements = {
                "ai_system_registry.yaml": ["version:", "systems:", "system_id:"],
                "agent_lifecycle_policy.rego": ["package aigov.agent_lifecycle", "allow_deploy"],
                "systemic_risk_bbn_model.bif": ["network", "variable", "probability"],
                "crisis_simulation_catalog.yaml": ["version:", "scenarios:", "id:"],
            }
            for token in token_requirements.get(rel, []):
                if token not in text:
                    errors.append(
                        f"Systemic artifact missing token '{token}': systemic_artifacts/{rel}"
                    )
            if rel == "ai_system_registry.yaml":
                if not re.search(r"^\s*risk_tier:\s*[0-4]\s*$", text, flags=re.MULTILINE):
                    errors.append("ai_system_registry.yaml must include risk_tier in range 0-4.")
                inline_jurisdictions = re.search(
                    r"^\s*jurisdictions:\s*\[[^\]]+\]\s*$", text, flags=re.MULTILINE
                )
                block_jurisdictions = re.search(
                    r"^\s*jurisdictions:\s*$\n(?:\s*-\s*[A-Z]{2,}\s*$)+",
                    text,
                    flags=re.MULTILINE,
                )
                if not inline_jurisdictions and not block_jurisdictions:
                    errors.append(
                        "ai_system_registry.yaml must include jurisdictions as inline or block list."
                    )
            if rel == "crisis_simulation_catalog.yaml":
                if not re.search(r"^\s*frequency:\s*(quarterly|monthly|semiannual|annual)\s*$", text, flags=re.MULTILINE):
                    errors.append(
                        "crisis_simulation_catalog.yaml must declare supported frequency "
                        "(monthly|quarterly|semiannual|annual)."
                    )
            if rel == "agent_lifecycle_policy.rego":
                if "input.risk_tier <= 2" not in text:
                    errors.append("agent_lifecycle_policy.rego must include low-tier deploy rule.")
                if "input.risk_tier >= 3" not in text:
                    errors.append("agent_lifecycle_policy.rego must include high-tier deploy rule.")
                if "input.validation_approved" not in text or "input.safety_case_approved" not in text:
                    errors.append(
                        "agent_lifecycle_policy.rego high-tier deploy rule must require validation and safety approvals."
                    )
    return errors


def run_checks() -> dict[str, list[str]]:
    checks = {
        "control_mapping_matrix.csv": validate_csv,
        "evidence_event_schema.json": validate_json_schema,
        "opa/release_gate.rego": validate_rego,
        "roadmap_2026_2030.yaml": validate_yaml_shape,
        "artifact_manifest.json": validate_manifest_hashes,
        "systemic_artifacts/*": validate_systemic_artifacts,
    }

    results: dict[str, list[str]] = {}
    for name, fn in checks.items():
        results[name] = fn()
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate governance blueprint artifacts.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON output for CI integrations.",
    )
    args = parser.parse_args()

    results = run_checks()
    all_errors: list[str] = []
    for name, errors in results.items():
        if errors:
            all_errors.append(f"[{name}]")
            all_errors.extend([f"  - {e}" for e in errors])

    if args.json:
        payload = {
            "ok": len(all_errors) == 0,
            "results": results,
        }
        print(json.dumps(payload, indent=2))
        return 0 if payload["ok"] else 1

    if all_errors:
        print("Artifact validation failed:")
        print("\n".join(all_errors))
        return 1

    print("Artifact validation passed for all governance blueprint assets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
