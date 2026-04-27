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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "governance_blueprint"


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


def run_checks() -> dict[str, list[str]]:
    checks = {
        "control_mapping_matrix.csv": validate_csv,
        "evidence_event_schema.json": validate_json_schema,
        "opa/release_gate.rego": validate_rego,
        "roadmap_2026_2030.yaml": validate_yaml_shape,
        "artifact_manifest.json": validate_manifest_hashes,
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
