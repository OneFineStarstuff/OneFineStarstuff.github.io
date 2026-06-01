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
MASTER_REFERENCE_DOC = ROOT / "ENTERPRISE_AGI_ASI_GOVERNANCE_MASTER_REFERENCE_2026_2035.md"


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


def validate_roadmap_2035_shape() -> list[str]:
    errors: list[str] = []
    path = ARTIFACTS / "roadmap_2026_2035.yaml"
    text = path.read_text(encoding="utf-8")

    required_tokens = [
        "program:",
        "horizon:",
        "segments:",
        "phase_0_foundation",
        "phase_4_supervisory_interoperability",
        "extension:",
        "period: 2035",
    ]
    for token in required_tokens:
        if token not in text:
            errors.append(f"YAML 2035 roadmap missing expected token: {token}")

    segment_names = re.findall(r"^\s*-\s+name:\s*([a-zA-Z0-9_]+)\s*$", text, flags=re.MULTILINE)
    expected = [
        "phase_0_foundation",
        "phase_1_policy_spec_industrialization",
        "phase_2_containment_perpetual_assurance",
        "phase_3_prudential_stress",
        "phase_4_supervisory_interoperability",
    ]
    if segment_names[:5] != expected:
        errors.append(f"YAML 2035 roadmap segment order mismatch: expected {expected}, got {segment_names[:5]}")
    if len(segment_names) != len(set(segment_names)):
        errors.append("YAML 2035 roadmap contains duplicate segment names.")

    # Lightweight semantic checks to ensure horizon and key thresholds are present.
    semantic_tokens = [
        "start: 2026-07-01",
        "end: 2035-12-31",
        "critical_breach_mttc_seconds_max: 90",
        "supervisory_requests_via_api_pct: 95",
        "manual_dossier_assembly_pct_max: 5",
    ]
    for token in semantic_tokens:
        if token not in text:
            errors.append(f"YAML 2035 roadmap missing required semantic token: {token}")

    return errors


def validate_regulatory_mapping_csv() -> list[str]:
    errors: list[str] = []
    path = ARTIFACTS / "regulatory_playbook_mapping_2026_2035.csv"
    required_headers = {
        "framework",
        "obligation",
        "control_family",
        "evidence_artifact",
        "automation_mechanism",
    }

    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return ["Regulatory playbook CSV has no header row."]

        missing = required_headers.difference(reader.fieldnames)
        if missing:
            errors.append(f"Regulatory playbook CSV missing required headers: {sorted(missing)}")

        rows = list(reader)
        if len(rows) < 10:
            errors.append("Regulatory playbook CSV must contain at least 10 mappings.")
        seen_frameworks: set[str] = set()
        for i, row in enumerate(rows, start=2):
            for key in required_headers:
                if not (row.get(key) or "").strip():
                    errors.append(f"Regulatory playbook CSV row {i} has empty '{key}'.")
            framework = (row.get("framework") or "").strip()
            if framework:
                seen_frameworks.add(framework)

        expected_frameworks = {
            "eu ai act annex iv",
            "nist ai rmf 1.0",
            "iso iec 42001 aims",
            "basel iii iv",
            "uk smcr",
            "icgc compute governance",
        }
        normalized_seen = {value.casefold() for value in seen_frameworks}
        missing_frameworks = sorted(expected_frameworks.difference(normalized_seen))
        if missing_frameworks:
            errors.append(
                f"Regulatory playbook CSV missing required framework mappings: {missing_frameworks}"
            )
    return errors


def validate_master_reference_markdown() -> list[str]:
    errors: list[str] = []
    if not MASTER_REFERENCE_DOC.exists():
        return [f"Master reference document not found: {MASTER_REFERENCE_DOC.name}"]

    text = MASTER_REFERENCE_DOC.read_text(encoding="utf-8")
    required_patterns = {
        "document title (2026–2035 scope)": r"^#\s+Enterprise AGI/ASI Governance Implementation Roadmap.*2035\)\s*$",
        "phase roadmap section": r"^##\s+2\)\s+Phased Roadmap.*2031.?2035.*$",
        "formal verification section": r"^##\s+4\)\s+Formal Verification and Policy-as-Code Conformance\s*$",
        "regulatory mapping section": r"^##\s+9\)\s+Regulatory Mapping Playbooks.*$",
        "KPI targets section": r"^##\s+11\)\s+Quantitative KPI Targets\s*$",
    }
    for label, pattern in required_patterns.items():
        if not re.search(pattern, text, flags=re.MULTILINE):
            errors.append(f"Master reference missing required section: {label}")
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
        "roadmap_2026_2035.yaml": validate_roadmap_2035_shape,
        "regulatory_playbook_mapping_2026_2035.csv": validate_regulatory_mapping_csv,
        "ENTERPRISE_AGI_ASI_GOVERNANCE_MASTER_REFERENCE_2026_2035.md": validate_master_reference_markdown,
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
