#!/usr/bin/env python3
"""Static validator for governance blueprint machine-readable artifacts.

Runs dependency-light checks so CI can validate artifacts without requiring
external tooling.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
from typing import Any
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "governance_blueprint"
REPORT_PATH = ROOT / "REGULATOR_READY_AGI_ASI_TECHNICAL_REPORT_2026_2030.md"


_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _path_stays_within_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _load_json(path: Path) -> tuple[Any, list[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except json.JSONDecodeError as exc:
        return None, [f"Invalid JSON in {path.name}: {exc}"]


def _load_json_object(path: Path, *, label: str) -> tuple[dict, list[str]]:
    data, load_errors = _load_json(path)
    if load_errors:
        return {}, load_errors
    if not isinstance(data, dict):
        return {}, [f"{label} must be a JSON object at the top level."]
    return data, []


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
    data, load_errors = _load_json_object(path, label=path.name)
    errors.extend(load_errors)
    if load_errors:
        return errors

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


def validate_compliance_profile() -> list[str]:
    errors: list[str] = []
    path = ARTIFACTS / "compliance_profile_2026.json"
    data, load_errors = _load_json_object(path, label=path.name)
    errors.extend(load_errors)
    if load_errors:
        return errors

    for key in ["profile_id", "version", "framework_mappings", "implementation_strategy"]:
        if key not in data:
            errors.append(f"compliance_profile_2026.json missing key: {key}")

    mappings = data.get("framework_mappings", [])
    if not isinstance(mappings, list) or len(mappings) < 5:
        errors.append("compliance_profile_2026.json must include at least 5 framework mappings.")
        return errors

    required_entry_keys = {"control_id", "control_family", "frameworks", "owner", "implementation", "evidence"}
    for idx, entry in enumerate(mappings, start=1):
        if not isinstance(entry, dict):
            errors.append(f"framework_mappings[{idx}] must be an object")
            continue
        missing = required_entry_keys.difference(entry.keys())
        if missing:
            errors.append(f"framework_mappings[{idx}] missing keys: {sorted(missing)}")

    return errors


def validate_annex_iv_template() -> list[str]:
    errors: list[str] = []
    path = ARTIFACTS / "annex_iv_technical_documentation_template.json"
    data, load_errors = _load_json_object(path, label=path.name)
    errors.extend(load_errors)
    if load_errors:
        return errors

    for key in ["template_id", "version", "sections", "metadata", "evidence_links"]:
        if key not in data:
            errors.append(f"annex_iv template missing key: {key}")

    sections = data.get("sections", [])
    if not isinstance(sections, list) or len(sections) < 8:
        errors.append("annex_iv template must define at least 8 required sections.")

    required_section_ids = {"A", "B", "C", "D", "E", "F", "G", "H"}
    section_ids = {str(s.get("id")) for s in sections if isinstance(s, dict)}
    if not required_section_ids.issubset(section_ids):
        errors.append("annex_iv template is missing one or more section IDs A-H.")

    return errors


def validate_rego_release_gate() -> list[str]:
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
            errors.append(f"release_gate.rego missing expected token: {token}")

    if text.count("allow if") < 3:
        errors.append("release_gate.rego must define at least three allow blocks.")

    return errors


def validate_rego_systemic_guardrails() -> list[str]:
    errors: list[str] = []
    path = ARTIFACTS / "opa" / "systemic_risk_guardrails.rego"
    text = path.read_text(encoding="utf-8")

    expected_tokens = [
        "package aigov.systemic",
        "default allow = false",
        "input.risk_tier >= 4",
        "input.safety_case.approved",
        "input.compute_registry.registered",
        "deny contains msg if",
    ]
    for token in expected_tokens:
        if token not in text:
            errors.append(f"systemic_risk_guardrails.rego missing expected token: {token}")

    if text.count("deny contains msg if") < 3:
        errors.append("systemic_risk_guardrails.rego must define at least three deny blocks.")

    return errors


def validate_yaml_shape() -> list[str]:
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
    expected_phases = ["foundation", "industrialization", "advanced_assurance", "resilience_and_advantage"]
    if phase_names[:4] != expected_phases:
        errors.append(f"YAML roadmap phase order mismatch: expected {expected_phases}, got {phase_names[:4]}")

    workstream_entries = re.findall(r"^\s*-\s+([a-zA-Z0-9_]+)\s*$", text.split("workstreams:")[-1], flags=re.MULTILINE)
    if len(workstream_entries) < 3:
        errors.append("YAML roadmap must define at least 3 workstreams.")

    for ln, line in enumerate(text.splitlines(), start=1):
        if "\t" in line:
            errors.append(f"YAML roadmap has tab indentation at line {ln}; use spaces only.")

    return errors


def validate_rollout_plan() -> list[str]:
    errors: list[str] = []
    path = ARTIFACTS / "rollout_plan_2026_2030.yaml"
    text = path.read_text(encoding="utf-8")

    for token in ["program:", "version:", "phases:", "Phase A", "Phase E", "dependencies:", "exit_criteria:"]:
        if token not in text:
            errors.append(f"rollout_plan_2026_2030.yaml missing expected token: {token}")

    phase_count = len(re.findall(r"^\s*-\s+name:\s+Phase\s+[A-E]", text, flags=re.MULTILINE))
    if phase_count < 5:
        errors.append("rollout_plan_2026_2030.yaml must define at least 5 phases (A-E).")

    return errors


def validate_report_structure() -> list[str]:
    errors: list[str] = []
    if not REPORT_PATH.exists():
        return [f"Missing report file: {REPORT_PATH.name}"]

    text = REPORT_PATH.read_text(encoding="utf-8")
    tag_pairs = [("<title>", "</title>"), ("<abstract>", "</abstract>"), ("<content>", "</content>")]
    for open_tag, close_tag in tag_pairs:
        if text.count(open_tag) != 1 or text.count(close_tag) != 1:
            errors.append(f"Technical report must contain exactly one {open_tag}/{close_tag} pair")
            continue
        if text.index(open_tag) > text.index(close_tag):
            errors.append(f"Technical report has invalid tag order for {open_tag}/{close_tag}")

    required_tokens = [
        "## 2) Integrated Regulatory Compliance Framework Mapping and Implementation",
        "## 3) Institutional-Grade Governance Platform Technical Architecture",
        "## 4) AGI/ASI Safety, Containment, and Crisis Simulation Blueprint",
        "## 5) Civilizational-Scale AI and Compute Governance Mechanisms",
        "## 7) 2026–2030 Dependency-Aware Implementation Roadmap",
        '<section audience="board">',
        '<section audience="regulator">',
        '<section audience="ai_platform_engineers">',
    ]
    for token in required_tokens:
        if token not in text:
            errors.append(f"Technical report missing required token: {token}")

    return errors


def validate_opa_parse_optional(opa_bin_override: str = "", require_opa: bool = False) -> list[str]:
    """Optionally validate Rego syntax if an OPA binary is available.

    Resolution order:
    1) OPA_BIN environment variable
    2) `opa` discovered on PATH
    """
    env_opa = os.getenv("OPA_BIN", "").strip()
    opa_bin = opa_bin_override.strip() or env_opa or shutil.which("opa")
    if not opa_bin:
        if require_opa:
            return ["OPA binary is required but not found. Set --opa-bin or OPA_BIN."]
        return []
    if not Path(opa_bin).exists():
        return [f"OPA_BIN path does not exist: {opa_bin}"]

    errors: list[str] = []
    targets = [ARTIFACTS / "opa" / "release_gate.rego", ARTIFACTS / "opa" / "systemic_risk_guardrails.rego"]
    for target in targets:
        try:
            proc = subprocess.run(
                [opa_bin, "parse", str(target)],
                capture_output=True,
                text=True,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"OPA parse execution failed for {target.name}: {exc}")
            continue
        if proc.returncode != 0:
            stderr = (proc.stderr or proc.stdout).strip()
            errors.append(f"OPA parse failed for {target.name}: {stderr}")
    return errors


def validate_manifest_schema() -> list[str]:
    errors: list[str] = []
    manifest_path = ARTIFACTS / "artifact_manifest.json"
    manifest, load_errors = _load_json_object(manifest_path, label=manifest_path.name)
    if load_errors:
        return load_errors

    required_keys = {"package", "version", "generated_utc", "artifacts", "external_artifacts"}
    missing = required_keys.difference(manifest.keys())
    if missing:
        errors.append(f"artifact_manifest.json missing keys: {sorted(missing)}")

    version = manifest.get("version", "")
    if not isinstance(version, str) or not re.match(r"^\d+\.\d+\.\d+$", version):
        errors.append("artifact_manifest.json version must use semantic version format (x.y.z).")

    generated_utc = manifest.get("generated_utc", "")
    if not isinstance(generated_utc, str) or not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", generated_utc):
        errors.append("artifact_manifest.json generated_utc must be in UTC ISO format YYYY-MM-DDTHH:MM:SSZ.")

    return errors


def validate_manifest_hashes() -> list[str]:
    errors: list[str] = []
    manifest_path = ARTIFACTS / "artifact_manifest.json"
    if not manifest_path.exists():
        return ["artifact_manifest.json not found."]

    manifest, load_errors = _load_json_object(manifest_path, label=manifest_path.name)
    if load_errors:
        return load_errors

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        return ["artifact_manifest.json must contain a non-empty 'artifacts' object."]

    for rel_path, expected_hash in artifacts.items():
        if not isinstance(rel_path, str):
            errors.append(f"Manifest artifact path key must be a string: {rel_path!r}")
            continue
        if not isinstance(expected_hash, str) or not _HEX64_RE.match(expected_hash):
            errors.append(f"Manifest hash for {rel_path} must be a 64-char lowercase hex SHA-256.")
            continue
        if rel_path.startswith("/") or ".." in Path(rel_path).parts:
            errors.append(f"Manifest artifact path is not allowed: {rel_path}")
            continue
        artifact_path = ARTIFACTS / rel_path
        if not _path_stays_within_root(artifact_path, ARTIFACTS):
            errors.append(f"Manifest artifact path escapes artifact root: {rel_path}")
            continue
        if not artifact_path.exists():
            errors.append(f"Manifest references missing file: {rel_path}")
            continue
        actual_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            errors.append(f"Hash mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}")

    external_artifacts = manifest.get("external_artifacts", {})
    if not isinstance(external_artifacts, dict):
        errors.append("artifact_manifest.json 'external_artifacts' must be an object when present.")
        return errors

    for rel_path, expected_hash in external_artifacts.items():
        if not isinstance(rel_path, str):
            errors.append(f"Manifest external artifact path key must be a string: {rel_path!r}")
            continue
        if not isinstance(expected_hash, str) or not _HEX64_RE.match(expected_hash):
            errors.append(f"Manifest external hash for {rel_path} must be a 64-char lowercase hex SHA-256.")
            continue
        if rel_path.startswith("/") or ".." in Path(rel_path).parts:
            errors.append(f"Manifest external artifact path is not allowed: {rel_path}")
            continue
        external_path = ROOT / rel_path
        if not _path_stays_within_root(external_path, ROOT):
            errors.append(f"Manifest external artifact path escapes repository root: {rel_path}")
            continue
        if not external_path.exists():
            errors.append(f"Manifest references missing external file: {rel_path}")
            continue
        actual_hash = hashlib.sha256(external_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            errors.append(f"External hash mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}")

    return errors


def run_checks(*, opa_bin_override: str = "", require_opa: bool = False) -> dict[str, list[str]]:
    checks = {
        "control_mapping_matrix.csv": validate_csv,
        "evidence_event_schema.json": validate_json_schema,
        "compliance_profile_2026.json": validate_compliance_profile,
        "annex_iv_technical_documentation_template.json": validate_annex_iv_template,
        "opa/release_gate.rego": validate_rego_release_gate,
        "opa/systemic_risk_guardrails.rego": validate_rego_systemic_guardrails,
        "roadmap_2026_2030.yaml": validate_yaml_shape,
        "rollout_plan_2026_2030.yaml": validate_rollout_plan,
        "REGULATOR_READY_AGI_ASI_TECHNICAL_REPORT_2026_2030.md": validate_report_structure,
        "artifact_manifest.schema": validate_manifest_schema,
        "opa.parse_optional": (lambda: validate_opa_parse_optional(opa_bin_override, require_opa=require_opa)),
        "artifact_manifest.json": validate_manifest_hashes,
    }

    return {name: fn() for name, fn in checks.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate governance blueprint artifacts.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output for CI integrations.")
    parser.add_argument("--opa-bin", type=str, default="", help="Optional explicit OPA binary path for optional parse checks.")
    parser.add_argument("--require-opa", action="store_true", help="Fail if OPA binary is unavailable for parse checks.")
    args = parser.parse_args()

    results = run_checks(opa_bin_override=args.opa_bin, require_opa=args.require_opa)
    all_errors: list[str] = []
    for name, errors in results.items():
        if errors:
            all_errors.append(f"[{name}]")
            all_errors.extend([f"  - {e}" for e in errors])

    if args.json:
        payload = {"ok": len(all_errors) == 0, "results": results}
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
