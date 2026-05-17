#!/usr/bin/env python3
"""Validator for enterprise AI governance artifact package."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError

import yaml

from governance_artifact_constants import (
    DEFAULT_CICD,
    DEFAULT_JSON,
    DEFAULT_MANIFEST,
    DEFAULT_REPORT,
    DEFAULT_SCHEMA,
    DEFAULT_YAML,
    MANIFEST_TRACKED_FILES,
)

TOOL_VERSION = "1.1.0"

REQUIRED_TOP_LEVEL = [
    "meta",
    "pillars",
    "regulatory_alignment",
    "control_stack",
    "cicd_policy_gates",
    "kpis",
    "control_catalog",
    "deterministic_replay_workflow",
]

REQUIRED_CICD_GATES = {
    "code_gate",
    "data_gate",
    "model_gate",
    "risk_gate",
    "compliance_gate",
    "release_gate",
    "runtime_gate",
}


def fail(msg: str) -> None:
    print(f"ERROR: {msg}")
    raise SystemExit(1)


def ensure_exists(path: Path) -> None:
    if not path.exists():
        fail(f"required file missing: {path}")


def load_yaml(path: Path) -> object:
    return yaml.safe_load(path.read_text())


def load_json(path: Path) -> object:
    return json.loads(path.read_text())


def validate_primary_artifact(data: dict) -> None:
    if not isinstance(data, dict):
        fail("artifact root must be a mapping")

    missing = [k for k in REQUIRED_TOP_LEVEL if k not in data]
    if missing:
        fail(f"missing required top-level keys: {missing}")

    if len(data["pillars"]) < 5:
        fail("expected at least 5 pillars")
    if len(data["regulatory_alignment"]) < 5:
        fail("expected at least 5 regulatory alignments")
    if len(data["cicd_policy_gates"]) < 5:
        fail("expected at least 5 CI/CD policy gates")
    if len(data["control_catalog"]) < 3:
        fail("expected at least 3 controls in catalog")
    if len(data["deterministic_replay_workflow"]) < 5:
        fail("deterministic replay workflow too short")

    for i, control in enumerate(data["control_catalog"], start=1):
        for field in ("id", "domain", "requirement", "enforcement", "evidence"):
            if field not in control:
                fail(f"control[{i}] missing field: {field}")

    meta = data["meta"]
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(meta.get("date", ""))):
        fail("meta.date must be ISO format YYYY-MM-DD")


def validate_schema_contract(schema: dict) -> None:
    if not isinstance(schema, dict):
        fail("schema file must be a JSON object")

    required = schema.get("required", [])
    if not isinstance(required, list):
        fail("schema.required must be a list")

    missing = [k for k in REQUIRED_TOP_LEVEL if k not in required]
    if missing:
        fail(f"schema.required missing expected keys: {missing}")


def normalize_for_schema(value: object) -> object:
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: normalize_for_schema(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize_for_schema(v) for v in value]
    return value

def validate_against_schema(schema: dict, artifact: dict) -> None:
    if importlib.util.find_spec("jsonschema") is None:
        fail("jsonschema dependency missing. Install with: pip install -r requirements-dev.txt")

    jsonschema = importlib.import_module("jsonschema")
    exceptions = importlib.import_module("jsonschema.exceptions")

    normalized = normalize_for_schema(artifact)
    try:
        jsonschema.validate(instance=normalized, schema=schema)
    except exceptions.ValidationError as exc:
        fail(f"schema validation failed: {exc.message}")


def validate_cicd_example(manifest: dict) -> None:
    if not isinstance(manifest, dict):
        fail("CI/CD example must be a mapping")

    gates = manifest.get("required_gates", [])
    if not isinstance(gates, list):
        fail("required_gates must be a list")

    gate_names = {item.get("name") for item in gates if isinstance(item, dict)}
    missing = sorted(REQUIRED_CICD_GATES - gate_names)
    if missing:
        fail(f"CI/CD example missing required gates: {missing}")

    export = manifest.get("policy_decision_export", {})
    if export.get("sink") != "kafka":
        fail("policy_decision_export.sink must be kafka")


def validate_report_template(path: Path) -> None:
    text = path.read_text().strip()
    wrapped = f"<root>{text}</root>"
    try:
        root = ET.fromstring(wrapped)
    except ParseError as exc:
        fail(f"report template XML is invalid: {exc}")

    expected = ["title", "abstract", "content"]
    tags = [child.tag for child in root]
    if tags != expected:
        fail(f"report template top-level tags must be {expected}, got {tags}")






def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_manifest(root: Path, manifest_path: Path) -> None:
    manifest = load_json(manifest_path)
    if manifest.get("version") != 1:
        fail("manifest version must be 1")
    if manifest.get("algorithm") != "sha256":
        fail("manifest algorithm must be sha256")

    entries = manifest.get("entries", [])
    if not isinstance(entries, list) or len(entries) == 0:
        fail("manifest entries must be a non-empty list")

    by_path: dict[str, str] = {}
    for entry in entries:
        rel = entry.get("path")
        expected = entry.get("sha256")
        if not rel or not expected:
            fail("manifest entries require path and sha256")
        if rel in by_path:
            fail(f"manifest has duplicate path entry: {rel}")
        by_path[rel] = expected

    expected_paths = sorted(MANIFEST_TRACKED_FILES)
    observed_paths = sorted(by_path.keys())
    if observed_paths != expected_paths:
        fail("manifest entries do not match expected tracked files")

    for rel in expected_paths:
        target = root / rel
        if not target.exists():
            fail(f"manifest references missing file: {rel}")
        actual = sha256_of(target)
        if actual != by_path[rel]:
            fail(f"manifest hash mismatch for {rel}")


def validate_yaml_json_parity(yaml_artifact: dict, json_artifact: dict, artifact_yaml: str, artifact_json: str) -> None:
    normalized_yaml = normalize_for_schema(yaml_artifact)
    if normalized_yaml != json_artifact:
        remediation = (
            "YAML/JSON artifact mismatch: run "
            "scripts/export_governance_artifact_json.py --root . "
            f"--yaml {shlex.quote(artifact_yaml)} --json {shlex.quote(artifact_json)}"
        )
        fail(remediation)


def validate_package(root: Path, artifact_yaml: str, artifact_json: str, schema_file: str, cicd_manifest: str, report_template: str, manifest_file: str, skip_manifest: bool) -> None:
    artifact_path = root / artifact_yaml
    json_artifact_path = root / artifact_json
    schema_path = root / schema_file
    cicd_path = root / cicd_manifest
    report_path = root / report_template
    manifest_path = root / manifest_file

    required_paths = [artifact_path, json_artifact_path, schema_path, cicd_path, report_path]
    if not skip_manifest:
        required_paths.append(manifest_path)
    for path in required_paths:
        ensure_exists(path)

    artifact = load_yaml(artifact_path)
    json_artifact = load_json(json_artifact_path)
    schema = load_json(schema_path)
    cicd = load_yaml(cicd_path)

    if not skip_manifest:
        validate_manifest(root, manifest_path)
    validate_primary_artifact(artifact)
    validate_yaml_json_parity(artifact, json_artifact, artifact_yaml, artifact_json)
    validate_schema_contract(schema)
    validate_against_schema(schema, artifact)
    validate_cicd_example(cicd)
    validate_report_template(report_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate governance artifact package")
    parser.add_argument("--root", default=".", help="Repository root path")
    parser.add_argument("--yaml", default=DEFAULT_YAML, help="YAML artifact path relative to --root")
    parser.add_argument("--json", default=DEFAULT_JSON, help="JSON artifact path relative to --root")
    parser.add_argument("--schema", default=DEFAULT_SCHEMA, help="Schema path relative to --root")
    parser.add_argument("--cicd", default=DEFAULT_CICD, help="CI/CD manifest path relative to --root")
    parser.add_argument("--report", default=DEFAULT_REPORT, help="Report template path relative to --root")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST, help="Manifest path relative to --root")
    parser.add_argument("--skip-manifest", action="store_true", help="Skip manifest hash validation")
    parser.add_argument("--version", action="version", version=f"validate_governance_artifact.py {TOOL_VERSION}")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(args.root).resolve()
    validate_package(root, args.yaml, args.json, args.schema, args.cicd, args.report, args.manifest, args.skip_manifest)
    print("OK: enterprise AI governance package validation passed")


if __name__ == "__main__":
    main()
