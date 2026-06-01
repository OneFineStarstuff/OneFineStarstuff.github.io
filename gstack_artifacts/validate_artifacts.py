#!/usr/bin/env python3
"""Validate G-Stack artifact pack structure and core semantics."""
from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime, timezone
import sys
from pathlib import Path
from typing import Iterable

try:
    import yaml
except Exception:
    yaml = None

try:
    from jsonschema import Draft202012Validator
except Exception:
    Draft202012Validator = None

REQUIRED_CONTROL_FIELDS = {"id", "layer", "title", "requirement", "mappings", "evidence"}
REQUIRED_MATRIX_COLUMNS = {
    "scenario_id",
    "scenario_name",
    "trigger_class",
    "severity",
    "target_layer",
    "pass_criteria",
    "owner",
}
CONTROL_ID_RE = re.compile(r"^[A-Z]+-[A-Z]+-\d{3}$")
SCENARIO_ID_RE = re.compile(r"^S-\d{2}$")
MAPPING_PREFIXES = ("ISO", "NIST", "GDPR", "EUAIA", "SR11-7", "Basel")
ALLOWED_SEVERITIES = {"T1", "T2", "T3", "T4"}
REQUIRED_TEMPLATE_MARKERS = [
    "## 1. Model/System Identification",
    "## 3. Control Attestations",
    "## 5. Compliance Crosswalk Status",
    "## 6. Signatures",
]


class ValidationError(RuntimeError):
    """Raised when an artifact validation check fails."""


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise ValidationError(msg)


def _validate_catalog_schema(payload: dict, schema_path: Path, strict_schema: bool) -> None:
    _assert(schema_path.exists(), f"Missing file: {schema_path}")
    if Draft202012Validator is None:
        _assert(not strict_schema, "jsonschema not installed; strict schema mode requires jsonschema")
        return
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.path))
    if errors:
        raise ValidationError(f"control catalog schema violation: {errors[0].message}")


def validate_catalog(path: Path, schema_path: Path, strict_schema: bool = False) -> None:
    _assert(path.exists(), f"Missing file: {path}")
    _assert(yaml is not None, "PyYAML not installed; cannot parse YAML")

    payload = yaml.safe_load(path.read_text())
    _assert(isinstance(payload, dict), "Control catalog root must be a mapping")
    _validate_catalog_schema(payload, schema_path, strict_schema)

    controls = payload.get("controls")
    _assert(isinstance(controls, list) and controls, "controls must be a non-empty list")

    seen_ids: set[str] = set()
    for i, control in enumerate(controls, start=1):
        _assert(isinstance(control, dict), f"control #{i} must be a mapping")
        missing = REQUIRED_CONTROL_FIELDS - set(control.keys())
        _assert(not missing, f"control #{i} missing keys: {sorted(missing)}")
        control_id = str(control["id"])
        _assert(CONTROL_ID_RE.match(control_id) is not None, f"invalid control id format: {control_id}")
        _assert(control_id not in seen_ids, f"duplicate control id: {control_id}")
        seen_ids.add(control_id)
        mappings = control.get("mappings", [])
        _assert(
            all(isinstance(m, str) and m.startswith(MAPPING_PREFIXES) for m in mappings),
            f"control {control_id} has invalid mapping prefix",
        )


def validate_matrix(path: Path) -> None:
    _assert(path.exists(), f"Missing file: {path}")

    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        header = set(reader.fieldnames or [])
        missing = REQUIRED_MATRIX_COLUMNS - header
        _assert(not missing, f"stress matrix missing columns: {sorted(missing)}")
        rows = list(reader)

    _assert(len(rows) >= 5, "stress test matrix must contain at least 5 scenarios")

    seen_ids: set[str] = set()
    for row in rows:
        sid = row.get("scenario_id", "")
        _assert(sid, "scenario_id cannot be empty")
        _assert(SCENARIO_ID_RE.match(sid) is not None, f"invalid scenario_id format: {sid}")
        _assert(sid not in seen_ids, f"duplicate scenario_id: {sid}")
        seen_ids.add(sid)
        sev = row.get("severity", "")
        _assert(sev in ALLOWED_SEVERITIES, f"invalid severity: {sev}")


def validate_template(path: Path) -> None:
    _assert(path.exists(), f"Missing file: {path}")
    text = path.read_text()
    missing = [m for m in REQUIRED_TEMPLATE_MARKERS if m not in text]
    _assert(not missing, f"template missing marker(s): {missing}")
    positions = [text.find(m) for m in REQUIRED_TEMPLATE_MARKERS]
    _assert(positions == sorted(positions), "template markers are out of required order")


def validate_artifact_pack(root: Path, strict_schema: bool = False) -> None:
    validate_catalog(root / "gstack_control_catalog.yaml", root / "schemas" / "control_catalog.schema.json", strict_schema=strict_schema)
    validate_matrix(root / "stress_test_matrix.csv")
    validate_template(root / "lifecycle_integrity_report_template.md")


def parse_args(argv: Iterable[str]) -> tuple[Path, bool, bool, Path | None]:
    parser = argparse.ArgumentParser(description="Validate G-Stack artifact pack")
    parser.add_argument("--root", "-r", default=Path(__file__).resolve().parent, type=Path, help="Artifact directory path")
    parser.add_argument("--strict-schema", action="store_true", help="Fail if jsonschema dependency is unavailable")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON result")
    parser.add_argument("--report-path", type=Path, default=None, help="Optional path to write JSON output")
    args = parser.parse_args(list(argv))
    return args.root.resolve(), bool(args.strict_schema), bool(args.json), args.report_path


def main(argv: Iterable[str] | None = None) -> int:
    root, strict_schema, as_json, report_path = parse_args(list(argv if argv is not None else sys.argv[1:]))
    timestamp = datetime.now(timezone.utc).isoformat()
    validator_version = "1.0"
    try:
        validate_artifact_pack(root, strict_schema=strict_schema)
    except ValidationError as exc:
        if as_json:
            payload = {"status":"failed","error":str(exc),"root":str(root),"strict_schema":strict_schema,"timestamp":timestamp,"validator_version":validator_version}
            text = json.dumps(payload)
            print(text)
            if report_path is not None:
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(text + "\n")
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if as_json:
        payload = {"status":"passed","root":str(root),"strict_schema":strict_schema,"timestamp":timestamp,"validator_version":validator_version}
        text = json.dumps(payload)
        print(text)
        if report_path is not None:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(text + "\n")
    else:
        print("OK: all G-Stack artifacts validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
