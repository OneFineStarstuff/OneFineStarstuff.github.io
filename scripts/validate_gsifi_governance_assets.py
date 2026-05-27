#!/usr/bin/env python3
"""Lightweight validation for GSIFI governance artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import functools
import importlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/gien-governance-event.schema.json"
SAMPLE_EVENT_PATH = ROOT / "docs/examples/gien_governance_event_sample.json"
REGO_PATH = ROOT / "docs/policies/sentinel-tiered-autonomy.rego"
SR_DSL_PATH = ROOT / "docs/examples/sr_dsl_fairness_regression_v1.txt"

# New G-Stack Artifacts
MASTER_ROADMAP = ROOT / "docs/reports/SENTINEL_G_MASTER_ROADMAP_2026_2035.md"


class ValidationError(RuntimeError):
    """Exception raised when validation fails."""


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValidationError(f"Unable to read file: {path}: {exc}") from exc


def load_json(path: Path) -> dict:
    """Load JSON from a file path."""
    try:
        return json.loads(_read_text(path))
    except json.JSONDecodeError as exc:
        msg = f"Unable to parse JSON: {path}: {exc}"
        raise ValidationError(msg) from exc


def _matches_json_type(value: object, expected_type: str) -> bool:
    types_map = {
        "string": lambda v: isinstance(v, str),
        "boolean": lambda v: isinstance(v, bool),
        "number": lambda v: (isinstance(v, (int, float)) and not isinstance(v, bool)),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "null": lambda v: v is None,
    }
    return types_map.get(expected_type, lambda _: False)(value)


def _validate_type(value: object, expected_type: str | list[str], key: str) -> None:
    expected_types = (
        [expected_type] if isinstance(expected_type, str) else expected_type
    )
    if any(_matches_json_type(value, cand) for cand in expected_types):
        return
    expected_display = ", ".join(expected_types)
    msg = f"Field '{key}' must match JSON Schema type(s): {expected_display}; got '{type(value).__name__}'"
    raise ValidationError(msg)


def _validate_date_time(value: str, key: str) -> None:
    if not value.endswith("Z"):
        raise ValidationError(f"Field '{key}' must be UTC and end with 'Z'")
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        msg = f"Field '{key}' is not valid RFC3339 datetime"
        raise ValidationError(msg) from exc


@functools.lru_cache(maxsize=1)
def _get_jsonschema_validator() -> type | None:
    if importlib.util.find_spec("jsonschema") is None:
        return None
    try:
        jsonschema_module = importlib.import_module("jsonschema")
    except ImportError:
        return None
    return getattr(jsonschema_module, "Draft202012Validator", None)


def _validate_with_jsonschema(schema: dict, sample: dict) -> None:
    validator_type = _get_jsonschema_validator()
    if validator_type is None:
        return
    try:
        validator = validator_type(schema)
        errors = list(validator.iter_errors(sample))
        if errors:
            errors = sorted(errors, key=lambda e: e.path)
            first = errors[0]
            p_str = ".".join(str(p) for p in first.path) or "<root>"
            msg = f"JSON Schema validation failed at {p_str}: {first.message}"
            raise ValidationError(msg)
    except ValidationError:
        raise
    except Exception as exc:
        if "jsonschema" in str(type(exc)):
            msg = f"JSON Schema validation failed: {exc}"
            raise ValidationError(msg) from exc
        raise


def _validate_field(key: str, value: object, prop: dict) -> None:
    expected_type = prop.get("type")
    if expected_type:
        _validate_type(value, expected_type, key)
    enum = prop.get("enum")
    if enum and value not in enum:
        msg = f"Field '{key}' is not in allowed enum: {value}"
        raise ValidationError(msg)
    pattern = prop.get("pattern")
    if pattern and isinstance(value, str) and re.fullmatch(pattern, value) is None:
        raise ValidationError(f"Field '{key}' does not match pattern")
    min_len = prop.get("minLength")
    if min_len is not None and isinstance(value, str) and len(value) < min_len:
        raise ValidationError(f"Field '{key}' shorter than minLength")
    max_len = prop.get("maxLength")
    if max_len is not None and isinstance(value, str) and len(value) > max_len:
        raise ValidationError(f"Field '{key}' longer than maxLength")
    if prop.get("format") == "date-time" and isinstance(value, str):
        _validate_date_time(value, key)


def validate_event_schema_and_sample(
    schema_path: Path = SCHEMA_PATH, sample_path: Path = SAMPLE_EVENT_PATH
) -> None:
    """Validate the event schema and a sample event."""
    schema = load_json(schema_path)
    sample = load_json(sample_path)
    if not isinstance(schema, dict):
        raise ValidationError("Schema root must be a JSON object")
    if not isinstance(sample, dict):
        raise ValidationError("Sample event root must be a JSON object")
    required = schema.get("required", [])
    if not isinstance(required, list):
        raise ValidationError("Schema field 'required' must be a list")
    missing = [k for k in required if k not in sample]
    if missing:
        raise ValidationError(f"Sample event missing required keys: {missing}")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ValidationError("Schema field 'properties' must be an object")
    additional_allowed = schema.get("additionalProperties", True)
    if additional_allowed is False:
        allowed = set(properties.keys())
        extras = [k for k in sample if k not in allowed]
        if extras:
            msg = f"Sample event contains unknown keys: {extras}"
            raise ValidationError(msg)
    for key, value in sample.items():
        _validate_field(key, value, properties.get(key, {}))
    _validate_with_jsonschema(schema, sample)


def validate_rego_policy(rego_path: Path = REGO_PATH) -> None:
    """Validate the Rego policy file."""
    text = _read_text(rego_path)
    required_fragments = [
        "package sentinel.governance",
        "default allow = false",
        "allow if",
        "violation[msg] if",
        "tier_3_requires_dual_authorization",
        "human_override_must_be_available",
    ]
    missing = [frag for frag in required_fragments if frag not in text]
    if missing:
        msg = f"Rego policy missing expected fragments: {missing}"
        raise ValidationError(msg)


def validate_sr_dsl(sr_dsl_path: Path = SR_DSL_PATH) -> None:
    """Validate the SR-DSL file."""
    text = _read_text(sr_dsl_path)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    expected_prefixes = ["TEST ", "SCOPE ", "ASSERT ", "ON_FAIL "]
    if not lines or not lines[0].startswith("TEST "):
        raise ValidationError("SR-DSL must begin with TEST")
    if not any(line.startswith("SCOPE ") for line in lines):
        raise ValidationError("SR-DSL missing SCOPE line")
    if sum(1 for line in lines if line.startswith("ASSERT ")) < 2:
        msg = "SR-DSL should include at least two ASSERT lines"
        raise ValidationError(msg)
    if not any(line.startswith("ON_FAIL ") for line in lines):
        raise ValidationError("SR-DSL missing ON_FAIL line")
    for line in lines:
        if not any(line.startswith(p) for p in expected_prefixes):
            raise ValidationError(f"Unexpected SR-DSL directive: {line}")


def validate_master_roadmap(path: Path = MASTER_ROADMAP) -> None:
    """Validate the Sentinel G Master Roadmap."""
    text = _read_text(path)
    required = [
        "Sentinel G Master Roadmap",
        "Phase 1",
        "Phase 2",
        "Phase 3",
        "Omni-Sentinel",
    ]
    missing = [r for r in required if r not in text]
    if missing:
        raise ValidationError(f"Roadmap missing sections: {missing}")


def validate_blueprints() -> None:
    """Check existence and basic content of technical blueprints and reports."""
    expected = [
        ROOT / "docs/blueprints/AGI_CONTAINMENT_TLA_SPEC.md",
        ROOT / "docs/blueprints/ZK_GSRI_CIRCUIT_DESIGN.md",
        ROOT / "docs/blueprints/KAFKA_PQC_WORM_AUDIT_ARCH.md",
        ROOT / "docs/blueprints/KAFKA_PQC_TOPIC_CONFIG.yaml",
        ROOT / "docs/blueprints/GC_IR_BRIDGE_ARCHITECTURE.md",
        ROOT / "docs/blueprints/WORKFLOWAI_PRO_INTEGRATION.md",
        ROOT / "docs/reports/MULTI_JURISDICTIONAL_REGULATORY_MAPPING_V1.md",
        ROOT / "docs/reports/RED_DAWN_SIM_TEMPLATE_V1.md",
        ROOT / "docs/reports/RED_DAWN_SIM_PLAYBOOK_V1.md",
        ROOT / "docs/reports/GSRI_SYSTEMIC_RISK_REPORT_TEMPLATE.md",
        ROOT / "docs/reports/INSTITUTIONAL_CONTROL_MAPPING_2026.md",
        ROOT / "docs/reports/SENTINEL_G_EXECUTIVE_ACTION_BRIEF_2026.md",
        ROOT / "docs/reports/REGULATOR_PROFILE_TEMPLATE.md",
        ROOT / "docs/reports/G_SRI_METHODOLOGY_V1.md",
        ROOT / "docs/reports/ICGC_PHASE_1_2_CONTROL_REFERENCE.md",
        ROOT / "docs/reports/ASI_CONTAINMENT_INCIDENT_RESPONSE.md",
        ROOT / "docs/reports/G_STACK_ARCHITECTURE_SPEC_V1.md",
        ROOT / "docs/schemas/SENTINEL_CONTROL_CATALOG_OSCAL.yaml",
        ROOT / "docs/schemas/SENTINEL_AGI_SSP_OSCAL.yaml",
        ROOT / "docs/schemas/GAI_SOC_TELEMETRY_SCHEMA.json",
        ROOT / "docs/schemas/SENTINEL_BBOM_V1.schema.json",
        ROOT / "docs/schemas/ZK_COMPLIANCE_PROOF_V1.schema.json",
        ROOT / "docs/examples/gai_soc_telemetry_sample.json",
        ROOT / "docs/examples/sentinel_bbom_sample.json",
        ROOT / "docs/examples/zk_compliance_proof_sample.json",
        ROOT / "docs/policies/gsri-thresholds.rego",
    ]
    for p in expected:
        if not p.exists():
            raise ValidationError(f"Missing governance artifact: {p.name}")

        # Basic YAML/JSON structural check for machine-readable files
        if p.suffix == ".yaml":
            try:
                yaml.safe_load(p.read_text())
            except Exception as exc:
                raise ValidationError(f"Invalid YAML in {p.name}: {exc}")
        elif p.suffix == ".json":
            try:
                json.loads(p.read_text())
            except Exception as exc:
                raise ValidationError(f"Invalid JSON in {p.name}: {exc}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Validate GSIFI assets")
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    parser.add_argument("--sample", type=Path, default=SAMPLE_EVENT_PATH)
    parser.add_argument("--rego", type=Path, default=REGO_PATH)
    parser.add_argument("--srdsl", type=Path, default=SR_DSL_PATH)
    parser.add_argument("--roadmap", type=Path, default=MASTER_ROADMAP)
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    args = parse_args(argv)
    try:
        validate_event_schema_and_sample(args.schema, args.sample)
        validate_rego_policy(args.rego)
        validate_sr_dsl(args.srdsl)
        validate_master_roadmap(args.roadmap)
        validate_blueprints()
    except ValidationError as exc:
        print(f"VALIDATION FAILED: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print("All GSIFI governance artifact checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
