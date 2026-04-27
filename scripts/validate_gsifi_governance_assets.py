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

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/gien-governance-event.schema.json"
SAMPLE_EVENT_PATH = ROOT / "docs/examples/gien_governance_event_sample.json"
REGO_PATH = ROOT / "docs/policies/sentinel-tiered-autonomy.rego"
SR_DSL_PATH = ROOT / "docs/examples/sr_dsl_fairness_regression_v1.txt"


class ValidationError(RuntimeError):
    pass


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValidationError(f"Unable to read file: {path}: {exc}") from exc


def load_json(path: Path) -> dict:
    try:
        return json.loads(_read_text(path))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Unable to parse JSON: {path}: {exc}") from exc


def _matches_json_type(value: object, expected_type: str) -> bool:
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "null":
        return value is None
    return False


def _validate_type(value: object, expected_type: str | list[str], key: str) -> None:
    expected_types = [expected_type] if isinstance(expected_type, str) else expected_type
    if any(_matches_json_type(value, candidate) for candidate in expected_types):
        return

    expected_display = ", ".join(expected_types)
    raise ValidationError(
        f"Field '{key}' must match JSON Schema type(s): {expected_display}; "
        f"got '{type(value).__name__}'"
    )


def _validate_date_time(value: str, key: str) -> None:
    if not value.endswith("Z"):
        raise ValidationError(f"Field '{key}' must be UTC and end with 'Z'")
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"Field '{key}' is not valid RFC3339 datetime") from exc

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

    validator = validator_type(schema)
    errors = sorted(validator.iter_errors(sample), key=lambda e: e.path)
    if errors:
        first = errors[0]
        path = ".".join(str(p) for p in first.path) or "<root>"
        raise ValidationError(f"JSON Schema validation failed at {path}: {first.message}")

def validate_event_schema_and_sample(
    schema_path: Path = SCHEMA_PATH,
    sample_path: Path = SAMPLE_EVENT_PATH,
) -> None:
    schema = load_json(schema_path)
    sample = load_json(sample_path)
    if not isinstance(schema, dict):
        raise ValidationError("Schema root must be a JSON object")
    if not isinstance(sample, dict):
        raise ValidationError("Sample event root must be a JSON object")

    _validate_with_jsonschema(schema, sample)

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
            raise ValidationError(f"Sample event contains unknown keys: {extras}")

    for key, value in sample.items():
        prop = properties.get(key, {})

        expected_type = prop.get("type")
        if expected_type:
            _validate_type(value, expected_type, key)

        enum = prop.get("enum")
        if enum and value not in enum:
            raise ValidationError(f"Field '{key}' is not in allowed enum: {value}")

        pattern = prop.get("pattern")
        if pattern and isinstance(value, str) and re.fullmatch(pattern, value) is None:
            raise ValidationError(f"Field '{key}' does not match required pattern")

        min_len = prop.get("minLength")
        if min_len is not None and isinstance(value, str) and len(value) < min_len:
            raise ValidationError(f"Field '{key}' shorter than minLength={min_len}")

        max_len = prop.get("maxLength")
        if max_len is not None and isinstance(value, str) and len(value) > max_len:
            raise ValidationError(f"Field '{key}' longer than maxLength={max_len}")

        if prop.get("format") == "date-time" and isinstance(value, str):
            _validate_date_time(value, key)


def validate_rego_policy(rego_path: Path = REGO_PATH) -> None:
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
        raise ValidationError(f"Rego policy missing expected fragments: {missing}")


def validate_sr_dsl(sr_dsl_path: Path = SR_DSL_PATH) -> None:
    lines = [line.strip() for line in _read_text(sr_dsl_path).splitlines() if line.strip()]
    expected_prefixes = ["TEST ", "SCOPE ", "ASSERT ", "ON_FAIL "]
    if not lines or not lines[0].startswith("TEST "):
        raise ValidationError("SR-DSL must begin with TEST")

    if not any(line.startswith("SCOPE ") for line in lines):
        raise ValidationError("SR-DSL missing SCOPE line")

    if sum(1 for line in lines if line.startswith("ASSERT ")) < 2:
        raise ValidationError("SR-DSL should include at least two ASSERT lines")

    if not any(line.startswith("ON_FAIL ") for line in lines):
        raise ValidationError("SR-DSL missing ON_FAIL line")

    for line in lines:
        if not any(line.startswith(prefix) for prefix in expected_prefixes):
            raise ValidationError(f"Unexpected SR-DSL directive: {line}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate GSIFI governance artifacts")
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    parser.add_argument("--sample", type=Path, default=SAMPLE_EVENT_PATH)
    parser.add_argument("--rego", type=Path, default=REGO_PATH)
    parser.add_argument("--srdsl", type=Path, default=SR_DSL_PATH)
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress success output; failures are still printed to stderr.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        validate_event_schema_and_sample(args.schema, args.sample)
        validate_rego_policy(args.rego)
        validate_sr_dsl(args.srdsl)
    except ValidationError as exc:
        print(f"VALIDATION FAILED: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        print("All GSIFI governance artifact checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
