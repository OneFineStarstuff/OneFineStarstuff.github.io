#!/usr/bin/env python3
"""Validate board AI roadmap artifact against JSON schema.

Uses `jsonschema` when available. If unavailable, falls back to a minimal
built-in validator that checks required structural constraints.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_SCHEMA_PATH = ROOT / "schemas" / "board-ai-roadmap-schema-v1.json"
DEFAULT_DATA_PATH = ROOT / "data" / "board-ai-roadmap-2026-2030.json"

REQUIRED_TOP_LEVEL = {
    "schema_version",
    "program",
    "financials",
    "domains",
    "jurisdictions",
    "stage_gates",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate board AI roadmap artifact against schema."
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help="Path to JSON schema file.",
    )
    parser.add_argument(
        "--data",
        type=Path,
        default=DEFAULT_DATA_PATH,
        help="Path to roadmap data JSON file.",
    )
    return parser.parse_args()


def _fallback_validate(data: dict) -> None:
    missing = REQUIRED_TOP_LEVEL - set(data)
    if missing:
        raise ValueError(f"missing required keys: {sorted(missing)}")

    if data.get("schema_version") != "board-ai-roadmap-v1":
        raise ValueError("schema_version must be board-ai-roadmap-v1")

    period = data.get("program", {}).get("period")
    if not isinstance(period, str) or not re.match(r"^\d{4}-\d{4}$", period):
        raise ValueError("program.period must match YYYY-YYYY")

    if not isinstance(data.get("domains"), list) or not data["domains"]:
        raise ValueError("domains must be a non-empty array")

    jurisdictions = data.get("jurisdictions")
    for key in ("US", "EU", "UK", "APAC"):
        if not isinstance(jurisdictions, dict) or key not in jurisdictions:
            raise ValueError("jurisdictions must include US, EU, UK, APAC")

    stage_gates = data.get("stage_gates")
    if not isinstance(stage_gates, list) or not stage_gates:
        raise ValueError("stage_gates must be a non-empty array")
    for idx, gate in enumerate(stage_gates):
        if not isinstance(gate, dict):
            raise ValueError(f"stage_gates[{idx}] must be an object")
        for field in ("gate", "target", "focus"):
            if field not in gate:
                raise ValueError(f"stage_gates[{idx}] missing field: {field}")
        target = gate.get("target")
        if not isinstance(target, str) or not re.match(r"^\d{4}-Q[1-4]$", target):
            raise ValueError(f"stage_gates[{idx}].target must match YYYY-QN")


def validate(schema_path: Path, data_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    data = json.loads(data_path.read_text(encoding="utf-8"))

    try:
        import jsonschema  # type: ignore

        jsonschema.validate(instance=data, schema=schema)
    except ModuleNotFoundError:
        _fallback_validate(data)


def main() -> int:
    args = parse_args()
    try:
        validate(args.schema, args.data)
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"Board AI roadmap artifact validation failed: {exc}", file=sys.stderr)
        return 1

    print("Board AI roadmap artifact validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
