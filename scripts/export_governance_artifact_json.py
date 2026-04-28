#!/usr/bin/env python3
"""Export governance YAML artifact to canonical JSON."""

from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path
import shlex

import yaml

from governance_artifact_constants import DEFAULT_JSON, DEFAULT_YAML

TOOL_VERSION = "1.1.0"


def normalize(value: object) -> object:
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def remediation_command(yaml_rel: str, json_rel: str) -> str:
    cmd = "scripts/export_governance_artifact_json.py --root ."
    cmd += f" --yaml {shlex.quote(yaml_rel)} --json {shlex.quote(json_rel)}"
    return cmd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export governance artifact YAML to JSON")
    parser.add_argument("--root", default=".")
    parser.add_argument("--yaml", default=DEFAULT_YAML, help="YAML artifact path relative to --root")
    parser.add_argument("--json", default=DEFAULT_JSON, help="JSON output path relative to --root")
    parser.add_argument("--verify", action="store_true", help="Check whether JSON output is up to date without writing")
    parser.add_argument("--version", action="version", version=f"export_governance_artifact_json.py {TOOL_VERSION}")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(args.root).resolve()

    yaml_path = root / args.yaml
    json_path = root / args.json

    if not yaml_path.exists():
        fail(f"YAML artifact not found: {yaml_path}")

    data = yaml.safe_load(yaml_path.read_text())
    normalized = normalize(data)
    rendered = json.dumps(normalized, indent=2, sort_keys=True) + "\n"

    if args.verify:
        if not json_path.exists():
            fail(f"JSON artifact not found: {json_path}")
        current = json_path.read_text()
        if current != rendered:
            fail(
                "JSON artifact is stale; run "
                f"{remediation_command(args.yaml, args.json)}"
            )
        print(f"OK: JSON verified {json_path}")
        return

    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(rendered)
    print(f"OK: wrote {json_path}")


if __name__ == "__main__":
    main()
