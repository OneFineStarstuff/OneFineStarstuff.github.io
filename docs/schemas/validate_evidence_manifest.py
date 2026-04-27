#!/usr/bin/env python3
"""Validate evidence bundle manifest structure using JSON Schema."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from _validation_deps import require_jsonschema


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo-root", type=Path, default=Path.cwd(), help="Repository root")
    p.add_argument("--manifest", type=Path, default=Path("docs/schemas/evidence_bundle_manifest.json"), help="Manifest path")
    p.add_argument(
        "--schema",
        type=Path,
        default=Path("docs/schemas/evidence_bundle_manifest.schema.json"),
        help="Manifest schema path",
    )
    return p.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    raise SystemExit(1)


def main() -> None:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    manifest_path = (repo_root / args.manifest).resolve()
    schema_path = (repo_root / args.schema).resolve()

    if not manifest_path.exists():
        fail(f"Manifest file not found: {manifest_path}")
    if not schema_path.exists():
        fail(f"Schema file not found: {schema_path}")

    try:
        manifest = load_json(manifest_path)
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in manifest file {manifest_path}: {exc}")

    try:
        schema = load_json(schema_path)
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in schema file {schema_path}: {exc}")

    try:
        Draft202012Validator = require_jsonschema()
    except SystemExit as exc:
        fail(str(exc).replace("[FAIL] ", ""))

    errors = sorted(Draft202012Validator(schema).iter_errors(manifest), key=lambda e: e.path)
    if errors:
        first = errors[0]
        loc = ".".join(str(x) for x in first.absolute_path) or "<root>"
        print(f"[FAIL] Evidence manifest schema validation failed at {loc}: {first.message}")
        raise SystemExit(1)

    print("[OK] Evidence manifest schema validation passed")


if __name__ == "__main__":
    main()
