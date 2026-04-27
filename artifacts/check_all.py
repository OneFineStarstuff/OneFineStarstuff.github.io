"""Unified artifact integrity + semantic validation entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

if __package__ in (None, ""):
    from build_manifest import build_manifest_payload
    from validate_artifacts import ValidationError, load_json, run_validation
else:
    from .build_manifest import build_manifest_payload
    from .validate_artifacts import ValidationError, load_json, run_validation


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run all artifact checks")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    return parser.parse_args()


def run_all() -> dict:
    from pathlib import Path

    generated = build_manifest_payload()
    existing = load_json(Path(__file__).resolve().parent / "artifact-manifest-v1.json")
    manifest_fresh = existing.get("version") == generated.get("version") and existing.get("files") == generated.get("files")

    validation_checks = run_validation(include_manifest=True)
    validation_ok = all(status == "pass" for status in validation_checks.values())

    errors: list[str] = []
    if not manifest_fresh:
        errors.append("manifest_not_fresh")
    if not validation_ok:
        errors.append("validation_checks_not_all_pass")

    return {
        "schema_version": "1.0",
        "checked_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "manifest_fresh": manifest_fresh,
        "validation_ok": validation_ok,
        "validation_checks": validation_checks,
        "errors": errors,
        "status": "ok" if not errors else "error",
    }


def run_cli(args: argparse.Namespace) -> int:
    try:
        result = run_all()
    except (ValidationError, ValueError, OSError, KeyError, TypeError) as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, indent=2, sort_keys=True))
        else:
            print(f"Checks failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("All checks passed." if result["status"] == "ok" else f"Checks failed: {', '.join(result['errors'])}")

    return 0 if result["status"] == "ok" else 1


def main() -> None:
    args = parse_args()
    raise SystemExit(run_cli(args))


if __name__ == "__main__":
    main()
