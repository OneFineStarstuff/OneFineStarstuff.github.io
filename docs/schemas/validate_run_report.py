#!/usr/bin/env python3
"""Validate governance validation_run_report.json against schema."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from _validation_deps import require_jsonschema


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    raise SystemExit(1)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--report", type=Path, default=Path("docs/schemas/validation_run_report.json"))
    p.add_argument("--schema", type=Path, default=Path("docs/schemas/validation_run_report.schema.json"))
    return p.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_summary_counts(report: dict) -> str | None:
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        return "checks must be a list"

    passed = sum(1 for item in checks if item.get("status") == "pass")
    failed = sum(1 for item in checks if item.get("status") == "fail")

    if "passed_checks" in report and report["passed_checks"] != passed:
        return f"passed_checks mismatch: expected {passed}, got {report['passed_checks']}"
    if "failed_checks" in report and report["failed_checks"] != failed:
        return f"failed_checks mismatch: expected {failed}, got {report['failed_checks']}"
    overall = report.get("overall_status")
    if overall == "pass" and failed > 0:
        return f"overall_status pass is inconsistent with failed checks: {failed}"
    if overall == "fail" and failed == 0 and checks:
        return "overall_status fail is inconsistent with zero failed checks"
    return None


def main() -> None:
    args = parse_args()
    root = args.repo_root.resolve()
    report_path = (root / args.report).resolve()
    schema_path = (root / args.schema).resolve()

    if not report_path.exists():
        fail(f"Validation report file not found: {report_path}")
    if not schema_path.exists():
        fail(f"Validation report schema file not found: {schema_path}")

    try:
        report = load_json(report_path)
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in validation report file {report_path}: {exc}")

    try:
        schema = load_json(schema_path)
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in schema file {schema_path}: {exc}")

    try:
        Draft202012Validator = require_jsonschema()
    except SystemExit as exc:
        fail(str(exc).replace("[FAIL] ", ""))

    errs = sorted(Draft202012Validator(schema).iter_errors(report), key=lambda e: e.path)
    if errs:
        err = errs[0]
        loc = ".".join(str(p) for p in err.absolute_path) or "<root>"
        print(f"[FAIL] Validation report schema failed at {loc}: {err.message}")
        raise SystemExit(1)

    summary_error = validate_summary_counts(report)
    if summary_error:
        print(f"[FAIL] Validation report semantic check failed: {summary_error}")
        raise SystemExit(1)

    print("[OK] Validation run report schema passed")


if __name__ == "__main__":
    main()
