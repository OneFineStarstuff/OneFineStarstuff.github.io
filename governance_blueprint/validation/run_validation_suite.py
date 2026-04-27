#!/usr/bin/env python3
"""Single entrypoint to run governance artifact checks consistently.

Used by CI and local pre-commit hooks to avoid command drift.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MALFORMED_VALIDATOR_JSON_RC = 3


def _run(cmd: list[str], *, quiet: bool = False) -> int:
    if not quiet:
        print("$", " ".join(cmd))
    completed = subprocess.run(cmd, cwd=ROOT)
    return completed.returncode


def build_steps(*, json_report: bool, skip_selftest: bool) -> list[list[str]]:
    steps: list[list[str]] = [
        [sys.executable, "governance_blueprint/validation/generate_artifact_manifest.py", "--check"],
    ]

    if json_report:
        steps.append(
            [
                sys.executable,
                "governance_blueprint/validation/validate_artifacts.py",
                "--json",
            ]
        )
    else:
        steps.append([sys.executable, "governance_blueprint/validation/validate_artifacts.py"])

    steps.append([sys.executable, "governance_blueprint/validation/lint_python_sources.py"])
    steps.append([sys.executable, "governance_blueprint/validation/validate_dashboard_links.py"])

    if not skip_selftest:
        steps.append([sys.executable, "governance_blueprint/validation/selftest_validate_artifacts.py"])
        steps.append([sys.executable, "governance_blueprint/validation/selftest_run_validation_suite.py"])

    return steps


def _write_suite_report(path: Path, step_results: list[dict], validator_report: dict | None) -> None:
    payload = {
        "ok": all(step["returncode"] == 0 for step in step_results),
        "generated_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "steps": step_results,
        "validator_report": validator_report,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json-report",
        type=str,
        default="",
        help="Optional output path for validator JSON report.",
    )
    parser.add_argument(
        "--suite-report",
        type=str,
        default="",
        help="Optional output path for full suite execution report JSON.",
    )
    parser.add_argument(
        "--skip-selftest",
        action="store_true",
        help="Skip validator self-tests (not recommended).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-step command echo output.",
    )
    parser.add_argument(
        "--no-fail-fast",
        action="store_true",
        help="Continue running remaining steps after a failure and return the first non-zero code.",
    )
    args = parser.parse_args()

    steps = build_steps(json_report=bool(args.json_report), skip_selftest=args.skip_selftest)
    step_results: list[dict] = []
    validator_payload: dict | None = None
    first_failure_rc = 0

    for cmd in steps:
        step_name = Path(cmd[1]).name if len(cmd) > 1 else "unknown"

        if args.json_report and cmd[-1] == "--json":
            report_path = Path(args.json_report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with report_path.open("w", encoding="utf-8") as out:
                completed = subprocess.run(cmd, cwd=ROOT, stdout=out)
            rc = completed.returncode
            if rc == 0:
                try:
                    validator_payload = json.loads(report_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    rc = MALFORMED_VALIDATOR_JSON_RC
                    print("Validator JSON report is malformed.")
            step_results.append({"name": step_name, "command": cmd, "returncode": rc})
            if rc != 0:
                if first_failure_rc == 0:
                    first_failure_rc = rc
                if not args.no_fail_fast:
                    if args.suite_report:
                        _write_suite_report(Path(args.suite_report), step_results, validator_payload)
                    return rc
            continue

        rc = _run(cmd, quiet=args.quiet)
        step_results.append({"name": step_name, "command": cmd, "returncode": rc})
        if rc != 0:
            if first_failure_rc == 0:
                first_failure_rc = rc
            if not args.no_fail_fast:
                if args.suite_report:
                    _write_suite_report(Path(args.suite_report), step_results, validator_payload)
                return rc

    if first_failure_rc != 0:
        if args.suite_report:
            _write_suite_report(Path(args.suite_report), step_results, validator_payload)
        return first_failure_rc

    if not args.quiet:
        print("Governance validation suite passed.")
    if args.suite_report:
        _write_suite_report(Path(args.suite_report), step_results, validator_payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
