#!/usr/bin/env python3
"""Single entrypoint to run governance artifact checks consistently.

Used by CI and local pre-commit hooks to avoid command drift.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATION_DIR = ROOT / "governance_blueprint" / "validation"
MALFORMED_VALIDATOR_JSON_RC = 3
NO_SELFTESTS_DISCOVERED_RC = 4


def _run(cmd: list[str], *, quiet: bool = False, env: dict | None = None) -> int:
    if not quiet:
        print("$", " ".join(cmd))
    completed = subprocess.run(cmd, cwd=ROOT, env=env)
    return completed.returncode


def _selftest_scripts() -> list[str]:
    try:
        git = subprocess.run(
            ["git", "ls-files", "governance_blueprint/validation/selftest_*.py"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if git.returncode == 0:
            paths = [
                line.strip()
                for line in git.stdout.splitlines()
                if line.strip().startswith("governance_blueprint/validation/selftest_")
                and line.strip().endswith(".py")
                and ".." not in Path(line.strip()).parts
            ]
            if paths:
                return sorted(paths)
    except (OSError, subprocess.SubprocessError):
        pass
    return sorted(
        str(p.relative_to(ROOT))
        for p in VALIDATION_DIR.glob("selftest_*.py")
        if p.is_file()
    )


def _is_selftest_step(step: list[str]) -> bool:
    if len(step) < 2:
        return False
    return Path(step[1]).name.startswith("selftest_") and step[1].endswith(".py")


def build_steps(*, json_report: bool, skip_selftest: bool, opa_bin: str = "", require_opa: bool = False) -> list[list[str]]:
    steps: list[list[str]] = [
        [sys.executable, "governance_blueprint/validation/generate_artifact_manifest.py", "--check"],
    ]

    validate_cmd = [sys.executable, "governance_blueprint/validation/validate_artifacts.py"]
    if json_report:
        validate_cmd.append("--json")
    if opa_bin:
        validate_cmd.extend(["--opa-bin", opa_bin])
    if require_opa:
        validate_cmd.append("--require-opa")
    steps.append(validate_cmd)

    steps.append([sys.executable, "governance_blueprint/validation/lint_python_sources.py"])
    steps.append([sys.executable, "governance_blueprint/validation/validate_dashboard_links.py"])

    if not skip_selftest:
        for selftest in _selftest_scripts():
            steps.append([sys.executable, selftest])

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
    parser.add_argument(
        "--opa-bin",
        type=str,
        default="",
        help="Optional explicit path to OPA binary for validator optional parse checks.",
    )
    parser.add_argument(
        "--require-opa",
        action="store_true",
        help="Fail validation if OPA binary is not available.",
    )
    args = parser.parse_args()

    steps = build_steps(
        json_report=bool(args.json_report),
        skip_selftest=args.skip_selftest,
        opa_bin=args.opa_bin,
        require_opa=args.require_opa,
    )
    if not args.skip_selftest:
        has_selftest = any(_is_selftest_step(step) for step in steps)
        if not has_selftest:
            print("No validation selftests were discovered; refusing to continue.")
            if args.suite_report:
                _write_suite_report(
                    Path(args.suite_report),
                    [
                        {
                            "name": "selftest_discovery",
                            "command": ["selftest_discovery"],
                            "returncode": NO_SELFTESTS_DISCOVERED_RC,
                        }
                    ],
                    None,
                )
            return NO_SELFTESTS_DISCOVERED_RC
    step_results: list[dict] = []
    validator_payload: dict | None = None
    first_failure_rc = 0

    for cmd in steps:
        step_name = Path(cmd[1]).name if len(cmd) > 1 else "unknown"

        if args.json_report and "validate_artifacts.py" in cmd[1] and "--json" in cmd:
            report_path = Path(args.json_report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with report_path.open("w", encoding="utf-8") as out:
                env = None
                if args.opa_bin:
                    env = {**os.environ, "OPA_BIN": args.opa_bin}
                completed = subprocess.run(cmd, cwd=ROOT, stdout=out, env=env)
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

        env = None
        if args.opa_bin:
            env = {**os.environ, "OPA_BIN": args.opa_bin}
        rc = _run(cmd, quiet=args.quiet, env=env)
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
