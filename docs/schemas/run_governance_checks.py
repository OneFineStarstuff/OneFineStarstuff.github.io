#!/usr/bin/env python3
"""Run governance checks and emit a machine-readable validation report."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COMMANDS = [
    "make --no-print-directory governance-validate",
    "make --no-print-directory governance-artifact-inventory",
    "make --no-print-directory governance-policy-test",
    "make --no-print-directory governance-validator-test",
    "make --no-print-directory governance-evidence-manifest",
    "make --no-print-directory governance-evidence-verify",
    "make --no-print-directory governance-evidence-schema",
    "make --no-print-directory governance-report-schema",
    "make --no-print-directory governance-check-generated",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--output",
        type=Path,
        default=Path("docs/schemas/validation_run_report.json"),
        help="Output path for generated run report",
    )
    p.add_argument("--include-timestamp", action="store_true", help="Include generated_at_utc timestamp")
    p.add_argument(
        "--command",
        action="append",
        dest="commands",
        help="Override default command list by specifying one or more shell commands",
    )
    p.add_argument("--max-tail-chars", type=int, default=2000, help="Max stdout/stderr tail captured per command")
    p.add_argument("--timeout-seconds", type=int, default=300, help="Max runtime per command before timeout")
    p.add_argument("--continue-on-failure", action="store_true", help="Run all commands even after failures")
    return p.parse_args()


def sanitize_output(text: str, repo_root: Path) -> str:
    """Redact absolute repository path for deterministic output."""
    text = text.replace(str(repo_root), "$REPO_ROOT")
    return normalize_nondeterministic_text(text)


def normalize_nondeterministic_text(text: str) -> str:
    """Normalize known variable timing substrings for deterministic reports."""
    return re.sub(r"Ran (\d+) tests in [0-9.]+s", r"Ran \1 tests in <redacted>s", text)


def tail_with_marker(text: str, max_chars: int) -> str:
    """Return tail of text with a deterministic truncation marker when clipped."""
    if len(text) <= max_chars:
        return text
    clipped = text[-max_chars:]
    return f"[truncated {len(text) - max_chars} chars]\n{clipped}"


def main() -> None:
    args = parse_args()
    commands = args.commands if args.commands else DEFAULT_COMMANDS

    report: dict[str, object] = {
        "checks": [],
        "overall_status": "pass",
    }

    if args.include_timestamp:
        report["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    checks: list[dict[str, object]] = []
    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=False,
                cwd=REPO_ROOT,
                timeout=args.timeout_seconds,
            )
            status = "pass" if proc.returncode == 0 else "fail"
            return_code = proc.returncode
            timed_out = False
            stdout_text = proc.stdout
            stderr_text = proc.stderr
        except subprocess.TimeoutExpired as exc:
            status = "fail"
            return_code = -1
            timed_out = True
            stdout_text = exc.stdout or ""
            stderr_text = (exc.stderr or "") + f"\n[timeout] command exceeded {args.timeout_seconds}s"

        checks.append(
            {
                "command": cmd,
                "status": status,
                "return_code": return_code,
                "stdout_tail": sanitize_output(tail_with_marker(stdout_text, args.max_tail_chars), REPO_ROOT),
                "stderr_tail": sanitize_output(tail_with_marker(stderr_text, args.max_tail_chars), REPO_ROOT),
                "timed_out": timed_out,
            }
        )
        if status == "fail":
            report["overall_status"] = "fail"
            if not args.continue_on_failure:
                break

    report["checks"] = checks

    passed_checks = sum(1 for item in checks if item["status"] == "pass")
    failed_checks = sum(1 for item in checks if item["status"] == "fail")
    report["passed_checks"] = passed_checks
    report["failed_checks"] = failed_checks

    out = args.output if args.output.is_absolute() else (REPO_ROOT / args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[OK] Validation run report written: {out}")

    if report["overall_status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
