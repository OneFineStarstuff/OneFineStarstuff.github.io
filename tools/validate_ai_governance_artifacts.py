#!/usr/bin/env python3
"""Validate BBOM and ARRE artifacts against repository JSON Schemas."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as exc:  # pragma: no cover
    print(
        "Missing dependency: jsonschema. Install with: "
        "python -m pip install -r requirements-governance.txt"
    )
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
FORMAT_CHECKER = FormatChecker()
VALIDATOR_VERSION = "1.1.0"


class ValidationError(Exception):
    """Raised when a governance artifact fails validation."""


def load_json(path: Path) -> dict:
    """Load JSON from path."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"Failed to parse JSON: {path} ({exc})") from exc


def write_report(report_file: Path, report: Dict[str, Any]) -> None:
    """Write validation report to file."""
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )


def validate_with_schema(data: dict, data_name: str, schema: dict) -> None:
    """Validate data against JSON schema."""
    validator = Draft202012Validator(schema, format_checker=FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        rendered = "; ".join(
            f"path={'/'.join(map(str, err.path)) or '<root>'}: {err.message}"
            for err in errors
        )
        raise ValidationError(f"{data_name} failed schema validation: {rendered}")


def validate_bbom_semantics(data: dict, data_name: str) -> None:
    """Check semantic rules for BBOM."""
    hazard = data.get("hazard_scores", {})
    thresholds = data.get("acceptance_thresholds", {})

    if (
        "max_deception" in thresholds
        and hazard.get("deception", 0) > thresholds["max_deception"]
    ):
        raise ValidationError(f"{data_name} violates max_deception threshold")
    if (
        "max_exfiltration" in thresholds
        and hazard.get("exfiltration", 0) > thresholds["max_exfiltration"]
    ):
        raise ValidationError(f"{data_name} violates max_exfiltration threshold")
    if (
        "max_jailbreak" in thresholds
        and hazard.get("jailbreak", 0) > thresholds["max_jailbreak"]
    ):
        raise ValidationError(f"{data_name} violates max_jailbreak threshold")


def validate_arre_semantics(data: dict, data_name: str) -> None:
    """Check semantic rules for ARRE."""
    period = data.get("period", {})
    try:
        start = date.fromisoformat(period["start"])
        end = date.fromisoformat(period["end"])
    except (KeyError, ValueError) as exc:
        raise ValidationError(f"{data_name} has invalid period date values") from exc

    if end < start:
        raise ValidationError(f"{data_name} has period.end before period.start")

    evidence_hashes = data.get("evidence_hashes", [])
    if len(set(evidence_hashes)) != len(evidence_hashes):
        raise ValidationError(f"{data_name} contains duplicate evidence_hashes")


def collect_artifacts(path: Path) -> list[Path]:
    """Collect all JSON files recursively."""
    if not path.exists():
        return []
    return sorted(path.rglob("*.json"))


def display_path(path: Path) -> str:
    """Get path relative to repo root."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate governance artifacts against JSON Schemas."
    )
    parser.add_argument(
        "--bbom-dir",
        default="artifacts/bbom",
        help="Directory containing BBOM JSON files.",
    )
    parser.add_argument(
        "--arre-dir",
        action="append",
        default=None,
        help="Directory containing ARRE JSON files.",
    )
    parser.add_argument(
        "--report-file",
        default=None,
        help="Optional output path for JSON validation report.",
    )
    return parser.parse_args(argv)


def get_artifact_sets(
    bbom_dir: str, arre_dirs: list[str] | None
) -> tuple[list[Path], list[Path], list[str]]:
    """Resolve artifact directories and collect files."""
    bbom_files = collect_artifacts(ROOT / bbom_dir)
    resolved_arre_dirs = arre_dirs or ["examples/arre", "evidence/arre"]
    arre_files: list[Path] = []
    for arre_dir in resolved_arre_dirs:
        arre_files.extend(collect_artifacts(ROOT / arre_dir))
    return bbom_files, sorted(set(arre_files)), resolved_arre_dirs


def build_summary(
    bbom_files: list[Path],
    arre_files: list[Path],
    bbom_dir: str,
    arre_dirs: list[str],
) -> Dict[str, Any]:
    """Initialize validation summary."""
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "validator_version": VALIDATOR_VERSION,
        "status": "unknown",
        "bbom_dir": bbom_dir,
        "arre_dirs": arre_dirs,
        "bbom_files_discovered": len(bbom_files),
        "arre_files_discovered": len(arre_files),
        "bbom_files_checked": 0,
        "arre_files_checked": 0,
        "passed_files": [],
        "failed_files": [],
        "errors": [],
        "bbom_failed": 0,
        "arre_failed": 0,
        "exit_code": 0,
    }


def validate_file(
    file: Path,
    schema: dict,
    semantic_validator: Callable[[dict, str], None],
    summary: Dict[str, Any],
    counter_key: str,
    failed_counter_key: str,
    errors: list[str],
    label: str,
) -> None:
    """Validate a single artifact file."""
    try:
        data = load_json(file)
        validate_with_schema(data, file.name, schema)
        semantic_validator(data, file.name)
        summary[counter_key] += 1
        summary["passed_files"].append(display_path(file))
        print(f"OK {label}: {display_path(file)}")
    except ValidationError as exc:
        error = str(exc)
        errors.append(error)
        summary["failed_files"].append({"file": display_path(file), "error": error})
        summary[failed_counter_key] += 1


def run_validation(
    bbom_dir: str, arre_dirs: list[str] | None
) -> tuple[list[str], Dict[str, Any]]:
    """Run full validation suite."""
    errors: list[str] = []

    bbom_files, arre_files, resolved_arre_dirs = get_artifact_sets(
        bbom_dir, arre_dirs
    )
    summary = build_summary(bbom_files, arre_files, bbom_dir, resolved_arre_dirs)

    try:
        bbom_schema = load_json(ROOT / "schemas" / "bbom.schema.json")
        arre_schema = load_json(ROOT / "schemas" / "arre_record.schema.json")
    except ValidationError as exc:
        errors.append(str(exc))
        summary["errors"] = errors
        summary["fatal_error"] = "schema_load_failure"
        summary["status"] = "failed"
        summary["exit_code"] = 2
        return errors, summary

    if not bbom_files:
        errors.append(f"No BBOM files found under {bbom_dir}")
    if not arre_files:
        msg = "No ARRE files found under directories: "
        errors.append(msg + ", ".join(resolved_arre_dirs))

    if errors:
        summary["errors"] = errors
        summary["status"] = "failed"
        summary["exit_code"] = 2
        return errors, summary

    for file in bbom_files:
        validate_file(
            file,
            bbom_schema,
            validate_bbom_semantics,
            summary,
            "bbom_files_checked",
            "bbom_failed",
            errors,
            "BBOM",
        )

    for file in arre_files:
        validate_file(
            file,
            arre_schema,
            validate_arre_semantics,
            summary,
            "arre_files_checked",
            "arre_failed",
            errors,
            "ARRE",
        )

    summary["errors"] = errors
    summary["status"] = "passed" if not errors else "failed"
    summary["exit_code"] = 0 if not errors else 2
    return errors, summary


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    args = parse_args(argv)
    errors, summary = run_validation(args.bbom_dir, args.arre_dir)

    if args.report_file:
        write_report(Path(args.report_file), summary)

    if errors:
        for error in errors:
            print(f"VALIDATION FAILED: {error}", file=sys.stderr)
        return 2

    print(
        "All governance artifacts validated successfully "
        "against JSON Schemas and semantic checks."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
