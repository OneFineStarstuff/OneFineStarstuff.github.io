#!/usr/bin/env python3
"""Fail-closed validator for the 2026-11-06 GIEN reconciliation register.

This validator checks the structure and evidence semantics of the reconciliation
record. It does not verify fictional telemetry or any production environment.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTER = (
    ROOT / "docs" / "remediation" / "gien-evidence-conflicts-2026-11-06.json"
)
ALLOWED_EVIDENCE_CLASSES = {
    "SIMULATED",
    "CODE_INSPECTED",
    "OBSERVED",
    "VERIFIED",
    "INDEPENDENTLY_ASSURED",
}
ALLOWED_FINDING_STATUSES = {
    "UNRECONCILED",
    "IMPLEMENTATION_GAP",
    "SIMULATION_ONLY",
    "NOT_REPRODUCED",
    "DESIGN_ONLY",
    "PARTIAL",
}
ALLOWED_SEVERITIES = {"P0", "P1", "P2", "P3"}


class ReconciliationError(ValueError):
    """Raised when a reconciliation record is incomplete or unsafe to release."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReconciliationError(message)


def _parse_utc(value: Any, label: str) -> datetime:
    _require(
        isinstance(value, str) and value.endswith("Z"),
        f"{label} must be UTC ISO-8601 ending in Z",
    )
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReconciliationError(f"{label} is not a valid ISO-8601 timestamp") from exc


def validate_document(data: dict[str, Any]) -> dict[str, Any]:
    """Validate structure, source links, severity/status vocabularies and release posture."""
    _require(isinstance(data, dict), "document must be a JSON object")
    for key in (
        "schema_version",
        "record_id",
        "fictional_simulation",
        "reporting_window",
        "disposition",
        "sources",
        "findings",
    ):
        _require(key in data, f"missing required top-level field: {key}")

    _require(data["schema_version"] == "1.0.0", "unsupported schema_version")
    _require(
        data["record_id"] == "GIEN-EVIDENCE-RECONCILIATION-2026-11-06",
        "unexpected record_id",
    )
    _require(data["fictional_simulation"] is True, "fictional_simulation must be true")

    window = data["reporting_window"]
    _require(isinstance(window, dict), "reporting_window must be an object")
    start = _parse_utc(window.get("start_utc"), "reporting_window.start_utc")
    end = _parse_utc(window.get("end_utc"), "reporting_window.end_utc")
    _require(start < end, "reporting window start must precede end")
    _require(
        (end - start).total_seconds() == 86400,
        "canonical reporting window must be exactly 24 hours",
    )
    _require(
        window.get("status") == "MOST_RECENT_COMPLETED_CANONICAL_WINDOW",
        "reporting window must be marked as the most recent completed canonical window",
    )

    sources = data["sources"]
    findings = data["findings"]
    _require(
        isinstance(sources, list) and bool(sources), "sources must be a non-empty list"
    )
    _require(
        isinstance(findings, list) and bool(findings),
        "findings must be a non-empty list",
    )

    source_ids: set[str] = set()
    for index, source in enumerate(sources):
        _require(isinstance(source, dict), f"sources[{index}] must be an object")
        source_id = source.get("source_id")
        _require(
            isinstance(source_id, str) and bool(source_id.strip()),
            f"sources[{index}] has no source_id",
        )
        _require(source_id not in source_ids, f"duplicate source_id: {source_id}")
        source_ids.add(source_id)
        _require(
            isinstance(source.get("repository_path"), str),
            f"{source_id} missing repository_path",
        )
        _require(
            isinstance(source.get("artifact_sha"), str)
            and bool(source["artifact_sha"]),
            f"{source_id} missing artifact_sha",
        )
        _require(
            source.get("evidence_class") in ALLOWED_EVIDENCE_CLASSES,
            f"{source_id} has unsupported evidence_class",
        )
        if source.get("source_window"):
            _require(
                source["source_window"] == f"{window['start_utc']}/{window['end_utc']}",
                f"{source_id} source_window does not match the reconciliation window",
            )

    finding_ids: set[str] = set()
    unresolved_p0 = 0
    for index, finding in enumerate(findings):
        _require(isinstance(finding, dict), f"findings[{index}] must be an object")
        finding_id = finding.get("finding_id")
        _require(
            isinstance(finding_id, str) and bool(finding_id.strip()),
            f"findings[{index}] has no finding_id",
        )
        _require(finding_id not in finding_ids, f"duplicate finding_id: {finding_id}")
        finding_ids.add(finding_id)
        _require(
            finding.get("severity") in ALLOWED_SEVERITIES,
            f"{finding_id} has unsupported severity",
        )
        _require(
            finding.get("status") in ALLOWED_FINDING_STATUSES,
            f"{finding_id} has unsupported status",
        )
        refs = finding.get("source_ids")
        _require(
            isinstance(refs, list) and bool(refs),
            f"{finding_id} must reference at least one source",
        )
        unknown_refs = sorted(set(refs) - source_ids)
        _require(
            not unknown_refs, f"{finding_id} references unknown sources: {unknown_refs}"
        )
        _require(
            isinstance(finding.get("required_closure"), list)
            and bool(finding["required_closure"]),
            f"{finding_id} needs closure criteria",
        )
        if finding["severity"] == "P0" and finding["status"] == "UNRECONCILED":
            unresolved_p0 += 1

    disposition = data["disposition"]
    _require(isinstance(disposition, dict), "disposition must be an object")
    if unresolved_p0:
        _require(
            disposition.get("external_filing") == "HOLD",
            "unresolved P0 findings require external_filing=HOLD",
        )
        _require(
            disposition.get("release_gate") == "BLOCK",
            "unresolved P0 findings require release_gate=BLOCK",
        )
    _require(
        disposition.get("operational_assurance") == "NOT_ESTABLISHED",
        "operational assurance cannot be promoted by this reconciliation-only validator",
    )

    return {
        "status": "PASS",
        "record_id": data["record_id"],
        "reporting_window": {
            "start_utc": window["start_utc"],
            "end_utc": window["end_utc"],
        },
        "source_count": len(sources),
        "finding_count": len(findings),
        "unresolved_p0_count": unresolved_p0,
        "external_filing": disposition["external_filing"],
        "release_gate": disposition["release_gate"],
        "scope_note": "Register structure validated; no operational telemetry or production control was verified.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_REGISTER,
        help="Path to reconciliation JSON",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable output"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress successful text output"
    )
    args = parser.parse_args(argv)

    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
        report = validate_document(data)
    except (OSError, json.JSONDecodeError, ReconciliationError) as exc:
        payload = {"status": "FAIL", "error": str(exc), "input": str(args.input)}
        print(
            json.dumps(payload, indent=2)
            if args.json
            else f"GIEN reconciliation validation FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    elif not args.quiet:
        print(
            "GIEN reconciliation register: PASS "
            f"({report['source_count']} sources; {report['finding_count']} findings; "
            f"{report['unresolved_p0_count']} unresolved P0)"
        )
        print(
            "External filing remains on HOLD; operational assurance is NOT ESTABLISHED."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
