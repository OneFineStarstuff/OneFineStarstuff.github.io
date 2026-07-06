#!/usr/bin/env python3
"""Validate an Omni-Sentinel daily DevSecOps evidence bundle."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "schemas"))
from _validation_deps import require_jsonschema  # noqa: E402


CONTROL_NAMES = (
    "sentinel_telemetry",
    "internal_endpoints",
    "g_sri",
    "worm_audit",
    "tee_attestation",
    "tpm_attestation",
    "zk_compliance",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root used to resolve relative paths.",
    )
    parser.add_argument(
        "--bundle",
        type=Path,
        default=Path("docs/operations/examples/daily_devsecops_evidence_2026-05-29.json"),
        help="Daily evidence bundle JSON file.",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("docs/operations/daily_devsecops_evidence.schema.json"),
        help="Daily evidence bundle JSON Schema file.",
    )
    parser.add_argument(
        "--allow-evidence-required",
        action="store_true",
        help="Allow evidence_required controls for dry-run/template bundles.",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def fail(message: str) -> None:
    print(f"[FAIL] {message}")
    raise SystemExit(1)


def resolve(repo_root: Path, path: Path) -> Path:
    if path.is_absolute():
        return path
    return repo_root / path


def validate_schema(bundle: dict[str, Any], schema: dict[str, Any]) -> None:
    Draft202012Validator = require_jsonschema()
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(bundle), key=lambda error: error.path)
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "<root>"
        fail(f"Schema validation failed at {location}: {first.message}")


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def control_status_errors(bundle: dict[str, Any], allow_evidence_required: bool) -> list[str]:
    errors: list[str] = []
    controls = bundle["controls"]
    certification_status = bundle["certification_status"]

    for name in CONTROL_NAMES:
        control = controls[name]
        status = control["status"]
        if status == "fail":
            errors.append(f"Control {name} is fail")
        if status == "evidence_required" and not allow_evidence_required:
            errors.append(f"Control {name} still requires evidence")
        if certification_status == "passed":
            require(status == "pass", f"Passed certification requires {name}=pass, found {status}", errors)
            require(bool(control["evidence_uris"]), f"Passed certification requires evidence_uris for {name}", errors)
            require(bool(control["evidence_hashes"]), f"Passed certification requires evidence_hashes for {name}", errors)

    if certification_status == "passed":
        open_deviations = [
            deviation["id"]
            for deviation in bundle["deviations"]
            if deviation["status"] in {"open", "mitigating"}
        ]
        require(not open_deviations, f"Passed certification cannot include open deviations: {open_deviations}", errors)
        for sign_off in bundle["sign_off"]:
            require(sign_off["decision"] == "approved", "Passed certification requires every sign-off decision to be approved", errors)

    return errors


def semantic_errors(bundle: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    controls = bundle["controls"]

    g_sri = controls["g_sri"]
    thresholds = g_sri["thresholds"]
    require(
        thresholds["green_max"] <= thresholds["watch_min"] < thresholds["halt_min"],
        "G-SRI thresholds must satisfy green_max <= watch_min < halt_min",
        errors,
    )
    require(g_sri["p95"] <= g_sri["max"], "G-SRI p95 cannot exceed max", errors)
    if bundle["certification_status"] == "passed":
        require(g_sri["max"] < thresholds["halt_min"], "Passed certification requires max G-SRI below halt threshold", errors)
        require(not g_sri["black_swan_override"], "Passed certification cannot have black_swan_override=true", errors)

    worm = controls["worm_audit"]
    if bundle["certification_status"] == "passed" or worm["status"] == "pass":
        require(worm["object_lock_enabled"], "WORM pass requires object_lock_enabled=true", errors)
        require(worm["expected_batches"] == worm["committed_batches"], "WORM pass requires expected_batches == committed_batches", errors)
        require(not worm["skipped_sequence_ids"], "WORM pass requires no skipped_sequence_ids", errors)
        require("object_lock_mode" in worm, "WORM pass requires object_lock_mode", errors)
        require("retention_until" in worm, "WORM pass requires retention_until", errors)
        require(bool(worm.get("cloudtrail_event_ids", [])), "WORM pass requires CloudTrail event IDs", errors)

    tee = controls["tee_attestation"]
    if bundle["certification_status"] == "passed" or tee["status"] == "pass":
        require(tee.get("measurement_match") is True, "TEE pass requires measurement_match=true", errors)
        require(tee.get("quote_freshness_seconds", 999999) <= 600, "TEE pass requires quote freshness <= 600 seconds", errors)

    tpm = controls["tpm_attestation"]
    if bundle["certification_status"] == "passed" or tpm["status"] == "pass":
        require(tpm.get("pcr_match") is True, "TPM pass requires pcr_match=true", errors)
        require(tpm.get("quote_freshness_seconds", 999999) <= 600, "TPM pass requires quote freshness <= 600 seconds", errors)

    zk = controls["zk_compliance"]
    if bundle["certification_status"] == "passed" or zk["status"] == "pass":
        require(zk.get("verifier_decision") == "ACCEPTED", "ZK pass requires verifier_decision=ACCEPTED", errors)

    return errors


def main() -> None:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    bundle_path = resolve(repo_root, args.bundle).resolve()
    schema_path = resolve(repo_root, args.schema).resolve()

    if not bundle_path.exists():
        fail(f"Bundle file not found: {bundle_path}")
    if not schema_path.exists():
        fail(f"Schema file not found: {schema_path}")

    try:
        bundle = load_json(bundle_path)
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in bundle file {bundle_path}: {exc}")

    try:
        schema = load_json(schema_path)
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in schema file {schema_path}: {exc}")

    validate_schema(bundle, schema)
    errors = control_status_errors(bundle, args.allow_evidence_required) + semantic_errors(bundle)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        raise SystemExit(1)

    print(f"[OK] Daily DevSecOps evidence bundle validation passed: {bundle_path}")


if __name__ == "__main__":
    main()
