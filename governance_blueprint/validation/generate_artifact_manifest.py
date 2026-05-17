#!/usr/bin/env python3
"""Generate or verify governance_blueprint/artifact_manifest.json."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "governance_blueprint"
MANIFEST_PATH = ARTIFACTS / "artifact_manifest.json"
DEFAULT_FILES = [
    "control_mapping_matrix.csv",
    "evidence_event_schema.json",
    "opa/release_gate.rego",
    "roadmap_2026_2030.yaml",
    "validation/validate_artifacts.py",
    "validation/selftest_validate_artifacts.py",
    "validation/generate_artifact_manifest.py",
    "validation/run_validation_suite.py",
    "validation/selftest_run_validation_suite.py",
    "validation/lint_python_sources.py",
    "validation/validate_dashboard_links.py",
]


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _existing_generated_utc() -> str | None:
    if not MANIFEST_PATH.exists():
        return None
    try:
        current = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    value = current.get("generated_utc")
    return value if isinstance(value, str) and value else None


def build_manifest(*, preserve_timestamp: bool = True) -> dict:
    artifacts: dict[str, str] = {}
    for rel in DEFAULT_FILES:
        p = ARTIFACTS / rel
        artifacts[rel] = sha256_of(p)

    generated_utc = _existing_generated_utc() if preserve_timestamp else None
    if not generated_utc:
        generated_utc = (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    return {
        "package": "enterprise_agi_asi_governance_blueprint",
        "version": "1.3.1",
        "generated_utc": generated_utc,
        "artifacts": artifacts,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail if manifest is out of date.")
    parser.add_argument(
        "--stamp-now",
        action="store_true",
        help="When generating, refresh generated_utc to current UTC time.",
    )
    args = parser.parse_args()

    if args.check:
        if not MANIFEST_PATH.exists():
            print("artifact_manifest.json is missing")
            return 1
        current_obj = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        expected_obj = build_manifest(preserve_timestamp=True)
        current_artifacts = current_obj.get("artifacts", {})
        expected_artifacts = expected_obj.get("artifacts", {})
        if current_artifacts != expected_artifacts:
            print("artifact_manifest.json is out of date; run generate_artifact_manifest.py")
            return 1
        print("artifact_manifest.json is up to date")
        return 0

    manifest = build_manifest(preserve_timestamp=not args.stamp_now)
    rendered = json.dumps(manifest, indent=2) + "\n"
    MANIFEST_PATH.write_text(rendered, encoding="utf-8")
    print(f"Wrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
