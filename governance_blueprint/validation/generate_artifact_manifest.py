#!/usr/bin/env python3
"""Generate or verify governance_blueprint/artifact_manifest.json."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "governance_blueprint"
MANIFEST_PATH = ARTIFACTS / "artifact_manifest.json"
BASE_DEFAULT_FILES = [
    "control_mapping_matrix.csv",
    "evidence_event_schema.json",
    "compliance_profile_2026.json",
    "annex_iv_technical_documentation_template.json",
    "civilizational_compute_governance_framework.yaml",
    "roadmap_2026_2030.yaml",
    "roadmap_2026_2035.yaml",
    "regulatory_playbook_mapping_2026_2035.csv",
    "validation/validate_artifacts.py",
    "validation/selftest_validate_artifacts.py",
    "validation/selftest_generate_artifact_manifest.py",
    "rollout_plan_2026_2030.yaml",
    "opa/release_gate.rego",
    "opa/systemic_risk_guardrails.rego",
    "validation/generate_artifact_manifest.py",
    "validation/run_validation_suite.py",
    "validation/lint_python_sources.py",
    "validation/validate_dashboard_links.py",
]
EXTERNAL_FILES = [
    "REGULATOR_READY_AGI_ASI_TECHNICAL_REPORT_2026_2030.md",
]
UTC_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def sha256_of(path: Path) -> str:
    """Return the SHA-256 digest of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_join(root: Path, rel: str) -> Path:
    """Resolve a relative artifact path and reject traversal outside root."""
    if rel.startswith("/") or ".." in Path(rel).parts:
        raise ValueError(f"Disallowed manifest path entry: {rel}")
    resolved = (root / rel).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"Manifest path escapes root: {rel}") from exc
    return resolved


def _filesystem_selftests() -> list[str]:
    """Return self-test paths discovered on disk when Git metadata is unavailable."""
    return sorted(
        str(path.relative_to(ARTIFACTS))
        for path in (ARTIFACTS / "validation").glob("selftest_*.py")
    )


def _default_files() -> list[str]:
    """Return stable base artifacts plus tracked or discovered self-tests."""
    git_executable = shutil.which("git")
    git = None
    if git_executable is not None:
        try:
            resolved_git = str(Path(git_executable).resolve())
            # Keep argv static for scanners and pin execution to the discovered binary.
            # nosec B607 -- executable is an absolute path resolved from shutil.which.
            git = subprocess.run(
                [
                    "git",
                    "ls-files",
                    "governance_blueprint/validation/selftest_*.py",
                ],
                executable=resolved_git,
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            git = None

    if git is not None and git.returncode == 0:
        selftests = []
        for line in git.stdout.splitlines():
            candidate = line.strip()
            if (
                not candidate.startswith("governance_blueprint/validation/selftest_")
                or not candidate.endswith(".py")
                or ".." in Path(candidate).parts
            ):
                continue
            try:
                rel = Path(candidate).relative_to("governance_blueprint")
            except ValueError:
                continue
            selftests.append(str(rel))
    else:
        selftests = _filesystem_selftests()

    selftests = sorted(selftests)
    return list(dict.fromkeys([*BASE_DEFAULT_FILES, *selftests]))


def _existing_generated_utc() -> str | None:
    """Return the stored timestamp only when its syntax is valid."""
    if not MANIFEST_PATH.exists():
        return None
    try:
        current = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    value = current.get("generated_utc")
    if not isinstance(value, str) or not UTC_TS_RE.fullmatch(value):
        return None
    return value


def build_manifest(*, preserve_timestamp: bool = True) -> dict:
    """Build the canonical manifest from the current artifact files."""
    artifacts: dict[str, str] = {}
    for rel in _default_files():
        path = _safe_join(ARTIFACTS, rel)
        if not path.is_file():
            raise FileNotFoundError(f"Manifest artifact is missing: {path}")
        artifacts[rel] = sha256_of(path)

    external_artifacts: dict[str, str] = {}
    for rel in EXTERNAL_FILES:
        path = _safe_join(ROOT, rel)
        if not path.is_file():
            raise FileNotFoundError(f"External manifest artifact is missing: {path}")
        external_artifacts[rel] = sha256_of(path)

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
        "version": "1.4.5",
        "generated_utc": generated_utc,
        "artifacts": artifacts,
        "external_artifacts": external_artifacts,
    }


def main() -> int:
    """Generate the manifest or compare it with a fresh canonical build."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check", action="store_true", help="Fail if manifest is out of date."
    )
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
        try:
            current_obj = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"artifact_manifest.json is invalid JSON: {exc}")
            return 1
        expected_obj = build_manifest(preserve_timestamp=True)
        if current_obj != expected_obj:
            print(
                "artifact_manifest.json is out of date; "
                "run generate_artifact_manifest.py"
            )
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
