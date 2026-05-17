#!/usr/bin/env python3
"""Generate a regulator-ready evidence bundle manifest for governance artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ARTIFACTS = [
    "docs/schemas/agi_asi_governance_profile_2026_2030.yaml",
    "docs/schemas/compliance_control_mapping.json",
    "docs/schemas/agi_asi_governance_profile.schema.json",
    "docs/schemas/compliance_control_mapping.schema.json",
    "docs/schemas/governance_artifacts_validation.py",
    "docs/schemas/policies/ai_governance.rego",
    "docs/schemas/policies/ai_governance_test.rego",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo-root", type=Path, default=Path.cwd(), help="Repository root path")
    p.add_argument(
        "--output",
        type=Path,
        default=Path("docs/schemas/evidence_bundle_manifest.json"),
        help="Manifest output path",
    )
    p.add_argument(
        "--include-timestamp",
        action="store_true",
        help="Include non-deterministic generation timestamp in output",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    output = (repo_root / args.output).resolve()

    manifest = {
        "bundle_version": "1.0.0",
        "artifacts": [],
    }
    if args.include_timestamp:
        manifest["generated_at_utc"] = datetime.now(timezone.utc).isoformat()

    for rel in DEFAULT_ARTIFACTS:
        p = (repo_root / rel).resolve()
        if not p.exists():
            raise SystemExit(f"Missing artifact: {rel}")
        manifest["artifacts"].append(
            {
                "path": rel,
                "sha256": sha256_file(p),
                "size_bytes": p.stat().st_size,
            }
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[OK] Evidence manifest written: {output}")


if __name__ == "__main__":
    main()
