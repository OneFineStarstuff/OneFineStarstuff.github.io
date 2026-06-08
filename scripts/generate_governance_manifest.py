#!/usr/bin/env python3
"""Generate manifest for governance artifact package."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path

from governance_artifact_constants import DEFAULT_MANIFEST, MANIFEST_TRACKED_FILES

TOOL_VERSION = "1.2.0"
MANIFEST_VERSION = "1.2.0"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_manifest(root: Path) -> dict:
    entries = []
    for rel in sorted(MANIFEST_TRACKED_FILES):
        target = root / rel
        if not target.exists():
            print(f"ERROR: tracked file missing: {rel}")
            raise SystemExit(1)
        entries.append({"path": str(rel), "sha256": sha256_of(target)})

    return {
        "version": 1,
        "algorithm": "sha256",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "entries": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate governance artifact manifest"
    )
    parser.add_argument("--root", default=".", help="Repository root path")
    parser.add_argument(
        "--output",
        default=DEFAULT_MANIFEST,
        help="Output manifest path relative to --root",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify existing manifest instead of writing",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"generate_governance_manifest.py {TOOL_VERSION}",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    manifest = generate_manifest(root)
    output_path = root / args.output

    if args.verify:
        if not output_path.exists():
            print(f"ERROR: manifest missing: {output_path}")
            raise SystemExit(1)
        existing = json.loads(output_path.read_text())
        # ignore generated_at during verification
        existing.pop("generated_at", None)
        manifest.pop("generated_at", None)
        if existing != manifest:
            print(f"ERROR: manifest is stale: {output_path}")
            raise SystemExit(1)
        print(f"OK: manifest verified {output_path}")
    else:
        output_path.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"OK: manifest written {output_path}")


if __name__ == "__main__":
    main()
