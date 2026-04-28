#!/usr/bin/env python3
"""Generate or verify a SHA-256 manifest for governance artifact package files."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from governance_artifact_constants import DEFAULT_MANIFEST, MANIFEST_TRACKED_FILES


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path) -> dict:
    entries = []
    for rel in MANIFEST_TRACKED_FILES:
        p = root / rel
        if not p.exists():
            raise SystemExit(f"ERROR: missing required artifact file: {rel}")
        entries.append({"path": rel, "sha256": sha256_of(p)})

    return {
        "version": 1,
        "algorithm": "sha256",
        "entries": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate or verify governance artifact SHA-256 manifest")
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default=DEFAULT_MANIFEST)
    parser.add_argument("--verify", action="store_true", help="Validate existing manifest content instead of writing")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    output = root / args.output
    manifest = build_manifest(root)

    rendered = json.dumps(manifest, indent=2) + "\n"

    if args.verify:
        if not output.exists():
            raise SystemExit(f"ERROR: manifest file missing: {output}")
        current = output.read_text()
        if current != rendered:
            raise SystemExit("ERROR: manifest is stale; run scripts/generate_governance_manifest.py --root .")
        print(f"OK: manifest verified {output}")
        return

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered)
    print(f"OK: wrote {output}")


if __name__ == "__main__":
    main()
