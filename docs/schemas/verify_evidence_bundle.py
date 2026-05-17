#!/usr/bin/env python3
"""Verify evidence bundle manifest integrity against current repository files."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo-root", type=Path, default=Path.cwd(), help="Repository root")
    p.add_argument(
        "--manifest",
        type=Path,
        default=Path("docs/schemas/evidence_bundle_manifest.json"),
        help="Manifest path relative to repo root",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    manifest_path = (repo_root / args.manifest).resolve()

    with manifest_path.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    failures = []
    for entry in manifest.get("artifacts", []):
        rel = entry["path"]
        expected_hash = entry["sha256"]
        expected_size = entry["size_bytes"]
        target = (repo_root / rel).resolve()

        if not target.exists():
            failures.append(f"Missing artifact: {rel}")
            continue

        actual_hash = sha256_file(target)
        actual_size = target.stat().st_size
        if actual_hash != expected_hash:
            failures.append(f"Hash mismatch for {rel}: expected {expected_hash}, got {actual_hash}")
        if actual_size != expected_size:
            failures.append(f"Size mismatch for {rel}: expected {expected_size}, got {actual_size}")

    if failures:
        print("[FAIL] Evidence bundle verification failed")
        for f in failures:
            print(f" - {f}")
        raise SystemExit(1)

    print("[OK] Evidence bundle manifest verified")


if __name__ == "__main__":
    main()
