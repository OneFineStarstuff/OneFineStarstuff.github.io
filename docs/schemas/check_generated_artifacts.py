#!/usr/bin/env python3
"""Ensure generated governance artifacts are up to date without mutating tracked files."""
from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], cwd: Path) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=cwd)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit(f"Generator failed (rc={proc.returncode}): {' '.join(cmd)}")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        tmp_manifest = td_path / "evidence_bundle_manifest.json"
        run([sys.executable, "docs/schemas/generate_evidence_bundle.py", "--output", str(tmp_manifest)], cwd=repo_root)

        expected_pairs = [
            (repo_root / "docs/schemas/evidence_bundle_manifest.json", tmp_manifest),
        ]

        stale = []
        for tracked, generated in expected_pairs:
            if not tracked.exists():
                stale.append(f"Missing tracked file: {tracked}")
                continue
            if sha256_file(tracked) != sha256_file(generated):
                stale.append(f"Out-of-date generated file: {tracked}")

    if stale:
        print("[FAIL] Generated deterministic artifacts are stale. Re-run generators and commit outputs.")
        for line in stale:
            print(f" - {line}")
        raise SystemExit(1)

    print("[OK] Generated governance artifacts are up to date")


if __name__ == "__main__":
    main()
