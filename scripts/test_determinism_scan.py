#!/usr/bin/env python3
"""Regression tests for scripts/determinism_scan.sh."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / "scripts" / "determinism_scan.sh"


def run_scan(source: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="gien-determinism-") as temp_dir:
        scan_root = Path(temp_dir)
        (scan_root / "fixture.ts").write_text(source, encoding="utf-8")
        env = os.environ.copy()
        env["DETERMINISM_SCAN_ROOT"] = str(scan_root)
        return subprocess.run(
            ["sh", str(SCANNER)],
            cwd=REPO_ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )


def main() -> int:
    comment_result = run_scan(
        """/** Documentation: Math.random() is forbidden. */
 // Math.random()
 /* Math.random() */
"""
    )
    if comment_result.returncode != 0:
        raise AssertionError(
            "Comment-only references must pass; output was:\\n"
            + comment_result.stdout
            + comment_result.stderr
        )
    print("PASS: comment-only references do not fail the scan")

    code_result = run_scan("export const sample = Math.random();" + chr(10))
    if code_result.returncode == 0:
        raise AssertionError("Executable Math.random() usage must fail the scan")
    print("PASS: executable Math.random() usage is rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
