#!/usr/bin/env python3
"""Compile validation Python sources to catch syntax errors early."""

from __future__ import annotations

import py_compile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATION_DIR = ROOT / "governance_blueprint" / "validation"


def main() -> int:
    failures: list[str] = []
    for path in sorted(VALIDATION_DIR.glob("*.py")):
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:
            failures.append(f"{path}: {exc.msg}")

    if failures:
        print("Python source lint failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Python source lint passed for validation scripts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
