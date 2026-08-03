#!/usr/bin/env python3
"""Validate required Python dependencies for governance checks."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path


DEFAULT_MODULES = ("yaml", "jsonschema")
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REQUIREMENTS = Path("docs/schemas/requirements-governance.txt")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--module",
        dest="modules",
        action="append",
        default=None,
        help="Python module to require (repeatable). Defaults to yaml and jsonschema.",
    )
    parser.add_argument(
        "--requirements",
        type=Path,
        default=DEFAULT_REQUIREMENTS,
        help="Requirements file shown in install hint.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root used to resolve relative --requirements paths.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    modules = tuple(dict.fromkeys(name.strip() for name in args.modules)) if args.modules else DEFAULT_MODULES
    if any(not name for name in modules):
        print("[FAIL] Module names must be non-empty")
        raise SystemExit(1)
    repo_root = args.repo_root.resolve()
    requirements_path = args.requirements
    if not requirements_path.is_absolute():
        requirements_path = (repo_root / requirements_path).resolve()

    try:
        requirements_hint = f"$REPO_ROOT/{requirements_path.relative_to(repo_root)}"
    except ValueError:
        requirements_hint = str(requirements_path)

    missing = sorted(name for name in modules if importlib.util.find_spec(name) is None)
    if missing:
        print(f"[FAIL] Missing Python dependencies: {', '.join(missing)}")
        print(f"Install with: python -m pip install -r {requirements_hint}")
        raise SystemExit(1)

    print(f"[OK] Governance Python dependencies are available: {', '.join(modules)}")


if __name__ == "__main__":
    main()
