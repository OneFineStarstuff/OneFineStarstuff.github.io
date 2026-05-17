#!/usr/bin/env python3
"""Validate that artifact paths listed in blueprint inventory exist in repository."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

DEFAULT_REPORT = Path("docs/reports/ENTERPRISE_CIVILIZATIONAL_AGI_ASI_BLUEPRINT_2026_2030.md")
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_HEADING_PATTERNS = [
    re.compile(r"^## .*Machine-Readable Governance Artifacts.*$", re.MULTILINE),
    re.compile(r"^## .*Generated artifact inventory.*$", re.MULTILINE),
]
PATH_PATTERN = re.compile(r"- `([^`]+)`")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT,
        help="Path to markdown blueprint report containing an artifact inventory list",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help="Repository root used to validate relative artifact paths",
    )
    return parser.parse_args()


def extract_inventory_section(report_text: str) -> str:
    for pattern in INVENTORY_HEADING_PATTERNS:
        heading_match = pattern.search(report_text)
        if heading_match is None:
            continue

        section_text = report_text[heading_match.end() :]
        next_heading_match = re.search(r"\n## ", section_text)
        if next_heading_match:
            section_text = section_text[: next_heading_match.start()]
        return section_text

    return ""


def collect_inventory_paths(inventory_text: str) -> list[str]:
    paths = PATH_PATTERN.findall(inventory_text)
    return [p for p in paths if p.startswith("docs/") or p.startswith(".") or p == "Makefile"]


def find_duplicate_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for path in paths:
        if path in seen and path not in duplicates:
            duplicates.append(path)
        seen.add(path)
    return duplicates


def validate_inventory_paths(paths: list[str], repo_root: Path) -> list[str]:
    return [rel for rel in paths if not (repo_root / rel).exists()]


def main() -> None:
    args = parse_args()
    report = args.report.resolve()
    repo_root = args.repo_root.resolve()

    if not report.exists():
        print(f"[FAIL] Blueprint report not found: {report}")
        raise SystemExit(1)

    report_text = report.read_text(encoding="utf-8")
    inventory_text = extract_inventory_section(report_text)
    if not inventory_text:
        print("[FAIL] Artifact inventory section not found (Machine-Readable Governance Artifacts)")
        raise SystemExit(1)

    paths = collect_inventory_paths(inventory_text)
    if not paths:
        print("[FAIL] No artifact paths found in report inventory")
        raise SystemExit(1)

    duplicates = find_duplicate_paths(paths)
    if duplicates:
        print("[FAIL] Artifact inventory contains duplicate paths:")
        for item in duplicates:
            print(f" - {item}")
        raise SystemExit(1)

    missing = validate_inventory_paths(paths, repo_root)
    if missing:
        print(f"[FAIL] Artifact inventory contains missing paths (repo root: {repo_root}):")
        for item in missing:
            print(f" - {item}")
        raise SystemExit(1)

    print(f"[OK] Artifact inventory paths verified ({len(paths)} entries)")


if __name__ == "__main__":
    main()
