#!/usr/bin/env python3
"""Validator for federated-zk docs package.

- Scans markdown files under docs/federated-zk-compliance/ plus top-level synthesis entry.
- Verifies local markdown links resolve.
- Verifies anchor references (same-file and cross-file) resolve to headings.
- Emits non-zero exit code on missing links/anchors.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import re

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent
TOP_LEVEL_ENTRY = REPO_ROOT / "FEDERATED_ZK_AI_COMPLIANCE_RESEARCH_PROGRAM_SYNTHESIS.md"

MD_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)


def slugify(heading: str) -> str:
    s = heading.strip().lower()
    s = re.sub(r"[`*_]", "", s)
    s = re.sub(r"[^a-z0-9\s-]", "", s)
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"-+", "-", s)
    return s


def extract_anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {slugify(h) for h in HEADING.findall(text)}


def is_external(link: str) -> bool:
    return link.startswith(("http://", "https://", "mailto:"))


def split_link(link: str) -> tuple[str, str]:
    if "#" in link:
        base, frag = link.split("#", 1)
        return base, frag
    return link, ""


def resolve_target(source: Path, link_base: str) -> Path:
    base = link_base or source.name
    return (source.parent / base).resolve()


def discover_markdown_files() -> list[Path]:
    return sorted(ROOT.glob("*.md")) + [TOP_LEVEL_ENTRY]


def validate(md_files: list[Path]) -> tuple[int, int, list[str]]:
    errors: list[str] = []
    checked = 0
    anchor_cache: dict[Path, set[str]] = {}

    for md in md_files:
        if not md.exists():
            errors.append(f"Missing expected file: {md}")
            continue

        text = md.read_text(encoding="utf-8")
        for m in MD_LINK.finditer(text):
            checked += 1
            link = m.group(1).strip()
            if is_external(link):
                continue

            base, frag = split_link(link)
            target = resolve_target(md, base)

            if not target.exists():
                errors.append(f"{md}: missing link target -> {link}")
                continue

            if frag and target.suffix.lower() == ".md":
                if target not in anchor_cache:
                    anchor_cache[target] = extract_anchors(target)
                if slugify(frag) not in anchor_cache[target]:
                    errors.append(f"{md}: missing anchor '#{frag}' in {target}")

    return checked, len(errors), errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate federated-zk markdown links/anchors.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if no links are checked (safety against mis-scoped runs).",
    )
    args = parser.parse_args()

    checked, error_count, errors = validate(discover_markdown_files())

    if error_count:
        print("FAIL")
        print(f"Checked links: {checked}")
        for err in errors:
            print(err)
        return 1

    if args.strict and checked == 0:
        print("FAIL")
        print("Checked links: 0")
        print("Strict mode requires at least one checked link.")
        return 1

    print("PASS: all checked markdown links and anchors resolve")
    print(f"Checked links: {checked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
