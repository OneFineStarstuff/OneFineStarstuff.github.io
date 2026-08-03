#!/usr/bin/env python3
"""Validate dashboard wiring for the governance blueprint page."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "rag-agentic-dashboard" / "public"
WHITEPAPER = PUBLIC / "whitepaper-suite.html"
BLUEPRINT = PUBLIC / "enterprise-agi-asi-governance-blueprint.html"


def main() -> int:
    errors: list[str] = []

    if not WHITEPAPER.exists():
        errors.append("whitepaper-suite.html is missing")
    if not BLUEPRINT.exists():
        errors.append("enterprise-agi-asi-governance-blueprint.html is missing")

    if errors:
        print("Dashboard link validation failed:")
        print("\n".join(f"- {e}" for e in errors))
        return 1

    whitepaper_text = WHITEPAPER.read_text(encoding="utf-8")
    blueprint_text = BLUEPRINT.read_text(encoding="utf-8")

    if "enterprise-agi-asi-governance-blueprint.html" not in whitepaper_text:
        errors.append("whitepaper-suite.html does not link to enterprise-agi-asi-governance-blueprint.html")

    if "whitepaper-suite.html" not in blueprint_text:
        errors.append("blueprint page is missing backlink to whitepaper-suite.html")

    if "index.html" not in blueprint_text:
        errors.append("blueprint page is missing backlink to index.html")

    if errors:
        print("Dashboard link validation failed:")
        print("\n".join(f"- {e}" for e in errors))
        return 1

    print("Dashboard link validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
