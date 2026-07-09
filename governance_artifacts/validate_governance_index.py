#!/usr/bin/env python3
"""Validate the Sentinel Governance Index v6.0 (SGI) against the repository.

This is the runnable check behind the claim "the Sentinel Governance Index
v6.0 indexes 24 real, verifiable artifacts". It fails (exit 1) unless ALL of
the following hold — each a named, falsifiable check:

  IDX-1  index parses and declares version 6.0 with exactly 24 artifacts
  IDX-2  artifact IDs are exactly SGI-01..SGI-24, unique, in order
  IDX-3  every referenced path exists in the repository (file or directory)
  IDX-4  no duplicate (path, title) pairs; titles are non-empty
  IDX-5  every gies_module is one of the declared modules (GIMM/GIAF/GEE/META)
  IDX-6  every tier is A/B/C/D, and every tier-A artifact names at least one
         invariant and a verified_by clause
  IDX-7  every 'run_runnable_assurance.sh step N' reference points at a step
         number that actually exists in the suite script
  IDX-8  the TLA+ artifacts that declare invariants actually contain those
         invariant names in their module text (spot-check on .tla paths)

Honest scope: this validates INDEX INTEGRITY (the index tells the truth about
what exists and how it is verified). It does not re-run the underlying
checks — the assurance suite (SGI-24) does that.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
INDEX = Path(__file__).resolve().parent / "sentinel_governance_index_v6.yaml"
SUITE = Path(__file__).resolve().parent / "run_runnable_assurance.sh"

VALID_TIERS = {"A", "B", "C", "D"}


def check(results: list, name: str, ok: bool, detail: str) -> None:
    results.append({"check": name, "passed": bool(ok), "detail": detail})


def main() -> int:
    results: list = []

    # IDX-1 parse + shape
    try:
        doc = yaml.safe_load(INDEX.read_text())
        arts = doc["artifacts"]
        meta = doc["index"]
        ok1 = meta["version"] == "6.0" and len(arts) == 24
        check(results, "IDX-1 index-shape", ok1,
              f"version={meta.get('version')} artifacts={len(arts)}")
    except Exception as exc:  # noqa: BLE001
        check(results, "IDX-1 index-shape", False, f"parse error: {exc}")
        print(json.dumps({"status": "FAIL", "results": results}, indent=2))
        return 1

    # IDX-2 IDs
    expected = [f"SGI-{i:02d}" for i in range(1, 25)]
    ids = [a.get("id") for a in arts]
    check(results, "IDX-2 ids-canonical", ids == expected,
          f"ids match SGI-01..SGI-24: {ids == expected}")

    # IDX-3 paths exist
    missing = [a["id"] for a in arts if not (ROOT / a["path"]).exists()]
    check(results, "IDX-3 paths-exist", not missing,
          f"missing={missing or 'none'}")

    # IDX-4 duplicates / titles
    pairs = [(a["path"], a["title"]) for a in arts]
    dup = len(pairs) != len(set(pairs))
    empty = [a["id"] for a in arts if not a.get("title", "").strip()]
    check(results, "IDX-4 no-duplicates", not dup and not empty,
          f"dup_pairs={dup} empty_titles={empty or 'none'}")

    # IDX-5 modules
    modules = set(meta.get("gies_modules", []))
    bad_mod = [a["id"] for a in arts if a.get("gies_module") not in modules]
    check(results, "IDX-5 gies-modules", not bad_mod,
          f"invalid={bad_mod or 'none'} declared={sorted(modules)}")

    # IDX-6 tiers + tier-A completeness
    bad_tier = [a["id"] for a in arts if a.get("tier") not in VALID_TIERS]
    incomplete_a = [a["id"] for a in arts
                    if a.get("tier") == "A"
                    and (not a.get("invariants") or not a.get("verified_by"))]
    check(results, "IDX-6 tiers-complete", not bad_tier and not incomplete_a,
          f"bad_tier={bad_tier or 'none'} tierA_incomplete={incomplete_a or 'none'}")

    # IDX-7 suite step references resolve
    suite_text = SUITE.read_text()
    declared_steps = {int(m) for m in re.findall(r"\[(\d+)/\d+\]", suite_text)}
    bad_steps = []
    for a in arts:
        for m in re.findall(r"run_runnable_assurance\.sh steps? ([\d\-]+)",
                            str(a.get("verified_by", ""))):
            nums = ([int(x) for x in m.split("-")] if "-" in m else [int(m)])
            rng = range(nums[0], nums[-1] + 1)
            if not all(n in declared_steps for n in rng):
                bad_steps.append((a["id"], m))
    check(results, "IDX-7 suite-steps-resolve", not bad_steps,
          f"unresolved={bad_steps or 'none'} suite_declares={sorted(declared_steps)}")

    # IDX-8 TLA invariants really exist in module text
    bad_inv = []
    for a in arts:
        p = ROOT / a["path"]
        if p.suffix == ".tla" and p.is_file():
            text = p.read_text()
            for inv in a.get("invariants", []):
                if not re.search(rf"^\s*{re.escape(inv)}\s*==", text, re.M):
                    bad_inv.append((a["id"], inv))
    check(results, "IDX-8 tla-invariants-present", not bad_inv,
          f"missing={bad_inv or 'none'}")

    passed = all(r["passed"] for r in results)
    tier_counts: dict = {}
    for a in arts:
        tier_counts[a["tier"]] = tier_counts.get(a["tier"], 0) + 1
    report = {
        "index": f"Sentinel Governance Index v{meta['version']}",
        "as_of": str(meta.get("as_of")),
        "artifacts": len(arts),
        "tier_counts": tier_counts,
        "results": results,
        "status": "PASS" if passed else "FAIL",
        "integrity_statement": (
            "A PASS proves the index is truthful about which artifacts exist, "
            "how they are tiered, and where each verification lives. It does "
            "not re-run the underlying checks; run_runnable_assurance.sh does."
        ),
    }
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
