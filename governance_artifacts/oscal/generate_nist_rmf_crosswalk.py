#!/usr/bin/env python3
"""
NIST AI RMF 1.0 profile crosswalk generator.

Auto-assembles a NIST AI RMF (NIST AI 100-1) crosswalk from the *verified* OSCAL
catalogs + live assurance evidence, sharing the engine in crosswalk_common.

For each of the four RMF functions (GOVERN / MAP / MEASURE / MANAGE, per
nist_ai_rmf_map.yaml) it resolves the mapped controls, attaches live evidence,
assigns an evidence_status, and computes a coverage analysis:
  - functions SATISFIED (>=1 green runnable control)
  - functions with only organisational evidence
  - functions with NO mapped control (uncovered) — reported honestly.

Honesty constraints:
  - refuses to assemble on a non-conformant catalog or an unknown control id;
  - a function is SATISFIED only when a mapped control's runnable check passed;
  - embeds a scope note and integrity statement (coverage crosswalk, NOT a
    certification).

Outputs (default governance_artifacts/oscal/generated/):
  nist_ai_rmf_crosswalk.json , nist_ai_rmf_crosswalk.md
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

import crosswalk_common as cc

OSCAL_DIR = Path(__file__).resolve().parent
FRAMEWORK_MAP = OSCAL_DIR / "nist_ai_rmf_map.yaml"
DEFAULT_OUT = OSCAL_DIR / "generated"


def build_crosswalk(verify_evidence: bool = True) -> dict:
    cfg = yaml.safe_load(FRAMEWORK_MAP.read_text())
    catalog = cc.load_catalogs(cfg["catalogs"])
    conformance = cc.run_conformance()
    runner = cc.EvidenceRunner(verify=verify_evidence)

    functions_out = []
    unknown_all = []
    for fn in cfg["functions"]:
        resolved, unknown = cc.resolve_controls(
            fn.get("controls", []), catalog, runner)
        unknown_all += [(fn["id"], u) for u in unknown]
        status = cc.status_for(resolved)
        functions_out.append({
            "id": fn["id"],
            "name": fn["name"],
            "narrative": " ".join(fn["narrative"].split()),
            "evidence_status": status,
            "control_count": len(resolved),
            "controls": resolved,
        })

    if unknown_all:
        raise ValueError(
            "nist_ai_rmf_map references unknown control ids: "
            + ", ".join(f"{f}:{c}" for f, c in unknown_all))

    satisfied = [f["id"] for f in functions_out if f["evidence_status"] == "SATISFIED"]
    uncovered = [f["id"] for f in functions_out if f["control_count"] == 0]
    coverage_pct = round(100 * len(satisfied) / len(functions_out), 1) if functions_out else 0.0
    return {
        "nist_rmf_crosswalk": {
            "title": "NIST AI RMF 1.0 Profile Crosswalk (auto-assembled)",
            "framework": cfg["framework"],
            "scope_note": " ".join(cfg["scope_note"].split()),
            "generated_at": cc.now_iso(),
            "generator": "governance_artifacts/oscal/generate_nist_rmf_crosswalk.py",
            "source_catalogs": cfg["catalogs"],
            "catalog_conformance": {
                "passed": conformance["passed"],
                "failed": conformance["failed"],
            },
            "coverage_analysis": {
                "functions_total": len(functions_out),
                "functions_satisfied": satisfied,
                "functions_uncovered": uncovered,
                "satisfied_coverage_pct": coverage_pct,
            },
            "integrity_statement": (
                "This is a coverage crosswalk auto-assembled from OSCAL controls "
                "that exist in the named catalogs (conformance verified: "
                f"{conformance['failed']} failures) and assurance checks executed "
                "in this run. A function is SATISFIED only when a mapped control's "
                "runnable check passed here. NIST AI RMF is voluntary guidance; "
                "this is a coverage crosswalk, NOT a certification or conformity "
                "assessment."
            ),
            "functions": functions_out,
        }
    }


def render_markdown(cw: dict) -> str:
    d = cw["nist_rmf_crosswalk"]
    ca = d["coverage_analysis"]
    badge = {"SATISFIED": "✅ SATISFIED", "PARTIAL": "🟡 PARTIAL",
             "PENDING-EVIDENCE": "⏳ PENDING-EVIDENCE"}
    lines = [
        f"# {d['title']}",
        "",
        f"- **Framework:** {d['framework']}",
        f"- **Generated:** {d['generated_at']}",
        f"- **Generator:** `{d['generator']}`",
        f"- **Source catalogs:** {', '.join(d['source_catalogs'])}",
        f"- **Catalog conformance:** {d['catalog_conformance']['passed']} passed, "
        f"{d['catalog_conformance']['failed']} failed",
        f"- **Functions SATISFIED:** {', '.join(ca['functions_satisfied']) or 'none'} "
        f"({ca['satisfied_coverage_pct']}%)",
        f"- **Functions uncovered:** {', '.join(ca['functions_uncovered']) or 'none'}",
        "",
        f"> **Scope.** {d['scope_note']}",
        "",
        f"> **Integrity statement.** {d['integrity_statement']}",
        "",
    ]
    for f in d["functions"]:
        lines += [
            f"## {f['id']} — {f['name']}",
            "",
            f"**Evidence status:** {badge.get(f['evidence_status'], f['evidence_status'])} "
            f"({f['control_count']} control(s))",
            "",
            f["narrative"],
            "",
        ]
        if not f["controls"]:
            lines += ["_No control mapped — uncovered function for this surface._", ""]
            continue
        lines += ["| Control | Tier | Backing check | Result | Regimes |",
                  "|---------|------|---------------|--------|---------|"]
        for c in f["controls"]:
            ev = c["live_evidence"]
            res = ("PASS" if ev["passed"] is True else "FAIL" if ev["passed"] is False
                   else "n/a (organisational)")
            regimes = "; ".join(r["citation"] for r in c["regimes"]) or "-"
            lines.append(
                f"| `{c['id']}` {c['title']} | {c['feasibility_tier'] or '-'} "
                f"| {ev['check']} ({ev['evidence_kind']}) | {res} | {regimes} |")
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="NIST AI RMF profile crosswalk generator")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT))
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--print", action="store_true")
    args = ap.parse_args(argv)

    cw = build_crosswalk(verify_evidence=not args.no_verify)
    if args.print:
        print(json.dumps(cw, indent=2))
        return 0

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "nist_ai_rmf_crosswalk.json").write_text(json.dumps(cw, indent=2))
    (out / "nist_ai_rmf_crosswalk.md").write_text(render_markdown(cw))
    d = cw["nist_rmf_crosswalk"]
    ca = d["coverage_analysis"]
    print(f"NIST AI RMF crosswalk assembled: "
          f"{len(ca['functions_satisfied'])}/{ca['functions_total']} functions "
          f"SATISFIED ({ca['satisfied_coverage_pct']}%); uncovered: "
          f"{', '.join(ca['functions_uncovered']) or 'none'}; "
          f"catalog conformance {d['catalog_conformance']['failed']} failures.")
    print(f"  -> {out / 'nist_ai_rmf_crosswalk.json'}")
    print(f"  -> {out / 'nist_ai_rmf_crosswalk.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
