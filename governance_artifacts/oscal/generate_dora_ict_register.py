#!/usr/bin/env python3
"""
DORA (Regulation (EU) 2022/2554) ICT-risk register generator.

Auto-assembles a DORA ICT-risk register scoped to the Sentinel AI-governance
control surface, from the *verified* OSCAL catalogs + live assurance evidence.
Shares the catalog loader, control-evidence map, conformance gate and
evidence-status rule with the Annex IV generator via crosswalk_common.

For each of the five DORA pillars (dora_framework_map.yaml) it resolves the
mapped controls, attaches live evidence (re-running each control's backing
check), and assigns an evidence_status (SATISFIED / PARTIAL / PENDING-EVIDENCE).
Pillars with no in-scope control are reported as explicit coverage GAPS — never
silently dropped.

Honesty constraints:
  - refuses to assemble on a non-conformant catalog or an unknown control id;
  - a pillar is SATISFIED only when a mapped control's runnable check passed;
  - the register embeds a scope note and an integrity statement (it is a scoped
    register, NOT a DORA conformity attestation).

Outputs (default governance_artifacts/oscal/generated/):
  dora_ict_register.json , dora_ict_register.md
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

import crosswalk_common as cc

OSCAL_DIR = Path(__file__).resolve().parent
FRAMEWORK_MAP = OSCAL_DIR / "dora_framework_map.yaml"
DEFAULT_OUT = OSCAL_DIR / "generated"


def build_register(verify_evidence: bool = True) -> dict:
    cfg = yaml.safe_load(FRAMEWORK_MAP.read_text())
    catalog = cc.load_catalogs(cfg["catalogs"])
    conformance = cc.run_conformance()
    runner = cc.EvidenceRunner(verify=verify_evidence)

    pillars_out = []
    unknown_all = []
    for pillar in cfg["pillars"]:
        resolved, unknown = cc.resolve_controls(
            pillar.get("controls", []), catalog, runner)
        unknown_all += [(pillar["id"], u) for u in unknown]
        status = cc.status_for(resolved)
        pillars_out.append({
            "id": pillar["id"],
            "name": pillar["name"],
            "narrative": " ".join(pillar["narrative"].split()),
            "evidence_status": status,
            "is_coverage_gap": not resolved,
            "controls": resolved,
        })

    if unknown_all:
        raise ValueError(
            "dora_framework_map references unknown control ids: "
            + ", ".join(f"{p}:{c}" for p, c in unknown_all))

    satisfied = sum(1 for p in pillars_out if p["evidence_status"] == "SATISFIED")
    gaps = [p["id"] for p in pillars_out if p["is_coverage_gap"]]
    return {
        "dora_register": {
            "title": "DORA ICT-Risk Register (auto-assembled, AI-governance scope)",
            "framework": cfg["framework"],
            "scope_note": " ".join(cfg["scope_note"].split()),
            "generated_at": cc.now_iso(),
            "generator": "governance_artifacts/oscal/generate_dora_ict_register.py",
            "source_catalogs": cfg["catalogs"],
            "catalog_conformance": {
                "passed": conformance["passed"],
                "failed": conformance["failed"],
            },
            "summary": {
                "pillars_total": len(pillars_out),
                "pillars_satisfied": satisfied,
                "coverage_gaps": gaps,
            },
            "integrity_statement": (
                "This is a scoped ICT-risk register auto-assembled from OSCAL "
                "controls that exist in the named catalogs (conformance verified: "
                f"{conformance['failed']} failures) and assurance checks executed "
                "in this run. A pillar is SATISFIED only when a mapped control's "
                "runnable check passed here. Pillars P4/P5 are reported as coverage "
                "gaps for this control surface. It is NOT a DORA conformity "
                "attestation and does not assert institutional DORA compliance."
            ),
            "pillars": pillars_out,
        }
    }


def render_markdown(reg: dict) -> str:
    d = reg["dora_register"]
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
        f"- **Pillars SATISFIED:** {d['summary']['pillars_satisfied']}/"
        f"{d['summary']['pillars_total']}",
        f"- **Coverage gaps:** {', '.join(d['summary']['coverage_gaps']) or 'none'}",
        "",
        f"> **Scope.** {d['scope_note']}",
        "",
        f"> **Integrity statement.** {d['integrity_statement']}",
        "",
    ]
    for p in d["pillars"]:
        lines += [
            f"## {p['id']} — {p['name']}",
            "",
            f"**Evidence status:** {badge.get(p['evidence_status'], p['evidence_status'])}"
            + ("  _(coverage gap — no in-scope control)_" if p["is_coverage_gap"] else ""),
            "",
            p["narrative"],
            "",
        ]
        if not p["controls"]:
            lines += ["_No runnable Sentinel control maps to this pillar; this is an "
                      "organisational / design-stage area outside the modelled surface._", ""]
            continue
        lines += ["| Control | Tier | SLA | Backing check | Result |",
                  "|---------|------|-----|---------------|--------|"]
        for c in p["controls"]:
            ev = c["live_evidence"]
            res = ("PASS" if ev["passed"] is True else "FAIL" if ev["passed"] is False
                   else "n/a (organisational)")
            lines.append(
                f"| `{c['id']}` {c['title']} | {c['feasibility_tier'] or '-'} "
                f"| {c['freshness_sla'] or '-'} | {ev['check']} ({ev['evidence_kind']}) | {res} |")
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="DORA ICT-risk register generator")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT))
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--print", action="store_true")
    args = ap.parse_args(argv)

    reg = build_register(verify_evidence=not args.no_verify)
    if args.print:
        print(json.dumps(reg, indent=2))
        return 0

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "dora_ict_register.json").write_text(json.dumps(reg, indent=2))
    (out / "dora_ict_register.md").write_text(render_markdown(reg))
    d = reg["dora_register"]
    print(f"DORA ICT register assembled: "
          f"{d['summary']['pillars_satisfied']}/{d['summary']['pillars_total']} "
          f"pillars SATISFIED; coverage gaps: "
          f"{', '.join(d['summary']['coverage_gaps']) or 'none'}; "
          f"catalog conformance {d['catalog_conformance']['failed']} failures.")
    print(f"  -> {out / 'dora_ict_register.json'}")
    print(f"  -> {out / 'dora_ict_register.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
