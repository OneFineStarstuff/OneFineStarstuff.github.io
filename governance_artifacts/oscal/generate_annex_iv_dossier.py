#!/usr/bin/env python3
"""
OSCAL-native EU AI Act Annex IV dossier generator.

Turns the *verified* Sentinel OSCAL catalogs + live assurance evidence into an
auto-assembled regulator deliverable. For each of the eight Annex IV technical-
documentation sections (A-H, per annex_iv_section_map.yaml) it:

  1. resolves the mapped OSCAL control ids against the catalogs (failing on any
     unknown id — no dangling references);
  2. pulls each control's statement, feasibility-tier, freshness-SLA, regime
     links (now resolved to back-matter citations), and evidence-query;
  3. attaches LIVE assurance evidence by mapping each control to the runnable
     assurance check that exercises it (CONTROL_EVIDENCE) and recording whether
     that check passed in this run;
  4. assigns each section an evidence_status:
       SATISFIED         - has >=1 control whose backing assurance check passed
       PARTIAL           - has controls but none currently backed by a green check
       PENDING-EVIDENCE  - mapped but evidence is organisational / not yet attached

Honesty constraints (consistent with the rest of the program):
  - A section is NEVER marked SATISFIED on prose alone; it requires a control
    whose runnable check passed in THIS run.
  - Controls that are Tier B/C/D or rely on hardware are surfaced as such; their
    evidence_kind is reported truthfully (e.g. "model-checked", "simulated",
    "organisational-record-PENDING").
  - The dossier embeds the exact commands a regulator can re-run.

Outputs (default into governance_artifacts/oscal/generated/):
  annex_iv_dossier.json  - OSCAL-flavoured machine-readable dossier
  annex_iv_dossier.md    - human-readable rendering

This is a Tier-A artifact for *assembly integrity*: it proves the dossier is
built only from real controls + real, currently-passing checks. It is NOT a
conformity assessment and does not assert the institution is compliant.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

OSCAL_DIR = Path(__file__).resolve().parent
GA_DIR = OSCAL_DIR.parent
REPO_ROOT = GA_DIR.parent
SECTION_MAP = OSCAL_DIR / "annex_iv_section_map.yaml"
MODEL_REGISTRY = GA_DIR / "model_registry.json"
DEFAULT_OUT = OSCAL_DIR / "generated"

# Control -> live assurance evidence descriptor. `check` is the human label of
# the runnable check that exercises the control; `kind` describes the evidence
# character truthfully; `command` is what a regulator re-runs. Controls whose
# evidence is organisational (not a runnable check) use kind=organisational and
# are reported PENDING-EVIDENCE.
CONTROL_EVIDENCE = {
    "con-04": {
        "check": "TLA+ KillSwitchAbstract reachability / dead-man's switch",
        "kind": "model-checked",
        "command": "java -cp governance_artifacts/tla/tools/tla2tools.jar tlc2.TLC "
                   "-config governance_artifacts/tla/KillSwitchAbstract.cfg "
                   "governance_artifacts/tla/KillSwitchAbstract.tla",
    },
    "con-07": {
        "check": "TLA+ KillSwitchAbstract one-way ratchet (ASA cannot de-escalate)",
        "kind": "model-checked",
        "command": "java -cp governance_artifacts/tla/tools/tla2tools.jar tlc2.TLC "
                   "-config governance_artifacts/tla/KillSwitchAbstract.cfg "
                   "governance_artifacts/tla/KillSwitchAbstract.tla",
    },
    "cry-02": {
        "check": "PQC WORM audit log (ML-DSA-65 sign + hash chain + tamper detect)",
        "kind": "cryptographically-verified",
        "command": "python3 -m pytest governance_artifacts/kafka/test_pqc_worm_logger_v2.py -q",
    },
    "cry-05": {
        "check": "SRC-1 Groth16 systemic-risk concentration bound proof",
        "kind": "zk-proven",
        "command": "bash governance_artifacts/zk/run_src1_proof.sh",
    },
    "env-01": {
        "check": "TLA+ AdmissionWithAttestation (no T0 run without valid attestation)",
        "kind": "model-checked",
        "command": "java -cp governance_artifacts/tla/tools/tla2tools.jar tlc2.TLC "
                   "-config governance_artifacts/tla/AdmissionWithAttestation.cfg "
                   "governance_artifacts/tla/AdmissionWithAttestation.tla",
    },
    "env-02": {
        "check": "Enclave-bound PQC key custody (hardware-dependent)",
        "kind": "organisational-record-PENDING",
        "command": None,
    },
    "rte-01": {
        "check": "SARA/ACR MoE routing stabilization invariants",
        "kind": "simulated",
        "command": "python3 -m pytest governance_artifacts/routing/test_sara_acr_router.py -q",
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_catalogs(catalog_names: list[str]) -> dict[str, dict]:
    """Return {control_id: enriched control dict} across the named catalogs."""
    controls: dict[str, dict] = {}
    for name in catalog_names:
        path = OSCAL_DIR / name
        if not path.is_file():
            raise FileNotFoundError(f"catalog not found: {path}")
        doc = json.loads(path.read_text())
        cat = doc["catalog"]
        # back-matter anchor -> title for regime link rendering
        anchors = {}
        for res in cat.get("back-matter", {}).get("resources", []):
            if res.get("uuid"):
                anchors[res["uuid"]] = res.get("title", res["uuid"])

        def walk(groups):
            for g in groups:
                for c in g.get("controls", []):
                    props = {p["name"]: p["value"] for p in c.get("props", [])}
                    stmt = next((p["prose"] for p in c.get("parts", [])
                                 if p.get("name") == "statement"), "")
                    regimes = []
                    for link in c.get("links", []):
                        href = link.get("href", "")
                        if href.startswith("#"):
                            a = href[1:]
                            regimes.append({
                                "rel": link.get("rel", "regime"),
                                "anchor": a,
                                "citation": anchors.get(a, a),
                            })
                    controls[c["id"]] = {
                        "id": c["id"],
                        "title": c.get("title", ""),
                        "statement": stmt,
                        "catalog": name,
                        "feasibility_tier": props.get("feasibility-tier"),
                        "freshness_sla": props.get("freshness-sla"),
                        "evidence_query": props.get("evidence-query"),
                        "regimes": regimes,
                    }
                walk(g.get("groups", []))
        walk(cat.get("groups", []))
    return controls


def _run_conformance() -> dict:
    """Run oscal_conformance.py --json and return its report (must pass)."""
    proc = subprocess.run(
        [sys.executable, str(OSCAL_DIR / "oscal_conformance.py"), "--json"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "OSCAL conformance failed; refusing to assemble a dossier on a "
            f"non-conformant catalog:\n{proc.stdout}\n{proc.stderr}"
        )
    return json.loads(proc.stdout)


def _run_check(command: str | None) -> bool | None:
    """Run a control's backing assurance command; True/False, or None if no
    runnable command (organisational evidence)."""
    if not command:
        return None
    proc = subprocess.run(command, cwd=REPO_ROOT, shell=True,
                          capture_output=True, text=True)
    return proc.returncode == 0


def build_dossier(verify_evidence: bool = True) -> dict:
    section_cfg = yaml.safe_load(SECTION_MAP.read_text())
    catalogs = section_cfg["catalogs"]
    controls = _load_catalogs(catalogs)

    conformance = _run_conformance()

    # Evaluate each control's backing check once (cache).
    evidence_cache: dict[str, bool | None] = {}

    def control_evidence(cid: str) -> dict:
        desc = CONTROL_EVIDENCE.get(cid, {
            "check": "(no runnable check mapped)",
            "kind": "organisational-record-PENDING",
            "command": None,
        })
        if cid not in evidence_cache:
            evidence_cache[cid] = (
                _run_check(desc["command"]) if verify_evidence else None
            )
        passed = evidence_cache[cid]
        return {
            "control_id": cid,
            "check": desc["check"],
            "evidence_kind": desc["kind"],
            "command": desc["command"],
            "passed": passed,
        }

    sections_out = []
    unknown = []
    for sec in section_cfg["sections"]:
        sec_controls = []
        any_passed = False
        any_runnable = False
        for cid in sec.get("controls", []):
            if cid not in controls:
                unknown.append((sec["id"], cid))
                continue
            ev = control_evidence(cid)
            entry = dict(controls[cid])
            entry["live_evidence"] = ev
            sec_controls.append(entry)
            if ev["command"]:
                any_runnable = True
            if ev["passed"] is True:
                any_passed = True

        if not sec_controls:
            status = "PENDING-EVIDENCE"
        elif any_passed:
            status = "SATISFIED"
        elif any_runnable:
            status = "PARTIAL"  # has runnable checks but none green this run
        else:
            status = "PENDING-EVIDENCE"  # only organisational evidence

        sections_out.append({
            "id": sec["id"],
            "name": sec["name"],
            "narrative": " ".join(sec["narrative"].split()),
            "evidence_status": status,
            "controls": sec_controls,
        })

    if unknown:
        raise ValueError(
            "annex_iv_section_map references unknown control ids: "
            + ", ".join(f"{s}:{c}" for s, c in unknown)
        )

    model_registry = (json.loads(MODEL_REGISTRY.read_text())
                      if MODEL_REGISTRY.is_file() else {})

    satisfied = sum(1 for s in sections_out if s["evidence_status"] == "SATISFIED")
    return {
        "dossier": {
            "title": "EU AI Act Annex IV Technical Documentation Dossier (auto-assembled)",
            "annex_iv_version": section_cfg["annex_iv_version"],
            "generated_at": _now(),
            "generator": "governance_artifacts/oscal/generate_annex_iv_dossier.py",
            "source_catalogs": catalogs,
            "catalog_conformance": {
                "passed": conformance["passed"],
                "failed": conformance["failed"],
            },
            "model_registry": model_registry.get("models", []),
            "summary": {
                "sections_total": len(sections_out),
                "sections_satisfied": satisfied,
                "sections_pending_or_partial": len(sections_out) - satisfied,
            },
            "integrity_statement": (
                "This dossier is auto-assembled only from OSCAL controls that "
                "exist in the named catalogs (conformance verified: "
                f"{conformance['failed']} failures) and from assurance checks "
                "executed in this run. A section is marked SATISFIED only when a "
                "mapped control's runnable check passed here. It is an assembly-"
                "integrity artifact, NOT a conformity assessment, and does not "
                "assert the institution is compliant with the EU AI Act."
            ),
            "sections": sections_out,
        }
    }


def render_markdown(dossier: dict) -> str:
    d = dossier["dossier"]
    lines = [
        f"# {d['title']}",
        "",
        f"- **Annex IV basis:** {d['annex_iv_version']}",
        f"- **Generated:** {d['generated_at']}",
        f"- **Generator:** `{d['generator']}`",
        f"- **Source catalogs:** {', '.join(d['source_catalogs'])}",
        f"- **Catalog conformance:** {d['catalog_conformance']['passed']} passed, "
        f"{d['catalog_conformance']['failed']} failed",
        f"- **Sections SATISFIED:** {d['summary']['sections_satisfied']}/"
        f"{d['summary']['sections_total']}",
        "",
        "> **Integrity statement.** " + d["integrity_statement"],
        "",
    ]
    if d["model_registry"]:
        lines += ["## Governed models (from registry)", ""]
        for m in d["model_registry"]:
            lines.append(
                f"- `{m.get('model_id')}` — {m.get('use_case')} "
                f"(risk tier: {m.get('risk_tier')}, status: {m.get('deployment_status')})"
            )
        lines.append("")

    badge = {"SATISFIED": "✅ SATISFIED",
             "PARTIAL": "🟡 PARTIAL",
             "PENDING-EVIDENCE": "⏳ PENDING-EVIDENCE"}
    for s in d["sections"]:
        lines += [
            f"## Annex IV §{s['id']} — {s['name']}",
            "",
            f"**Evidence status:** {badge.get(s['evidence_status'], s['evidence_status'])}",
            "",
            s["narrative"],
            "",
        ]
        if not s["controls"]:
            lines += ["_No control evidence mapped yet._", ""]
            continue
        lines += ["| Control | Tier | SLA | Backing check | Result | Regimes |",
                  "|---------|------|-----|---------------|--------|---------|"]
        for c in s["controls"]:
            ev = c["live_evidence"]
            res = ("PASS" if ev["passed"] is True
                   else "FAIL" if ev["passed"] is False
                   else "n/a (organisational)")
            regimes = "; ".join(r["citation"] for r in c["regimes"]) or "-"
            lines.append(
                f"| `{c['id']}` {c['title']} | {c['feasibility_tier'] or '-'} "
                f"| {c['freshness_sla'] or '-'} | {ev['check']} ({ev['evidence_kind']}) "
                f"| {res} | {regimes} |"
            )
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="OSCAL-native Annex IV dossier generator")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT))
    ap.add_argument("--no-verify", action="store_true",
                    help="skip running backing assurance checks (faster; statuses become PARTIAL/PENDING)")
    ap.add_argument("--print", action="store_true", help="print JSON to stdout instead of writing files")
    args = ap.parse_args(argv)

    dossier = build_dossier(verify_evidence=not args.no_verify)

    if args.print:
        print(json.dumps(dossier, indent=2))
        return 0

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "annex_iv_dossier.json").write_text(json.dumps(dossier, indent=2))
    (out / "annex_iv_dossier.md").write_text(render_markdown(dossier))

    d = dossier["dossier"]
    print(f"Annex IV dossier assembled: "
          f"{d['summary']['sections_satisfied']}/{d['summary']['sections_total']} "
          f"sections SATISFIED; catalog conformance "
          f"{d['catalog_conformance']['failed']} failures.")
    print(f"  -> {out / 'annex_iv_dossier.json'}")
    print(f"  -> {out / 'annex_iv_dossier.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
