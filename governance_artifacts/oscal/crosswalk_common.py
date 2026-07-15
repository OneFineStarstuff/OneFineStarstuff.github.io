#!/usr/bin/env python3
"""
Shared crosswalk engine for OSCAL-native regulator deliverables.

One source of truth for:
  - loading the Sentinel OSCAL catalogs into enriched control dicts
    (statement, feasibility-tier, freshness-sla, evidence-query, resolved
    regime citations);
  - the control -> live assurance-evidence map (CONTROL_EVIDENCE) and a
    cached runner that records whether each control's backing check passed;
  - the OSCAL conformance gate (refuse to assemble on a non-conformant catalog).

Used by:
  generate_annex_iv_dossier.py     (EU AI Act Annex IV)
  generate_dora_ict_register.py    (DORA ICT-risk register)
  generate_nist_rmf_crosswalk.py   (NIST AI RMF profile crosswalk)

Evidence-status semantics (shared honesty model):
  SATISFIED         - >=1 mapped control whose runnable check passed this run.
  PARTIAL           - has runnable-backed controls but none passed this run.
  PENDING-EVIDENCE  - mapped only to organisational/hardware evidence, or no
                      controls mapped (i.e. a genuine coverage gap).
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

OSCAL_DIR = Path(__file__).resolve().parent
GA_DIR = OSCAL_DIR.parent
REPO_ROOT = GA_DIR.parent
DEFAULT_CATALOGS = [
    "catalog_sentinel_v24_excerpt.json",
    "catalog_sentinel_v24_env_rte.json",
]

# Control -> live assurance evidence. `kind` describes the evidence character
# truthfully; `command` is what a regulator re-runs (None = organisational
# evidence, reported PENDING). Kept here so all generators agree on what each
# control's evidence actually is.
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


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_catalogs(catalog_names: list[str] | None = None) -> dict[str, dict]:
    """Return {control_id: enriched control dict} across the named catalogs."""
    names = catalog_names or DEFAULT_CATALOGS
    controls: dict[str, dict] = {}
    for name in names:
        path = OSCAL_DIR / name
        if not path.is_file():
            raise FileNotFoundError(f"catalog not found: {path}")
        cat = json.loads(path.read_text())["catalog"]
        anchors = {r["uuid"]: r.get("title", r["uuid"])
                   for r in cat.get("back-matter", {}).get("resources", [])
                   if r.get("uuid")}

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


def run_conformance() -> dict:
    """Run oscal_conformance.py --json; raise if non-conformant."""
    proc = subprocess.run(
        [sys.executable, str(OSCAL_DIR / "oscal_conformance.py"), "--json"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "OSCAL conformance failed; refusing to assemble a deliverable on a "
            f"non-conformant catalog:\n{proc.stdout}\n{proc.stderr}"
        )
    return json.loads(proc.stdout)


class EvidenceRunner:
    """Runs (and caches) each control's backing assurance check."""

    def __init__(self, verify: bool = True):
        self.verify = verify
        self._cache: dict[str, bool | None] = {}

    def evidence(self, control_id: str) -> dict:
        desc = CONTROL_EVIDENCE.get(control_id, {
            "check": "(no runnable check mapped)",
            "kind": "organisational-record-PENDING",
            "command": None,
        })
        if control_id not in self._cache:
            if self.verify and desc["command"]:
                proc = subprocess.run(desc["command"], cwd=REPO_ROOT, shell=True,
                                      capture_output=True, text=True)
                self._cache[control_id] = proc.returncode == 0
            else:
                self._cache[control_id] = None
        return {
            "control_id": control_id,
            "check": desc["check"],
            "evidence_kind": desc["kind"],
            "command": desc["command"],
            "passed": self._cache[control_id],
        }


def status_for(control_entries: list[dict]) -> str:
    """Shared evidence-status rule given a section/element's resolved controls
    (each carrying a 'live_evidence' dict)."""
    if not control_entries:
        return "PENDING-EVIDENCE"
    any_passed = any(c["live_evidence"]["passed"] is True for c in control_entries)
    any_runnable = any(c["live_evidence"]["command"] for c in control_entries)
    if any_passed:
        return "SATISFIED"
    if any_runnable:
        return "PARTIAL"
    return "PENDING-EVIDENCE"


def resolve_controls(control_ids: list[str], catalog: dict[str, dict],
                     runner: EvidenceRunner) -> tuple[list[dict], list[str]]:
    """Resolve control ids -> enriched entries with live_evidence. Returns
    (resolved, unknown_ids)."""
    resolved, unknown = [], []
    for cid in control_ids:
        if cid not in catalog:
            unknown.append(cid)
            continue
        entry = dict(catalog[cid])
        entry["live_evidence"] = runner.evidence(cid)
        resolved.append(entry)
    return resolved, unknown
