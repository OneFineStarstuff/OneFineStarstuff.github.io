#!/usr/bin/env python3
"""
2028 G-SIFI Pilot — Acceptance-Gate Checklist (runnable).

Operationalizes section 14 ("2028 G-SIFI pilot deployment") of
governance_blueprint/DECADAL_STRATEGIC_TECHNICAL_PLAN_2026_2035.md.

Each of the six monthly pilot gates is either:
  * AUTOMATED  - verifiable now against in-repo artifacts (feasibility Tier A).
                 The script actually runs the check and reports PASS/FAIL.
  * MANUAL     - depends on real hardware / vendor accounts / a supervisor
                 (Tier B). The script prints the precise acceptance criterion
                 and the evidence the pilot team must capture; it does not fake
                 a pass.

Exit code is non-zero ONLY if an AUTOMATED gate fails. MANUAL gates never fail
the run (they are reported as PENDING-EVIDENCE), because faking them would
violate the program's integrity discipline.

Usage:
    python3 governance_artifacts/pilot/run_pilot_acceptance_gates.py
    python3 .../run_pilot_acceptance_gates.py --json      # machine-readable
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GA = ROOT / "governance_artifacts"

# ANSI (suppressed when not a tty)
_TTY = sys.stdout.isatty()
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
YEL = "\033[33m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
RST = "\033[0m" if _TTY else ""


@dataclass
class GateResult:
    month: int
    gate_id: str
    title: str
    kind: str  # "automated" | "manual"
    status: str  # "PASS" | "FAIL" | "PENDING-EVIDENCE"
    detail: str
    criterion: str
    evidence: list[str] = field(default_factory=list)


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 240) -> tuple[int, str]:
    """Run a command, return (rc, combined_output)."""
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s: {' '.join(cmd)}"


# ---------------------------------------------------------------------------
# AUTOMATED gate checks (Tier A) — each returns (ok: bool, detail: str)
# ---------------------------------------------------------------------------
def check_terraform_validate() -> tuple[bool, str]:
    tf = ROOT / "governance_blueprint" / "terraform"
    rc, out = _run(["terraform", "init", "-backend=false", "-input=false", "-no-color"], cwd=tf)
    if rc != 0:
        return False, f"terraform init failed: {out.strip().splitlines()[-1] if out.strip() else rc}"
    rc, out = _run(["terraform", "validate", "-no-color"], cwd=tf)
    ok = rc == 0 and ("Success" in out or "valid" in out.lower())
    return ok, out.strip().splitlines()[-1] if out.strip() else f"rc={rc}"


def check_opa_gates() -> tuple[bool, str]:
    rc, out = _run(["opa", "test", str(GA / "rego")])
    line = next((l for l in out.splitlines() if l.startswith("PASS:") or l.startswith("FAIL")), out.strip()[-80:])
    return rc == 0, line.strip()


def check_worm_tamper() -> tuple[bool, str]:
    rc, out = _run(["python3", str(GA / "kafka" / "pqc_worm_logger_v2.py")])
    ok = rc == 0 and "tampering detected" in out
    return ok, "ML-DSA-65 sign+chain verify; tampering detected" if ok else out.strip()[-120:]


def check_zk_relayer() -> tuple[bool, str]:
    rc, out = _run(["bash", "run_relayer_pipeline.sh"], cwd=GA / "zk", timeout=300)
    ok = rc == 0 and "relayer pipeline complete" in out
    line = next((l.strip() for l in out.splitlines() if "compiles" in l), "")
    return ok, line or (out.strip()[-120:])


def check_containment_tlc() -> tuple[bool, str]:
    jar = GA / "tla" / "tools" / "tla2tools.jar"
    rc, out = _run(
        ["java", "-cp", str(jar), "tlc2.TLC",
         "-config", str(GA / "tla" / "SentinelContainmentProtocol.cfg"),
         str(GA / "tla" / "SentinelContainmentProtocol.tla")],
        timeout=300,
    )
    ok = "No error has been found" in out
    states = next((l.strip() for l in out.splitlines() if "distinct states found" in l), "")
    return ok, ("ratchet invariants hold; " + states) if ok else out.strip()[-120:]


def check_full_assurance() -> tuple[bool, str]:
    rc, out = _run(["bash", str(GA / "run_runnable_assurance.sh")], timeout=400)
    ok = rc == 0 and "ALL RUNNABLE ASSURANCE CHECKS PASSED" in out
    npass = sum(1 for l in out.splitlines() if "PASS" in l and "ASSURANCE" not in l)
    return ok, f"{npass} checks PASS" if ok else out.strip()[-160:]


# ---------------------------------------------------------------------------
# Gate catalog — mirrors the §14 month-by-month pilot table.
# ---------------------------------------------------------------------------
def build_gates() -> list[GateResult]:
    gates: list[GateResult] = []

    # Month 1 — enclave substrate + attestation + OPA decision service
    ok, detail = check_terraform_validate()
    gates.append(GateResult(
        1, "P1-IAC", "Enclave substrate IaC validates in pilot account",
        "automated", "PASS" if ok else "FAIL", detail,
        criterion="`terraform validate` clean for the multi-region confidential-enclave module",
    ))
    gates.append(GateResult(
        1, "P1-ATTEST", "First PCR_MATCH=TRUE admission on real hardware",
        "manual", "PENDING-EVIDENCE",
        "Tier B: requires TDX/SEV-SNP hardware + AMD/Intel attestation roots.",
        criterion="A T0 workload is admitted only after a fresh, signature-valid attestation with PCR_MATCH=TRUE",
        evidence=["attestation verifier log showing PCR_MATCH=TRUE",
                  "golden measurement registry entry used for the admission"],
    ))

    # Month 2 — use-cases behind gates + StaR-MoE
    ok, detail = check_opa_gates()
    gates.append(GateResult(
        2, "P2-OPA", "T1 decisions routed through OPA release/credit/fairness gates",
        "automated", "PASS" if ok else "FAIL", detail,
        criterion="OPA policy suite green; 100% of T1 decisions evaluated by a default-deny gate",
    ))
    gates.append(GateResult(
        2, "P2-MOE", "StaR-MoE routing drift index <= 0.1",
        "manual", "PENDING-EVIDENCE",
        "Tier B: requires the pilot's live MoE model + production traffic.",
        criterion="MoE routing drift index <= 0.1 over the pilot window (SARA+ACR enabled)",
        evidence=["StaR-MoE telemetry export showing drift_index timeseries <= 0.1"],
    ))

    # Month 3 — 24h monitor + G-SRI + PQC WORM
    ok, detail = check_worm_tamper()
    gates.append(GateResult(
        3, "P3-WORM", "PQC WORM audit integrity 100% (tamper detected)",
        "automated", "PASS" if ok else "FAIL", detail,
        criterion="ML-DSA-65 signatures + hash chain verify; any tamper is detected",
    ))
    gates.append(GateResult(
        3, "P3-GSRI", "24h monitor + G-SRI emitting to production Kafka/S3 Object Lock",
        "manual", "PENDING-EVIDENCE",
        "Tier B: requires production Kafka + S3 Object Lock (COMPLIANCE) bucket.",
        criterion="G-SRI checkpoints written every interval; WORM batches retained under Object Lock",
        evidence=["S3 Object Lock retention config (COMPLIANCE mode)",
                  "24h monitor checkpoint log with G-SRI + PCR_MATCH"],
    ))

    # Month 4 — containment dry-runs (Red-Dawn) + dead-man's switch
    ok, detail = check_containment_tlc()
    gates.append(GateResult(
        4, "P4-CONTAIN", "Containment ratchet behaves per TLA+ model",
        "automated", "PASS" if ok else "FAIL", detail,
        criterion="SentinelContainmentProtocol TLC: TrippedStaysTripped + KillSwitchIntegrity hold",
    ))
    gates.append(GateResult(
        4, "P4-MTTC", "Critical-breach MTTC <= 60s in Red-Dawn simulation",
        "manual", "PENDING-EVIDENCE",
        "Tier B: requires a staged live containment exercise (GAI-SOC).",
        criterion="Measured mean-time-to-containment <= 60s across Red-Dawn scenarios",
        evidence=["Red-Dawn exercise report with per-scenario MTTC measurements"],
    ))

    # Month 5 — zk systemic-risk proof via relayer + OSCAL dossier
    ok, detail = check_zk_relayer()
    gates.append(GateResult(
        5, "P5-ZK", "zk systemic-risk proof -> on-chain verifier (relayer)",
        "automated", "PASS" if ok else "FAIL", detail,
        criterion="Groth16 proof exported to a Solidity verifier that compiles; calldata produced",
    ))
    gates.append(GateResult(
        5, "P5-DOSSIER", "OSCAL Annex IV dossier >= 98% auto-assembled",
        "manual", "PENDING-EVIDENCE",
        "Tier B: requires the institution's live control evidence feeds.",
        criterion=">= 98% of the Annex IV dossier assembled automatically from OSCAL + WORM evidence",
        evidence=["dossier-assembly report with manual-fraction <= 2%"],
    ))

    # Month 6 — supervisor read-only + reproducible assurance (go-decision)
    ok, detail = check_full_assurance()
    gates.append(GateResult(
        6, "P6-REPRO", "Independent reproduction of the assurance suite (16/16)",
        "automated", "PASS" if ok else "FAIL", detail,
        criterion="`run_runnable_assurance.sh` reproduces green in the pilot environment",
    ))
    gates.append(GateResult(
        6, "P6-SUPERVISOR", "Supervisor signs off on evidence reproducibility",
        "manual", "PENDING-EVIDENCE",
        "Requires a participating supervisor (observer role).",
        criterion="Supervisor confirms dashboards + GIEN events + proofs are independently reproducible",
        evidence=["signed supervisor sign-off memo", "supervisor dashboard access audit record"],
    ))

    return gates


def main() -> int:
    ap = argparse.ArgumentParser(description="2028 G-SIFI pilot acceptance-gate checklist")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    print("=" * 70)
    print(" 2028 G-SIFI Pilot — Acceptance-Gate Checklist")
    print(" (automated gates verified now; manual/Tier-B gates report criteria)")
    print("=" * 70)

    gates = build_gates()

    if args.json:
        print(json.dumps([g.__dict__ for g in gates], indent=2))

    automated_fail = 0
    by_month: dict[int, list[GateResult]] = {}
    for g in gates:
        by_month.setdefault(g.month, []).append(g)

    for month in sorted(by_month):
        print(f"\nMonth {month}")
        for g in by_month[month]:
            if g.status == "PASS":
                badge = f"{GREEN}PASS{RST}"
            elif g.status == "FAIL":
                badge = f"{RED}FAIL{RST}"
                automated_fail += 1
            else:
                badge = f"{YEL}MANUAL{RST}"
            print(f"  [{badge}] {g.gate_id:<13} {g.title}")
            print(f"           {DIM}criterion:{RST} {g.criterion}")
            if g.detail:
                print(f"           {DIM}detail   :{RST} {g.detail}")
            if g.kind == "manual" and g.evidence:
                print(f"           {DIM}evidence :{RST} " + "; ".join(g.evidence))

    n_auto = sum(1 for g in gates if g.kind == "automated")
    n_auto_pass = sum(1 for g in gates if g.kind == "automated" and g.status == "PASS")
    n_manual = sum(1 for g in gates if g.kind == "manual")

    print("\n" + "=" * 70)
    print(f" Automated gates: {n_auto_pass}/{n_auto} PASS   |   "
          f"Manual/Tier-B gates pending evidence: {n_manual}")
    if automated_fail == 0:
        print(f" {GREEN}ALL AUTOMATED PILOT GATES PASS{RST} — "
              f"go-decision blocked only on {n_manual} manual/Tier-B evidence items.")
    else:
        print(f" {RED}{automated_fail} AUTOMATED PILOT GATE(S) FAILED{RST} — fix before pilot go-decision.")
    print("=" * 70)
    return 1 if automated_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
