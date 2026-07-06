#!/usr/bin/env python3
"""
Evidence freshness-SLA gate for the Sentinel v2.4 governance artifacts
(18th assurance check).

Why this exists
---------------
The OSCAL catalogs declare a per-control ``freshness-sla`` prop (e.g. env-01
attestation evidence must be at most PT5M old; cry-05's zk concentration proof
at most P3M). Conformance check C3 (oscal_conformance.py) validates only the
*format* of that prop. Until now nothing recorded WHEN each control's evidence
was last produced, and nothing failed when evidence went stale relative to its
declared SLA — the SLA was prose. This tool makes it enforced:

``--run``   executes every control's mapped runnable assurance check (the same
            single-source-of-truth CONTROL_EVIDENCE map used by the regulator
            deliverable generators) and writes a **freshness ledger**
            (oscal/generated/evidence_freshness_ledger.json) recording, per
            control: pass/fail, the UTC instant the evidence was produced, and
            wall-clock duration. Entries are protected by a ledger digest
            (SHA-256 over the canonical entries JSON).

``--audit`` loads the catalogs + ledger and, per control, checks (each named
            and falsifiable):
              ledger-digest      the ledger digest recomputes (casual edits to
                                 a timestamp without re-digesting FAIL);
              evidence-recorded  every runnable control has a ledger entry;
              evidence-passed    the recorded check passed;
              evidence-fresh     age(now or --as-of, evidence_generated_at)
                                 <= the control's declared freshness-sla.
            Controls whose evidence is organisational (no runnable command,
            e.g. env-02) are reported NOT-RUNNABLE — never counted fresh,
            never silently passed; they do not fail the gate but are disclosed
            in the summary.

Exit code 0 iff the audit passes (every runnable control recorded, passed,
and fresh, with an intact ledger digest).

Honesty notes
-------------
- A PASS proves the named runnable checks succeeded within their declared
  SLAs *on this machine at the recorded instants*. It is not a certification.
- The ledger digest makes casual tampering detectable; it is NOT a signature.
  An adversary who re-forges the whole ledger (entries + digest) defeats it —
  pair with the ML-DSA-65-signed distribution bundle (checks 16/17) for
  signed provenance.
- Duration-to-seconds conversion uses the fixed convention 1M=30d, 1Y=365d
  (stated here so audits are reproducible); a compound SLA like ``P1D/P90D``
  is interpreted as (periodic, retest) and the FIRST period is enforced.

Usage
-----
  python3 governance_artifacts/check_evidence_freshness.py --run --audit
  python3 governance_artifacts/check_evidence_freshness.py --audit --print
  python3 governance_artifacts/check_evidence_freshness.py --audit --as-of 2026-07-04T00:00:00Z
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

GA_DIR = Path(__file__).resolve().parent
OSCAL_DIR = GA_DIR / "oscal"
REPO_ROOT = GA_DIR.parent
DEFAULT_LEDGER = OSCAL_DIR / "generated" / "evidence_freshness_ledger.json"

sys.path.insert(0, str(OSCAL_DIR))
import crosswalk_common as cc  # noqa: E402  (single source of truth for evidence map)

LEDGER_VERSION = "1.0"

# ISO-8601 duration: PnYnMnWnD(TnHnMnS). Same grammar family as
# oscal_conformance.py's C3 check, but here we also CONVERT to seconds.
_ISO_DUR = re.compile(
    r"^P(?:(?P<Y>\d+)Y)?(?:(?P<Mo>\d+)M)?(?:(?P<W>\d+)W)?(?:(?P<D>\d+)D)?"
    r"(?:T(?:(?P<H>\d+)H)?(?:(?P<Mi>\d+)M)?(?:(?P<S>\d+)S)?)?$"
)

# Fixed, stated conversion convention (reproducible audits).
_SECONDS = {"Y": 365 * 86400, "Mo": 30 * 86400, "W": 7 * 86400,
            "D": 86400, "H": 3600, "Mi": 60, "S": 1}


def parse_sla_seconds(value: str) -> int:
    """Convert a freshness-sla prop to enforced seconds.

    A compound value like ``P1D/P90D`` is (periodic, retest); the FIRST
    period is the enforced freshness bound. Raises ValueError on malformed
    or zero-length durations.
    """
    first = value.split("/", 1)[0]
    m = _ISO_DUR.match(first)
    if not m or first == "P" or first == "PT":
        raise ValueError(f"malformed ISO-8601 duration: {value!r}")
    parts = {k: int(v) for k, v in m.groupdict().items() if v is not None}
    if not parts:
        raise ValueError(f"malformed ISO-8601 duration: {value!r}")
    total = sum(_SECONDS[k] * v for k, v in parts.items())
    if total <= 0:
        raise ValueError(f"zero-length freshness SLA: {value!r}")
    return total


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def ledger_digest(entries: list[dict]) -> str:
    """SHA-256 over the canonical (sorted-key, compact) entries JSON."""
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# --run: produce the freshness ledger
# ---------------------------------------------------------------------------

def run_ledger(ledger_path: Path) -> dict:
    """Execute every runnable control check and write the freshness ledger."""
    entries = []
    for cid in sorted(cc.CONTROL_EVIDENCE):
        desc = cc.CONTROL_EVIDENCE[cid]
        entry = {
            "control_id": cid,
            "check": desc["check"],
            "evidence_kind": desc["kind"],
            "command": desc["command"],
        }
        if desc["command"] is None:
            entry.update(passed=None, evidence_generated_at=None,
                         duration_seconds=None)
        else:
            t0 = time.monotonic()
            proc = subprocess.run(desc["command"], cwd=REPO_ROOT, shell=True,
                                  capture_output=True, text=True)
            entry.update(
                passed=proc.returncode == 0,
                evidence_generated_at=iso(now_utc()),
                duration_seconds=round(time.monotonic() - t0, 3),
            )
        entries.append(entry)

    doc = {"evidence_freshness_ledger": {
        "version": LEDGER_VERSION,
        "generated_at": iso(now_utc()),
        "generator": "governance_artifacts/check_evidence_freshness.py --run",
        "digest_convention": ("sha256 over json.dumps(entries, sort_keys=True, "
                              "separators=(',',':'))"),
        "entries": entries,
        "ledger_sha256": ledger_digest(entries),
    }}
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_text(json.dumps(doc, indent=2))
    return doc


# ---------------------------------------------------------------------------
# --audit: enforce the declared SLAs against the ledger
# ---------------------------------------------------------------------------

def audit_ledger(ledger_path: Path, as_of: datetime | None = None) -> dict:
    """Audit the ledger against the catalogs' declared freshness SLAs."""
    as_of = as_of or now_utc()
    catalog = cc.load_catalogs()
    report: dict = {
        "as_of": iso(as_of),
        "ledger_path": str(ledger_path.relative_to(REPO_ROOT)
                           if ledger_path.is_relative_to(REPO_ROOT)
                           else ledger_path),
        "sla_convention": "1M=30d, 1Y=365d; compound A/B enforces first period A",
        "controls": [],
        "errors": [],
    }

    if not ledger_path.is_file():
        report["errors"].append(f"ledger not found: {ledger_path}")
        return _finish(report, digest_ok=False)

    try:
        led = json.loads(ledger_path.read_text())["evidence_freshness_ledger"]
        entries = {e["control_id"]: e for e in led["entries"]}
        digest_ok = ledger_digest(led["entries"]) == led.get("ledger_sha256")
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        report["errors"].append(f"ledger unreadable: {exc}")
        return _finish(report, digest_ok=False)
    if not digest_ok:
        report["errors"].append(
            "ledger-digest MISMATCH: entries were modified without re-digesting")

    for cid in sorted(cc.CONTROL_EVIDENCE):
        desc = cc.CONTROL_EVIDENCE[cid]
        ctl = catalog.get(cid, {})
        sla = ctl.get("freshness_sla")
        row = {"control_id": cid, "check": desc["check"],
               "freshness_sla": sla, "sla_seconds": None,
               "evidence_generated_at": None, "age_seconds": None,
               "passed": None}

        if desc["command"] is None:
            row["status"] = "NOT-RUNNABLE"
            report["controls"].append(row)
            continue

        if not sla:
            row["status"] = "SLA-MISSING"
            report["controls"].append(row)
            continue
        try:
            row["sla_seconds"] = parse_sla_seconds(sla)
        except ValueError as exc:
            row["status"] = "SLA-MALFORMED"
            report["errors"].append(f"{cid}: {exc}")
            report["controls"].append(row)
            continue

        entry = entries.get(cid)
        if entry is None or entry.get("evidence_generated_at") is None:
            row["status"] = "NOT-RECORDED"
            report["controls"].append(row)
            continue

        row["passed"] = entry.get("passed")
        row["evidence_generated_at"] = entry["evidence_generated_at"]
        age = (as_of - parse_iso(entry["evidence_generated_at"])).total_seconds()
        row["age_seconds"] = round(age, 3)

        if row["passed"] is not True:
            row["status"] = "FAILED"          # a failed check is never fresh
        elif age < 0:
            row["status"] = "FUTURE-DATED"    # clock skew / forged timestamp
        elif age <= row["sla_seconds"]:
            row["status"] = "FRESH"
        else:
            row["status"] = "STALE"
        report["controls"].append(row)

    return _finish(report, digest_ok=digest_ok)


_GATE_FAIL = {"STALE", "FAILED", "NOT-RECORDED", "FUTURE-DATED",
              "SLA-MISSING", "SLA-MALFORMED"}


def _finish(report: dict, digest_ok: bool) -> dict:
    counts: dict[str, int] = {}
    for row in report["controls"]:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    runnable = [r for r in report["controls"] if r["status"] != "NOT-RUNNABLE"]
    failing = [r["control_id"] for r in runnable if r["status"] in _GATE_FAIL]
    report["ledger_digest_ok"] = digest_ok
    report["summary"] = {
        "controls_total": len(report["controls"]),
        "runnable": len(runnable),
        "not_runnable_disclosed": counts.get("NOT-RUNNABLE", 0),
        "by_status": counts,
        "failing_controls": failing,
    }
    report["status"] = ("PASS" if digest_ok and not failing
                        and not report["errors"] and runnable else "FAIL")
    report["integrity_statement"] = (
        "A PASS proves the named runnable checks succeeded within their "
        "catalog-declared freshness SLAs at the recorded instants on this "
        "machine. The ledger digest detects casual edits, not a re-forged "
        "ledger; it is not a signature and this is not a certification. "
        "Organisational-evidence controls are disclosed as NOT-RUNNABLE and "
        "never counted fresh."
    )
    return {"freshness_audit": report}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Evidence freshness-SLA ledger + audit gate")
    ap.add_argument("--run", action="store_true",
                    help="run all mapped checks and (re)write the ledger")
    ap.add_argument("--audit", action="store_true",
                    help="audit the ledger against catalog freshness SLAs")
    ap.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    ap.add_argument("--as-of", default=None,
                    help="audit as of this UTC instant (YYYY-MM-DDTHH:MM:SSZ)")
    ap.add_argument("--print", action="store_true",
                    help="print the audit report JSON to stdout")
    args = ap.parse_args(argv)

    if not args.run and not args.audit:
        ap.error("nothing to do: pass --run and/or --audit")

    ledger_path = Path(args.ledger)
    if args.run:
        doc = run_ledger(ledger_path)
        led = doc["evidence_freshness_ledger"]
        ran = [e for e in led["entries"] if e["command"]]
        print(f"freshness ledger written: {len(ran)} runnable checks recorded "
              f"({sum(1 for e in ran if e['passed'])} passed) -> {ledger_path}",
              file=sys.stderr)

    if not args.audit:
        return 0

    as_of = parse_iso(args.as_of) if args.as_of else None
    result = audit_ledger(ledger_path, as_of=as_of)
    rep = result["freshness_audit"]
    if args.print:
        print(json.dumps(result, indent=2))
    else:
        for row in rep["controls"]:
            sla = row["freshness_sla"] or "-"
            age = ("" if row["age_seconds"] is None
                   else f" age={int(row['age_seconds'])}s")
            print(f"  {row['status']:<13} {row['control_id']:<8} "
                  f"sla={sla}{age}", file=sys.stderr)
    # Summary always goes to stderr so it survives --print JSON redirection.
    print(f"freshness audit: {rep['status']} "
          f"({rep['summary']['runnable']} runnable, "
          f"{rep['summary']['by_status'].get('FRESH', 0)} fresh, "
          f"{rep['summary']['not_runnable_disclosed']} organisational "
          f"disclosed)", file=sys.stderr)
    return 0 if rep["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
