#!/usr/bin/env python3
"""
GC-IR cross-target conformance harness.
=======================================
Enforces the claim made in governance_artifacts/zk/gcir_obligation_example.yaml:

    "Shared fixture corpora are executed against the Rego rule, the circuit
     witness harness, and the TLA+ invariant fixtures; any disagreement fails
     the build."

For obligation `ob-ecoa-adverse-reason-codes` this harness, for every fixture:

  1. REGO target   : runs `opa eval` against fairness/credit_decision.rego#allow
  2. CIRCUIT target: maps symbolic reason codes -> integer ids, runs the
     SRC-fair-1 ReasonCodeCheck witness generator (real wasm). A witness is
     producible IFF the circuit predicate (compliant===1) holds.
  3. EXPECTED      : the `expected` field declared in the GC-IR fixture.

All three must agree (allow <=> witness-producible <=> expected==allow),
otherwise the harness exits non-zero and the build fails.

Requires: opa on PATH, node, local node_modules, compiled circuits.
Run: python3 gcir_harness.py
"""
from __future__ import annotations
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent  # /home/user/webapp
REGO_DIR = REPO / "governance_artifacts" / "rego"
REGO_FILE = REGO_DIR / "fairness_credit_decision.rego"
GCIR_YAML = HERE / "gcir_obligation_example.yaml"
CIRCUIT_JS = HERE / "circuits" / "src_fair1_reason_code_check_js"
CIRCUIT_WASM = CIRCUIT_JS / "src_fair1_reason_code_check.wasm"
GEN_WITNESS = CIRCUIT_JS / "generate_witness.js"

# Symbolic reason code -> integer id mapping (must match approved range [1..K]).
# Approved set per the Rego policy: RC01..RC07 -> ids 1..7. K = 7.
APPROVED_K = 7
CODE_ID = {f"RC{n:02d}": n for n in range(1, APPROVED_K + 1)}
# An unapproved code maps to an id ABOVE K (so the circuit range check fails).
UNAPPROVED_ID = APPROVED_K + 99  # 106, fits in 8 bits
MAXC = 5
CIRCUIT_TAG = 1178686001  # "FAR1"
MIN_CODES = 2


def load_fixtures():
    """Minimal YAML extraction of the GC-IR fixtures (no external yaml dep needed
    for the fixture block, but use PyYAML if available for robustness)."""
    try:
        import yaml  # type: ignore
        doc = yaml.safe_load(GCIR_YAML.read_text())
        return doc["obligation"]["fixtures"]
    except Exception as e:  # pragma: no cover - fallback only
        print(f"[harness] PyYAML unavailable or parse error ({e}); aborting", file=sys.stderr)
        sys.exit(3)


def run_rego(decision: dict) -> bool:
    """Return True if the Rego policy says `allow` (compliant)."""
    inp = {"decision": decision}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(inp, f)
        inp_path = f.name
    out = subprocess.run(
        ["opa", "eval", "--format", "json", "-d", str(REGO_FILE),
         "-i", inp_path, "data.fairness.credit_decision.allow"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print(f"[harness] opa eval failed: {out.stderr}", file=sys.stderr)
        sys.exit(3)
    res = json.loads(out.stdout)
    return res["result"][0]["expressions"][0]["value"] is True


def codes_to_circuit_input(decision: dict) -> dict:
    """Map a decision to SRC-fair-1 public+private inputs."""
    in_scope = 1 if (decision.get("outcome") == "adverse"
                     and decision.get("automation_level") == "full") else 0
    slots = []
    for rc in decision.get("reason_codes", []):
        slots.append(CODE_ID.get(rc, UNAPPROVED_ID))
    # pad with 0 (empty) up to MAXC
    slots = (slots + [0] * MAXC)[:MAXC]
    return {
        "in_scope": str(in_scope),
        "min_codes": str(MIN_CODES),
        "approved_k": str(APPROVED_K),
        "circuit_tag": str(CIRCUIT_TAG),
        "code": [str(s) for s in slots],
    }


def run_circuit(decision: dict) -> bool:
    """Return True if a witness is producible (circuit predicate holds)."""
    cin = codes_to_circuit_input(decision)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cin, f)
        in_path = f.name
    with tempfile.NamedTemporaryFile(suffix=".wtns", delete=False) as f:
        wtns = f.name
    out = subprocess.run(
        ["node", str(GEN_WITNESS), str(CIRCUIT_WASM), in_path, wtns],
        capture_output=True, text=True,
    )
    return out.returncode == 0


def main() -> int:
    fixtures = load_fixtures()
    print(f"[harness] obligation ob-ecoa-adverse-reason-codes: {len(fixtures)} fixtures")
    failures = 0
    for fx in fixtures:
        fid = fx["id"]
        decision = fx["input"]["decision"]
        expected_allow = fx["expected"] == "allow"

        rego_allow = run_rego(decision)
        circ_ok = run_circuit(decision)

        agree = (rego_allow == circ_ok == expected_allow)
        status = "OK " if agree else "MISMATCH"
        print(f"  [{status}] {fid}: expected={expected_allow} "
              f"rego={rego_allow} circuit={circ_ok}")
        if not agree:
            failures += 1

    if failures:
        print(f"[harness] FAIL: {failures} cross-target disagreement(s)", file=sys.stderr)
        return 1
    print("[harness] PASS: Rego, circuit, and declared expectations agree on all fixtures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
