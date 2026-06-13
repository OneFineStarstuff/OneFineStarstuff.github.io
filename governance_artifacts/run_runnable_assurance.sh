#!/usr/bin/env bash
# =============================================================================
# Runnable assurance suite for the Sentinel AI Governance Stack v2.4 artifacts.
#
# Executes every artifact in this directory that makes a verifiable claim and
# fails fast on any error. This is the executable backbone behind the
# "regulator-ready" assertions in the master reference docs: instead of prose,
# these checks PROVE the named controls hold.
#
#   Step 1  OPA policy tests        -> deny-by-default release gate + credit gate
#   Step 2  TLA+ TLC model check    -> con-04/con-07 containment ratchet invariants
#   Step 3  GC-IR cross-target      -> Rego <=> circuit witness <=> expectation
#   Step 4  SRC-1 Groth16 proof     -> cry-05 systemic-risk concentration bound
#   Step 5  Schema validation       -> existing governance artifact validator
#
# Usage:  bash governance_artifacts/run_runnable_assurance.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GA="$ROOT/governance_artifacts"
export PATH="$PATH:$HOME/.local/bin"

pass() { printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; exit 1; }

echo "=============================================================="
echo " Sentinel v2.4 — Runnable Assurance Suite"
echo "=============================================================="

echo "[1/5] OPA policy tests (release gate + high-impact credit)"
if opa test "$GA/rego/" >/tmp/opa_out 2>&1; then
  pass "$(grep -E 'PASS:' /tmp/opa_out | tail -1)"
else
  cat /tmp/opa_out; fail "OPA policy tests"
fi

echo "[2/5] TLA+ TLC model check (KillSwitchAbstract — con-04/con-07)"
if java -cp "$GA/tla/tools/tla2tools.jar" tlc2.TLC \
      -config "$GA/tla/KillSwitchAbstract.cfg" \
      "$GA/tla/KillSwitchAbstract.tla" >/tmp/tlc_out 2>&1 \
   && grep -q "No error has been found" /tmp/tlc_out; then
  pass "containment ratchet invariants hold ($(grep -oE '[0-9]+ distinct states' /tmp/tlc_out | head -1))"
else
  cat /tmp/tlc_out; fail "TLA+ model check"
fi

echo "[3/5] GC-IR cross-target conformance (Rego <=> circuit <=> expectation)"
if ( cd "$GA/zk" && python3 gcir_harness.py ) >/tmp/gcir_out 2>&1; then
  pass "$(grep -E 'PASS:' /tmp/gcir_out | tail -1 | sed 's/\[harness\] //')"
else
  cat /tmp/gcir_out; fail "GC-IR cross-target harness"
fi

echo "[4/5] SRC-1 Groth16 proof flow (cry-05 concentration bound)"
if ( cd "$GA/zk" && bash run_src1_proof.sh ) >/tmp/src1_out 2>&1 \
   && grep -q "violation fixture rejected" /tmp/src1_out; then
  pass "compliant proof verified; violation fixture rejected (soundness)"
else
  tail -20 /tmp/src1_out; fail "SRC-1 proof flow"
fi

echo "[5/5] Governance artifact schema validation"
if python3 "$GA/validate_artifacts.py" >/tmp/val_out 2>&1; then
  pass "$(tail -1 /tmp/val_out)"
else
  cat /tmp/val_out; fail "artifact schema validation"
fi

echo "=============================================================="
echo " ALL RUNNABLE ASSURANCE CHECKS PASSED"
echo "=============================================================="
