#!/usr/bin/env bash
# =============================================================================
# Runnable assurance suite for the Sentinel AI Governance Stack v2.4 artifacts.
#
# Executes every artifact in this directory that makes a verifiable claim and
# fails fast on any error. This is the executable backbone behind the
# "regulator-ready" assertions in the master reference docs: instead of prose,
# these checks PROVE the named controls hold.
#
#   Step 1  OPA policy tests        -> release gate, credit gate, attestation gate
#   Step 2  TLA+ containment ratchet -> con-04/con-07 invariants
#   Step 3  TLA+ attested admission  -> env-01 (no run without attestation)
#   Step 4  TLA+ SentinelContainmentProtocol -> dead-man's switch one-way ratchet
#   Step 5  GC-IR cross-target      -> Rego <=> circuit witness <=> expectation
#   Step 6  SRC-1 Groth16 proof     -> cry-05 systemic-risk concentration bound
#   Step 7  zk-SNARK relayer pipeline -> Solidity Groth16 verifier + calldata
#   Step 8  SARA/ACR MoE routing    -> rte-01 routing stability invariants
#   Step 9  PQC WORM (ML-DSA-65)    -> cry-02 signed, hash-chained audit log
#   Step 10 Solidity + contract logic -> OmegaActual hardening (SEC-01..06)
#   Step 11 Schema validation       -> existing governance artifact validator
#   Step 12 OSCAL conformance       -> catalog prop/href cross-reference integrity
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

echo "[1/12] OPA policy tests (release gate + credit + attestation/PCR_MATCH)"
if opa test "$GA/rego/" >/tmp/opa_out 2>&1; then
  pass "$(grep -E 'PASS:' /tmp/opa_out | tail -1)"
else
  cat /tmp/opa_out; fail "OPA policy tests"
fi

echo "[2/12] TLA+ TLC model check (KillSwitchAbstract — con-04/con-07)"
if java -cp "$GA/tla/tools/tla2tools.jar" tlc2.TLC \
      -config "$GA/tla/KillSwitchAbstract.cfg" \
      "$GA/tla/KillSwitchAbstract.tla" >/tmp/tlc_out 2>&1 \
   && grep -q "No error has been found" /tmp/tlc_out; then
  pass "containment ratchet invariants hold ($(grep -oE '[0-9]+ distinct states' /tmp/tlc_out | head -1))"
else
  cat /tmp/tlc_out; fail "TLA+ model check"
fi

echo "[3/12] TLA+ TLC model check (AdmissionWithAttestation — env-01)"
if java -cp "$GA/tla/tools/tla2tools.jar" tlc2.TLC \
      -config "$GA/tla/AdmissionWithAttestation.cfg" \
      "$GA/tla/AdmissionWithAttestation.tla" >/tmp/tlc_att 2>&1 \
   && grep -q "No error has been found" /tmp/tlc_att; then
  pass "no T0 workload runs without valid attestation ($(grep -oE '[0-9]+ distinct states' /tmp/tlc_att | head -1))"
else
  cat /tmp/tlc_att; fail "TLA+ attested-admission model check"
fi

echo "[4/12] TLA+ TLC model check (SentinelContainmentProtocol — dead-man's switch)"
if java -cp "$GA/tla/tools/tla2tools.jar" tlc2.TLC \
      -config "$GA/tla/SentinelContainmentProtocol.cfg" \
      "$GA/tla/SentinelContainmentProtocol.tla" >/tmp/tlc_scp 2>&1 \
   && grep -q "No error has been found" /tmp/tlc_scp; then
  pass "TrippedStaysTripped + KillSwitchIntegrity hold ($(grep -oE '[0-9]+ distinct states' /tmp/tlc_scp | head -1))"
else
  cat /tmp/tlc_scp; fail "TLA+ SentinelContainmentProtocol model check"
fi

echo "[5/12] GC-IR cross-target conformance (Rego <=> circuit <=> expectation)"
if ( cd "$GA/zk" && python3 gcir_harness.py ) >/tmp/gcir_out 2>&1; then
  pass "$(grep -E 'PASS:' /tmp/gcir_out | tail -1 | sed 's/\[harness\] //')"
else
  cat /tmp/gcir_out; fail "GC-IR cross-target harness"
fi

echo "[6/12] SRC-1 Groth16 proof flow (cry-05 concentration bound)"
if ( cd "$GA/zk" && bash run_src1_proof.sh ) >/tmp/src1_out 2>&1 \
   && grep -q "violation fixture rejected" /tmp/src1_out; then
  pass "compliant proof verified; violation fixture rejected (soundness)"
else
  tail -20 /tmp/src1_out; fail "SRC-1 proof flow"
fi

echo "[7/12] zk-SNARK relayer pipeline (Solidity Groth16 verifier + calldata)"
if ( cd "$GA/zk" && bash run_relayer_pipeline.sh ) >/tmp/relayer_out 2>&1 \
   && grep -q "relayer pipeline complete" /tmp/relayer_out; then
  pass "$(grep -E 'OK .* compiles' /tmp/relayer_out | sed 's/^[[:space:]]*//')"
else
  tail -20 /tmp/relayer_out; fail "zk-SNARK relayer pipeline"
fi

echo "[8/12] SARA/ACR MoE routing stabilization (rte-01)"
if python3 "$GA/routing/sara_acr_router.py" >/tmp/rte_out 2>&1 \
   && grep -q "satisfies all rte-01 invariants" /tmp/rte_out; then
  pass "$(grep -E 'STABILIZED' /tmp/rte_out | sed 's/^[[:space:]]*//')"
else
  cat /tmp/rte_out; fail "SARA/ACR routing stability"
fi

echo "[9/12] PQC WORM audit log (ML-DSA-65 / CRYSTALS-Dilithium — cry-02)"
if python3 "$GA/kafka/pqc_worm_logger_v2.py" >/tmp/worm_out 2>&1 \
   && grep -q "tampering detected" /tmp/worm_out; then
  pass "ML-DSA-65 signatures + hash chain verify; tampering detected"
else
  cat /tmp/worm_out; fail "PQC WORM logger"
fi

echo "[10/12] Solidity compile + OmegaActual hardening logic (SEC-01..06)"
if ( cd "$ROOT/governance_blueprint/contracts" && node compile.js ) >/tmp/solc_out 2>&1 \
   && python3 -m pytest "$ROOT/governance_blueprint/contracts/test_contract_logic.py" -q >/tmp/clogic_out 2>&1; then
  pass "both contracts compile (0 warnings); $(grep -oE '[0-9]+ passed' /tmp/clogic_out | head -1) contract-logic tests"
else
  cat /tmp/solc_out; tail -20 /tmp/clogic_out; fail "Solidity compile / contract logic"
fi

echo "[11/12] Governance artifact schema validation"
if python3 "$GA/validate_artifacts.py" >/tmp/val_out 2>&1; then
  pass "$(tail -1 /tmp/val_out)"
else
  cat /tmp/val_out; fail "artifact schema validation"
fi

echo "[12/12] OSCAL catalog conformance (prop/href cross-reference integrity)"
if python3 "$GA/oscal/oscal_conformance.py" >/tmp/oscal_out 2>&1; then
  pass "$(grep -E 'OSCAL conformance:' /tmp/oscal_out | tail -1)"
else
  cat /tmp/oscal_out; fail "OSCAL catalog conformance"
fi

echo "=============================================================="
echo " ALL RUNNABLE ASSURANCE CHECKS PASSED"
echo "=============================================================="
