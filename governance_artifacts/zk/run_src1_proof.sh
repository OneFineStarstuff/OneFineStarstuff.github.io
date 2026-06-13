#!/usr/bin/env bash
# =============================================================================
# SRC-1 ConcentrationBound — end-to-end Groth16 proving + verification flow
# Backs OSCAL control cry-05 (systemic-risk concentration bound zk attestation).
#
# Produces, under build/:
#   - Powers-of-Tau (dev ceremony, NOT production-secure)
#   - circuit-specific proving/verifying keys (src1_final.zkey, verification_key.json)
#   - witness, proof.json, public.json for the COMPLIANT fixture
#   - a Sentinel zk proof-statement envelope conforming to proof_statement_schema.json
#
# It then demonstrates the NEGATIVE case: witness generation for the VIOLATION
# fixture must FAIL, proving you cannot mint a compliance proof for a
# non-compliant (over-concentrated) portfolio.
#
# Usage:  bash run_src1_proof.sh
# Requires: circom (on PATH or ~/.local/bin), node, local node_modules/snarkjs.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
export PATH="$PATH:$HOME/.local/bin"

SNARKJS="node node_modules/snarkjs/build/cli.cjs"
CIRCUIT="circuits/src1_concentration_bound"
BUILD="build"
mkdir -p "$BUILD"

echo "==> [1/8] Compile circuit (idempotent)"
if [ ! -f "${CIRCUIT}.r1cs" ]; then
  circom "${CIRCUIT}.circom" --r1cs --wasm --sym --O0 -o circuits/
fi

echo "==> [2/8] Powers of Tau (dev ceremony — power 12)"
if [ ! -f "${BUILD}/pot12_final.ptau" ]; then
  $SNARKJS powersoftau new bn128 12 "${BUILD}/pot12_0000.ptau" -v
  echo "sentinel-dev-entropy-1" | $SNARKJS powersoftau contribute "${BUILD}/pot12_0000.ptau" "${BUILD}/pot12_0001.ptau" --name="dev1" -v
  $SNARKJS powersoftau prepare phase2 "${BUILD}/pot12_0001.ptau" "${BUILD}/pot12_final.ptau" -v
fi

echo "==> [3/8] Groth16 circuit-specific setup"
$SNARKJS groth16 setup "${CIRCUIT}.r1cs" "${BUILD}/pot12_final.ptau" "${BUILD}/src1_0000.zkey"
echo "sentinel-dev-entropy-2" | $SNARKJS zkey contribute "${BUILD}/src1_0000.zkey" "${BUILD}/src1_final.zkey" --name="dev2" -v
$SNARKJS zkey export verificationkey "${BUILD}/src1_final.zkey" "${BUILD}/verification_key.json"

echo "==> [4/8] Witness for COMPLIANT fixture"
node "${CIRCUIT}_js/generate_witness.js" \
  "${CIRCUIT}_js/${CIRCUIT##*/}.wasm" \
  inputs/src1_compliant.witness.json \
  "${BUILD}/witness_compliant.wtns"

echo "==> [5/8] Generate Groth16 proof (compliant)"
$SNARKJS groth16 prove "${BUILD}/src1_final.zkey" "${BUILD}/witness_compliant.wtns" \
  "${BUILD}/proof.json" "${BUILD}/public.json"

echo "==> [6/8] Verify proof"
$SNARKJS groth16 verify "${BUILD}/verification_key.json" "${BUILD}/public.json" "${BUILD}/proof.json"

echo "==> [7/8] Emit Sentinel zk proof-statement envelope"
VK_FP=$(sha256sum "${BUILD}/verification_key.json" | cut -d' ' -f1)
node -e '
const fs=require("fs");
const pub=JSON.parse(fs.readFileSync("build/public.json"));
const env={
  proof_id:"src1-"+new Date().toISOString().slice(0,10)+"-period-Q1",
  statement:"Foundation-model decision-volume HHI <= board-ratified threshold (basis points). circuit_tag pins SRC-1.",
  proving_system:"groth16",
  public_inputs:pub.map(String),
  verification:{
    gc_ir_verifier:"SRC-1::ConcentrationBound(n=8)",
    key_fingerprint:"sha256:"+process.argv[1]
  }
};
fs.writeFileSync("build/proof_statement.json",JSON.stringify(env,null,2));
console.log(JSON.stringify(env,null,2));
' "$VK_FP"

echo "==> [8/8] NEGATIVE TEST — witness gen for VIOLATION fixture must FAIL"
if node "${CIRCUIT}_js/generate_witness.js" \
      "${CIRCUIT}_js/${CIRCUIT##*/}.wasm" \
      inputs/src1_violation.witness.json \
      "${BUILD}/witness_violation.wtns" 2>/dev/null; then
  echo "FAIL: violation fixture unexpectedly produced a witness (soundness broken)"
  exit 1
else
  echo "OK: violation fixture rejected by circuit constraints (cannot prove false compliance)"
fi

echo ""
echo "SRC-1 proof flow complete. Artifacts in ${BUILD}/"
