#!/usr/bin/env bash
# =============================================================================
# zk-SNARK relayer pipeline (SRC-1 ConcentrationBound -> on-chain verification).
#
# Closes the loop between the off-chain Groth16 proof (run_src1_proof.sh) and an
# on-chain verifier:
#   1. Ensure a proof exists (reuse build/ from run_src1_proof.sh, else generate).
#   2. Export a Solidity Groth16 verifier from the verifying key (snarkjs).
#   3. Produce ABI-encoded calldata the relayer would submit to verifyProof(...).
#   4. Compile the exported verifier with solc to prove it is on-chain-deployable.
#
# This is the "zk-SNARK relayer" referenced in the architecture: a privileged,
# attested off-chain agent that submits period systemic-risk proofs to the
# OmegaActual settlement layer. zk-STARK migration path is documented in
# RUNNABLE_ASSURANCE.md (transparent setup, no trusted ceremony).
#
# Usage: bash run_relayer_pipeline.sh
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
export PATH="$PATH:$HOME/.local/bin"
SNARKJS="node node_modules/snarkjs/build/cli.cjs"
BUILD="build"

echo "==> [1/4] Ensure SRC-1 proof artifacts exist"
if [ ! -f "${BUILD}/proof.json" ] || [ ! -f "${BUILD}/src1_final.zkey" ]; then
  echo "    (no proof found; running run_src1_proof.sh)"
  bash run_src1_proof.sh >/dev/null 2>&1
fi

echo "==> [2/4] Export Solidity Groth16 verifier"
$SNARKJS zkey export solidityverifier "${BUILD}/src1_final.zkey" "${BUILD}/SRC1Verifier.sol"
# Pin a stable pragma the local solc understands.
sed -i 's/pragma solidity .*/pragma solidity ^0.8.20;/' "${BUILD}/SRC1Verifier.sol"
echo "    wrote ${BUILD}/SRC1Verifier.sol"

echo "==> [3/4] Generate relayer calldata for verifyProof(...)"
$SNARKJS zkey export soliditycalldata "${BUILD}/public.json" "${BUILD}/proof.json" \
  > "${BUILD}/relayer_calldata.txt"
echo "    wrote ${BUILD}/relayer_calldata.txt"
head -c 160 "${BUILD}/relayer_calldata.txt"; echo " ..."

echo "==> [4/4] Compile exported verifier with solc"
node - "$BUILD" <<'NODE'
const fs = require("fs");
const path = require("path");
const solc = require("../../governance_blueprint/contracts/node_modules/solc");
const build = process.argv[2];
const src = fs.readFileSync(path.join(build, "SRC1Verifier.sol"), "utf8");
const input = {
  language: "Solidity",
  sources: { "SRC1Verifier.sol": { content: src } },
  settings: { optimizer: { enabled: true, runs: 200 },
              outputSelection: { "*": { "*": ["evm.bytecode.object"] } } },
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
const errs = (out.errors || []).filter((e) => e.severity === "error");
if (errs.length) { errs.forEach((e)=>console.log("    "+e.formattedMessage.split("\n")[0])); process.exit(1); }
const cname = Object.keys(out.contracts["SRC1Verifier.sol"])[0];
const bc = out.contracts["SRC1Verifier.sol"][cname].evm.bytecode.object;
console.log(`    OK ${cname} compiles (bytecode ${bc.length/2} bytes)`);
NODE

echo ""
echo "zk-SNARK relayer pipeline complete: proof -> Solidity verifier -> calldata -> compiles."
