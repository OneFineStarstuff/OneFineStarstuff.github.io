# Technical Evidence Pipeline: From Enclave to WORM

This document specifies the data transformation lifecycle within the Supervisory Control Plane (SCP), explaining how raw AI telemetry is converted into indelible, regulator-ready evidence.

## 1. Step 1: Decision Trace Generation (Inside TEE)
As an AI model executes an action, the **Omni-Sentinel Sidecar** (running within the same TEE enclave) captures a **Decision Trace**.

- **Payload:** Model inputs, predicted outputs, policy tokens, and confidence scores.
- **Security:** The trace is never exposed to the host OS in unencrypted form.

## 2. Step 2: PQC Signing and Hashing
The Decision Trace is passed to the **PQC-Signer** service.

- **Algorithm:** ML-DSA-65 (Post-Quantum Signatures).
- **Result:** A **Signed Decision Trace**.
- **Indelibility:** Once signed, any modification to the trace will invalidate the signature.

## 3. Step 3: ZK Witness Extraction (Evidence Binder)
The **Evidence Binder** service extracts the necessary witnesses for ZK proof generation.

- **Private Inputs:** Raw telemetry values required by the circuit (e.g., specific demographic data for a fairness check).
- **Public Inputs:** Merkle root and policy hash.
- **Privacy:** The raw telemetry is processed only within the ZK Prover enclave and then discarded.

## 4. Step 4: ZK Proof Generation
The **ZK Prover** executes the Circom circuit (e.g., `GSM_Transition_Circuit.circom`).

- **Artifact:** A Groth16 zk-SNARK proof.
- **Statement Proved:** "This decision trace satisfies policy P and is anchored to Merkle root R."

## 5. Step 5: Merkle Log Anchoring (PQC-WORM)
The hash of the Signed Decision Trace and the ZK Proof are added to the institution's **Merkle Log**.

- **Commitment:** The daily Merkle root is committed to S3 Object Lock storage with a 10-year retention policy.
- **Gossip:** The root is shared with the GIEN via the **SIP v3.0** protocol.

## 6. Step 6: Regulator Verification
The regulator's **Verifier Node** performs the final check:

1. **Root Audit:** Verifies the Merkle path from the proof to the daily public root.
2. **Signature Audit:** Checks the PQC signature on the Decision Trace metadata.
3. **ZK Audit:** Verifies the proof against the public inputs.

## Evidence Pipeline Summary

| Stage | Data Format | Location | Auditor Access |
| :--- | :--- | :--- | :--- |
| **Generation** | Raw JSON (Encrypted) | Enclave (Security Zone A) | None |
| **Signing** | Signed Decision Trace | Enclave (Security Zone B) | Metadata Only |
| **Proving** | ZK Proof + Witnesses | ZK Prover Enclave | Proof Only |
| **Anchoring** | Merkle Tree Root | PQC-WORM (S3) | Public Root |
| **Verification** | Verified Attestation | Verifier Node CLI | Full (Mathematically) |
