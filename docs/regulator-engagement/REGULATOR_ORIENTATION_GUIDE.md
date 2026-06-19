# Regulator Orientation Guide: Interpreting SCP Evidence

This guide helps supervisory technical auditors understand and interpret the outputs of the **Sentinel Verifier Node CLI** and the associated cryptographic evidence.

## 1. The Decision Trace Metadata
When you fetch a trace using `sentinel-verifier traces fetch --id [ID]`, you will see:
- **gsm_state:** The lifecycle state of the model at the time (DEV, STAGING, PROD).
- **policy_hash:** The unique ID of the OPA/Rego policy bundle that authorized the action.
- **timestamp_merkle:** The exact time the event was anchored to the institutional WORM log.

## 2. Understanding ZK Proof Statements
ZK proofs prove a *boolean statement* without revealing the inputs.
- **Example:** "Fairness Constraint Satisfied."
- **Audit Value:** If the Verifier Node returns `[SUCCESS]`, it means the mathematical proof for the fairness circuit matched the witness hash in the Merkle log. You do not need to re-run the fairness test yourself; you are verifying the *execution* of the test.

## 3. Detecting Non-Compliance
The Verifier Node will flag non-compliance in three primary ways:
1. **Invalid Signature:** The Decision Trace was not signed by a recognized institutional PQC key (suggests tampering).
2. **Merkle Path Failure:** The proof exists but is not part of the notarized daily Merkle root (suggests an un-anchored/shadow decision).
3. **ZK Proof Rejection:** The proof logic failed to satisfy the circuit constraints (suggests the model acted outside policy boundaries).

## 4. Attestation Heartbeats
Heartbeats are the "Pulse" of the system.
- **Healthy:** Heartbeats are received every 60 seconds.
- ** Amber:** 1-2 missing windows (suggests minor network latency).
- **Red:** 3+ missing windows (Supervisory Node should investigate for potential containment failure).
