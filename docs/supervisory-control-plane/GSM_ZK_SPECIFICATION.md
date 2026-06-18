# Governance State Machine (GSM) ZK Specification

## 1. Objective
To provide a zero-knowledge proof of validity for transitions in the AI Governance State Machine (GSM), ensuring that model promotions (e.g., Staging -> Production) only occur when all policy, evidence, and supervisory quorum requirements are met.

## 2. Circuit Architecture: `GSMTransition.circom`

### Public Inputs
- **current_state_hash:** Poseidon hash of `(state_id, policy_root, epoch)`.
- **next_state_hash:** Poseidon hash of `(next_state_id, policy_root, epoch + 1)`.
- **policy_hash:** Reference to the OPA/Rego policy bundle that authorizes the transition.
- **evidence_root:** Merkle root of the PQC-WORM evidence trail for the current epoch.

### Private Inputs
- **current_state_id:** Integer ID of the current state (0: DEV, 1: STAGING, 2: PROD, 3: QUARANTINE).
- **next_state_id:** Integer ID of the target state.
- **transition_id:** ID representing the specific transition logic being invoked.
- **epoch:** Incremental counter preventing replay attacks.
- **quorum_count:** Number of valid supervisory signatures gathered.

### Constraints
1. **Hash Consistency:** The prover must prove knowledge of state components that hash to the public values.
2. **State Transition Logic:** Enforces allowed paths (e.g., cannot go directly from DEV to PROD without passing STAGING).
3. **Quorum Enforcement:** Verifies that the number of authorizing signatures meets the threshold defined in the policy.
4. **Temporal Monotonicity:** Ensures the epoch increments by exactly 1.

## 3. PQC-WORM Anchoring

The GSM state is anchored to the PQC-WORM Audit Plane:
1. **Decision Trace:** Every GSM transition generates a "Decision Trace" containing the transition metadata.
2. **Signature:** The Decision Trace is signed using the institution's ML-DSA-65 private key.
3. **Merkle Integration:** The hash of the Decision Trace is added to the daily Merkle tree.
4. **Regulator Verifier:** The regulator downloads the Signed Decision Trace and the ZK proof to verify the transition without seeing the underlying telemetry.
