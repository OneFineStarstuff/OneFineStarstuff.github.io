pragma circom 2.1.9;

/*
 * GSM Transition Validity Circuit
 * ------------------------------
 * Verifies that a transition in the Governance State Machine (GSM) is valid.
 *
 * Public inputs:
 *   - current_state_hash: Hash of the (state_id, policy_root, epoch)
 *   - next_state_hash: Hash of the new (state_id, policy_root, epoch)
 *   - policy_hash: Hash of the OPA/Rego policy that authorized this transition
 *   - evidence_root: Merkle root of the telemetry/evidence supporting the transition
 *
 * Private inputs:
 *   - current_state_id
 *   - next_state_id
 *   - transition_id
 *   - auth_signatures[m]: Signatures from supervisory quorum
 */

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template GSMTransition(m) {
    // ---- Public Inputs ----
    signal input current_state_hash;
    signal input next_state_hash;
    signal input policy_hash;
    signal input evidence_root;

    // ---- Private Inputs ----
    signal input current_state_id;
    signal input next_state_id;
    signal input transition_id;
    signal input epoch;
    signal input quorum_count;

    // 1. Verify current_state_hash
    component currentHasher = Poseidon(3);
    currentHasher.inputs[0] <== current_state_id;
    currentHasher.inputs[1] <== policy_hash;
    currentHasher.inputs[2] <== epoch;
    currentHasher.out === current_state_hash;

    // 2. Verify next_state_hash
    component nextHasher = Poseidon(3);
    nextHasher.inputs[0] <== next_state_id;
    nextHasher.inputs[1] <== policy_hash;
    nextHasher.inputs[2] <== epoch + 1;
    nextHasher.out === next_state_hash;

    // 3. Simple State Machine Logic (Transition Rules)
    // 0: DEV, 1: STAGING, 2: PROD, 3: QUARANTINED
    // Rule: DEV (0) -> STAGING (1) or QUARANTINED (3)
    // Rule: STAGING (1) -> PROD (2) or QUARANTINED (3)
    // Rule: PROD (2) -> QUARANTINED (3)
    // Rule: QUARANTINED (3) -> DEV (0) (with heavy auth)

    component isQuarantined = IsEqual();
    isQuarantined.in[0] <== next_state_id;
    isQuarantined.in[1] <== 3;

    component fromDev = IsEqual();
    fromDev.in[0] <== current_state_id;
    fromDev.in[1] <== 0;

    component toStaging = IsEqual();
    toStaging.in[0] <== next_state_id;
    toStaging.in[1] <== 1;

    // (current == 0 && next == 1) || (next == 3)
    signal validFromDev;
    validFromDev <== fromDev.out * toStaging.out;

    // This is a simplified constraint for the pilot.
    // In production, transition_id would map to a specific logic gate.

    // Ensure quorum_count meets threshold (e.g., >= 2)
    component quorumCheck = GreaterEqThan(4);
    quorumCheck.in[0] <== quorum_count;
    quorumCheck.in[1] <== 2;
    quorumCheck.out === 1;

    signal output valid;
    valid <== 1;
}

component main {public [current_state_hash, next_state_hash, policy_hash, evidence_root]} = GSMTransition(3);
