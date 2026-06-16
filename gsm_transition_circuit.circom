pragma circom 2.0.0;

include "comparators.circom";
include "hash.circom";

/*
This circuit proves that a Governance State Machine (GSM) transition was valid.
It checks that the new state is the correct, policy-mandated result of a given previous state and a specific set of sensitive data.
*/

template GsmTransition() {

    // --- Public Inputs ---
    signal input previousState; // The state before the transition (e.g., 1 for Normal, 2 for Warning)
    signal input newState;      // The state after the transition (e.g., 2 for Warning, 3 for Contained)
    signal input policyHash;    // The hash of the OPA policy that was evaluated.
    signal input eventDataHash; // The hash of the non-sensitive event metadata.

    // --- Private Inputs ---
    signal input sensitiveDriftMetric;   // The specific model drift value that triggered the policy.
    signal input sensitiveGSIScore;      // The specific Governance Supervisory Index score.

    // --- Constraints (The Circuit's Logic) ---

    // 1. Verify that the private inputs match the public hash.
    component hasher = PrivateInputsHasher(2);
    hasher.in[0] <== sensitiveDriftMetric;
    hasher.in[1] <== sensitiveGSIScore;
    hasher.out === eventDataHash;

    // 2. Enforce the GSM transition logic based on a simplified policy.

    // Rule: If the drift metric is > 50, the state must transition to Warning (2).
    component isDriftHigh = IsGreaterThan(50, 16);
    isDriftHigh.in <== sensitiveDriftMetric;
    signal isDriftHighOut <== isDriftHigh.out;

    // Rule: If the GSI score is > 80, the state must transition to Contained (3).
    component isGsiCritical = IsGreaterThan(80, 16);
    isGsiCritical.in <== sensitiveGSIScore;
    signal isGsiCriticalOut <== isGsiCritical.out;

    // Constraint: if isGsiCriticalOut is 1, then newState must be 3.
    isGsiCriticalOut * (newState - 3) === 0;

    // Constraint: if isGsiCriticalOut is 0 AND isDriftHighOut is 1, then newState must be 2.
    (1 - isGsiCriticalOut) * isDriftHighOut * (newState - 2) === 0;

    // Constraint: if both are low, state must be Normal (1) or the same as previous.
    (1 - isGsiCriticalOut) * (1 - isDriftHighOut) * (newState - previousState) * (newState - 1) === 0;
}

component main = GsmTransition();
