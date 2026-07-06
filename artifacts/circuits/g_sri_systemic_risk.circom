pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

// Reference Groth16/Circom circuit for a G-SRI systemic-risk band proof.
// Private witness: component scores and weights.
// Public signals: threshold band, policy version, and evidence commitment.
// Production circuits should add fixed-point normalization, Poseidon commitments,
// version pinning, and audited trusted-setup governance.

template Range100() {
    signal input value;
    signal output ok;

    component lower = LessEqThan(16);
    lower.in[0] <== 0;
    lower.in[1] <== value;

    component upper = LessEqThan(16);
    upper.in[0] <== value;
    upper.in[1] <== 100;

    ok <== lower.out * upper.out;
}

template GSRIWeightedSum(n) {
    signal input scores[n];
    signal input weights[n];
    signal input thresholdLow;
    signal input thresholdHigh;
    signal input policyVersion;
    signal input evidenceCommitment;

    signal output inBand;
    signal output publicPolicyVersion;
    signal output publicEvidenceCommitment;

    signal products[n];
    signal accum[n + 1];
    accum[0] <== 0;

    component ranges[n];
    for (var i = 0; i < n; i++) {
        ranges[i] = Range100();
        ranges[i].value <== scores[i];
        ranges[i].ok === 1;
        products[i] <== scores[i] * weights[i];
        accum[i + 1] <== accum[i] + products[i];
    }

    component aboveLow = LessEqThan(32);
    aboveLow.in[0] <== thresholdLow;
    aboveLow.in[1] <== accum[n];

    component belowHigh = LessEqThan(32);
    belowHigh.in[0] <== accum[n];
    belowHigh.in[1] <== thresholdHigh;

    inBand <== aboveLow.out * belowHigh.out;
    publicPolicyVersion <== policyVersion;
    publicEvidenceCommitment <== evidenceCommitment;
}

component main {public [thresholdLow, thresholdHigh, policyVersion, evidenceCommitment]} = GSRIWeightedSum(10);
