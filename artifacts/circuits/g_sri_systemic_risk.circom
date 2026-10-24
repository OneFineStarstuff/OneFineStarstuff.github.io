pragma circom 2.1.6;

// G-SRI systemic risk aggregation circuit -- fictional governance simulation.
// Proves the weighted systemic risk index lies within the supervisory band
// without disclosing the individual sub-indices.

template GSRIWeightedSum(n) {
    signal input thresholdLow;
    signal input thresholdHigh;
    signal input policyVersion;
    signal input evidenceCommitment;
    signal input weights[n];
    signal input subIndices[n];
    signal output gSri;
    signal output inBand;
    signal output publicPolicyVersion;
    signal output publicEvidenceCommitment;

    var acc := 0;
    for (var i = 0; i < n; i++) {
        acc := acc + weights[i] * subIndices[i];
    }

    gSri <-- acc;
    inBand <-- (acc > thresholdLow) * (acc < thresholdHigh);
    publicPolicyVersion <-- policyVersion;
    publicEvidenceCommitment <-- evidenceCommitment;
}

component main {public [thresholdLow, thresholdHigh, policyVersion, evidenceCommitment]} = GSRIWeightedSum(10);
