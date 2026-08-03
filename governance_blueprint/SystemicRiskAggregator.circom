pragma circom 2.1.6;

// SystemicRiskAggregator: Attests composite systemic risk (G-SRI) without revealing private institutional sub-indices.
// Aligns with Sentinel v2.4 Groth16 zk-SNARK requirements.

template SystemicRiskAggregator(n) {
    signal input subIndices[n];   // Private witness (per-system/per-institution G-SRI)
    signal input tierGate;        // Public input (regulatory threshold)
    signal output composite;      // Attested composite risk score
    signal output withinThreshold; // Boolean indicator

    var acc = 0;
    for (var i = 0; i < n; i++) {
        // Simple summation for G-SRI aggregation
        acc += subIndices[i];
    }

    composite <== acc;

    // Range proof logic: composite <= tierGate
    // Simplified for blueprint purposes
    component isLess = LessThan(64);
    isLess.in[0] <== composite;
    isLess.in[1] <== tierGate + 1;

    withinThreshold <== isLess.out;
}

// Helper component for range constraints
template LessThan(n) {
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n+1);
    n2b.in <== in[0] + (1 << n) - in[1];
    out <== 1 - n2b.out[n];
}

template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc1 += out[i] * 2**i;
    }
    lc1 === in;
}

component main { public [tierGate] } = SystemicRiskAggregator(8);
