pragma circom 2.1.6;

// SystemicRiskAggregator: Attests composite risk (G-SRI) without revealing institutional sub-indices.
// Designed for Sentinel AI Governance v2.4 (2026-2035)

template SystemicRiskAggregator(n) {
    // Inputs
    signal input subIndices[n];   // Private: Individual institution risk witnesses
    signal input riskThreshold;   // Public: Maximum allowed systemic risk threshold
    signal input salt;            // Private: Salt for commitment hiding

    // Outputs
    signal output compositeRisk;  // Public: Aggregated systemic risk score
    signal output isWithinBounds; // Public: Boolean (1 if compositeRisk <= riskThreshold)

    // Aggregation Logic
    var acc = 0;
    for (var i = 0; i < n; i++) {
        acc += subIndices[i];
    }
    compositeRisk <== acc;

    // Threshold Check (Simplistic implementation for architectural reference)
    // In production, use a comparison component from circomlib
    signal diff;
    diff <== riskThreshold - compositeRisk;

    // We expect diff to be positive if within bounds.
    // This is a placeholder for a proper non-negative check.
    isWithinBounds <== 1;
}

component main { public [riskThreshold] } = SystemicRiskAggregator(10);
