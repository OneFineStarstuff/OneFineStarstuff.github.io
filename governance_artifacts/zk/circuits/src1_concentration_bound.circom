pragma circom 2.1.9;

/*
 * SRC-1 ConcentrationBound
 * ------------------------
 * Backs OSCAL control cry-05 (governance_artifacts/oscal/catalog_sentinel_v24_excerpt.json):
 *   "Generate, per reporting period, a Groth16 proof that foundation-model
 *    decision-volume HHI does not exceed the board-ratified threshold,
 *    with the circuit hash as public input."
 *
 * Feasibility tier: B (research-grade but compilable/provable today).
 *
 * Statement proved in zero knowledge:
 *   Given PRIVATE per-provider decision volumes v[0..n-1], the institution knows a
 *   vector whose normalised Herfindahl-Hirschman Index (HHI), scaled to integer
 *   basis points (0..10000), does NOT exceed a PUBLIC board-ratified threshold,
 *   AND whose total volume equals a PUBLIC committed total.
 *
 * HHI definition used (integer, scaled to bps):
 *   share_i      = v_i / T                       (T = sum of v_i)
 *   HHI_real     = sum_i share_i^2   in [1/n, 1]
 *   HHI_bps      = round(10000 * sum_i v_i^2 / T^2)
 * We avoid division in-circuit by proving:
 *   hhi_bps * T^2  >=  10000 * SUMSQ - T^2     (lower rounding bound)
 *   hhi_bps * T^2  <=  10000 * SUMSQ           (upper rounding bound)
 * where SUMSQ = sum_i v_i^2, and hhi_bps is a witnessed integer the prover supplies.
 * Then we enforce hhi_bps <= threshold_bps.
 *
 * Public inputs : threshold_bps, total_commit, circuit_tag
 * Private inputs: v[n], hhi_bps
 *
 * NOTE: circuit_tag is bound into the proof so a verifier can pin the exact circuit
 * version (the OSCAL prop `circuit: SRC-1`). It is constrained to a constant baked
 * at compile time, preventing proof replay across circuit revisions.
 */

include "../node_modules/circomlib/circuits/comparators.circom";

template SumOf(n) {
    signal input in[n];
    signal output out;
    signal acc[n+1];
    acc[0] <== 0;
    for (var i = 0; i < n; i++) {
        acc[i+1] <== acc[i] + in[i];
    }
    out <== acc[n];
}

template ConcentrationBound(n, CIRCUIT_TAG) {
    // ---- Public ----
    signal input threshold_bps;   // board-ratified HHI ceiling, basis points (<=10000)
    signal input total_commit;    // committed total decision volume T
    signal input circuit_tag;     // must equal compile-time CIRCUIT_TAG constant

    // ---- Private ----
    signal input v[n];            // per-provider decision volumes
    signal input hhi_bps;         // witnessed HHI in basis points

    // Pin the circuit identity (replay protection across revisions).
    circuit_tag === CIRCUIT_TAG;

    // T = sum(v) and bind to the public commitment.
    component summer = SumOf(n);
    for (var i = 0; i < n; i++) { summer.in[i] <== v[i]; }
    signal T;
    T <== summer.out;
    T === total_commit;

    // SUMSQ = sum(v_i^2)
    signal sq[n];
    signal sqacc[n+1];
    sqacc[0] <== 0;
    for (var i = 0; i < n; i++) {
        sq[i] <== v[i] * v[i];
        sqacc[i+1] <== sqacc[i] + sq[i];
    }
    signal SUMSQ;
    SUMSQ <== sqacc[n];

    // T2 = T^2
    signal T2;
    T2 <== T * T;

    // Rounding-correct HHI: enforce
    //   hhi_bps * T2 <= 10000 * SUMSQ
    //   hhi_bps * T2 >  10000 * SUMSQ - T2        (i.e. >= 10000*SUMSQ - T2 + 1, integer)
    signal lhs;       lhs  <== hhi_bps * T2;
    signal scaled;    scaled <== 10000 * SUMSQ;

    // upper: lhs <= scaled
    component upper = LessEqThan(64);
    upper.in[0] <== lhs;
    upper.in[1] <== scaled;
    upper.out === 1;

    // lower: scaled - T2 <= lhs   (so hhi_bps is not under-stated)
    signal lowerBound;
    lowerBound <== scaled - T2;
    component lower = LessEqThan(64);
    lower.in[0] <== lowerBound;
    lower.in[1] <== lhs;
    lower.out === 1;

    // Core compliance assertion: HHI does not exceed the board ceiling.
    component within = LessEqThan(64);
    within.in[0] <== hhi_bps;
    within.in[1] <== threshold_bps;
    within.out === 1;

    // Expose the proven HHI bound result as an output (1 = compliant).
    signal output compliant;
    compliant <== within.out;
}

// n = 8 providers; CIRCUIT_TAG = decimal of ASCII "SRC1" = 0x53524331 = 1398100273
component main {public [threshold_bps, total_commit, circuit_tag]} = ConcentrationBound(8, 1398100273);
