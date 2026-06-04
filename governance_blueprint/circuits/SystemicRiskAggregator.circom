pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

/**
 * @title SystemicRiskAggregator
 * @dev Aggregates regional risk metrics and proves G-SRI is below threshold without exposing raw data.
 */
template SystemicRiskAggregator(n_regions) {
    signal input regions[n_regions];
    signal input threshold;
    signal output is_safe;

    component lt = LessThan(32);

    var sum = 0;
    for (var i = 0; i < n_regions; i++) {
        sum += regions[i];
    }

    lt.in[0] <== sum / n_regions;
    lt.in[1] <== threshold;

    is_safe <== lt.out;
}

component main = SystemicRiskAggregator(4);
