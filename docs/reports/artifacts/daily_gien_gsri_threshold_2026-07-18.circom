pragma circom 2.1.8;

include "circomlib/comparators.circom";

template GSRIRiskThreshold(n) {
    signal input privateRiskScores[n];
    signal input threshold;
    signal output compliant;
    signal sum;

    var accumulator = 0;
    for (var i = 0; i < n; i++) {
        accumulator += privateRiskScores[i];
    }
    sum <== accumulator;

    component lessThan = LessThan(64);
    lessThan.in[0] <== sum;
    lessThan.in[1] <== threshold;
    compliant <== lessThan.out;
}

component main { public [threshold] } = GSRIRiskThreshold(16);
