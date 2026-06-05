pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

template GSRIValidator(n) {
    signal input gsri_raw; // scaled by 10000
    signal input threshold_raw; // e.g., 7500 for 0.75
    signal input nonce;
    signal output safe;

    component lt = LessThan(n);
    lt.in[0] <== gsri_raw;
    lt.in[1] <== threshold_raw;

    safe <== lt.out;
}

component main {public [threshold_raw]} = GSRIValidator(32);
