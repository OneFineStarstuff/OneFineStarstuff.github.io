pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";

/*
This file provides a template for hashing inputs using the Poseidon hash function.
Poseidon is a ZK-friendly hash function that is efficient to compute inside a SNARK.
*/

template PrivateInputsHasher(nInputs) {
    signal input in[nInputs];
    signal output out;

    // Instantiate the Poseidon hash function.
    // The number of inputs is `nInputs`, and the output is a single element.
    component poseidon = Poseidon(nInputs);

    // Wire the inputs to the Poseidon component.
    for (var i = 0; i < nInputs; i++) {
        poseidon.inputs[i] <== in[i];
    }

    // The output of the template is the output of the Poseidon hash.
    out <== poseidon.out;
}
