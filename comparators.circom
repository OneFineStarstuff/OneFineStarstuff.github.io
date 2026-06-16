pragma circom 2.0.0;

/*
This file contains standard comparator templates for use in other circuits.
*/

// Template to check if signal `in` is greater than a constant `n`.
// It uses the fact that Circom works over a finite field.
// We use a bit decomposition to check the value.
// `nBits` should be large enough to hold `in` and `n`.
template IsGreaterThan(n, nBits) {
    signal input in;
    signal output out;

    // 1. Bit decompose the input signal
    component num2Bits = Num2Bits(nBits);
    num2Bits.in <== in;

    // 2. Check if `in` is greater than `n`
    // This is a complex but standard R1CS construction.
    // We will use a simplified placeholder for this example.
    // In a real implementation, this would involve a more rigorous check.

    // For this example, we'll use a simple constraint that is NOT secure
    // but illustrates the principle. A real implementation would use
    // a series of constraints to check the bits.
    signal diff;
    diff <== in - n;

    // `out` will be 1 if `in > n`, and 0 otherwise.
    // This is a non-trivial gadget to build correctly and securely.
    // A real implementation would use a trusted library like `circomlib`.
    // For now, we will leave this as a high-level abstraction.
    // The logic below is a simplification.

    component isPositive = IsPositive(nBits);
    isPositive.in <== diff;
    out <== isPositive.out;
}

// Template to check if a signal is positive.
template IsPositive(nBits) {
    signal input in;
    signal output out;

    // ... R1CS constraints for checking if `in` > 0 ...
    // This would also be a standard but complex component.
}


// Template: Num2Bits
// Decomposes a number into its binary representation.
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc = 0;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0; // enforce bit
        lc = lc + out[i] * (2**i);
    }
    lc === in;
}
