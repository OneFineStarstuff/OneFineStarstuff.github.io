pragma circom 2.1.9;

/*
 * SRC-fair-1 ReasonCodeCheck
 * --------------------------
 * GC-IR obligation ob-ecoa-adverse-reason-codes (gcir_obligation_example.yaml),
 * `circuit` emission target. Constrained predicate subset:
 *   For an adverse, fully-automated credit decision, prove (without revealing the
 *   specific codes) that there are >=2 reason codes and EVERY supplied code is a
 *   member of the approved set.
 *
 * Encoding:
 *   - There are MAXC code slots. Each slot holds an integer code id in [0..K]
 *     where 1..K are valid approved-code ids and 0 means "empty slot".
 *   - present[i] = 1 if slot i is non-empty.
 *   - Constraint A: sum(present) >= 2.
 *   - Constraint B: every non-empty slot's code id is in [1..K] (approved range).
 *     (The approved-set membership is modelled as a contiguous id range [1..K];
 *      the off-chain harness maps symbolic RCxx <-> id and pins the set root.)
 *   - circuit_tag pins SRC-fair-1.
 *
 * Public  : in_scope (1 if adverse&full), min_codes (=2), approved_k (=K), circuit_tag
 * Private : code[MAXC]
 * Output  : compliant (1 iff predicate holds OR not in scope)
 */

include "../node_modules/circomlib/circuits/comparators.circom";

template ReasonCodeCheck(MAXC, K_MAX_BITS, CIRCUIT_TAG) {
    signal input in_scope;       // public: 1 if adverse & fully-automated
    signal input min_codes;      // public: required minimum (2)
    signal input approved_k;     // public: highest valid approved code id (K)
    signal input circuit_tag;    // public: pins circuit identity

    signal input code[MAXC];     // private: code ids, 0 = empty

    circuit_tag === CIRCUIT_TAG;

    // in_scope is boolean
    in_scope * (in_scope - 1) === 0;

    // present[i] = (code[i] != 0)
    signal present[MAXC];
    component isZero[MAXC];
    for (var i = 0; i < MAXC; i++) {
        isZero[i] = IsZero();
        isZero[i].in <== code[i];
        present[i] <== 1 - isZero[i].out;     // 1 if non-empty
    }

    // count = sum(present)
    signal cnt[MAXC+1];
    cnt[0] <== 0;
    for (var i = 0; i < MAXC; i++) { cnt[i+1] <== cnt[i] + present[i]; }
    signal count;
    count <== cnt[MAXC];

    // Constraint A (only enforced in scope): count >= min_codes.
    // enough = (count >= min_codes)
    component geMin = GreaterEqThan(8);
    geMin.in[0] <== count;
    geMin.in[1] <== min_codes;
    signal enough;
    enough <== geMin.out;

    // Constraint B (only enforced in scope): for each non-empty slot, code in [1..K].
    // valid_i = present_i ? (code_i <= K) : 1   (empty slots are vacuously fine)
    component leK[MAXC];
    signal inRange[MAXC];
    signal slotOk[MAXC];
    for (var i = 0; i < MAXC; i++) {
        leK[i] = LessEqThan(K_MAX_BITS);
        leK[i].in[0] <== code[i];
        leK[i].in[1] <== approved_k;
        inRange[i] <== leK[i].out;                 // 1 if code_i <= K
        // slotOk = present ? inRange : 1  ==  1 - present*(1-inRange)
        slotOk[i] <== 1 - present[i] * (1 - inRange[i]);
    }
    // allOk = AND of slotOk  (product is fine; each is boolean)
    signal okAcc[MAXC+1];
    okAcc[0] <== 1;
    for (var i = 0; i < MAXC; i++) { okAcc[i+1] <== okAcc[i] * slotOk[i]; }
    signal allOk;
    allOk <== okAcc[MAXC];

    // predicateHolds = enough AND allOk
    signal predicateHolds;
    predicateHolds <== enough * allOk;

    // compliant = in_scope ? predicateHolds : 1
    //           = 1 - in_scope*(1 - predicateHolds)
    signal compliant;
    compliant <== 1 - in_scope * (1 - predicateHolds);

    // The circuit only produces a witness for COMPLIANT decisions.
    compliant === 1;

    signal output ok;
    ok <== compliant;
}

// MAXC=5 slots, K up to 8 bits, tag = ASCII "FAR1" = 1178686001
component main {public [in_scope, min_codes, approved_k, circuit_tag]} =
    ReasonCodeCheck(5, 8, 1178686001);
