# Whitepaper: Zero-Knowledge Fairness Attestations

**Document ID:** SCP-WP-001
**Version:** 1.0
**Status:** **Draft**

## 1. Abstract

This whitepaper proposes a novel method for regulators to verify a specific property of an AI model—in this case, a fairness metric—without requiring direct access to the model, its intellectual property, or the sensitive data it processes. We demonstrate how a Zero-Knowledge Succinct Non-Interactive Argument of Knowledge (zk-SNARK) can be used to generate a verifiable, privacy-preserving proof that a model's demographic parity score falls within a regulator-approved range. This represents a significant step towards solving the "black box" problem in AI auditing.

## 2. The Challenge: Auditing with Privacy

Regulators need to verify claims about AI models (e.g., "the model is fair"), but organizations cannot simply expose their proprietary models or the sensitive data used for testing. This creates an auditing impasse. Traditional methods involve trusted third parties and legal agreements, which are slow, costly, and still involve data exposure. Our goal is to replace this trust-based system with a purely mathematical, verifiable one.

## 3. Proposed Solution: zk-SNARK for Fairness

We define fairness for this example as **demographic parity**. A model achieves demographic parity if the rate of positive outcomes is the same across different protected groups (e.g., the loan approval rate for different demographic groups is equal).

Our system works as follows:

1.  **The Assertion:** The model operator wishes to prove the assertion: *"For the official regulator-provided test dataset, the demographic parity score of our model is between 0.98 and 1.02."*

2.  **The ZK Circuit:** We design a zk-SNARK circuit that takes the following as **private inputs**:
    *   The model's weights and parameters.
    *   The confidential test dataset provided by the regulator.

3.  **Circuit Logic:** The circuit performs the following steps internally:
    *   It runs the test dataset through the model to get predictions.
    *   It calculates the demographic parity score based on those predictions.
    *   It checks if this calculated score is within the required range [0.98, 1.02].
    *   If the check passes, the circuit completes successfully.

4.  **Proof Generation:** The model operator runs this circuit to generate a small, cryptographic proof (the zk-SNARK). This proof attests that the circuit ran correctly and that the final check passed.

5.  **Verification:** The operator submits this proof to the SCP. The Regulator Verifier Node can then, using only the **public inputs** (the range [0.98, 1.02]), perform a simple mathematical check on the proof. If the verification passes, the regulator is given mathematical certainty that the assertion is true, even though they have learned nothing about the model, the data, or the exact fairness score.

## 4. Integration with the SCP Sandbox

This process is integrated into our secure enclave architecture:

*   The entire proof generation process happens inside the **secure model enclave**. This is critical, as it ensures the process itself is tamper-proof.
*   The generated proof is cryptographically signed by the enclave's attestation key before being sent to the SCP.
*   This signed proof is then logged as a permanent governance event in the PQC-WORM audit trail, creating an immutable record of the fairness attestation.

## 5. Conclusion & Next Steps

This zk-SNARK based approach offers a path to resolve the conflict between regulatory oversight and commercial privacy. It enables provable, fine-grained audits of AI model properties without forcing the disclosure of sensitive information.

The next step is to move from this theoretical design to a practical implementation, which will be a key focus of the next sandbox phase. The final goal for Q3 is to design the `Human-in-the-Loop` workflow, which complements these automated attestations with a framework for handling exceptions and high-stakes decisions.