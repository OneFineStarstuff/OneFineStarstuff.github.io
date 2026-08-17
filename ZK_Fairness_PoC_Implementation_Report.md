# ZK Fairness PoC Implementation Report

## 1. Introduction

This report details the implementation of a proof-of-concept (PoC) for using zero-knowledge proofs (ZKPs) to attest to the fairness of a machine learning (ML) model.

## 2. Methodology

We used the ZoKrates framework to create a zk-SNARK that proves a model's prediction is independent of a sensitive attribute. The following steps were taken:

1.  **Model Training:** A logistic regression model was trained to predict loan approvals based on a dataset containing a sensitive attribute (e.g., gender).
2.  **ZK-SNARK Circuit:** A ZoKrates circuit was created to prove that the model's prediction does not change when the sensitive attribute is changed.
3.  **Proof Generation:** A zk-SNARK proof was generated for a specific prediction.
4.  **Verification:** The proof was verified using the ZoKrates verifier.

## 3. Results

The PoC successfully demonstrated that it is possible to use zk-SNARKs to attest to the fairness of an ML model without revealing the model or the data. The verification process was successful, confirming that the model's prediction was indeed independent of the sensitive attribute.

## 4. Next Steps

The next step is to integrate this fairness attestation into the SCP's policy-as-code engine. This will allow us to create policies that automatically halt models that are found to be unfair.