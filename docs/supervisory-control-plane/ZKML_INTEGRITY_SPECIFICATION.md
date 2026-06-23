# zkML Pipeline Integrity Specification

This document specifies the protocols for ensuring the integrity of AI model weights and inference results within the Supervisory Control Plane (SCP) using Zero-Knowledge Machine Learning (zkML) techniques.

## 1. Model Weight Attestation
To prevent "shadow models" or unauthorized weight tampering, the SCP enforces a strict attestation flow:
1. **Enclave Loading:** Model weights are loaded only within a verified TEE enclave (AMD SEV-SNP/Intel TDX).
2. **Commitment Hashing:** A Poseidon hash of the model weights is generated and signed using the institutional ML-DSA-65 key.
3. **ZK-Binding:** A Groth16 circuit proves that the loaded weights match the commitment anchored in the **GSM PROD State**.

## 2. Inference Integrity (zkML)
High-risk decisions (e.g., credit approvals, high-value trades) utilize zkML to prove that the inference was executed correctly by the sanctioned model.
- **Circuit:** The ZK Prover executes a circuit that takes the input data and model commitment as public inputs and produces a proof of correct execution.
- **Optimization:** For latency-sensitive G-SIFI workflows, the SCP utilizes "Partial zkML" where only the final sensitive layers or safety guardrails are proven in zero-knowledge.

## 3. Pipeline Health Monitoring
The **GAI-SOC** monitors the following health metrics for the zkML pipeline:
- **Proof Generation Latency:** Threshold < 5000ms for real-time gates.
- **Witness Consistency:** Automated checks ensuring telemetry traces match ZK circuit inputs.
- **Enclave PCR Match:** Continuous vTPM attestation of the ZK Prover nodes.

## 4. Integration with Merkle Log
Every ZK inference proof is hashed and anchored to the institution's daily Merkle root, providing a mathematically non-repudiable link between the model action and the safety proof.
