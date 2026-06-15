# Sentinel AI Governance Stack v2.4 Implementation Notes

## MoE Stability Metrics
- **C_res (Alignment Resonance):** Measures expert alignment with safety constraints. Simulated as 0.85-0.95.
- **H_sh (Shannon Routing Entropy):** Quantifies expert selection stability. Simulated as 2.5-3.0.
- **DP_gap (Demographic Parity Gap):** Measures bias in model outcomes. Simulated as <0.04.

## Post-Quantum WORM Audit
- Integration with ML-DSA-65 (Dilithium) and SPHINCS+ for signature veracity.
- Enforcement of S3 Object Lock in COMPLIANCE mode for G-SIFI long-term retention.

## Hardware Attestation
- Mandatory PCR_MATCH=TRUE via vTPM/TEE for all monitoring nodes to prevent man-in-the-middle telemetry spoofing.

## G-SRI Scaling
- G-SRI is scaled to 0-100 range with an intervention threshold of 85.0 for G-SIFI operational risk management.
