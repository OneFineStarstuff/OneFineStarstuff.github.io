# PQC Key Management Policy: G-SIFI AI Governance

This document specifies the policy for managing Post-Quantum Cryptographic (PQC) keys used for signing audit events and verifying identity within the Supervisory Control Plane (SCP).

## 1. Cryptographic Standards
- **Algorithm:** ML-DSA-65 (CRYSTALS-Dilithium) as per NIST FIPS 204.
- **Hybrid Mode:** During the transition period, all signatures will be hybrid (ML-DSA-65 + RSA-4096 or ECDSA P-384) to ensure backward compatibility and immediate security.

## 2. Key Generation & Storage
- **Enclave Root of Trust:** All PQC keys must be generated within an HSM-backed TEE enclave (Security Zone B).
- **No Export:** Private keys never leave the enclave boundary in unencrypted form.
- **Attestation:** Key generation events are recorded in the Merkle log with a vTPM PCR attestation.

## 3. Key Lifecycle
- **Rotation Interval:** 12 months (Standard); 24 hours (Session-based ephemeral keys).
- **Revocation:** Managed via the **SIP v3.0** gossip protocol. A Signed Revocation Token (SRT) is broadcast to all GIEN Roots.
- **Recovery:** M-of-N multi-sig recovery shares stored across geographically dispersed enclaves.

## 4. Regulator Key Access
- **Public Keys:** Institution public keys are published to the GIEN public ledger and included in the **Regulator Takeaway Packet**.
- **Verifier Tokens:** Regulator-specific public keys are used to sign Verifier Node CLI credentials.

## 5. Audit & Compliance
- **Key Access Logs:** All private key usage is recorded in the PQC-WORM audit plane.
- **Policy Enforcement:** OPA/Rego policies gate the use of the PQC-Signer service (e.g., "Require dual-approval for production release signing").
