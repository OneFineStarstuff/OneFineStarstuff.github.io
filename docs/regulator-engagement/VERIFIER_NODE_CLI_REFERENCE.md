# Verifier Node command-line tool Reference

This reference guide provides technical auditors with the commands and expected outputs for the **Sentinel Verifier Node**, the primary tool for independent verification of institutional AI compliance.

## 1. Environment Setup
Auditors should ensure they have their PQC-compatible environment initialized and the institution's public key imported.

```bash
# Initialize verifier environment
sentinel-verifier init --institution G-SIFI-01

# Import institutional PQC public key
sentinel-verifier keys import --path ./keys/gsifi-01-mldsa65.pub
```

## 2. Verifying Merkle Roots (SIP v3.0)
Verify that the institution's current Signed Tree Head (STH) matches the global GIEN consensus.

```bash
# Fetch and verify current STH
sentinel-verifier roots verify --epoch current
```

**Expected Output:**
```text
[INFO] Fetching root for G-SIFI-01, Epoch 428...
[SUCCESS] PQC Signature Valid (ML-DSA-65)
[SUCCESS] Merkle Root: 0x5f3e... matched GIEN consensus.
```

## 3. Verifying ZK Proof Bundles
Check a specific Decision Trace Pack against its ZK proof and the public Merkle log.

```bash
# Verify a specific proof bundle
sentinel-verifier proofs verify --id PROOF-2028-06-15-XF
```

**Expected Output:**
```text
[INFO] Proof Statement: "Model promotion STAGING -> PROD satisfied fairness circuit V2"
[DEBUG] Checking witnesses against Merkle path...
[DEBUG] Executing Groth16 Verifier...
[SUCCESS] ZK Proof Verified.
```

## 4. Monitoring Attestation Heartbeats
Check if the institution has provided required attestations within the allowed window.

```bash
# Check attestation health
sentinel-verifier heartbeats status
```

**Expected Output:**
```text
Last Attestation: 2028-06-19 09:12:00 UTC
Missing Windows: 0
Status: [HEALTHY]
```

## 5. Detecting Equivocation
Run a consistency check across multiple GIEN Roots to detect forked Merkle logs.

```bash
# Run equivocation check
sentinel-verifier gossip audit --institution G-SIFI-01
```

**Expected Output (Adversarial Detection):**
```text
[ALERT] EQUIVOCATION DETECTED in G-SIFI-01
Epoch: 425
Root A (SG): 0xABCD...
Root B (EU): 0x1234...
[CRITICAL] Generating Equivocation Evidence Pack...
```
