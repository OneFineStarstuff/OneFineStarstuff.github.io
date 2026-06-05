# Omni-Sentinel Security Policy

## High-Stakes AGI/ASI Security

This project manages high-stakes AGI/ASI governance. We operate under a **Zero-Trust** and **Hardware-Root-of-Trust** philosophy.

## Supported Versions

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| v2.4.x  | :white_check_mark: | Active Monitoring (Sentinel AI) |
| v4.0.x  | :white_check_mark: | R&D / Safety Gated (Sentinel ASI) |
| < v2.0  | :x:                | Deprecated |

## Reporting a Vulnerability

Due to the civilizational risk profiles of the models governed by this pipeline, please follow our coordinated disclosure process:

1. **Do NOT open a public issue.**
2. Report all vulnerabilities via encrypted channel to `agi-security@bank.example.com`.
3. Use the provided PGP key (Fingerprint: REDACTED_FOR_DEMO).
4. Our security team will acknowledge within 120 minutes for P0/Critical issues.

## Critical Infrastructure Standards
- **Hardware**: All production environments must utilize TPM 2.0 and TEE (Intel TDX/AMD SEV-SNP).
- **Audit**: All logs are PQC-signed and stored on simulated S3 Object Lock (WORM).
- **G-SRI**: Systemic Risk Index breaches (>0.75) result in automated GRACEFUL_HALT.
