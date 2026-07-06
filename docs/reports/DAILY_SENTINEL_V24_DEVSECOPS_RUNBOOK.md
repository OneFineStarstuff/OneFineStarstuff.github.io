# Daily Sentinel AI v2.4 DevSecOps Operational Check Runbook

This runbook defines the daily evidence pack used to validate the Omni-Sentinel Cognitive Execution Environment for G-SIFI and Fortune 500 financial-services deployments.

## Required checks

1. **Sentinel telemetry/dashboard health** — verify the Sentinel v2.4 dashboard or API endpoint returns a 2xx health result. The default endpoint is `https://sentinel.internal.g-sifi.local`.
2. **Global Systemic Risk Index (G-SRI)** — verify a signed, fresh G-SRI evidence bundle reports `current_value < threshold` under the approved risk-appetite policy version.
3. **PQC WORM audit batches** — verify `pqc_worm_logger.py` committed the latest audit batch to the designated S3 Object Lock bucket, including object version, Object Lock mode, retention-until timestamp, Merkle root, PQC signature algorithm, and commit-lag SLO.
4. **TEE/TPM attestation** — verify fresh attestation evidence reports `PCR_MATCH=true`, trusted TEE status, node identity, PCR policy hash, TPM quote ID, and verifier identity.

## Evidence JSON fields

### G-SRI evidence

```json
{
  "timestamp_utc": "2026-05-29T12:00:00Z",
  "current_value": 0.41,
  "threshold": 0.70,
  "policy_version": "gsri-risk-appetite-2026.05",
  "signed": true
}
```

### WORM evidence

```json
{
  "timestamp_utc": "2026-05-29T12:00:00Z",
  "logger_name": "pqc_worm_logger.py",
  "batch_status": "committed",
  "bucket": "sentinel-object-lock-audit",
  "object_key": "audit/2026/05/29/batch-0001.jsonl",
  "object_version_id": "3HL4kqtJlcpXrof3vjVBH40Nrjfkd",
  "object_lock_mode": "COMPLIANCE",
  "retention_until_utc": "2033-05-29T12:00:00Z",
  "merkle_root": "sha256:abc123",
  "pqc_signature_alg": "ML-DSA-65",
  "pqc_signature_verified": true,
  "commit_lag_seconds": 42
}
```

### TEE/TPM attestation evidence

```json
{
  "timestamp_utc": "2026-05-29T12:00:00Z",
  "PCR_MATCH": true,
  "tee_status": "trusted",
  "node_id": "sentinel-prod-01",
  "pcr_policy_hash": "sha256:def456",
  "tpm_quote_id": "quote-20260529-0001",
  "verifier_id": "attestor-v2.4.3",
  "attestation_signature_verified": true
}
```

## CLI usage

Run a live check with dashboard/API reachability and the designated Object Lock bucket:

```bash
python -m scripts.daily_sentinel_operational_check \
  --gsri-evidence /secure/evidence/gsri.json \
  --worm-evidence /secure/evidence/worm.json \
  --expected-worm-bucket sentinel-object-lock-audit \
  --attestation-evidence /secure/evidence/attestation.json
```

Run an offline evidence-pack check when the dashboard network is intentionally unavailable:

```bash
python -m scripts.daily_sentinel_operational_check \
  --skip-dashboard \
  --gsri-evidence /secure/evidence/gsri.json \
  --worm-evidence /secure/evidence/worm.json \
  --attestation-evidence /secure/evidence/attestation.json
```

Use `--json` for machine-readable CI output. The JSON payload includes `generated_at_utc`, `overall_status`, and a `results` array so CI can route each failed check to the correct control owner. Use `--require-compliance-object-lock` when governance policy forbids S3 Object Lock GOVERNANCE mode for the audit bucket.

## Fail-closed rules

Treat the daily control state as **RED** when any of the following conditions occurs:

- Sentinel dashboard/API health is not 2xx and the outage is not covered by an approved maintenance window.
- G-SRI evidence is missing, stale, unsigned, or at/above the policy threshold.
- `pqc_worm_logger.py` has not committed the latest WORM batch, the bucket does not match the designated Object Lock bucket, Object Lock metadata is missing, retention is expired, the PQC signature is not verified, or commit lag exceeds the SLO.
- TEE/TPM attestation is stale, `PCR_MATCH` is not true, TEE status is not trusted/verified, or the attestation signature is not verified.

## Regulatory mapping

The daily evidence pack supports EU AI Act technical documentation and systemic-risk GPAI monitoring, NIST AI RMF 1.0 and AI 600-1 operational risk management, ISO/IEC 42001 AIMS monitoring evidence, SR 11-7/SR 26-2 model-risk governance, DORA and NIS2 operational-resilience evidence, GDPR accountability, and Basel operational-risk oversight.
