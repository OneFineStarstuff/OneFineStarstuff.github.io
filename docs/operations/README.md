# Omni-Sentinel Daily DevSecOps Operations Evidence

This directory contains daily operational assurance material for the Omni-Sentinel Cognitive Execution Environment.

## Files

- `OMNI_SENTINEL_DAILY_DEVSECOPS_CHECK_2026-05-28.md`: narrative daily check and sign-off worksheet from the original operational review.
- `daily_devsecops_evidence.schema.json`: machine-readable contract for daily evidence bundles covering Sentinel telemetry, internal endpoints, G-SRI, WORM audit batches, TPM/TEE attestations, ZK compliance proofs, deviations, emerging risks, roadmap actions, and sign-off decisions.
- `examples/daily_devsecops_evidence_2026-05-29.json`: current example bundle for 2026-05-29. It is intentionally marked `evidence_required` because production telemetry, AWS Object Lock evidence, and attestation quotes are not stored in this repository.
- `validate_daily_devsecops_evidence.py`: schema and semantic validator for daily evidence bundles.
- `test_validate_daily_devsecops_evidence.py`: unit tests for pass/fail validator behavior.

## Validation

Dry-run/template validation permits missing production evidence:

```bash
python docs/operations/validate_daily_devsecops_evidence.py \
  --bundle docs/operations/examples/daily_devsecops_evidence_2026-05-29.json \
  --allow-evidence-required
```

Certification validation must omit `--allow-evidence-required`. A bundle marked `passed` must include evidence URIs and hashes for every control, G-SRI below the halt threshold, complete WORM batch continuity with S3 Object Lock metadata, TEE measurement match, TPM `pcr_match=true`, accepted ZK verifier output, no open deviations, and approved sign-offs.

```bash
python docs/operations/validate_daily_devsecops_evidence.py \
  --bundle path/to/production-daily-evidence.json
```
