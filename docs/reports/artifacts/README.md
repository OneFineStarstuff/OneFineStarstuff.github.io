# Regulator Blueprint Artifacts (2026–2030)

This folder contains machine-readable artifacts used by the regulator-ready AGI/ASI governance blueprint.

## Files

- `gsifi_governance_policy_profile_2030.yaml`
  Tiered governance profile and threshold controls.
- `tier3_annex_iv_evidence_template.json`
  Annex IV style evidence template for Tier-3 systems.
- `tiered_release_gate.rego`
  Deny-by-default OPA/Rego gate with Tier-4 containment/signoff requirements.
- `regulator_validator_report_schema.json`
  JSON contract for validator output (`ok`, `checks[]`, `name/status/detail`).

## Validation Commands

```bash
# Human-readable validation
python scripts/validate_regulator_blueprint_artifacts.py

# JSON output validation
python scripts/validate_regulator_blueprint_artifacts.py --json

# Combined core + regulator checks
bash scripts/run_blueprint_artifact_checks.sh --skip-install
```

## Notes

- CI workflow: `.github/workflows/regulator-blueprint-validation.yml`
- Make targets:
  - `make validate-regulator-blueprint-artifacts`
  - `make test-regulator-blueprint-artifacts`
  - `make check-regulator-blueprint-artifacts`
