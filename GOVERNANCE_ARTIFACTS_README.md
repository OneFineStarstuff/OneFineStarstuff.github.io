# Governance Artifacts Quickstart

This repository includes a daily G-SIFI AGI/ASI governance package with
canonical artifacts, policy sketches, and validation tooling.

## Files
- `DAILY_GSIFI_AGI_ASI_GOVERNANCE_2026_2030.md`
- `artifacts/daily_governance_report.schema.json`
- `artifacts/daily_governance_report.example.json`
- `policies/sentinel_governance.rego`
- `tools/validate_governance_artifacts.py`
- `test_governance_snippets.py`
- `test_validate_governance_artifacts.py`

## Local Validation
Install governance check dependencies:

```bash
pip install -r requirements-governance-checks.txt
```

Run Python syntax checks:

```bash
make daily-gsifi-governance-pycompile
```

Run the full combined check suite:

```bash
make daily-gsifi-governance-checks
```

Run the canonical validator:

```bash
python tools/validate_governance_artifacts.py
# or
make daily-gsifi-governance-validate
```

Run the unit tests:

```bash
pytest -q test_governance_snippets.py test_validate_governance_artifacts.py test_run_gsifi_governance_checks.py test_generate_gsifi_governance_report.py test_daily_gsifi_governance_workflow.py
# or
make daily-gsifi-governance-test
```

Generate a JUnit report locally:

```bash
mkdir -p artifacts/test-results
pytest -q --junitxml=artifacts/test-results/gsifi-governance-tests.xml \
  test_governance_snippets.py test_validate_governance_artifacts.py test_run_gsifi_governance_checks.py test_generate_gsifi_governance_report.py test_daily_gsifi_governance_workflow.py
```

## CI
CI workflow:
- `.github/workflows/daily-gsifi-governance-validation.yml`

It runs:
1. `make daily-gsifi-governance-ci`
2. Uploads JUnit + JSON run-summary artifacts.


Generate JUnit + JSON run evidence:

```bash
make daily-gsifi-governance-evidence
```
This repository includes machine-readable governance artifacts for AI controls:

- `schemas/bbom.schema.json`
- `schemas/arre_record.schema.json`
- `artifacts/bbom/*.json`
- `examples/arre/*.json`
- `tools/validate_ai_governance_artifacts.py`

## Local validation

```bash
python -m pip install -r requirements-governance.txt
python tools/validate_ai_governance_artifacts.py
```

## Custom paths

```bash
python tools/validate_ai_governance_artifacts.py \
  --bbom-dir artifacts/bbom \
  --arre-dir examples/arre \
  --arre-dir evidence/arre
```

## CI

Validation is enforced in `.github/workflows/governance-artifacts.yml`.

The validator enforces both JSON Schema compliance and semantic checks (for example BBOM threshold conformance and ARRE period consistency).

Additional semantic checks include date format validation (via JSON Schema format checking) and duplicate ARRE evidence hash detection.

Generate an auditable machine-readable summary report:

```bash
python tools/validate_ai_governance_artifacts.py --report-file .reports/governance-validation.json
```

Report output includes discovered/checked counters, `passed_files`, `failed_files`, and `errors` for audit trails.

The GitHub Actions workflow also uploads the report as a CI artifact (`governance-validation-report`) for audit retention.

When schema loading fails, reports include `fatal_error: "schema_load_failure"` and the associated error in `errors`.

Report output also includes `validator_version` and overall `status` (`passed`/`failed`) for easier pipeline gating.

Reports include `exit_code` (0 for pass, 2 for validation failure) to simplify CI/CD policy gating.

Per-domain failure counters (`bbom_failed`, `arre_failed`) are included to support targeted remediation dashboards.
