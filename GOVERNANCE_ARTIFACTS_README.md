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
