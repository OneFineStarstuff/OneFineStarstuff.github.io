# GSIFI Governance Check Summary

Status: **passed**

| Command | Return code |
|---|---:|
| `/usr/local/bin/python tools/validate_governance_artifacts.py` | 0 |
| `/usr/local/bin/python -m pytest -q --junitxml=artifacts/test-results/gsifi-governance-tests.xml test_governance_snippets.py test_validate_governance_artifacts.py test_run_gsifi_governance_checks.py test_generate_gsifi_governance_report.py test_daily_gsifi_governance_workflow.py` | 0 |
