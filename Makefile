.DEFAULT_GOAL := check-gsifi-governance

.PHONY: validate-gsifi-governance validate-gsifi-governance-module test-gsifi-governance lint-gsifi-governance check-gsifi-governance

validate-gsifi-governance:
	python scripts/validate_gsifi_governance_assets.py

validate-gsifi-governance-module:
	python -m scripts.validate_gsifi_governance_assets

test-gsifi-governance:
	python -m py_compile scripts/validate_gsifi_governance_assets.py tests/conftest.py tests/test_validate_gsifi_governance_assets.py tests/test_validate_gsifi_governance_cli.py
	pytest -q tests

lint-gsifi-governance:
	npx --yes markdownlint-cli@0.39.0 --config docs/reports/.markdownlint.json docs/reports/GSIFI_AGI_ASI_GOVERNANCE_BLUEPRINT_2026_2030.md docs/reports/GSIFI_GOVERNANCE_ARTIFACTS_RUNBOOK.md

check-gsifi-governance: validate-gsifi-governance validate-gsifi-governance-module test-gsifi-governance lint-gsifi-governance
