.PHONY: governance-setup governance-deps-check governance-lint governance-validate governance-artifact-inventory governance-policy-test governance-validator-test governance-evidence-manifest governance-evidence-verify governance-evidence-schema governance-report governance-report-schema governance-check-generated

governance-setup:
	python -m pip install -r docs/schemas/requirements-governance.txt

governance-deps-check:
	python docs/schemas/check_dependencies.py

governance-lint:
	yamllint -c .yamllint docs/schemas/agi_asi_governance_profile_2026_2030.yaml
	python -m json.tool docs/schemas/compliance_control_mapping.json > /dev/null

governance-validate: governance-deps-check governance-lint
	python docs/schemas/governance_artifacts_validation.py

governance-artifact-inventory:
	python docs/schemas/validate_artifact_inventory.py

governance-policy-test:
	opa fmt --fail docs/schemas/policies/ai_governance.rego
	opa fmt --fail docs/schemas/policies/ai_governance_test.rego
	opa test docs/schemas/policies/ai_governance.rego docs/schemas/policies/ai_governance_test.rego

governance-validator-test: governance-deps-check
	python docs/schemas/test_governance_artifacts_validation.py -v
	python docs/schemas/test_generate_evidence_bundle.py -v
	python docs/schemas/test_verify_evidence_bundle.py -v
	python docs/schemas/test_validate_evidence_manifest.py -v
	python docs/schemas/test_validate_run_report.py -v
	python docs/schemas/test_run_governance_checks.py -v
	python docs/schemas/test_validate_artifact_inventory.py -v
	python docs/schemas/test_check_generated_artifacts.py -v
	python docs/schemas/test_check_dependencies.py -v
	python docs/schemas/test_validation_deps.py -v

governance-evidence-manifest:
	python docs/schemas/generate_evidence_bundle.py

governance-evidence-verify:
	python docs/schemas/verify_evidence_bundle.py

governance-evidence-schema: governance-deps-check
	python docs/schemas/validate_evidence_manifest.py

governance-report:
	python docs/schemas/run_governance_checks.py --max-tail-chars 1200

governance-report-schema: governance-deps-check
	python docs/schemas/validate_run_report.py

governance-check-generated:
	python docs/schemas/check_generated_artifacts.py
PYTHON ?= python3

.PHONY: gov-manifest gov-manifest-check gov-validate gov-validate-json gov-lint gov-dashboard-check gov-selftest gov-suite gov-suite-json gov-suite-report gov-suite-ci gov-clean

gov-manifest:
	$(PYTHON) governance_blueprint/validation/generate_artifact_manifest.py

gov-manifest-check:
	$(PYTHON) governance_blueprint/validation/generate_artifact_manifest.py --check

gov-validate:
	$(PYTHON) governance_blueprint/validation/validate_artifacts.py

gov-validate-json:
	$(PYTHON) governance_blueprint/validation/validate_artifacts.py --json

gov-lint:
	$(PYTHON) governance_blueprint/validation/lint_python_sources.py

gov-dashboard-check:
	$(PYTHON) governance_blueprint/validation/validate_dashboard_links.py

gov-selftest:
	$(PYTHON) governance_blueprint/validation/selftest_validate_artifacts.py
	$(PYTHON) governance_blueprint/validation/selftest_run_validation_suite.py

gov-suite:
	$(PYTHON) governance_blueprint/validation/run_validation_suite.py

gov-suite-json:
	$(PYTHON) governance_blueprint/validation/run_validation_suite.py --json-report governance-artifact-validation-report.json
	@echo "Wrote governance-artifact-validation-report.json"

gov-suite-report:
	$(PYTHON) governance_blueprint/validation/run_validation_suite.py --json-report governance-artifact-validation-report.json --suite-report governance-validation-suite-report.json
	@echo "Wrote governance-artifact-validation-report.json and governance-validation-suite-report.json"

gov-suite-ci:
	$(PYTHON) governance_blueprint/validation/run_validation_suite.py --quiet --json-report governance-artifact-validation-report.json --suite-report governance-validation-suite-report.json
	@echo "Wrote governance-artifact-validation-report.json and governance-validation-suite-report.json (quiet mode)"

gov-clean:
	$(PYTHON) -c "from pathlib import Path; import shutil; report=Path('governance-artifact-validation-report.json'); suite=Path('governance-validation-suite-report.json'); report.exists() and report.unlink(); suite.exists() and suite.unlink(); [shutil.rmtree(p) for p in Path('governance_blueprint/validation').rglob('__pycache__') if p.is_dir()]"
