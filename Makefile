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
