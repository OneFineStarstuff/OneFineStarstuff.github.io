.PHONY: build-governance-json check-governance-json-clean check-governance-manifest-clean validate-governance test-governance test-governance-ci summarize-governance-tests build-governance-manifest verify-governance

build-governance-json:
	python scripts/export_governance_artifact_json.py --root .

check-governance-json-clean:
	python scripts/export_governance_artifact_json.py --root . --verify

validate-governance:
	python scripts/validate_governance_artifact.py --root .

test-governance:
	pytest -q test_validate_governance_artifact.py test_export_governance_artifact_json.py test_summarize_governance_test_results.py test_governance_artifact_integrity.py test_generate_governance_manifest.py

test-governance-ci:
	mkdir -p artifacts/test-results
	pytest -q test_validate_governance_artifact.py test_export_governance_artifact_json.py test_summarize_governance_test_results.py test_governance_artifact_integrity.py test_generate_governance_manifest.py --junitxml=artifacts/test-results/governance-tests.xml

summarize-governance-tests:
	python scripts/summarize_governance_test_results.py --report artifacts/test-results/governance-tests.xml

build-governance-manifest:
	python scripts/generate_governance_manifest.py --root .

check-governance-manifest-clean:
	python scripts/generate_governance_manifest.py --root . --verify

verify-governance:
	$(MAKE) check-governance-json-clean
	$(MAKE) check-governance-manifest-clean
	$(MAKE) validate-governance
	$(MAKE) test-governance-ci
	$(MAKE) summarize-governance-tests
