.PHONY: governance-test governance-validate governance-validate-json governance-validate-json-check governance-check

governance-test:
	python3 -m unittest discover tool_tests

governance-validate:
	python3 tools/validate_governance_reports.py

governance-validate-json:
	python3 tools/validate_governance_reports.py --json

governance-validate-json-check:
	python3 tools/validate_governance_reports.py --json > /tmp/governance_validation.json
	python3 -c 'import json; p=json.load(open("/tmp/governance_validation.json", "r", encoding="utf-8")); assert p.get("status")=="passed", f"Validator JSON status not passed: {p}"; print("Validator JSON status is passed.")'

governance-check: governance-test governance-validate governance-validate-json-check
