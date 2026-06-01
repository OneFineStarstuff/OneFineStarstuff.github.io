# G-Stack Artifacts

This folder contains machine-usable governance artifacts and a local validator.

## Files
- `gstack_control_catalog.yaml`: Control catalog with control IDs, mappings, and evidence fields.
- `stress_test_matrix.csv`: Scenario matrix for stress/war-game execution.
- `lifecycle_integrity_report_template.md`: Reporting template for lifecycle attestation.
- `validate_artifacts.py`: CLI validator for artifact structural and semantic checks.

## Usage
```bash
python3 gstack_artifacts/validate_artifacts.py
# or
python3 gstack_artifacts/validate_artifacts.py --root gstack_artifacts
python3 gstack_artifacts/validate_artifacts.py --root gstack_artifacts --strict-schema
python3 gstack_artifacts/validate_artifacts.py --root gstack_artifacts --json
```

## Exit codes
- `0`: all validations passed
- `1`: one or more validations failed

## Notes
- Requires `PyYAML` (provided in `requirements-dev.txt`).
- `--strict-schema` also requires `jsonschema` (provided in `requirements-dev.txt`).


## CI targets
- `make gstack-test-ci`: run unit tests and capture logs to `artifacts/test-results/gstack-unittest.log`.
- `make gstack-validate-strict`: run strict schema validation (requires `jsonschema`).
- `make gstack-validate-json-check`: generate JSON validation report and assert `status == passed`.
- `make gstack-ci`: composite target used by CI to run setup, tests, strict validation, and JSON report checks.

- `make gstack-clean`: remove generated local validation/test artifacts.

- JSON output includes `validator_version` to support traceable automation/audit pipelines.
